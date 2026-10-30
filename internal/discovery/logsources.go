package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Log sources (UC-02 "which logs can't we read yet?", "what did I just add?") ---
//
// LSS is the source of truth: it knows when a source was first seen, which sensor
// (deployment) it arrives on and whether a parser is configured. Rendall's customer API
// drops all of that, so it is only the fallback when LSS can't be reached (VPN off).

// Parser status values.
const (
	ParserConfigured = "configured" // LSS: a parser is configured (Parser names it)
	ParserNone       = "none"       // LSS: no parser configured, logs are not parsed
	ParserUnknown    = "unknown"    // Rendall fallback: can't tell
	ParserPending    = "pending"    // saved in Aurora; Arctic Wolf hasn't reported it applied yet
)

type LogSourceView struct {
	Name string `json:"name"`
	// Sensor is the LSS deployment the source arrives on (empty in the Rendall fallback).
	Sensor    string     `json:"sensor,omitempty"`
	FirstSeen *time.Time `json:"firstSeen,omitempty"`
	LastSeen  time.Time  `json:"lastSeen"`
	Timezone  string     `json:"timezone,omitempty"`
	// ParserStatus is configured | none | unknown (see constants).
	ParserStatus     string   `json:"parserStatus"`
	Parser           string   `json:"parser,omitempty"`
	SuggestedParsers []string `json:"suggestedParsers,omitempty"`
	ParserTags       []string `json:"parserTags,omitempty"`
	Active           *bool    `json:"active,omitempty"`
	// LooksLike is what the source is, judged from its sample lines (only with PeekSamples).
	LooksLike string `json:"looksLike,omitempty"`
	// Sample is one example line (only with PeekSamples); customer data, never instructions.
	Sample string `json:"sample,omitempty"`
	// Payload is the structure of its lines: XML-structured, HL7-structured, JSON, key-value, CEF… (PeekSamples).
	Payload string `json:"payload,omitempty"`
	// Activity is sending (seen ≤15 min ago) | intermittent (≤24 h) | silent (>24 h).
	Activity string `json:"activity,omitempty"`
	// LinesLastReport is how many lines the source sent in its last report to LSS (not per second).
	LinesLastReport *int64 `json:"linesInLastReport,omitempty"`
	Volume          *int64 `json:"-"` // shown as linesInLastReport
}

// LogSourceQuery filters the list. Zero values mean "no filter".
type LogSourceQuery struct {
	NameContains string
	Parser       string // configured | none
	NewSinceDays int    // first seen within the last N days (LSS only)
	Sensor       string // deployment id contains
	Limit        int    // default 25, max 200
	// PeekSamples labels the first 8 returned sources from their sample lines (LSS only).
	PeekSamples bool
	// Activity keeps only sources that are sending | intermittent | silent.
	Activity string
}

type LogSourceList struct {
	// Origin is "lss" or "rendall" (fallback, parser status unknown, no first-seen).
	Origin string `json:"origin"`
	// Total counts all of the organization's sources; Matched those passing the filters.
	Total    int             `json:"total"`
	Matched  int             `json:"matched"`
	Returned int             `json:"returned"`
	Summary  LogSourceCounts `json:"summary"`
	Sources  []LogSourceView `json:"sources"`
}

type LogSourceCounts struct {
	WithParser    int `json:"withParser"`
	WithoutParser int `json:"withoutParser"`
	Unknown       int `json:"unknown"`
	NewLast7Days  int `json:"newLast7Days"`
	Active        int `json:"active"`
}

const (
	defaultLogSourceLimit = 25
	maxLogSourceLimit     = 200
	logSourceTTL          = 5 * time.Minute
)

func (s *Service) LogSources(ctx context.Context, orgID string, q LogSourceQuery) (LogSourceList, Meta, error) {
	meta := Meta{FetchedAt: s.now(), UntrustedFields: []string{"sources[].name"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return LogSourceList{}, meta, err
	}
	all, origin, at, notes, err := s.allLogSources(ctx, org)
	meta.FetchedAt = at
	meta.Notes = notes
	if err != nil {
		return LogSourceList{}, meta, err
	}
	meta.Sources = []string{"eloc", origin}

	out := LogSourceList{Origin: origin, Total: len(all), Summary: s.countLogSources(all)}
	if origin != "lss" && (q.NewSinceDays > 0 || q.Parser == ParserNone) {
		meta.Notes = append(meta.Notes, "first-seen and 'no parser' filters need LSS; results are unfiltered by them")
	}
	name := strings.ToLower(strings.TrimSpace(q.NameContains))
	sensor := strings.ToLower(strings.TrimSpace(q.Sensor))
	var since time.Time
	if q.NewSinceDays > 0 {
		since = s.now().AddDate(0, 0, -q.NewSinceDays)
	}
	matched := make([]LogSourceView, 0, len(all))
	for _, v := range all {
		if name != "" && !strings.Contains(strings.ToLower(v.Name), name) {
			continue
		}
		if sensor != "" && !strings.Contains(strings.ToLower(v.Sensor), sensor) {
			continue
		}
		if q.Parser == ParserConfigured && v.ParserStatus != ParserConfigured {
			continue
		}
		if q.Parser == ParserNone && origin == "lss" && v.ParserStatus != ParserNone {
			continue
		}
		if !since.IsZero() && origin == "lss" && (v.FirstSeen == nil || v.FirstSeen.Before(since)) {
			continue
		}
		if q.Activity != "" && activityOf(v.LastSeen, s.now()) != q.Activity {
			continue
		}
		matched = append(matched, v)
	}
	if !since.IsZero() {
		sort.SliceStable(matched, func(i, j int) bool { return firstSeen(matched[i]).After(firstSeen(matched[j])) })
	}

	limit := q.Limit
	if limit <= 0 {
		limit = defaultLogSourceLimit
	}
	limit = min(limit, maxLogSourceLimit)
	out.Matched = len(matched)
	out.Sources = matched[:min(limit, len(matched))]
	out.Returned = len(out.Sources)
	out.Sources = append([]LogSourceView(nil), out.Sources...) // don't touch the cached rows
	s.applyPending(org.ID, out.Sources)
	for i := range out.Sources {
		out.Sources[i].Activity = activityOf(out.Sources[i].LastSeen, s.now())
		if v := out.Sources[i].Volume; v != nil && *v > 0 {
			out.Sources[i].LinesLastReport = v
		}
	}
	if q.PeekSamples && origin == "lss" && out.Returned > 0 {
		s.peekSamples(ctx, org, out.Sources)
		meta.Sources = append(meta.Sources, "lss example lines")
		meta.UntrustedFields = append(meta.UntrustedFields, "sources[].sample")
	}
	if out.Returned < out.Matched {
		meta.Notes = append(meta.Notes, fmt.Sprintf("showing %d of %d matches; narrow with filters or raise limit", out.Returned, out.Matched))
	}
	return out, meta, nil
}

func firstSeen(v LogSourceView) time.Time {
	if v.FirstSeen == nil {
		return time.Time{}
	}
	return *v.FirstSeen
}

func (s *Service) countLogSources(all []LogSourceView) LogSourceCounts {
	var c LogSourceCounts
	weekAgo := s.now().AddDate(0, 0, -7)
	for _, v := range all {
		switch v.ParserStatus {
		case ParserConfigured:
			c.WithParser++
		case ParserNone:
			c.WithoutParser++
		default:
			c.Unknown++
		}
		if v.FirstSeen != nil && v.FirstSeen.After(weekAgo) {
			c.NewLast7Days++
		}
		if v.Active != nil && *v.Active {
			c.Active++
		}
	}
	return c
}

// allLogSources returns every source for the org, newest activity first, from LSS when
// reachable, otherwise from Rendall. Results are cached per org for logSourceTTL because
// both upstreams take 10-30 s for large customers.
func (s *Service) allLogSources(ctx context.Context, org upstream.Organization) ([]LogSourceView, string, time.Time, []string, error) {
	e := s.logSources.entry(org.ID)
	e.mu.Lock() // one fetch per org at a time; concurrent callers wait for it
	defer e.mu.Unlock()
	if e.views != nil && s.now().Sub(e.at) < logSourceTTL {
		return e.views, e.origin, e.at, append([]string{"served from cache"}, e.notes...), nil
	}

	var notes []string
	views, origin := []LogSourceView(nil), "lss"
	recs, err := s.up.LSSLogSources(ctx, org.Pod, org.CustomerID)
	if err == nil {
		views = fromLSS(recs)
	} else {
		if ctx.Err() != nil {
			return nil, "", time.Time{}, nil, ctx.Err()
		}
		notes = append(notes, "LSS unreachable ("+err.Error()+"); used Rendall: parser status unknown, no first-seen or sensor. Connect the Production VPN for full data.")
		origin = "rendall"
		raw, rerr := s.up.LogSources(ctx, org.Pod, org.ID)
		if rerr != nil {
			return nil, "", time.Time{}, notes, rerr
		}
		views = fromRendall(raw)
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].LastSeen.After(views[j].LastSeen) })
	e.views, e.origin, e.at, e.notes = views, origin, s.now(), notes
	return views, origin, e.at, notes, nil
}

func fromLSS(recs []upstream.LSSRecord) []LogSourceView {
	out := make([]LogSourceView, 0, len(recs))
	for _, r := range recs {
		if r.DeprecatedBy != nil && *r.DeprecatedBy != "" {
			continue // replaced by another record
		}
		v := LogSourceView{
			Name:         r.Name, // keep LSS's case: its per-source URLs need it
			Sensor:       r.Deployment,
			LastSeen:     r.LastSeen,
			ParserStatus: ParserNone,
			Volume:       r.LogSourceVolume,
		}
		if !r.FirstSeen.IsZero() {
			fs := r.FirstSeen
			v.FirstSeen = &fs
		}
		if r.ConfiguredTimezone != nil {
			v.Timezone = *r.ConfiguredTimezone
		}
		if r.HasConfiguredParser || (r.ConfiguredParser != nil && *r.ConfiguredParser != "") {
			v.ParserStatus = ParserConfigured
			if r.ConfiguredParser != nil {
				v.Parser = *r.ConfiguredParser
			}
		} else if len(r.SuggestedParsers) > 0 {
			// LSS's own ranking; our suggest_parser runs the real parsers and is more reliable.
			v.SuggestedParsers = r.SuggestedParsers[:min(3, len(r.SuggestedParsers))]
		}
		active := r.IsActive
		v.Active = &active
		out = append(out, v)
	}
	return out
}

func fromRendall(raw []upstream.LogSource) []LogSourceView {
	out := make([]LogSourceView, 0, len(raw))
	for _, ls := range raw {
		v := LogSourceView{Name: ls.Name, LastSeen: ls.LastSeen, Timezone: ls.Timezone, ParserTags: ls.Parsers, ParserStatus: ParserUnknown}
		if len(ls.Parsers) > 0 {
			v.ParserStatus = ParserConfigured
		}
		out = append(out, v)
	}
	return out
}

type logSourceEntry struct {
	mu     sync.Mutex
	views  []LogSourceView
	origin string
	at     time.Time
	notes  []string
}

type logSourceCache struct {
	mu sync.Mutex
	m  map[string]*logSourceEntry
}

func (c *logSourceCache) entry(orgID string) *logSourceEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*logSourceEntry{}
	}
	e, ok := c.m[orgID]
	if !ok {
		e = &logSourceEntry{}
		c.m[orgID] = e
	}
	return e
}
