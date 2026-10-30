package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// ChangeSetLogSourceParser saves the parser (and optionally the timezone) a customer confirmed
// for a sensor log source. The log source settings in XConf require a support ticket on every
// change, so applying it first opens a Zendesk ticket for the customer (Rendall createTicket),
// then saves through the Log Source Orchestrator with that ticket as X-Ticket. Where LSO isn't
// available, the ticket carries the exact change for Arctic Wolf staff to apply.
const ChangeSetLogSourceParser = "set_log_source_parser"

const zendeskTicketURL = "https://arcticwolf.zendesk.com/agent/tickets/"

var (
	parserNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$`)
	utcOffsetPattern  = regexp.MustCompile(`^[+-](0\d|1[0-4]):[0-5]\d$`)
)

// parserTarget is what a parser change needs at apply time (kept off the card).
type parserTarget struct {
	source, deployment, oldParser, parser, oldTimezone, timezone string
}

func (s *Service) prepareParserChange(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	miss := missing(params, "source", "parser")
	if len(miss) > 0 {
		return miss, nil
	}
	parser, timezone := str(params, "parser"), str(params, "timezone")
	if !parserNamePattern.MatchString(parser) {
		return nil, fmt.Errorf("%w: %q is not a valid parser name", ErrChangeInvalid, parser)
	}
	if timezone != "" && !utcOffsetPattern.MatchString(timezone) {
		return nil, fmt.Errorf("%w: timezone must be a UTC offset such as +05:30 or -06:00", ErrChangeInvalid)
	}

	views, _, _, _, err := s.allLogSources(ctx, org)
	if err != nil {
		return nil, err
	}
	var found *LogSourceView
	var sensors []string
	for i := range views {
		if !strings.EqualFold(views[i].Name, str(params, "source")) {
			continue
		}
		if sensor := str(params, "sensor"); sensor != "" && !strings.EqualFold(views[i].Sensor, sensor) {
			continue
		}
		sensors = append(sensors, views[i].Sensor)
		if found == nil {
			found = &views[i]
		}
	}
	switch {
	case len(sensors) > 1:
		return nil, fmt.Errorf("%w: %q arrives on more than one sensor (%s); ask which one and pass it as sensor", ErrChangeInvalid, str(params, "source"), strings.Join(sensors, ", "))
	case found == nil:
		return nil, fmt.Errorf("%w: no log source named %q; use list_log_sources to find the exact name", ErrChangeInvalid, str(params, "source"))
	case found.Sensor == "":
		return nil, fmt.Errorf("%w: the sensor %q arrives on is unknown (the Log Source Service isn't reachable); try again later", ErrChangeInvalid, found.Name)
	case found.Parser == parser && (timezone == "" || timezone == found.Timezone):
		return nil, fmt.Errorf("%w: %q already uses %s", ErrChangeInvalid, found.Name, parser)
	}

	// A source with no parser yet is added to Arctic Wolf's log source settings, which need a
	// timezone too (LSO refuses a parser alone). Keep the one LSS reports if it's an offset,
	// otherwise assume UTC and say so on the card.
	defaultedTZ := false
	if timezone == "" && found.Parser == "" {
		timezone, defaultedTZ = "+00:00", true
		if utcOffsetPattern.MatchString(found.Timezone) {
			timezone = found.Timezone
		}
	}

	t := &parserTarget{source: found.Name, deployment: found.Sensor, oldParser: orDefault(found.Parser, "none"),
		parser: parser, oldTimezone: found.Timezone, timezone: timezone}
	ch.parser = t
	ch.Title = "Use parser " + parser + " for " + found.Name
	body := map[string]any{"configured_parser": parser}
	if timezone != "" {
		body["configured_timezone"] = timezone
	}
	ch.Body = body
	ch.Details = []ChangeDetail{
		{"Log source", found.Name},
		{"Sensor", found.Sensor},
		{"Parser", t.oldParser + " → " + parser},
	}
	if timezone != "" {
		tzLine := orDefault(found.Timezone, "not set") + " → " + timezone
		if defaultedTZ {
			tzLine = timezone + " (assumed; change it if the device logs in local time)"
		}
		ch.Details = append(ch.Details, ChangeDetail{"Timezone", tzLine})
	}
	ch.Details = append(ch.Details, ChangeDetail{"Record", "A support ticket is opened for this change (required for every log source setting change)"})
	if s.up.LSOEnabled() {
		ch.Method, ch.Path = "PUT", "/api/v1/customers/"+org.ID+"/deployments/"+found.Sensor+"/log-sources/"+found.Name+"/"
		ch.Assumptions = []string{"Saved through the Log Source Orchestrator into Arctic Wolf's log source settings (XConf); takes effect when the pipeline next reads them, usually within 10 minutes."}
	} else {
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/tickets"
		ch.Assumptions = []string{"Self-service saving isn't available in this region yet: the ticket asks Arctic Wolf staff to apply exactly this change."}
	}
	return nil, nil
}

// applyParserChange opens the ticket, then saves through LSO when it's available.
// It returns the ticket URL and a one-line outcome for the customer.
func (s *Service) applyParserChange(ctx context.Context, org upstream.Organization, ch Change) (string, string, error) {
	t := ch.parser
	if t == nil {
		return "", "", fmt.Errorf("%w: change has no log source target", ErrChangeInvalid)
	}
	requester := "the customer"
	if token, err := upstream.TokenFrom(ctx); err == nil {
		if email := jwtEmail(token); email != "" {
			requester = email
		}
	}
	timezoneLine := "unchanged"
	if t.timezone != "" {
		timezoneLine = orDefault(t.oldTimezone, "not set") + " → " + t.timezone
	}
	description := fmt.Sprintf("Log source parser change confirmed in Aurora by %s (change %s).\n\n"+
		"Log source: %s\nSensor (deployment): %s\nParser: %s → %s\nTimezone: %s\n",
		requester, ch.ID, t.source, t.deployment, t.oldParser, t.parser, timezoneLine)
	if !s.up.LSOEnabled() {
		description += "\nSelf-service saving isn't available for this organization yet. Please apply this change."
	} else {
		description += "\nAurora saves this change through the Log Source Orchestrator; this ticket is its audit record."
	}
	var id string
	if os.Getenv("DISCOVERY_LOCAL_TICKETS") == "1" {
		// Local end-to-end runs (local LSO + XConf): no Zendesk ticket is created.
		id = "LOCAL-" + strings.TrimPrefix(ch.ID, "chg_")
		log.Printf("apply_change %s: local test ticket %s (DISCOVERY_LOCAL_TICKETS=1); ticket text:\n%s", ch.ID, id, description)
	} else {
		var err error
		id, err = s.up.CreateTicket(ctx, org.Pod, org.ID, upstream.TicketInput{
			Subject:     "Log source parser change: " + t.source + " → " + t.parser,
			Description: description,
			Tags:        []string{"aurora_self_service", "log_source_parser_change"},
		})
		if err != nil {
			return "", "", fmt.Errorf("could not open the support ticket this change needs: %w", err)
		}
	}
	ticketURL := zendeskTicketURL + id

	if !s.up.LSOEnabled() {
		return ticketURL, "Ticket #" + id + " opened: Arctic Wolf staff will apply the parser change.", nil
	}
	body := map[string]any{"configured_parser": t.parser}
	if t.timezone != "" {
		body["configured_timezone"] = t.timezone
	}
	reason := "Customer confirmed in Aurora (change " + ch.ID + ")"
	if err := s.up.LSOUpdateLogSource(ctx, org.Pod, org.ID, t.deployment, t.source, body, reason, ticketURL); err != nil {
		log.Printf("apply_change %s: LSO save failed, ticket %s left for staff: %v", ch.ID, id, err)
		return ticketURL, "NOT saved automatically (" + shortReason(err) + "). Ticket #" + id + " asks Arctic Wolf staff to apply it; until then the source stays unparsed.", nil
	}
	s.markParserPending(org.ID, t.deployment, t.source, t.parser)
	return ticketURL, "Saved (ticket #" + id + " records it). It takes effect within about 10 minutes; until then the source shows as pending.", nil
}

// jwtEmail reads the Arctic Wolf email claim from a token without verifying it (display only).
func jwtEmail(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	for _, key := range []string{"https://rtkwlf.io/email", "email"} {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// shortReason keeps the useful part of an upstream error for the customer.
func shortReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "invalid request: "); i >= 0 {
		msg = msg[i+len("invalid request: "):]
	}
	if i := strings.Index(msg, `","`); i >= 0 {
		msg = msg[:i]
	}
	msg = strings.Trim(msg, `"{}`)
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}

// pendingParser is a parser saved through LSO that LSS hasn't reported yet.
type pendingParser struct {
	parser string
	at     time.Time
}

const pendingParserTTL = 24 * time.Hour

func pendingKey(orgID, deployment, source string) string {
	return orgID + "|" + strings.ToLower(deployment) + "|" + strings.ToLower(source)
}

func (s *Service) markParserPending(orgID, deployment, source, parser string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pending == nil {
		s.pending = map[string]pendingParser{}
	}
	s.pending[pendingKey(orgID, deployment, source)] = pendingParser{parser: parser, at: s.now()}
	invalidateLogSources(s, orgID)
}

// applyPending marks sources whose saved parser LSS hasn't reported yet as "pending".
func (s *Service) applyPending(orgID string, views []LogSourceView) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for i := range views {
		key := pendingKey(orgID, views[i].Sensor, views[i].Name)
		p, ok := s.pending[key]
		if !ok {
			continue
		}
		switch {
		case s.now().Sub(p.at) > pendingParserTTL:
			delete(s.pending, key)
		case views[i].ParserStatus == ParserConfigured && views[i].Parser == p.parser:
			delete(s.pending, key) // LSS caught up
		default:
			views[i].ParserStatus, views[i].Parser = ParserPending, p.parser
		}
	}
}
