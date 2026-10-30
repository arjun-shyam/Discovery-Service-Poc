package discovery

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- What a log source is, judged from its lines (not its hostname) ---
//
// Hostnames mislead ("OT-W2-HVFWD-02" is a Splunk heavy forwarder, not a firewall). When asked, the
// source list reads two or three of LSS's example lines per source and labels each with fixed rules.

type looksRule struct {
	label string
	re    *regexp.Regexp
}

// Order matters: the first match wins.
var looksRules = []looksRule{
	{"Palo Alto firewall", regexp.MustCompile(`,\d{12},(TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|HIPMATCH|USERID|DECRYPTION),|(?i)PAN-OS|paloalto`)},
	{"Cisco ASA / Firepower firewall", regexp.MustCompile(`%(ASA|FTD)-\d`)},
	{"Fortinet FortiGate firewall", regexp.MustCompile(`devname=\S+.*logid=|logid=\S+.*devname=|FortiGate`)},
	{"Check Point firewall", regexp.MustCompile(`(?i)checkpoint|product:\s*"?VPN-1`)},
	{"SonicWall firewall", regexp.MustCompile(`(?i)\bid=firewall\b|sonicwall`)},
	{"Sophos firewall", regexp.MustCompile(`(?i)sophos.*(firewall|xg)|device_name="SFW"`)},
	{"Juniper / NetScreen firewall", regexp.MustCompile(`(?i)RT_FLOW|NetScreen`)},
	{"Windows events", regexp.MustCompile(`(?i)MSWinEventLog|EventID[=:]\s*\d|Microsoft-Windows-`)},
	{"Splunk", regexp.MustCompile(`(?i)splunkd|splunk|audit.*action=.*(token|search)`)},
	{"DNS server", regexp.MustCompile(`named\[\d+\]|\bquery: \S+ IN `)},
	{"DHCP server", regexp.MustCompile(`(?i)dhcpd|DHCPACK|DHCPREQUEST`)},
	{"Linux auth (SSH / sudo)", regexp.MustCompile(`\b(sshd|sudo|su)\[\d+\]`)},
	{"Network switch / router", regexp.MustCompile(`%[A-Z0-9_]+-\d-[A-Z0-9_]+:|%LINK-|%LINEPROTO-`)},
	{"Web proxy", regexp.MustCompile(`(?i)squid|zscaler|bluecoat|TCP_(MISS|HIT)`)},
	{"VMware ESXi / vCenter", regexp.MustCompile(`(?i)vmkernel|hostd|vpxa|vcenter`)},
}

var cefHeader = regexp.MustCompile(`CEF:\d\|([^|]*)\|([^|]*)\|`)
var leefHeader = regexp.MustCompile(`LEEF:[\d.]+\|([^|]*)\|([^|]*)\|`)
var syslogProgram = regexp.MustCompile(`^(?:<\d+>)?(?:\d?\s*)?(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+|\d{4}-\d\d-\d\dT[\d:.]+\S*)\s+\S+\s+([A-Za-z][\w./-]{1,40})(?:\[\d+\])?:`)

// looksLike labels a source from a few of its lines; "" when the lines say nothing recognisable.
func looksLike(lines []string) string {
	joined := strings.Join(lines, "\n")
	for _, r := range looksRules {
		if r.re.MatchString(joined) {
			return r.label
		}
	}
	for _, l := range lines {
		if m := cefHeader.FindStringSubmatch(l); m != nil {
			return strings.TrimSpace(m[1] + " " + m[2] + " (CEF)")
		}
		if m := leefHeader.FindStringSubmatch(l); m != nil {
			return strings.TrimSpace(m[1] + " " + m[2] + " (LEEF)")
		}
	}
	for _, l := range lines {
		if m := syslogProgram.FindStringSubmatch(l); m != nil {
			return "syslog from " + m[1]
		}
	}
	return "unknown"
}

const maxPeek = 8

// peekSamples labels the first sources (in place) from LSS example lines, in parallel.
func (s *Service) peekSamples(ctx context.Context, org upstream.Organization, sources []LogSourceView) {
	var wg sync.WaitGroup
	for i := range sources[:min(maxPeek, len(sources))] {
		if sources[i].Sensor == "" {
			continue
		}
		wg.Add(1)
		go func(v *LogSourceView) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			lines, err := s.up.LSSExampleLines(cctx, org.Pod, v.Sensor, v.Name)
			if err != nil || len(lines) == 0 {
				v.LooksLike = "unknown (no sample lines yet)"
				return
			}
			lines = lines[:min(3, len(lines))]
			v.LooksLike = looksLike(lines)
			v.Payload = payloadShape(lines)
			sample := lines[0]
			if len(sample) > 200 {
				sample = sample[:200] + "…"
			}
			v.Sample = sample
		}(&sources[i])
	}
	wg.Wait()
}

var (
	xmlShape  = regexp.MustCompile(`<\?xml|<[A-Za-z][\w:.-]*(\s+[\w:.-]+="[^"]*")*\s*>.*</[A-Za-z][\w:.-]*>`)
	hl7Shape  = regexp.MustCompile(`MSH\|\^~\\&|\r?(PID|EVN|OBR|ORC)\|`)
	jsonShape = regexp.MustCompile(`\{\s*"[^"]+"\s*:`)
	kvPair    = regexp.MustCompile(`\b[A-Za-z_][\w.-]*=("[^"]*"|\S+)`)
	csvShape  = regexp.MustCompile(`^[^,]*(,[^,]*){8,}$`)
)

// payloadShape describes how a source's lines are structured, for sources nobody recognises yet.
func payloadShape(lines []string) string {
	joined := strings.Join(lines, "\n")
	switch {
	case cefHeader.MatchString(joined):
		return "CEF"
	case leefHeader.MatchString(joined):
		return "LEEF"
	case hl7Shape.MatchString(joined):
		return "HL7-structured"
	case xmlShape.MatchString(joined):
		return "XML-structured"
	case jsonShape.MatchString(joined):
		return "JSON"
	}
	kv, csv := 0, 0
	for _, l := range lines {
		if len(kvPair.FindAllString(l, -1)) >= 4 {
			kv++
		}
		if csvShape.MatchString(l) {
			csv++
		}
	}
	switch {
	case kv > 0 && kv*2 >= len(lines):
		return "key-value"
	case csv > 0 && csv*2 >= len(lines):
		return "comma-separated"
	}
	return "plain text"
}

// activityOf says how steadily a source is sending, from when LSS last saw it.
func activityOf(lastSeen, now time.Time) string {
	switch age := now.Sub(lastSeen); {
	case lastSeen.IsZero():
		return "unknown"
	case age <= 15*time.Minute:
		return "sending"
	case age <= 24*time.Hour:
		return "intermittent"
	default:
		return "silent"
	}
}
