package discovery

import (
	"testing"
	"time"
)

func TestLooksLikeJudgesByContentNotHostname(t *testing.T) {
	cases := map[string][]string{
		"Splunk": {`10-23-2026 18:00:01.123 +0000 INFO  AuditLogger - Audit:[timestamp=10-23-2026 18:00:01.123, user=splunk-system-user, action=validate_token, info=succeeded]`,
			`10-23-2026 18:00:02 splunkd started (build abc)`},
		"Palo Alto firewall":             {`<14>Oct 23 18:00:01 PA-440 1,2026/10/23 18:00:01,012801012345,TRAFFIC,end,2561,2026/10/23 18:00:01,10.0.0.5,8.8.8.8`},
		"Cisco ASA / Firepower firewall": {`<166>Oct 23 2026 18:00:01: %ASA-6-302013: Built outbound TCP connection 1 for outside:8.8.8.8/53`},
		"Fortinet FortiGate firewall":    {`date=2026-10-23 time=18:00:01 devname="FGT60F" devid="FGT60F123" logid="0000000013" type="traffic"`},
		"Windows events":                 {`<13>Oct 23 18:00:01 DC01 MSWinEventLog	1	Security	123	Thu Oct 23 18:00:01 2026	4624	Microsoft-Windows-Security-Auditing`},
		"DNS server":                     {`Oct 23 18:00:01 dns01 named[1234]: client 10.0.0.1#5353: query: example.com IN A + (10.0.0.2)`},
		"Acme Widget (CEF)":              {`CEF:0|Acme|Widget|1.0|100|Login|5|src=10.0.0.1`},
		"syslog from myapp":              {`<13>Oct 23 18:00:01 host01 myapp[22]: hello`},
		"unknown":                        {`just some text`},
	}
	for want, lines := range cases {
		if got := looksLike(lines); got != want {
			t.Errorf("looksLike(%q) = %q, want %q", lines[0], got, want)
		}
	}
}

func TestPayloadShapeAndActivity(t *testing.T) {
	cases := map[string][]string{
		"HL7-structured":  {`MSH|^~\&|SYNGO|MRI|EPIC|HOSP|202610231800||ADT^A01|123|P|2.5`},
		"XML-structured":  {`<AuditMessage><EventIdentification EventActionCode="R"/></AuditMessage>`},
		"JSON":            {`{"event":"login","user":"jdoe"}`},
		"key-value":       {`badge=1234 door=ER-2 result=granted reader=7 ts=1792000000`},
		"comma-separated": {`a,b,c,d,e,f,g,h,i,j`},
		"plain text":      {`hello world`},
	}
	for want, lines := range cases {
		if got := payloadShape(lines); got != want {
			t.Errorf("payloadShape(%q) = %q, want %q", lines[0], got, want)
		}
	}
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	for want, ago := range map[string]time.Duration{"sending": 5 * time.Minute, "intermittent": 3 * time.Hour, "silent": 48 * time.Hour} {
		if got := activityOf(now.Add(-ago), now); got != want {
			t.Errorf("activityOf(-%v) = %q, want %q", ago, got, want)
		}
	}
}
