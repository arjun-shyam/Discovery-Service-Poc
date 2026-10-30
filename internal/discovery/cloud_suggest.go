package discovery

import (
	"context"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- "Here's what your Arctic Wolf team told me you run" (UC-03 cloud sensors step) ---
//
// The cloud information section (Rendall cloud-service-configuration: cloud services and endpoint
// security tools) says what the customer runs. The integrations that match are offered first.

// cloudKeywords maps a cloud-information answer to words in integration names or types.
var cloudKeywords = map[string][]string{
	"office365": {"microsoft 365", "office 365", "office365", "entra", "azure ad", "defender"},
	"gcp":       {"google workspace", "google cloud", "gcp"},
	"aws_cloud": {"aws"}, "cloud_trail": {"cloudtrail"}, "guard_duty": {"guardduty"}, "security_hub": {"security hub", "securityhub"}, "waf": {"waf"},
	"crowdstrike": {"crowdstrike"}, "crowdstrikecontainment": {"crowdstrike"}, "sentinelone": {"sentinelone", "sentinel one"},
	"sophos": {"sophos"}, "microsoftdefender": {"defender"}, "carbonblack": {"carbon black", "carbonblack"},
	"ciscosecure": {"cisco secure"}, "cylance": {"cylance"}, "meraki": {"meraki"}, "webroot": {"webroot"},
	"kaspersky": {"kaspersky"}, "paloalto": {"palo alto", "cortex"}, "symantec": {"symantec"}, "mcafee": {"mcafee", "trellix"},
	"trendmicro": {"trend micro", "trendmicro"},
}

// cloudAnswers reads the cloud information answers (cloud types, AWS services, endpoint tools).
func (s *Service) cloudAnswers(ctx context.Context, org upstream.Organization) map[string]string {
	var cfg struct {
		Data map[string]any `json:"data"`
	}
	out := map[string]string{}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/cloud-service-configuration", &cfg); err != nil {
		return out
	}
	items, _ := cfg.Data["cloudServices"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		t, _ := m["cloud_type"].(string)
		if t != "" {
			out[t] = "you said you use " + map[string]string{"office365": "Microsoft 365", "gcp": "Google", "aws_cloud": "AWS"}[t]
		}
		for _, svc := range anyStrings(m["service_type"]) {
			out[svc] = "you said you use AWS " + strings.ReplaceAll(svc, "_", " ")
		}
	}
	for _, e := range anyStrings(cfg.Data["endpointSolutions"]) {
		out[e] = "you said you use " + e + " for endpoint security"
	}
	return out
}

// suggestionFor says why an integration matches the customer's cloud information ("" = no match).
func suggestionFor(answers map[string]string, sc upstream.IntegrationSchema) string {
	return suggestionForName(answers, sc.IntegrationName+" "+sc.DeploymentType)
}

func suggestionForName(answers map[string]string, nameAndType string) string {
	hay := strings.ToLower(nameAndType)
	for answer, why := range answers {
		for _, kw := range cloudKeywords[answer] {
			if strings.Contains(hay, kw) {
				return why
			}
		}
	}
	return ""
}
