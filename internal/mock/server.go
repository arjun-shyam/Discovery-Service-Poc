// Package mock serves fake ELOC and Rendall responses for unit tests only; the service
// itself always calls the real upstreams. All names are invented and labelled MOCK.
package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

const (
	OrgID = "00000000-0000-0000-0000-00000000b4c0"
	Pod   = "mock"
)

// NewServer starts one server that answers both ELOC and Rendall paths.
// LSOCall is one recorded Log Source Orchestrator write.
type LSOCall struct {
	Path, Reason, Ticket string
	Body                 map[string]any
}

var (
	lsoMu    sync.Mutex
	lsoCalls []LSOCall
)

func recordLSO(c LSOCall) {
	lsoMu.Lock()
	defer lsoMu.Unlock()
	lsoCalls = append(lsoCalls, c)
}

// Write is one recorded device write (activation, scanner request, scan schedule).
type Write struct {
	Method, Path string
	Body         map[string]any
}

var (
	writeMu sync.Mutex
	writes  []Write
)

// Writes returns and clears the recorded device writes.
func Writes() []Write {
	writeMu.Lock()
	defer writeMu.Unlock()
	out := writes
	writes = nil
	return out
}

// LSOCalls returns and clears the recorded Log Source Orchestrator writes.
func LSOCalls() []LSOCall {
	lsoMu.Lock()
	defer lsoMu.Unlock()
	out := lsoCalls
	lsoCalls = nil
	return out
}

func NewServer() *httptest.Server {
	now := time.Now().UTC()
	routes := map[string]any{
		"/api/v1/organizations": []map[string]string{
			{"id": OrgID, "name": "MOCK Bacon Security", "customerID": "mock-cust", "pod": Pod},
		},
		"/api/v2/organizations/" + OrgID + "/sites": []map[string]any{
			{"uuid": "site-topeka", "name": "MOCK Topeka Clinic", "time_zone": "America/Chicago"},
			{"uuid": "site-hq", "name": "MOCK Head Office", "time_zone": "America/New_York"},
		},
		"/api/v2/organizations/" + OrgID + "/sites/site-topeka/sensors": []map[string]any{
			{"uuid": "sensor-1", "shorthand": "MOCK-TOP-SENSOR", "deployment": "dep-123", "deployment_type": "physical", "ip_address": "10.20.0.5", "site_uuid": "site-topeka"},
		},
		"/api/v2/organizations/" + OrgID + "/sites/site-hq/sensors": []map[string]any{},
		"/api/v1/organizations/" + OrgID + "/log-sources": []map[string]any{
			{"name": "10.20.4.11", "lastSeen": now.Add(-5 * time.Minute), "timezone": "", "parsers": []string{}, "tags": []string{}},
			{"name": "10.20.4.12", "lastSeen": now.Add(-20 * time.Minute), "timezone": "", "parsers": []string{}, "tags": []string{}},
			{"name": "fw01.mock.local", "lastSeen": now.Add(-1 * time.Minute), "timezone": "America/Chicago", "parsers": []string{"Firewall"}, "tags": []string{}},
		},
		// LSS: same sources with the fields Rendall drops; 10.20.4.12 arrives on two sensors.
		"/customers/mock-cust/": []map[string]any{
			{"name": "10.20.4.11", "deployment": "mockdep1", "first_seen": now.AddDate(0, 0, -2), "last_seen": now.Add(-5 * time.Minute), "has_configured_parser": false, "configured_parser": nil, "suggested_parsers": []string{"exlog-infoblox_ddi", "log-veeam"}, "is_active": true, "log_source_volume": 1200},
			{"name": "10.20.4.12", "deployment": "mockdep1", "first_seen": now.AddDate(0, -3, 0), "last_seen": now.Add(-20 * time.Minute), "has_configured_parser": true, "configured_parser": "exlog-infoblox_ddi", "is_active": true},
			{"name": "10.20.4.12", "deployment": "mockdep2", "first_seen": now.AddDate(0, 0, -1), "last_seen": now.Add(-30 * time.Minute), "has_configured_parser": false, "is_active": true},
			{"name": "FW01.mock.local", "deployment": "mockdep2", "first_seen": now.AddDate(-1, 0, 0), "last_seen": now.Add(-1 * time.Minute), "has_configured_parser": true, "configured_parser": "exlog-paloalto", "is_active": true},
			{"name": "old.mock.local", "deployment": "mockdep1", "first_seen": now.AddDate(-2, 0, 0), "last_seen": now.AddDate(-1, 0, 0), "has_configured_parser": false, "is_active": false, "deprecated_by": "fw01.mock.local"},
		},
		// LSS example lines: 10.20.4.12 on mockdep1 has some, 10.20.4.11 has none (archive fallback).
		"/deployments/mockdep1/sources/10.20.4.12/example-log-lines/": map[string]any{"lines": []string{"named[2]: client 10.0.0.2#53: query: mock.local IN A"}},
		"/deployments/mockdep1/sources/10.20.4.11/example-log-lines/": map[string]any{"lines": []string{}},
		"/api/v1/organizations/" + OrgID + "/contacts": map[string]any{"total": 1, "items": []map[string]any{
			{"id": "c1", "firstName": "MOCK", "lastName": "Owner", "title": "IT Lead", "contactType": "primary",
				"emailAddresses": []map[string]string{{"email": "owner@mock.example"}}, "phoneNumbers": []map[string]string{{"phone": "+1 555 0100 1234"}},
				"work": map[string]string{"timezone": "America/Chicago", "startTime": "09:00:00", "endTime": "17:00:00"}, "contactTypes": map[string]bool{"primary": true}},
		}},
		"/api/v2/organizations/" + OrgID + "/escalation-configs": map[string]any{"total": 1, "items": []map[string]any{
			{"timeType": "any", "conditions": map[string]any{"type": []map[string]string{{"displayName": "MOCK alert"}}, "priority": []string{"high"}},
				"tiers": []map[string]any{{"communicationPreferences": []map[string]string{{"firstName": "MOCK", "lastName": "Owner"}}}}},
		}},
		"/api/v1/organizations/" + OrgID + "/onboarding-team-contacts":       map[string]any{"pm": map[string]string{"firstName": "MOCK", "lastName": "PM"}, "pse": map[string]string{"firstName": "", "lastName": ""}},
		"/api/v2/organizations/" + OrgID + "/federated-authentication":       map[string]any{"results": []map[string]any{}},
		"/api/v1/organizations/" + OrgID + "/scanner-summary":                map[string]int{"connected": 1, "new": 0},
		"/api/v1/organizations/" + OrgID + "/cloud-service-configuration":    map[string]any{"data": map[string]any{"cloudServices": []string{"aws"}, "endpointSolutions": []string{"crowdstrike"}}},
		"/api/v1/organizations/" + OrgID + "/agent/platforms":                []map[string]string{{"platformOs": "windows", "displayName": "Microsoft Windows", "softwareVersion": "2026-01_47"}},
		"/api/v1/organizations/" + OrgID + "/purchased-cloud-sensor-vendors": []string{"okta_pollerbear"},
		"/api/v2/organizations/" + OrgID + "/secrets-schema": []map[string]any{{
			"deployment_type": "okta_pollerbear", "integration_name": "Okta", "setup_guide_url": "https://docs.mock/okta", "license_model": "BASE",
			"credential_schema": map[string]any{"required": []string{"domain", "api_key"}, "sensitiveFields": []string{"api_key"},
				"properties": map[string]any{"domain": map[string]any{"displayName": "Okta domain", "order": 0}, "api_key": map[string]any{"displayName": "API token", "order": 1}}},
		}, {
			"deployment_type": "crowdstrike_falcon", "integration_name": "CrowdStrike Falcon", "setup_guide_url": "https://docs.mock/cs", "license_model": "PREMIUM",
			"credential_schema": map[string]any{"required": []string{"client_id"}, "properties": map[string]any{"client_id": map[string]any{"displayName": "Client ID"}}},
		}},
		"/api/v1/organizations/" + OrgID + "/email-domains": []string{"mock.example"},
		// Credential Management Service (CSPM accounts), mounted under /cms in tests.
		"/cms/api/v1/schemas": []map[string]any{
			{"schemaType": "prod_cspm_aws", "integrationName": "AWS", "required": []string{"account_id", "role_arn"}, "sensitiveFields": []string{},
				"properties": map[string]any{"account_id": map[string]any{"displayName": "Account ID", "order": 0}, "role_arn": map[string]any{"displayName": "IAM role ARN", "order": 1}}},
			{"schemaType": "test_cspm_aws", "integrationName": "AWS (test)", "properties": map[string]any{}},
		},
		"/cms/api/v1/organizations/" + OrgID + "/credentials/metadata": map[string]any{"data": []map[string]any{
			{"id": "cred-1", "schemaType": "prod_cspm_azure", "integrationInstanceId": "0b0b0b0b-1111-2222-3333-444444444444"},
			{"id": "cred-2", "schemaType": "prod_okta", "integrationInstanceId": "x"},
		}},
		// Ingestion orchestrator (Aurora Integrations), mounted under /ingest/api/v1 in tests.
		"/ingest/api/v1/customers/" + OrgID + "/available-integrations": []map[string]any{
			{"integration_type": "m365", "display_name": "Microsoft 365", "connection_type": "RESTAPI", "license_model": "INCLUDED", "licensed": true, "setup_guide_url": "https://docs.mock/m365",
				"credential_schema": map[string]any{"properties": map[string]any{
					"tenant_id":     map[string]any{"displayName": "Tenant ID", "order": 0, "required": true},
					"client_secret": map[string]any{"displayName": "Client secret", "order": 1, "required": true, "sensitive": true}}}},
			{"integration_type": "crowdstrike", "display_name": "CrowdStrike Falcon", "connection_type": "RESTAPI", "license_model": "PREMIUM", "licensed": false,
				"credential_schema": map[string]any{"properties": map[string]any{"client_id": map[string]any{"displayName": "Client ID", "required": true}}}},
			{"integration_type": "generic_webhook", "display_name": "Generic webhook", "connection_type": "WEBHOOK", "license_model": "INCLUDED", "licensed": true,
				"credential_schema": map[string]any{"properties": map[string]any{}}},
		},
		"/ingest/api/v1/customers/" + OrgID + "/sensors": []map[string]any{
			{"deployment_id": "ing-1", "integration_type": "m365", "name": "Contoso M365", "connection_type": "RESTAPI",
				"extended_health": map[string]any{"state": "unhealthy", "statuses": []map[string]any{{"status": "credentials_invalid", "severity": "high", "call_to_action": "UPDATE_CREDENTIALS"}}}},
		},
		// Physical sensor licences and the AWN203 model group (mirroring only, no transceiver choice).
		"/api/v1/organizations/" + OrgID + "/license-usage": map[string]any{"quotas": map[string]any{"awn203": map[string]int{"quota": 2, "used": 0}}},
		"/api/v1/groups/awn203": map[string]any{"displayLabel": "AWN 203", "questions": []map[string]any{
			{"capabilityType": "deployment", "label": "Deployment Type", "required": true, "options": []map[string]string{{"value": "mirroring", "label": "Port Mirroring"}}},
		}},
		"/api/v1/groups/awn203/models": []map[string]string{{"value": "awn203"}},
		"/api/v1/organizations/" + OrgID + "/sensors": map[string]any{"total": 2, "items": []map[string]any{
			{"uuid": "s1", "name": "MOCK-TOP-SENSOR", "deploymentID": "mockdep1", "status": "healthy", "product": "physical", "ip": "10.20.0.5", "siteName": "MOCK Topeka Clinic"},
			{"uuid": "s2", "name": "MOCK-HQ-VSENSOR", "deploymentID": "mockdep2", "serialNumber": "VN-MOCK-VS-2", "status": "unhealthy", "product": "virtual", "siteName": "MOCK Head Office"},
			{"uuid": "s3", "name": "MOCK-HQ-VLC", "serialNumber": "VN-MOCK-VLC-1", "status": "awaitingActivation", "product": "vlc", "siteName": "MOCK Head Office"},
		}},
		// Scanners: one connected with a schedule, one connected without, one waiting for
		// activation, one physical on its way.
		"/api/v1/organizations/" + OrgID + "/scanners": map[string]any{"total": 4, "errorCode": "", "items": []map[string]any{
			{"id": "scn-1", "name": "MOCK-TOP-SCANNER", "status": "scanning", "type": "physical", "version": "2026.10", "ip": "10.20.0.9", "serialNumber": "LR-MOCK-SCN-1", "deploymentID": "mockscn1", "siteName": "MOCK Topeka Clinic"},
			{"id": "scn-2", "name": "MOCK-HQ-VSCANNER", "status": "connected", "type": "virtual", "version": "2026.10", "ip": "10.30.0.9", "serialNumber": "VN-MOCK-SCN-2", "deploymentID": "mockscn2", "siteName": "MOCK Head Office"},
			{"id": "", "name": "MOCK-AWS-VSCANNER", "status": "awaitingActivation", "type": "virtual", "version": "", "ip": "", "serialNumber": "EC2-MOCK-SCN-3", "siteName": "N/A"},
			{"id": "", "name": "MOCK-BRANCH-SCANNER", "status": "shipped", "type": "physical", "version": "", "ip": "", "serialNumber": "", "siteName": "MOCK Topeka Clinic"},
		}},
		"/api/v1/organizations/" + OrgID + "/iva/scn-1/scan-schedules": map[string]any{"items": []map[string]any{
			{"id": "sch-1", "name": "MOCK Clinic LAN", "scanningEnabled": true, "status": "active", "frequency": "weekly", "lastScan": "2026-10-25T22:00:00Z", "nextScan": "2026-11-01T22:00:00Z", "timezone": "UTC", "priority": 100,
				"targets": []map[string]any{{"name": "10.20.0.0/24"}}},
		}},
		"/api/v1/organizations/" + OrgID + "/iva/scn-2/scan-schedules": map[string]any{"items": []map[string]any{}},
		"/api/v1/organizations/" + OrgID + "/scanners/scn-1": map[string]any{"connectionStatus": "connected", "denyList": []string{"10.20.0.9"}, "dnsServers": []string{"10.20.0.2"},
			"settings": map[string]any{"hostIdentification": true, "vulnerabilityScanning": true}, "hostIdentificationScanIntensity": "medium"},
		"/api/v1/organizations/" + OrgID + "/scanners/scn-1/jobs/issues": []map[string]any{{"jobID": 7, "severity": "warning", "description": "MOCK feed update delayed"}},
		"/api/v1/organizations/" + OrgID + "/scanner-license-usage":      map[string]any{"quotas": map[string]any{"physical": map[string]int{"quota": 2, "used": 1}, "virtual": map[string]int{"quota": 0, "used": 2}}},
		"/api/v1/organizations/" + OrgID + "/virtualsensor/download":     map[string]string{"url": "https://downloads.mock/appliance.ova?sig=MOCK", "sha256": "deadbeef"},
		"/api/v1/organizations/" + OrgID + "/cloud-sensors": map[string]any{"total": 1, "items": []map[string]any{
			{"name": "MOCK Okta", "deploymentID": "mockdep3", "status": "invalidCredentials", "vendor": "okta", "type": "okta_pollerbear", "credential": map[string]string{"uuid": "secret-ref"}},
		}},
		"/api/v1/organizations/" + OrgID + "/sensor-summary":       map[string]int{"healthy": 1, "unhealthy": 0, "shipped": 0, "new": 0},
		"/api/v1/organizations/" + OrgID + "/cloud-sensor-summary": map[string]int{"healthy": 0, "pendingCustomerConfig": 1},
		"/api/v1/organizations/" + OrgID + "/logsearch/job-1": map[string]any{
			"search": map[string]any{"id": "job-1", "percent": 100, "count": 2, "failed": false},
		},
		"/api/v1/organizations/" + OrgID + "/logsearch/job-1/results": []map[string]string{
			{"timestamp": "2026-10-24T01:00:00Z", "deployment": "mockdep1", "host": "10.20.4.11", "body": "named[1]: client 10.0.0.1#5353: query: example.com IN A"},
			{"timestamp": "2026-10-24T01:00:01Z", "deployment": "mockdep1", "host": "10.99.9.9", "body": "mentions 10.20.4.11 but is from another host"},
		},
		"/api/v1/organizations/" + OrgID + "/onboarding-agent-overview": map[string]any{"totalAgents": map[string]int{"deployed": 0, "indicated": 10}},
		"/api/v1/organizations/" + OrgID + "/tickets":                   map[string]any{"id": "9001"},
		// Site as Rendall returns it (OrganizationSiteV2): a physical-sensor site.
		"/api/v2/organizations/" + OrgID + "/sites/site-topeka": map[string]any{"uuid": "site-topeka", "name": "MOCK Topeka Clinic", "time_zone": "America/Chicago",
			"address":    map[string]any{"street1": "1 Main St", "city": "Topeka", "provinceState": "KS", "postalZip": "66603", "country": "US"},
			"ip_subnets": []string{"10.20.0.0/24"}, "firewalls": []string{"Palo Alto PA-440"}, "ha_firewall_type": "none", "dns": []string{"10.20.0.2"},
			"dhcp": []string{}, "switches": []string{}, "ad_domain_controllers": 2, "max_isp_bandwidth_purchased": 500, "client_vpn_services": "",
			"proxy": "", "authentication_server_8021x": "", "is_third_party_site": false, "log_source_forward_site": nil, "notes": ""},
		// Day-2 management reads: one sensor and one scanner profile.
		"/api/v1/organizations/" + OrgID + "/sensors/s2": map[string]any{"uuid": "s2", "name": "MOCK-HQ-VSENSOR", "deploymentID": "mockdep2", "device_type": "virtual",
			"model": "AWN-v100", "configuration": "mirroring", "ipAddress": "10.30.0.5", "site": map[string]any{"uuid": "site-hq", "name": "MOCK Head Office"}},
		"/api/v2/organizations/" + OrgID + "/scanners/scn-2": map[string]any{"uuid": "scn-2", "name": "MOCK-HQ-VSCANNER", "siteUuid": "site-hq", "type": "virtual",
			"scannerDetails": map[string]any{"settings": []map[string]any{{"name": "hostIdentificationScans", "enabled": true}, {"name": "vulnerabilityScans", "enabled": true},
				{"name": "CGIScanning", "enabled": true}, {"name": "bruteForceChecks", "enabled": true}, {"name": "onlyPingTheTarget", "enabled": false}},
				"dnsServers": []string{"10.30.0.2"}, "denyList": []string{"10.30.0.250"}, "hostIdentificationScanIntensity": "low", "hostIdentificationScanPeriod": 5,
				"maxConcurrentVulnerabilityScans": 0, "selfScanEnabled": false}},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/log-sources/") {
			// Log Source Orchestrator write.
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordLSO(LSOCall{Path: r.URL.Path, Reason: r.Header.Get("X-Reason"), Ticket: r.Header.Get("X-Ticket"), Body: body})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "/sensor/") || strings.HasSuffix(r.URL.Path, "/scan-schedules") ||
			r.URL.Path == "/api/v2/organizations/"+OrgID+"/scanners" || r.URL.Path == "/api/v2/organizations/"+OrgID+"/sites") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeMu.Lock()
			writes = append(writes, Write{Method: r.Method, Path: r.URL.Path, Body: body})
			writeMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodPut && (strings.Contains(r.URL.Path, "/sensor-profiles/") || strings.Contains(r.URL.Path, "/scanners/") || strings.Contains(r.URL.Path, "/sites/") ||
			strings.HasSuffix(r.URL.Path, "/scan-schedules/disable")) ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete ||
			r.Method == http.MethodPost && (strings.HasSuffix(r.URL.Path, "/log-sources/tag") || strings.HasSuffix(r.URL.Path, "/iva/scan")) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeMu.Lock()
			writes = append(writes, Write{Method: r.Method, Path: r.URL.Path, Body: body})
			writeMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if (strings.HasPrefix(r.URL.Path, "/ingest/") || strings.HasPrefix(r.URL.Path, "/cms/")) && r.Method != http.MethodGet {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeMu.Lock()
			writes = append(writes, Write{Method: r.Method, Path: r.URL.Path, Body: body})
			writeMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/converse-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"text\": \"<thinking>hidden</thinking>CVE-2024-3400 \"}\n\ndata: {\"text\": \"is critical.\"}\n\n"))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/organizations/"+OrgID+"/data-explorer/analyzed-logs" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"total": 3, "rows": [][]any{
				{"exlog-infoblox_ddi", "dns01.mock.local", 900},
				{"exlog-infoblox_ddi", nil, 100},
				{"exlog-okta", "pollerbear", 50},
			}})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/organizations/"+OrgID+"/logsearch" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "job-1", "percent": 0})
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}
