package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/notxdr/discovery-service/internal/discovery"
	"github.com/notxdr/discovery-service/internal/mock"
	"github.com/notxdr/discovery-service/internal/parser"
	"github.com/notxdr/discovery-service/internal/upstream"
)

// fakeParser records what it was given so tests can check the service's filtering.
type fakeParser struct{ gotRows []upstream.RawLogRow }

func (f *fakeParser) Suggest(_ context.Context, rows []upstream.RawLogRow) (parser.SuggestResult, error) {
	f.gotRows = rows
	return parser.SuggestResult{Suggestions: []parser.Suggestion{{Parser: "exlog-infoblox_ddi", FieldsExtracted: 8}}, LinesUsed: len(rows)}, nil
}

func (f *fakeParser) Preview(_ context.Context, rows []upstream.RawLogRow, p string) (parser.PreviewResult, error) {
	return parser.PreviewResult{Parser: p, Lines: []parser.PreviewLine{{Raw: rows[0].Body, Fields: map[string]any{"dns.qname": "example.com"}}}}, nil
}

func newTestRouter(t *testing.T) http.Handler {
	h, _ := newTestRouterWithParser(t)
	return h
}

func newTestRouterWithParser(t *testing.T) (http.Handler, *fakeParser) {
	return newTestRouterLSS(t, true)
}

// newTestRouterLSS builds the router against the mock upstreams, with or without LSS
// (without = the VPN-off fallback to Rendall).
func newTestRouterLSS(t *testing.T, withLSS bool) (http.Handler, *fakeParser) {
	t.Helper()
	srv := mock.NewServer()
	t.Cleanup(srv.Close)
	cfg := upstream.Config{ElocURL: srv.URL, RendallURLTemplate: srv.URL, ASAURLTemplate: srv.URL}
	if withLSS {
		cfg.LSSURLTemplate = srv.URL
	}
	up := upstream.New(cfg)
	fp := &fakeParser{}
	svc := discovery.New(up, fp)
	svc.SamplePoll = time.Millisecond
	return NewRouter(svc), fp
}

func get(t *testing.T, h http.Handler, path string, withAuth bool) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if withAuth {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestRequiresToken(t *testing.T) {
	code, _ := get(t, newTestRouter(t), "/v1/orgs", false)
	if code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}
}

func TestFindOrganization(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs?name=bacon", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if n := len(body["data"].([]any)); n != 1 {
		t.Fatalf("want 1 org, got %d", n)
	}
}

func TestUnknownOrgIs404(t *testing.T) {
	code, _ := get(t, newTestRouter(t), "/v1/orgs/not-mine/setup/status", true)
	if code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", code)
	}
}

func TestSiteSearchReturnsSensors(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/sites?name=topeka", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	sites := body["data"].([]any)
	if len(sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(sites))
	}
	sensors := sites[0].(map[string]any)["sensors"].([]any)
	if len(sensors) != 1 {
		t.Fatalf("want 1 sensor, got %d", len(sensors))
	}
}

func TestUnrecognisedLogSources(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources?unrecognised=true", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	if data["origin"] != "lss" {
		t.Fatalf("want origin lss, got %v", data["origin"])
	}
	// 10.20.4.11 and 10.20.4.12 on mockdep2 have no parser; 10.20.4.12 on mockdep1 does.
	sources := data["sources"].([]any)
	if len(sources) != 2 {
		t.Fatalf("want 2 sources without a parser, got %d", len(sources))
	}
	for _, src := range sources {
		if src.(map[string]any)["parserStatus"] != "none" {
			t.Fatalf("want parserStatus none, got %v", src)
		}
	}
	meta := body["meta"].(map[string]any)
	if meta["untrustedFields"] == nil {
		t.Fatal("log source names must be flagged as untrusted")
	}
}

func TestLogSourcesFromLSS(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	if data["total"].(float64) != 4 {
		t.Fatalf("want 4 sources (deprecated record dropped), got %v", data["total"])
	}
	summary := data["summary"].(map[string]any)
	if summary["withParser"].(float64) != 2 || summary["withoutParser"].(float64) != 2 || summary["newLast7Days"].(float64) != 2 {
		t.Fatalf("unexpected summary %v", summary)
	}
	first := data["sources"].([]any)[0].(map[string]any)
	if first["name"] != "FW01.mock.local" || first["parser"] != "exlog-paloalto" || first["sensor"] != "mockdep2" {
		t.Fatalf("want most recently seen source first with parser and sensor, got %v", first)
	}
}

func TestNewLogSourcesNewestFirst(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources?newSinceDays=7", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	sources := body["data"].(map[string]any)["sources"].([]any)
	if len(sources) != 2 {
		t.Fatalf("want 2 sources first seen this week, got %d", len(sources))
	}
	newest := sources[0].(map[string]any)
	if newest["name"] != "10.20.4.12" || newest["sensor"] != "mockdep2" {
		t.Fatalf("want 10.20.4.12 on mockdep2 first, got %v", newest)
	}
}

func TestLogSourceLimitSaysWhatIsHidden(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources?limit=1", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	if data["returned"].(float64) != 1 || data["matched"].(float64) != 4 {
		t.Fatalf("want 1 of 4, got %v of %v", data["returned"], data["matched"])
	}
	if !strings.Contains(fmt.Sprint(body["meta"].(map[string]any)["notes"]), "showing 1 of 4") {
		t.Fatalf("want a note about hidden rows, got %v", body["meta"])
	}
}

func TestLogSourcesFallBackToRendall(t *testing.T) {
	h, _ := newTestRouterLSS(t, false)
	code, body := get(t, h, "/v1/orgs/"+mock.OrgID+"/log-sources", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	if data["origin"] != "rendall" {
		t.Fatalf("want origin rendall, got %v", data["origin"])
	}
	for _, src := range data["sources"].([]any) {
		source := src.(map[string]any)
		if source["parserStatus"] == "none" {
			t.Fatalf("rendall can't tell unparsed sources apart, got %v", source)
		}
	}
	if !strings.Contains(fmt.Sprint(body["meta"].(map[string]any)["notes"]), "LSS unreachable") {
		t.Fatalf("want a note explaining the fallback, got %v", body["meta"])
	}
}

func TestSuggestionsUseOnlyThisSourcesLines(t *testing.T) {
	h, fp := newTestRouterWithParser(t)
	code, body := get(t, h, "/v1/orgs/"+mock.OrgID+"/log-sources/10.20.4.11/suggestions", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", code, body)
	}
	if len(fp.gotRows) != 1 || fp.gotRows[0].Host != "10.20.4.11" {
		t.Fatalf("parser must only get lines from the requested host, got %+v", fp.gotRows)
	}
	if body["meta"].(map[string]any)["stubbed"] == true {
		t.Fatal("suggestions are real now and must not be marked stubbed")
	}
}

func TestPreviewFlagsUntrustedText(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources/10.20.4.11/preview?parser=exlog-infoblox_ddi", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body["meta"].(map[string]any)["untrustedFields"] == nil {
		t.Fatal("raw log text must be flagged as untrusted")
	}
}

func TestSetupStatusCoversAllAreas(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/setup/status", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	areas := body["data"].([]any)
	if len(areas) != 11 {
		t.Fatalf("want 11 areas, got %d", len(areas))
	}
	// Only the areas without a customer-facing API may be unknown.
	noAPI := map[string]bool{"security_policies": true, "cloud_scanner": true}
	for _, a := range areas {
		area := a.(map[string]any)
		if area["status"] == "unknown" && !noAPI[area["area"].(string)] {
			t.Fatalf("area failed: %v", area)
		}
	}
}

func rpc(t *testing.T, h http.Handler, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON-RPC response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestMCPListsReadOnlyTools(t *testing.T) {
	out := rpc(t, newTestRouter(t), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 37 {
		t.Fatalf("want 37 tools, got %d", len(tools))
	}
	// Tools that change state: apply_change acts after the customer confirms (and can
	// decommission, so it is destructive); the other two only store UI state.
	writes := map[string]bool{"apply_change": true, "save_onboarding_progress": true, "submit_secure_fields": true}
	for _, tl := range tools {
		name := tl.(map[string]any)["name"].(string)
		ann := tl.(map[string]any)["annotations"].(map[string]any)
		if name == "apply_change" && ann["destructiveHint"] != true {
			t.Fatal("apply_change must be marked destructive")
		}
		if writes[name] {
			if ann["readOnlyHint"] != false {
				t.Fatalf("tool %s writes and must not be read-only", name)
			}
			continue
		}
		if ann["readOnlyHint"] != true {
			t.Fatalf("tool %v must be read-only", name)
		}
	}
}

func TestMCPCallsToolAsUser(t *testing.T) {
	out := rpc(t, newTestRouter(t), `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_site_sensors","arguments":{"org_id":"`+mock.OrgID+`","site_name":"topeka"}}}`)
	res := out["result"].(map[string]any)
	if res["isError"] != false {
		t.Fatalf("tool failed: %v", res)
	}
}

func TestMCPMissingArgumentIsToolError(t *testing.T) {
	out := rpc(t, newTestRouter(t), `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"suggest_parser","arguments":{"org_id":"x"}}}`)
	if out["result"].(map[string]any)["isError"] != true {
		t.Fatal("missing argument must come back as a tool error")
	}
}

func TestMCPRequiresToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	newTestRouter(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestCORSAllowsOnlyListedOrigin(t *testing.T) {
	h := WithCORS(newTestRouter(t), []string{"http://localhost:3000"})
	for origin, want := range map[string]string{"http://localhost:3000": "http://localhost:3000", "https://evil.example": ""} {
		req := httptest.NewRequest(http.MethodOptions, "/v1/orgs", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Fatalf("origin %s: want %q, got %q", origin, want, got)
		}
	}
}

func TestParserActivitySumsOnlyThatParser(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/parsers/exlog-infoblox_ddi/activity", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	if data["eventsLast24h"].(float64) != 1000 || len(data["topHosts"].([]any)) != 1 {
		t.Fatalf("unexpected activity: %v", data)
	}
}

func TestAskAssistantStripsThinking(t *testing.T) {
	out := rpc(t, newTestRouter(t), `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ask_arctic_wolf_assistant","arguments":{"org_id":"`+mock.OrgID+`","question":"what is CVE-2024-3400"}}}`)
	res := out["result"].(map[string]any)
	answer := res["structuredContent"].(map[string]any)["data"].(map[string]any)["answer"]
	if answer != "CVE-2024-3400 is critical." {
		t.Fatalf("unexpected answer %q", answer)
	}
}

func TestSensorsNeedingAttention(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/sensors?status=unhealthy", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	data := body["data"].(map[string]any)
	sensors := data["sensors"].([]any)
	if len(sensors) != 1 || sensors[0].(map[string]any)["name"] != "MOCK-HQ-VSENSOR" {
		t.Fatalf("want the one unhealthy sensor, got %v", sensors)
	}
	// mockdep2 carries two LSS sources; the newest was seen 1 minute ago.
	if sensor := sensors[0].(map[string]any); sensor["lastLogSeen"] == nil || sensor["logSources"].(float64) != 2 {
		t.Fatalf("want last log time and source count from LSS, got %v", sensor)
	}
	byStatus := data["byStatus"].(map[string]any)
	if byStatus["cloud"].(map[string]any)["invalidCredentials"].(float64) != 1 {
		t.Fatalf("want cloud counts by status, got %v", byStatus)
	}
}

func TestCloudSensorsHideCredentials(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/sensors?kind=cloud", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if strings.Contains(fmt.Sprint(body), "secret-ref") {
		t.Fatal("cloud sensor credentials must not be returned")
	}
}

func TestSyslogDestinationForSource(t *testing.T) {
	out := rpc(t, newTestRouter(t), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_syslog_destination","arguments":{"org_id":"`+mock.OrgID+`","source":"10.20.4.12"}}}`)
	result := out["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("tool failed: %v", result)
	}
	data := result["structuredContent"].(map[string]any)["data"].(map[string]any)
	// 10.20.4.12 was seen last on mockdep1 (20 min ago), whose sensor is MOCK-TOP-SENSOR.
	if data["sensor"].(map[string]any)["name"] != "MOCK-TOP-SENSOR" {
		t.Fatalf("want the sensor the source arrives on, got %v", data["sensor"])
	}
	if ports := data["ports"].([]any); len(ports) != 2 || ports[0].(map[string]any)["port"].(float64) != 514 {
		t.Fatalf("want documented ports 514 and 6514, got %v", ports)
	}
	if data["otherSourcesOnSensorLast24h"].(float64) != 1 {
		t.Fatalf("want 1 other recent source on mockdep1, got %v", data["otherSourcesOnSensorLast24h"])
	}
}

func TestSamplesPreferLSSExampleLines(t *testing.T) {
	code, body := get(t, newTestRouter(t), "/v1/orgs/"+mock.OrgID+"/log-sources/10.20.4.12/samples", true)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	rows := body["data"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["deployment"] != "mockdep1" {
		t.Fatalf("want the LSS example line from the newest sensor, got %v", rows)
	}
	if !strings.Contains(fmt.Sprint(body["meta"]), "example lines") {
		t.Fatalf("want meta to say the lines came from LSS, got %v", body["meta"])
	}
}

func callTool(t *testing.T, h http.Handler, name, args string) map[string]any {
	t.Helper()
	out := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)
	return out["result"].(map[string]any)
}

func TestContactsAreMasked(t *testing.T) {
	result := callTool(t, newTestRouter(t), "get_contacts", `{"org_id":"`+mock.OrgID+`"}`)
	text := fmt.Sprint(result["structuredContent"])
	if strings.Contains(text, "owner@mock.example") || strings.Contains(text, "0100 1234") {
		t.Fatalf("contact details must be masked, got %s", text)
	}
	if !strings.Contains(text, "o***@mock.example") || !strings.Contains(text, "MOCK PM") {
		t.Fatalf("want masked email and onboarding PM, got %s", text)
	}
}

func TestContactChangeApplied(t *testing.T) {
	h := newTestRouter(t)
	prepared := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"add_contact","fields":{"first_name":"Priya","last_name":"Sharma","title":"IT Manager","email":"priya@mock.example","phone":"+91 98000 00000","timezone":"Asia/Kolkata","roles":"secondary"}}`)
	if prepared["isError"] == true {
		t.Fatalf("prepare failed: %v", prepared)
	}
	change := prepared["structuredContent"].(map[string]any)["data"].(map[string]any)
	if change["status"] != "prepared" || change["method"] != "POST" || change["body"].(map[string]any)["contactType"] != "secondary" {
		t.Fatalf("unexpected change %v", change)
	}
	applied := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`)
	if status := applied["structuredContent"].(map[string]any)["data"].(map[string]any)["status"]; status != "applied" {
		t.Fatalf("want applied, got %v", status)
	}
	again := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`)
	if again["isError"] != true {
		t.Fatal("a change must not apply twice")
	}
}

func TestSSOSecretGoesThroughSecureCardOnly(t *testing.T) {
	h := newTestRouter(t)
	prepared := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"configure_sso","fields":{"issuer_url":"https://idp.mock.example","client_id":"abc","domains":"mock.example"}}`)
	change := prepared["structuredContent"].(map[string]any)["data"].(map[string]any)
	id := change["id"].(string)
	if change["status"] != "needs_secure_fields" {
		t.Fatalf("want needs_secure_fields, got %v", change["status"])
	}
	if early := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`"}`); early["isError"] != true {
		t.Fatal("must not apply before the secret arrives")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/orgs/"+mock.OrgID+"/changes/"+id+"/secrets", strings.NewReader(`{"clientSecret":"s3cret-value"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "s3cret-value") {
		t.Fatalf("secret must be accepted and never echoed: %d %s", rec.Code, rec.Body.String())
	}
	code, body := get(t, h, "/v1/orgs/"+mock.OrgID+"/changes/"+id, true)
	if code != http.StatusOK || strings.Contains(fmt.Sprint(body), "s3cret-value") || body["data"].(map[string]any)["status"] != "prepared" {
		t.Fatalf("want prepared change without the secret, got %d %v", code, body)
	}
	applied := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`"}`)
	if strings.Contains(fmt.Sprint(applied), "s3cret-value") {
		t.Fatal("secret leaked in apply result")
	}
}

func TestConnectCloudAppUsesIntegrationForm(t *testing.T) {
	h := newTestRouter(t)
	prepared := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"okta_pollerbear","name":"Okta prod"}}`)
	change := prepared["structuredContent"].(map[string]any)["data"].(map[string]any)
	fields := change["secureFields"].([]any)
	if len(fields) != 2 || fields[0].(map[string]any)["name"] != "domain" || fields[1].(map[string]any)["sensitive"] != true {
		t.Fatalf("want domain then sensitive api_key on the secure card, got %v", fields)
	}
	bad := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"nope","name":"x"}}`)
	if bad["isError"] != true {
		t.Fatal("unknown integration type must fail")
	}
}

func newTestRouterWithLSO(t *testing.T) http.Handler {
	t.Helper()
	srv := mock.NewServer()
	t.Cleanup(srv.Close)
	svc := discovery.New(upstream.New(upstream.Config{ElocURL: srv.URL, RendallURLTemplate: srv.URL, ASAURLTemplate: srv.URL,
		LSSURLTemplate: srv.URL, LSOURLTemplate: srv.URL}), &fakeParser{})
	return NewRouter(svc)
}

func newTestRouterWithIngestion(t *testing.T) http.Handler {
	t.Helper()
	srv := mock.NewServer()
	t.Cleanup(srv.Close)
	svc := discovery.New(upstream.New(upstream.Config{ElocURL: srv.URL, RendallURLTemplate: srv.URL, ASAURLTemplate: srv.URL,
		LSSURLTemplate: srv.URL, IngestionURLTemplate: srv.URL + "/ingest/api/v1", CMSURLTemplate: srv.URL + "/cms"}), &fakeParser{})
	return NewRouter(svc)
}

func prepareParser(t *testing.T, h http.Handler, fields string) map[string]any {
	t.Helper()
	prepared := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"set_log_source_parser","fields":`+fields+`}`)
	if prepared["isError"] == true {
		t.Fatalf("prepare failed: %v", prepared)
	}
	return prepared["structuredContent"].(map[string]any)["data"].(map[string]any)
}

func TestParserChangeWithoutLSOOpensTicketForStaff(t *testing.T) {
	h := newTestRouter(t)
	mock.LSOCalls()
	change := prepareParser(t, h, `{"source":"10.20.4.11","parser":"log-veeam"}`)
	if change["method"] != "POST" || !strings.HasSuffix(change["path"].(string), "/tickets") {
		t.Fatalf("without LSO the change should open a ticket, got %v %v", change["method"], change["path"])
	}
	applied := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`)
	data := applied["structuredContent"].(map[string]any)["data"].(map[string]any)
	if data["status"] != "applied" || data["reference"] != "https://arcticwolf.zendesk.com/agent/tickets/9001" {
		t.Fatalf("want applied with ticket reference, got %v", data)
	}
	if !strings.Contains(data["outcome"].(string), "staff will apply") {
		t.Fatalf("outcome should say staff apply it, got %q", data["outcome"])
	}
	if calls := mock.LSOCalls(); len(calls) != 0 {
		t.Fatalf("LSO must not be called when it is off, got %v", calls)
	}
}

func TestParserChangeWithLSOSavesWithTicket(t *testing.T) {
	h := newTestRouterWithLSO(t)
	mock.LSOCalls()
	change := prepareParser(t, h, `{"source":"10.20.4.11","parser":"log-veeam","timezone":"-06:00"}`)
	if change["method"] != "PUT" {
		t.Fatalf("with LSO the change should be a PUT, got %v", change["method"])
	}
	applied := callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`)
	data := applied["structuredContent"].(map[string]any)["data"].(map[string]any)
	if data["status"] != "applied" || !strings.HasPrefix(data["outcome"].(string), "Saved") {
		t.Fatalf("want saved, got %v", data)
	}
	calls := mock.LSOCalls()
	if len(calls) != 1 {
		t.Fatalf("want one LSO write, got %v", calls)
	}
	c := calls[0]
	if c.Ticket != "https://arcticwolf.zendesk.com/agent/tickets/9001" || !strings.Contains(c.Reason, "Customer confirmed in Aurora") {
		t.Fatalf("LSO write must carry the ticket and reason, got %+v", c)
	}
	if c.Path != "/api/v1/customers/"+mock.OrgID+"/deployments/mockdep1/log-sources/10.20.4.11/" ||
		c.Body["configured_parser"] != "log-veeam" || c.Body["configured_timezone"] != "-06:00" {
		t.Fatalf("unexpected LSO write %+v", c)
	}
}

func TestParserChangeAsksForSensorWhenSourceIsOnTwo(t *testing.T) {
	h := newTestRouter(t)
	res := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"set_log_source_parser","fields":{"source":"10.20.4.12","parser":"log-veeam"}}`)
	if res["isError"] != true || !strings.Contains(fmt.Sprint(res), "more than one sensor") {
		t.Fatalf("want ask-for-sensor error, got %v", res)
	}
	change := prepareParser(t, h, `{"source":"10.20.4.12","sensor":"mockdep2","parser":"log-veeam"}`)
	if !strings.Contains(fmt.Sprint(change["details"]), "mockdep2") {
		t.Fatalf("want the chosen sensor on the card, got %v", change["details"])
	}
}

func TestNewSourceGetsATimezoneAndShowsPendingAfterSave(t *testing.T) {
	h := newTestRouterWithLSO(t)
	mock.LSOCalls()
	change := prepareParser(t, h, `{"source":"10.20.4.11","parser":"log-veeam"}`)
	if tz := change["body"].(map[string]any)["configured_timezone"]; tz != "+00:00" {
		t.Fatalf("a source new to the settings needs a timezone; want the +00:00 default, got %v", tz)
	}
	callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`)
	if calls := mock.LSOCalls(); len(calls) != 1 || calls[0].Body["configured_timezone"] != "+00:00" {
		t.Fatalf("LSO must get parser and timezone together: %v", calls)
	}
	got := data(t, callTool(t, h, "list_log_sources", `{"org_id":"`+mock.OrgID+`","name_contains":"10.20.4.11"}`))
	src := got["sources"].([]any)[0].(map[string]any)
	if src["parserStatus"] != "pending" || src["parser"] != "log-veeam" {
		t.Fatalf("a saved parser shows as pending until LSS reports it: %v", src)
	}
}
