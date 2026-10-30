package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/notxdr/discovery-service/internal/mock"
)

func data(t *testing.T, res map[string]any) map[string]any {
	t.Helper()
	if res["isError"] == true {
		t.Fatalf("tool failed: %v", res)
	}
	return res["structuredContent"].(map[string]any)["data"].(map[string]any)
}

func TestScannersShowHealthSchedulesAndNextSteps(t *testing.T) {
	_ = mock.Writes()
	out := data(t, callTool(t, newTestRouter(t), "list_scanners", `{"org_id":"`+mock.OrgID+`"}`))
	if out["total"].(float64) != 4 || out["health"] != "needsAttention" {
		t.Fatalf("want 4 scanners, fleet needsAttention; got %v / %v", out["total"], out["health"])
	}
	byName := map[string]map[string]any{}
	for _, s := range out["scanners"].([]any) {
		byName[s.(map[string]any)["name"].(string)] = s.(map[string]any)
	}
	if byName["MOCK-TOP-SCANNER"]["schedules"].(float64) != 1 {
		t.Fatalf("connected scanner with one schedule: %v", byName["MOCK-TOP-SCANNER"])
	}
	if byName["MOCK-HQ-VSCANNER"]["schedules"].(float64) != 0 || !strings.Contains(byName["MOCK-HQ-VSCANNER"]["nextStep"].(string), "no scan schedules") {
		t.Fatalf("connected scanner without schedules must say so: %v", byName["MOCK-HQ-VSCANNER"])
	}
	if _, read := byName["MOCK-BRANCH-SCANNER"]["schedules"]; read {
		t.Fatal("schedules must not be read for a scanner that has not connected")
	}
	if !strings.Contains(byName["MOCK-AWS-VSCANNER"]["nextStep"].(string), "activate_appliance") {
		t.Fatalf("awaiting scanner must point at activation: %v", byName["MOCK-AWS-VSCANNER"])
	}
	lic := out["licences"].(map[string]any)
	if lic["used"].(float64) != 1 || lic["total"].(float64) != 2 {
		t.Fatalf("physical licences 1/2, virtual unlimited; got %v", lic)
	}
}

func TestScannerDetails(t *testing.T) {
	out := data(t, callTool(t, newTestRouter(t), "get_scanner", `{"org_id":"`+mock.OrgID+`","scanner":"LR-MOCK-SCN-1"}`))
	if out["connection"] != "connected" || len(out["schedules"].([]any)) != 1 || len(out["issues"].([]any)) != 1 {
		t.Fatalf("unexpected details %v", out)
	}
	if out["settings"].(map[string]any)["denyList"] == nil {
		t.Fatal("settings must include the deny list")
	}
}

func TestPendingActivationsCoverSensorsAndScanners(t *testing.T) {
	out := data(t, callTool(t, newTestRouter(t), "list_pending_activations", `{"org_id":"`+mock.OrgID+`"}`))
	got := map[string]string{}
	for _, a := range out["appliances"].([]any) {
		got[a.(map[string]any)["serialNumber"].(string)] = a.(map[string]any)["kind"].(string)
	}
	if got["VN-MOCK-VLC-1"] != "sensor" || got["EC2-MOCK-SCN-3"] != "scanner" || len(got) != 2 {
		t.Fatalf("want the waiting vLC and vScanner, got %v", got)
	}
}

func TestActivateApplianceSendsInstallCall(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	bad := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"activate_appliance","fields":{"serial_number":"LR-MOCK-SCN-1"}}`)
	if bad["isError"] != true {
		t.Fatal("an already-active appliance must not be activated")
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"activate_appliance","fields":{"serial_number":"EC2-MOCK-SCN-3"}}`))
	if change["path"] != "/api/v1/organizations/"+mock.OrgID+"/sensor/EC2-MOCK-SCN-3" || len(mock.Writes()) != 0 {
		t.Fatalf("prepare must build the install call without sending it: %v", change)
	}
	applied := data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`))
	w := mock.Writes()
	if applied["status"] != "applied" || len(w) != 1 || w[0].Path != "/api/v1/organizations/"+mock.OrgID+"/sensor/EC2-MOCK-SCN-3" {
		t.Fatalf("want one install call after confirmation, got %v / %v", applied["status"], w)
	}
}

func TestRequestScannerMatchesPortalBody(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"request_scanner","fields":{"name":"Branch scanner","site":"MOCK Topeka Clinic","dhcp":"yes",
		"ship_first_name":"Ana","ship_last_name":"Diaz","ship_email":"ana@mock.example","ship_phone":"+1 555 0100","street1":"1 Main St","city":"Topeka","province_state":"KS","postal_code":"66603","country":"US"}}`))
	body := change["body"].(map[string]any)
	if change["path"] != "/api/v2/organizations/"+mock.OrgID+"/scanners" || body["type"] != "physical" || body["configuration"] != "scanner" ||
		body["siteUuid"] != "site-topeka" || body["networkConfiguration"].(map[string]any)["ipAddress"] != "dhcpOverride" {
		t.Fatalf("body must match the Unified Portal Add Scanner request: %v", change)
	}
	applied := data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`))
	if applied["status"] != "applied" || len(mock.Writes()) != 1 {
		t.Fatal("scanner request must be sent once after confirmation")
	}
}

func TestScanScheduleWeeklyCronAndLimits(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	cases := map[string]string{
		"public":       `"targets":"8.8.8.0/24","frequency":"continuous"`,
		"too big":      `"targets":"10.0.0.0/15","frequency":"continuous"`,
		"over limit":   `"targets":"10.0.0.0/16,10.1.0.0/24","frequency":"continuous"`,
		"no time":      `"targets":"10.30.0.0/24","frequency":"daily"`,
		"not ready":    `"targets":"10.30.0.0/24","frequency":"continuous","scanner":"MOCK-BRANCH-SCANNER"`,
		"bad weekday":  `"targets":"10.30.0.0/24","frequency":"weekly","start_time_utc":"22:00","days":"funday"`,
		"bad priority": `"targets":"10.30.0.0/24","frequency":"continuous","priority":"urgent"`,
	}
	for name, fields := range cases {
		args := `{"org_id":"` + mock.OrgID + `","kind":"create_scan_schedule","fields":{"scanner":"MOCK-HQ-VSCANNER","name":"x",` + fields + `}}`
		if res := callTool(t, h, "prepare_change", args); res["isError"] != true {
			t.Errorf("%s: want rejection, got %v", name, res)
		}
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_scan_schedule","fields":{"scanner":"MOCK-HQ-VSCANNER","name":"HQ servers",
		"targets":"10.30.0.0/24,10.30.1.10-10.30.1.20","frequency":"weekly","start_time_utc":"22:30","days":"tue,sat","window_hours":"6","priority":"medium"}}`))
	body := change["body"].(map[string]any)
	cron := body["schedule"].([]any)
	if change["path"] != "/api/v1/organizations/"+mock.OrgID+"/iva/scn-2/scan-schedules" || body["priority"].(float64) != 50 || body["timezone"] != "UTC" || len(cron) != 2 {
		t.Fatalf("unexpected schedule change %v", change)
	}
	first := cron[0].(map[string]any)
	if first["dayOfWeek"].([]any)[0].(float64) != 2 || first["hour"].([]any)[0].(float64) != 22 || first["minute"].([]any)[0].(float64) != 30 || first["length"].(float64) != 360 {
		t.Fatalf("weekly cron must be one entry per day like the portal: %v", first)
	}
	if !strings.Contains(change["details"].([]any)[1].(map[string]any)["value"].(string), "267 addresses") {
		t.Fatalf("details must count the addresses: %v", change["details"])
	}
	cont := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_scan_schedule","fields":{"scanner":"scn-2","name":"all","targets":"10.30.0.0/16","frequency":"continuous"}}`))
	if _, has := cont["body"].(map[string]any)["schedule"]; has {
		t.Fatal("continuous schedules send no cron, like the portal")
	}
}

func TestApplianceDownloadCoversCloudAccounts(t *testing.T) {
	out := data(t, callTool(t, newTestRouter(t), "get_appliance_download", `{"org_id":"`+mock.OrgID+`","appliance":"sensor"}`))
	if out["url"] != "https://downloads.mock/appliance.ova?sig=MOCK" {
		t.Fatalf("want the signed link, got %v", out["url"])
	}
	steps := map[string]string{}
	for _, p := range out["platforms"].([]any) {
		pm := p.(map[string]any)
		var all []string
		for _, s := range pm["steps"].([]any) {
			all = append(all, s.(string))
		}
		steps[pm["platform"].(string)] = strings.Join(all, " | ")
	}
	if !strings.Contains(steps["AWS"], "vsensor_ami") || !strings.Contains(steps["AWS"], "no keys") || !strings.Contains(steps["VMware vSphere / ESXi / Nutanix"], "Mirroring") {
		t.Fatalf("AWS must use the account-ID path and vSphere must pick Mirroring: %v", steps)
	}
}

func TestSetupHealthListsActions(t *testing.T) {
	out := data(t, callTool(t, newTestRouter(t), "get_setup_health", `{"org_id":"`+mock.OrgID+`"}`))
	actions := strings.Join(func() []string {
		var s []string
		for _, a := range out["actions"].([]any) {
			s = append(s, a.(string))
		}
		return s
	}(), "\n")
	for _, want := range []string{"unhealthy sensor", "Activate 1 sensor", "MOCK-HQ-VSCANNER", "MOCK-AWS-VSCANNER", "no parser"} {
		if !strings.Contains(actions, want) {
			t.Errorf("actions should mention %q:\n%s", want, actions)
		}
	}
	if out["sensors"].(map[string]any)["status"] != "attention" || out["scanners"].(map[string]any)["status"] != "attention" {
		t.Fatalf("unexpected area status %v", out)
	}
}

func TestManageSensorsScannersSchedulesAndTags(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	apply := func(kind, fields string) (map[string]any, mock.Write) {
		t.Helper()
		change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"`+kind+`","fields":`+fields+`}`))
		if len(mock.Writes()) != 0 {
			t.Fatalf("%s: prepare must not send anything", kind)
		}
		applied := data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`))
		w := mock.Writes()
		if applied["status"] != "applied" || len(w) != 1 {
			t.Fatalf("%s: want one call after confirmation, got %v / %v", kind, applied["status"], w)
		}
		return change, w[0]
	}

	_, w := apply("move_sensor_site", `{"sensor":"MOCK-HQ-VSENSOR","site":"MOCK Topeka Clinic"}`)
	if w.Method != "PUT" || w.Path != "/api/v1/organizations/"+mock.OrgID+"/sensor-profiles/s2" ||
		w.Body["site_uuid"] != "site-topeka" || w.Body["shorthand"] != "MOCK-HQ-VSENSOR" || w.Body["deployment_type"] != "virtual" {
		t.Fatalf("move_sensor_site must PUT the whole profile with the new site: %+v", w)
	}

	_, w = apply("decommission_sensor", `{"sensor":"mockdep2"}`)
	if w.Method != "DELETE" || w.Path != "/api/v1/organizations/"+mock.OrgID+"/deployments/mockdep2/sensor/VN-MOCK-VS-2" {
		t.Fatalf("an activated vSensor is decommissioned in sensor management: %+v", w)
	}
	if bad := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"decommission_sensor","fields":{"sensor":"MOCK-TOP-SENSOR"}}`); bad["isError"] != true {
		t.Fatal("a healthy physical sensor can't be removed online (RMA)")
	}

	change, w := apply("update_scanner_settings", `{"scanner":"MOCK-HQ-VSCANNER","cgi_scanning":"no","scan_period_minutes":"30"}`)
	if w.Method != "PUT" || w.Path != "/api/v2/organizations/"+mock.OrgID+"/scanners/scn-2" || w.Body["cgiScan"] != false ||
		w.Body["hostIden"] != true || w.Body["hostIdentificationScanPeriod"] != float64(30) || w.Body["name"] != "MOCK-HQ-VSCANNER" ||
		w.Body["site"] != "site-hq" || len(w.Body["scanExclusionList"].([]any)) != 1 {
		t.Fatalf("update_scanner_settings must keep current values and change only CGI + period: %+v", w)
	}
	if len(change["details"].([]any)) != 3 { // scanner + two changes
		t.Fatalf("card must show only what changes: %v", change["details"])
	}
	if bad := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_scanner_settings","fields":{"scanner":"scn-2","scan_period_minutes":"7"}}`); bad["isError"] != true {
		t.Fatal("scan period outside the portal options must be rejected")
	}

	_, w = apply("update_scanner_network", `{"scanner":"scn-2","dhcp":"yes"}`)
	if w.Method != "PATCH" || w.Body["ipAddress"] != "dhcpOverride" {
		t.Fatalf("update_scanner_network: %+v", w)
	}

	_, w = apply("pause_scan_schedule", `{"schedule":"MOCK Clinic LAN"}`)
	d := w.Body["disable"].([]any)[0].(map[string]any)
	if w.Method != "PUT" || d["scannerId"] != "scn-1" || d["scanningDisabled"] != true {
		t.Fatalf("pause_scan_schedule: %+v", w)
	}

	_, w = apply("scan_now", `{"scanner":"scn-1","hosts":"10.20.0.20,10.20.0.21"}`)
	if w.Method != "POST" || len(w.Body["scans"].([]any)[0].(map[string]any)["hosts"].([]any)) != 2 {
		t.Fatalf("scan_now: %+v", w)
	}

	_, w = apply("tag_log_sources", `{"tag":"medical","log_sources":"fw01.MOCK.local"}`)
	if w.Method != "POST" || w.Body["logSources"].([]any)[0] != "fw01.mock.local" {
		t.Fatalf("tag_log_sources must use the exact source name: %+v", w)
	}
	_, w = apply("untag_log_sources", `{"tag":"medical","log_sources":"fw01.mock.local"}`)
	if w.Method != "DELETE" {
		t.Fatalf("untag_log_sources: %+v", w)
	}
}

func TestSitesBranchLikeThePortal(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	base := `"name":"Branch","street":"2 Elm St","city":"Topeka","state":"KS","postal_code":"66604","country":"us","time_zone":"America/Chicago"`

	// No physical sensor → the vSensor/vLC question is required; network questions are not.
	bad := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_site","fields":{`+base+`,"physical_sensor":"no","essential_log_sources":"no"}}`)
	if bad["isError"] != true || !strings.Contains(bad["structuredContent"].(map[string]any)["error"].(string), "virtual_sensor") {
		t.Fatalf("no physical sensor must ask about vSensor/vLC: %v", bad)
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_site","fields":{`+base+`,"physical_sensor":"no","essential_log_sources":"no","virtual_sensor":"none","log_source_site":"MOCK Topeka Clinic"}}`))
	body := change["body"].(map[string]any)
	if body["virtual_sensor_type"] != "none" || body["log_source_forward_site"] != "site-topeka" || len(body["firewalls"].([]any)) != 0 || body["ad_domain_controllers"] != float64(0) {
		t.Fatalf("log-forward site must carry the forward site and no network answers: %v", body)
	}

	// Physical sensor → AD, firewalls, HA, DNS, DHCP required ("none" counts as an answer).
	bad = callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_site","fields":{`+base+`,"physical_sensor":"yes","essential_log_sources":"no"}}`)
	if bad["isError"] != true || !strings.Contains(bad["structuredContent"].(map[string]any)["error"].(string), "ad_domain_controllers") {
		t.Fatalf("physical sensor site must ask the network questions: %v", bad)
	}
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"create_site","fields":{`+base+`,"physical_sensor":"yes","essential_log_sources":"no",
		"ad_domain_controllers":"1","firewalls":"Fortinet 60F","ha_firewall_type":"none","dns":"10.1.0.2","dhcp":"none","ip_subnets":"10.1.0.0/24,10.1.1.1-10.1.1.50"}}`))
	body = change["body"].(map[string]any)
	if _, has := body["virtual_sensor_type"]; has || len(body["dhcp"].([]any)) != 0 || len(body["ip_subnets"].([]any)) != 2 {
		t.Fatalf("physical site body: %v", body)
	}
	applied := data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+change["id"].(string)+`"}`))
	if w := mock.Writes(); applied["status"] != "applied" || len(w) != 1 || w[0].Path != "/api/v2/organizations/"+mock.OrgID+"/sites" {
		t.Fatalf("create_site must POST once after confirmation: %v %v", applied["status"], w)
	}

	// update_site keeps every current value and changes only what was given.
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_site","fields":{"site":"MOCK Topeka Clinic","ad_domain_controllers":"3"}}`))
	body = change["body"].(map[string]any)
	if change["method"] != "PUT" || body["ad_domain_controllers"] != float64(3) || body["firewalls"].([]any)[0] != "Palo Alto PA-440" ||
		body["max_isp_bandwidth_purchased"] != float64(500) || body["uuid"] != "site-topeka" || body["name"] != "MOCK Topeka Clinic" {
		t.Fatalf("update_site must keep current values: %v", body)
	}

	// delete_site warns about devices still at the site.
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"delete_site","fields":{"site":"MOCK Topeka Clinic"}}`))
	found := false
	for _, d := range change["details"].([]any) {
		if strings.Contains(d.(map[string]any)["value"].(string), "MOCK-TOP-SENSOR") {
			found = true
		}
	}
	if change["method"] != "DELETE" || !found {
		t.Fatalf("delete_site must list the devices at the site: %v", change)
	}
}

func TestPrerequisitesMatchThePortal(t *testing.T) {
	h := newTestRouter(t)
	_ = mock.Writes()
	errOf := func(out map[string]any) string {
		t.Helper()
		if out["isError"] != true {
			t.Fatalf("want a tool error, got %v", out)
		}
		return out["structuredContent"].(map[string]any)["error"].(string)
	}
	ship := `"name":"Clinic sensor","site":"MOCK Topeka Clinic","dhcp":"yes","ship_first_name":"Ana","ship_last_name":"Diaz","ship_email":"ana@mock.example","ship_phone":"+1 555 0100","street1":"1 Main St","city":"Topeka","province_state":"KS","postal_code":"66603","country":"US"`

	// Physical sensor: the licence's model group decides the deployment type.
	if e := errOf(callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"request_sensor","fields":{"license":"awn203","deployment_type":"internal_tap",`+ship+`}}`)); !strings.Contains(e, "mirroring") {
		t.Fatalf("AWN203 is mirroring only: %s", e)
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"request_sensor","fields":{"license":"awn203","deployment_type":"mirroring",`+ship+`}}`))
	tech := change["body"].(map[string]any)["technical_requirements"].(map[string]any)
	if tech["deployment_type"] != "mirroring" || tech["customer_configured"] != false {
		t.Fatalf("technical requirements: %v", tech)
	}

	// Scan exclusions are set on the scanner before schedules.
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_scanner_settings","fields":{"scanner":"scn-2","add_exclusions":"10.30.0.20,10.30.0.100-10.30.0.110","remove_exclusions":"10.30.0.250"}}`))
	if ex := change["body"].(map[string]any)["scanExclusionList"].([]any); len(ex) != 2 || ex[0] != "10.30.0.20" {
		t.Fatalf("exclusions must be merged into the deny list: %v", ex)
	}
	errOf(callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_scanner_settings","fields":{"scanner":"scn-2","add_exclusions":"printer01"}}`))

	// Premium cloud app not purchased → can't connect; a quote request instead.
	if e := errOf(callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"crowdstrike_falcon","name":"CS"}}`)); !strings.Contains(e, "request_cloud_quote") {
		t.Fatalf("premium must point to a quote request: %s", e)
	}
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"request_cloud_quote","fields":{"type":"crowdstrike_falcon"}}`))
	if b := change["body"].(map[string]any); b["ticketType"] != "cloudRequestQuote" || change["path"] != "/api/v1/organizations/"+mock.OrgID+"/tickets" {
		t.Fatalf("quote ticket: %v", change)
	}
	if e := errOf(callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"okta_pollerbear","name":"Okta","expiry":"2001-01-01"}}`)); !strings.Contains(e, "future") {
		t.Fatalf("past expiry must be rejected: %s", e)
	}

	// Fixing a cloud app: new credentials on the secure card; removing it.
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_cloud_credentials","fields":{"cloud_app":"MOCK Okta"}}`))
	if change["method"] != "PUT" || change["status"] != "needs_secure_fields" || change["path"] != "/api/v1/organizations/"+mock.OrgID+"/customer-credential/mockdep3" {
		t.Fatalf("update credentials: %v", change)
	}
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"remove_cloud_app","fields":{"cloud_app":"mockdep3"}}`))
	if change["method"] != "DELETE" {
		t.Fatalf("remove cloud app: %v", change)
	}

	// Only an activated sensor can be decommissioned.
	if e := errOf(callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"decommission_sensor","fields":{"sensor":"MOCK-HQ-VLC"}}`)); !strings.Contains(e, "Awaiting Activation") {
		t.Fatalf("awaiting-activation sensor: %s", e)
	}
	if len(mock.Writes()) != 0 {
		t.Fatal("prepare must never send anything")
	}
}

func TestContactEmailMustBeOnARegisteredDomain(t *testing.T) {
	h := newTestRouter(t)
	out := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"add_contact","fields":{"first_name":"Ana","last_name":"Diaz","title":"IT","email":"ana@gmail.com","phone":"+1 555 0100","timezone":"America/Chicago","roles":"primary"}}`)
	if out["isError"] != true || !strings.Contains(out["structuredContent"].(map[string]any)["error"].(string), "mock.example") {
		t.Fatalf("an address outside the registered domains must be refused, naming them: %v", out)
	}
}

func TestLicenceRequestAndADSensor(t *testing.T) {
	h := newTestRouter(t)
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"request_licences","fields":{"device":"physical_sensor","quantity":"2","model":"awn201"}}`))
	if b := change["body"].(map[string]any); b["ticketType"] != "sensorCollectorRequestQuote" || !strings.Contains(b["subject"].(string), "2 × physical sensor") {
		t.Fatalf("licence request ticket: %v", change)
	}
	if out := callTool(t, h, "get_ad_sensor_installer", `{"org_id":"`+mock.OrgID+`","sensor":"nope"}`); out["isError"] != true {
		t.Fatal("unknown sensor must list the sensors with an IP")
	}
}

func TestWatchForLogsSeesArrivedSource(t *testing.T) {
	h := newTestRouter(t)
	got := data(t, callTool(t, h, "watch_for_logs", `{"org_id":"`+mock.OrgID+`","source":"10.20.4.11","wait_seconds":1}`))
	if got["arrived"] != true || got["source"].(map[string]any)["sensor"] != "mockdep1" {
		t.Fatalf("a source LSS already sees must be reported as arrived: %v", got)
	}
	got = data(t, callTool(t, h, "watch_for_logs", `{"org_id":"`+mock.OrgID+`","source":"10.99.99.99","wait_seconds":1}`))
	if got["arrived"] != false {
		t.Fatalf("an unknown source has not arrived: %v", got)
	}
}

func TestCloudAppsSuggestedFromCloudInformation(t *testing.T) {
	h := newTestRouter(t)
	out := callTool(t, h, "list_cloud_integrations", `{"org_id":"`+mock.OrgID+`","from_cloud_information":"yes"}`)
	list := out["structuredContent"].(map[string]any)["data"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["type"] != "crowdstrike_falcon" || list[0].(map[string]any)["suggestedBecause"] == "" {
		t.Fatalf("CrowdStrike must be suggested because the customer said they use it: %v", list)
	}
}

func TestCloudAppsGoThroughAuroraIntegrations(t *testing.T) {
	h := newTestRouterWithIngestion(t)
	_ = mock.Writes()
	list := callTool(t, h, "list_cloud_integrations", `{"org_id":"`+mock.OrgID+`","name_contains":"microsoft"}`)["structuredContent"].(map[string]any)["data"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["type"] != "m365" || list[0].(map[string]any)["connected"] != float64(1) {
		t.Fatalf("catalog must come from the ingestion orchestrator: %v", list)
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"m365","name":"Contoso"}}`))
	if change["path"] != "/customers/"+mock.OrgID+"/integration/m365/sensor" || change["status"] != "needs_secure_fields" {
		t.Fatalf("connect must POST to the ingestion orchestrator and collect credentials on the card: %v", change)
	}
	id := change["id"].(string)
	callTool(t, h, "submit_secure_fields", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`","values":{"tenant_id":"t-1","client_secret":"s3cret"}}`)
	applied := data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`"}`))
	w := mock.Writes()
	if applied["status"] != "applied" || len(w) != 1 || w[0].Path != "/ingest/api/v1/customers/"+mock.OrgID+"/integration/m365/sensor" ||
		w[0].Body["credential"].(map[string]any)["client_secret"] != "s3cret" {
		t.Fatalf("credentials must be sent once under credential: %v %v", applied["status"], w)
	}
	if b, _ := json.Marshal(applied); strings.Contains(string(b), "s3cret") {
		t.Fatal("the secret must never come back")
	}
	if out := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"crowdstrike","name":"CS"}}`); out["isError"] != true {
		t.Fatal("an unlicensed premium integration can't be connected")
	}
	if out := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"generic_webhook","name":"W"}}`); out["isError"] != true {
		t.Fatal("webhook integrations are finished on the Integrations page (the token must not go through chat)")
	}
	apps := callTool(t, h, "list_cloud_apps", `{"org_id":"`+mock.OrgID+`"}`)["structuredContent"].(map[string]any)["data"].([]any)
	if a := apps[0].(map[string]any); a["health"] != "unhealthy" || len(a["actions"].([]any)) != 1 {
		t.Fatalf("cloud app must show health and the call to action: %v", apps)
	}
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"update_cloud_credentials","fields":{"cloud_app":"Contoso M365"}}`))
	if change["method"] != "PUT" || change["path"] != "/customers/"+mock.OrgID+"/integration/m365/sensor/ing-1" {
		t.Fatalf("update credentials: %v", change)
	}
}

func TestCloudScannerAccountsLikeThePortal(t *testing.T) {
	h := newTestRouterWithIngestion(t)
	_ = mock.Writes()
	got := data(t, callTool(t, h, "list_cloud_scanner_accounts", `{"org_id":"`+mock.OrgID+`"}`))
	if accts := got["accounts"].([]any); len(accts) != 1 || accts[0].(map[string]any)["provider"] != "Azure" {
		t.Fatalf("only CSPM accounts are listed: %v", got)
	}
	if out := callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_scanner","fields":{"provider":"aws","account":"12345"}}`); out["isError"] != true {
		t.Fatal("an AWS account id is 12 digits")
	}
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_scanner","fields":{"provider":"aws","account":"123456789012"}}`))
	b := change["body"].(map[string]any)
	if b["schemaType"] != "prod_cspm_aws" || b["integrationInstanceId"] != "123456789012" || change["status"] != "needs_secure_fields" {
		t.Fatalf("CSPM body must match the portal: %v", change)
	}
	id := change["id"].(string)
	callTool(t, h, "submit_secure_fields", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`","values":{"role_arn":"arn:aws:iam::123456789012:role/AW"}}`)
	data(t, callTool(t, h, "apply_change", `{"org_id":"`+mock.OrgID+`","change_id":"`+id+`"}`))
	w := mock.Writes()
	if len(w) != 1 || w[0].Path != "/cms/api/v1/organizations/"+mock.OrgID+"/credentials" ||
		w[0].Body["credential"].(map[string]any)["role_arn"] != "arn:aws:iam::123456789012:role/AW" || w[0].Body["credential"].(map[string]any)["account_id"] != "123456789012" {
		t.Fatalf("CSPM account must be created once with the role ARN: %v", w)
	}
	change = data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"remove_cloud_scanner","fields":{"account":"0b0b0b0b-1111-2222-3333-444444444444"}}`))
	if change["path"] != "/api/v1/organizations/"+mock.OrgID+"/credentials/cred-1" || change["method"] != "DELETE" {
		t.Fatalf("remove: %v", change)
	}
}

func TestNewSourcesAreLabelledFromTheirLines(t *testing.T) {
	h := newTestRouter(t)
	got := data(t, callTool(t, h, "list_log_sources", `{"org_id":"`+mock.OrgID+`","name_contains":"10.20.4","peek_samples":"yes"}`))
	labels := map[string]string{}
	for _, s := range got["sources"].([]any) {
		m := s.(map[string]any)
		labels[m["name"].(string)+"@"+m["sensor"].(string)], _ = m["looksLike"].(string)
	}
	if labels["10.20.4.12@mockdep1"] != "DNS server" || labels["10.20.4.11@mockdep1"] != "unknown (no sample lines yet)" {
		t.Fatalf("labels must come from sample lines: %v", labels)
	}
}

func TestApplianceAccountTypesUseThePortalPath(t *testing.T) {
	h := newTestRouterWithIngestion(t)
	// okta_pollerbear is only in the Rendall catalog in the mock, like vsensor_ami in prod.
	change := data(t, callTool(t, h, "prepare_change", `{"org_id":"`+mock.OrgID+`","kind":"connect_cloud_app","fields":{"type":"okta_pollerbear","name":"Okta"}}`))
	if change["path"] != "/api/v2/organizations/"+mock.OrgID+"/cloud-sensors" {
		t.Fatalf("a type Aurora Integrations doesn't know must go the Unified Portal way: %v", change["path"])
	}
	list := callTool(t, h, "list_cloud_integrations", `{"org_id":"`+mock.OrgID+`"}`)["structuredContent"].(map[string]any)["data"].([]any)
	types := map[string]bool{}
	for _, it := range list {
		types[it.(map[string]any)["type"].(string)] = true
	}
	if !types["m365"] || !types["okta_pollerbear"] {
		t.Fatalf("both catalogs must be listed: %v", types)
	}
}
