package discovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Day-2 management of sensors, scanners, scan schedules and log sources ---
//
// The same Rendall calls the Unified Portal makes from its Sensors, Scanners, Scan Schedules
// and Log Sources pages (rtkwlf/arcticexperience apis/rendall/src/queries):
//   move_sensor_site        PUT    /api/v1/organizations/{org}/sensor-profiles/{uuid}    (updateSensorProfileByUUID)
//   decommission_sensor     DELETE /api/v1/organizations/{org}/sensor-profiles/{uuid}    (deleteSensorProfileByUUID)
//   update_scanner_settings PUT    /api/v2/organizations/{org}/scanners/{id}             (editScannerConfigV2)
//   update_scanner_network  PATCH  /api/v2/organizations/{org}/scanners/{id}/network-configuration
//   decommission_scanner    DELETE /api/v2/organizations/{org}/scanners/{id}             (deleteScannerProfile)
//   pause_scan_schedule     PUT    /api/v1/organizations/{org}/iva/scan-schedules/disable (bulkDisableIvaSchedule)
//   delete_scan_schedule    DELETE /api/v1/organizations/{org}/scan-schedules/iva        (deleteIvaSchedules)
//   scan_now                POST   /api/v1/organizations/{org}/iva/scan                  (scanIvaNow)
//   tag_log_sources         POST   /api/v1/organizations/{org}/log-sources/tag           (createLogSourceTag)
//   untag_log_sources       DELETE /api/v1/organizations/{org}/log-sources/tag           (deleteLogSourceTag)

const (
	ChangeMoveSensorSite        = "move_sensor_site"
	ChangeDecommissionSensor    = "decommission_sensor"
	ChangeUpdateScannerSettings = "update_scanner_settings"
	ChangeUpdateScannerNetwork  = "update_scanner_network"
	ChangeDecommissionScanner   = "decommission_scanner"
	ChangePauseScanSchedule     = "pause_scan_schedule"
	ChangeDeleteScanSchedule    = "delete_scan_schedule"
	ChangeScanNow               = "scan_now"
	ChangeTagLogSources         = "tag_log_sources"
	ChangeUntagLogSources       = "untag_log_sources"
)

// Unified Portal option lists (scanner-configuration use-scan-period-options / max-concurrent).
var scannerScanPeriods = map[int]bool{5: true, 30: true, 60: true, 120: true}

// Scanner switches: request field → IVA setting name (transform-to-scanner-details-form.ts).
var scannerSwitches = []struct{ field, setting, body, label string }{
	{"host_identification", "hostIdentificationScans", "hostIden", "Host identification"},
	{"vulnerability_scanning", "vulnerabilityScans", "vulnScan", "Vulnerability scanning"},
	{"cgi_scanning", "CGIScanning", "cgiScan", "CGI scanning"},
	{"brute_force_scanning", "bruteForceChecks", "bruteScan", "Brute force checks"},
	{"ping_only", "onlyPingTheTarget", "pingOnly", "Ping-only discovery"},
}

func (s *Service) prepareManage(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	switch kind {
	case ChangeMoveSensorSite, ChangeDecommissionSensor:
		miss, err = s.prepareSensorManage(ctx, org, ch, kind, params)
	case ChangeUpdateScannerSettings:
		miss, err = s.prepareScannerSettings(ctx, org, ch, params)
	case ChangeUpdateScannerNetwork:
		miss, err = s.prepareScannerNetwork(ctx, org, ch, params)
	case ChangeDecommissionScanner:
		miss, err = s.prepareScannerDecommission(ctx, org, ch, params)
	case ChangePauseScanSchedule, ChangeDeleteScanSchedule:
		miss, err = s.prepareScheduleManage(ctx, org, ch, kind, params)
	case ChangeScanNow:
		miss, err = s.prepareScanNow(ctx, org, ch, params)
	case ChangeTagLogSources, ChangeUntagLogSources:
		miss, err = s.prepareLogSourceTag(ctx, org, ch, kind, params)
	case ChangeUpdateSite, ChangeDeleteSite:
		miss, err = s.prepareSiteManage(ctx, org, ch, kind, params)
	default:
		return nil, false, nil
	}
	return miss, true, err
}

func (s *Service) findSensorRow(ctx context.Context, org upstream.Organization, want string) (upstream.SensorRow, error) {
	rows, err := s.up.Sensors(ctx, org.Pod, org.ID)
	if err != nil {
		return upstream.SensorRow{}, fmt.Errorf("could not read sensors: %w", err)
	}
	want = strings.TrimSpace(want)
	for _, r := range rows {
		if strings.EqualFold(r.UUID, want) || strings.EqualFold(r.SerialNumber, want) || strings.EqualFold(r.DeploymentID, want) || strings.EqualFold(r.Name, want) {
			return r, nil
		}
	}
	return upstream.SensorRow{}, fmt.Errorf("%w: sensor %q not found; use list_sensors", ErrChangeInvalid, want)
}

func (s *Service) findSite(ctx context.Context, org upstream.Organization, want string) (upstream.Site, error) {
	sites, err := s.up.Sites(ctx, org.Pod, org.ID)
	if err != nil {
		return upstream.Site{}, fmt.Errorf("could not read sites: %w", err)
	}
	for _, st := range sites {
		if strings.EqualFold(st.UUID, want) || strings.EqualFold(strings.TrimSpace(st.Name), strings.TrimSpace(want)) {
			return st, nil
		}
	}
	return upstream.Site{}, fmt.Errorf("%w: site %q not found; use get_onboarding_checklist (sites) or create_site", ErrChangeInvalid, want)
}

func (s *Service) prepareSensorManage(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) ([]string, error) {
	need := []string{"sensor"}
	if kind == ChangeMoveSensorSite {
		need = append(need, "site")
	}
	if miss := missing(params, need...); len(miss) > 0 {
		return miss, nil
	}
	row, err := s.findSensorRow(ctx, org, str(params, "sensor"))
	if err != nil {
		return nil, err
	}
	path := "/api/v1/organizations/" + org.ID + "/sensor-profiles/" + url.PathEscape(row.UUID)
	ident := []ChangeDetail{{"Sensor", row.Name}, {"Type", orDefault(row.Product, "unknown") + " " + row.Model}, {"Status", row.Status}, {"Serial", orDefault(row.SerialNumber, "not assigned yet")}}

	physical := strings.EqualFold(row.Product, "physical")
	if kind == ChangeDecommissionSensor {
		// Sensor rules (Sensors Feature capability matrix / "Sensor Use Cases, Workflows, and APIs
		// Overview" 6976962849): a physical sensor can only be removed while it is still New (the
		// request is cancelled); past New it goes back through an RMA with Arctic Wolf. An activated
		// vSensor or vLC is decommissioned in sensor management; one Awaiting Activation can't be.
		switch {
		case physical && strings.EqualFold(row.Status, "new"):
			ch.Title = "Cancel the request for sensor " + row.Name
			ch.Method, ch.Path, ch.Body = "DELETE", path, nil
			ch.Details = append(ident, ChangeDetail{"Effect", "Deletes the sensor request before Arctic Wolf prepares and ships it; the licence is freed."})
			ch.Assumptions = []string{"Same as Delete on a New sensor in the Unified Portal. To undo, request the sensor again."}
		case physical:
			return nil, fmt.Errorf("%w: %s is a physical sensor that is already %s, so it can't be removed online; returns and replacements go through Arctic Wolf (RMA). Offer to contact the Concierge team", ErrChangeInvalid, row.Name, row.Status)
		case strings.EqualFold(row.Status, "awaitingActivation"):
			return nil, fmt.Errorf("%w: %s is still Awaiting Activation; Arctic Wolf only decommissions an activated sensor. Activate it first (activate_appliance) or simply don't use it", ErrChangeInvalid, row.Name)
		case row.DeploymentID == "" || row.SerialNumber == "":
			return nil, fmt.Errorf("%w: %s has no deployment or serial number on record yet, so it can't be decommissioned online; ask the Concierge team", ErrChangeInvalid, row.Name)
		default:
			ch.Title = "Decommission " + row.Product + " " + row.Name
			ch.Method, ch.Body = "DELETE", nil
			ch.Path = "/api/v1/organizations/" + org.ID + "/deployments/" + url.PathEscape(row.DeploymentID) + "/sensor/" + url.PathEscape(row.SerialNumber)
			ch.Details = append(ident, ChangeDetail{"Effect", "Stops the virtual appliance and removes it. Logs and traffic it collects stop being monitored; the VM can then be deleted."})
			ch.Assumptions = []string{"Same as Decommission on a vSensor or vLC in the Unified Portal. It cannot be undone: a new appliance has to be downloaded and activated."}
		}
		return nil, nil
	}
	// Edit rules: physical New/Staged/Healthy may change site; other physical states can't be edited;
	// a vSensor or vLC can change site except while Awaiting Activation.
	if physical && !contains([]string{"new", "staged", "healthy"}, strings.ToLower(row.Status)) {
		return nil, fmt.Errorf("%w: %s is %s; a physical sensor's site can only be changed while it is New, Staged or Healthy. Ask the Concierge team", ErrChangeInvalid, row.Name, row.Status)
	}
	if !physical && strings.EqualFold(row.Status, "awaitingActivation") {
		return nil, fmt.Errorf("%w: %s is Awaiting Activation; its site can be set once it's activated", ErrChangeInvalid, row.Name)
	}

	site, err := s.findSite(ctx, org, str(params, "site"))
	if err != nil {
		return nil, err
	}
	// The PUT takes the whole profile: start from the sensor as Rendall has it and change only
	// the site, as the Unified Portal sensor page does.
	var cur map[string]any
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/sensors/"+url.PathEscape(row.UUID), &cur); err != nil {
		return nil, fmt.Errorf("could not read sensor %s: %w", row.Name, err)
	}
	body := sensorProfileFrom(cur)
	body["uuid"] = row.UUID
	body["site_uuid"] = site.UUID
	ch.Title = "Move sensor " + row.Name + " to site " + site.Name
	ch.Method, ch.Path, ch.Body = "PUT", path, body
	ch.Details = append(ident, ChangeDetail{"Current site", orDefault(row.SiteName, "none")}, ChangeDetail{"New site", site.Name})
	return nil, nil
}

// sensorProfileFrom maps Rendall's Sensor (GET …/sensors/{id}) onto the SensorProfile the PUT
// expects. Unknown values are left out rather than guessed.
func sensorProfileFrom(cur map[string]any) map[string]any {
	out := map[string]any{}
	copyKey := func(from, to string) {
		if v, ok := cur[from]; ok && v != nil && v != "" {
			out[to] = v
		}
	}
	copyKey("name", "shorthand")
	copyKey("device_type", "deployment_type")
	copyKey("deploymentID", "deployment")
	copyKey("ipAddress", "ip_address")
	copyKey("subnetMask", "subnet")
	copyKey("defaultGateway", "default_gateway")
	copyKey("primaryDns", "primary_dns")
	copyKey("secondaryDns", "secondary_dns")
	copyKey("model", "required_hardware")
	copyKey("configuration", "configuration")
	copyKey("shipping_info", "shipping_info")
	copyKey("technical_requirements", "technical_requirements")
	copyKey("notes", "notes")
	return out
}

func (s *Service) scannerProfile(ctx context.Context, org upstream.Organization, id string) (map[string]any, error) {
	var prof map[string]any
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/scanners/"+url.PathEscape(id), &prof); err != nil {
		return nil, err
	}
	return prof, nil
}

func settingEnabled(details map[string]any, name string) bool {
	items, _ := details["settings"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["name"] == name {
			b, _ := m["enabled"].(bool)
			return b
		}
	}
	return false
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func numberOf(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}

func (s *Service) prepareScannerSettings(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	if miss := missing(params, "scanner"); len(miss) > 0 {
		return miss, nil
	}
	row, err := s.findScanner(ctx, org, str(params, "scanner"))
	if err != nil {
		return nil, err
	}
	prof, err := s.scannerProfile(ctx, org, row.ID)
	if err != nil {
		return nil, fmt.Errorf("could not read scanner %s: %w", row.Name, err)
	}
	details, _ := prof["scannerDetails"].(map[string]any)
	if details == nil {
		details = map[string]any{}
	}
	// Current values, exactly as the Unified Portal form loads them.
	name, _ := prof["name"].(string)
	site, _ := prof["siteUuid"].(string)
	body := map[string]any{
		"name":                            name,
		"site":                            nilIfEmpty(site),
		"hostIdenServers":                 orEmptyList(details["dnsServers"]),
		"scanExclusionList":               orEmptyList(details["denyList"]),
		"portBlockRules":                  orEmptyList(details["portBlockRules"]),
		"selfScanEnabled":                 details["selfScanEnabled"] == true,
		"hostIdentificationScanIntensity": orDefault(fmt.Sprint(orNil(details["hostIdentificationScanIntensity"], "low")), "low"),
		"hostIdentificationScanPeriod":    numberOf(details["hostIdentificationScanPeriod"], 5),
		"maxConcurrentVulnerabilityScans": numberOf(details["maxConcurrentVulnerabilityScans"], 0),
	}
	for _, sw := range scannerSwitches {
		body[sw.body] = settingEnabled(details, sw.setting)
	}

	var changed []ChangeDetail
	if v := str(params, "name"); v != "" && v != name {
		changed = append(changed, ChangeDetail{"Name", name + " → " + v})
		body["name"] = v
	}
	if v := str(params, "site"); v != "" {
		st, err := s.findSite(ctx, org, v)
		if err != nil {
			return nil, err
		}
		if st.UUID != site {
			changed = append(changed, ChangeDetail{"Site", orDefault(row.SiteName, "none") + " → " + st.Name})
			body["site"] = st.UUID
		}
	}
	for _, sw := range scannerSwitches {
		if v := str(params, sw.field); v != "" {
			want := yes(params, sw.field)
			if want != body[sw.body] {
				changed = append(changed, ChangeDetail{sw.label, onOff(body[sw.body] == true) + " → " + onOff(want)})
				body[sw.body] = want
			}
		}
	}
	if v := str(params, "self_scan"); v != "" && yes(params, "self_scan") != body["selfScanEnabled"] {
		changed = append(changed, ChangeDetail{"Self scanning", onOff(body["selfScanEnabled"] == true) + " → " + onOff(yes(params, "self_scan"))})
		body["selfScanEnabled"] = yes(params, "self_scan")
	}
	if v := strings.ToLower(str(params, "intensity")); v != "" {
		if v != "low" && v != "medium" && v != "high" {
			return nil, fmt.Errorf("%w: intensity must be low, medium or high", ErrChangeInvalid)
		}
		if v != body["hostIdentificationScanIntensity"] {
			changed = append(changed, ChangeDetail{"Scanning intensity", fmt.Sprint(body["hostIdentificationScanIntensity"]) + " → " + v})
			body["hostIdentificationScanIntensity"] = v
		}
	}
	if v := str(params, "scan_period_minutes"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || !scannerScanPeriods[n] {
			return nil, fmt.Errorf("%w: scan_period_minutes must be 5, 30, 60 or 120", ErrChangeInvalid)
		}
		if n != body["hostIdentificationScanPeriod"] {
			changed = append(changed, ChangeDetail{"Scan period", fmt.Sprintf("%v → %d minutes", body["hostIdentificationScanPeriod"], n)})
			body["hostIdentificationScanPeriod"] = n
		}
	}
	if v := str(params, "max_concurrent_scans"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 30 {
			return nil, fmt.Errorf("%w: max_concurrent_scans must be 0 (unlimited) to 30", ErrChangeInvalid)
		}
		if n != body["maxConcurrentVulnerabilityScans"] {
			changed = append(changed, ChangeDetail{"Max concurrent vulnerability scans", fmt.Sprintf("%v → %d", body["maxConcurrentVulnerabilityScans"], n)})
			body["maxConcurrentVulnerabilityScans"] = n
		}
	}
	if add, remove := list(params, "add_exclusions"), list(params, "remove_exclusions"); len(add)+len(remove) > 0 {
		cur, _ := body["scanExclusionList"].([]any)
		merged, ex, err := mergeExclusions(cur, add, remove)
		if err != nil {
			return nil, err
		}
		if len(ex) > 0 {
			body["scanExclusionList"] = merged
			changed = append(changed, ChangeDetail{"Scan exclusions", strings.Join(ex, ", ")})
		}
	}
	if len(changed) == 0 {
		return nil, fmt.Errorf("%w: nothing to change; give at least one of add_exclusions, remove_exclusions, name, site, host_identification, vulnerability_scanning, cgi_scanning, brute_force_scanning, ping_only, self_scan, intensity, scan_period_minutes, max_concurrent_scans", ErrChangeInvalid)
	}
	if body["hostIden"] == false && body["vulnScan"] == true {
		changed = append(changed, ChangeDetail{"Note", "Vulnerability scanning needs host identification; with host identification off no vulnerability scans run."})
	}
	ch.Title = "Update scanner " + row.Name
	ch.Method, ch.Path, ch.Body = "PUT", "/api/v2/organizations/"+org.ID+"/scanners/"+url.PathEscape(row.ID), body
	ch.Details = append([]ChangeDetail{{"Scanner", row.Name}}, changed...)
	ch.Assumptions = []string{"Same as Save Changes on the Unified Portal scanner page. The scanner picks the change up from its queue within minutes."}
	return nil, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orNil(v any, def any) any {
	if v == nil {
		return def
	}
	return v
}

func orEmptyList(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func (s *Service) prepareScannerNetwork(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	if miss := missing(params, "scanner"); len(miss) > 0 {
		return miss, nil
	}
	dhcp := yes(params, "dhcp")
	if !dhcp {
		if miss := missing(params, "scanner", "static_ip", "subnet_mask", "gateway", "primary_dns"); len(miss) > 0 {
			return miss, nil
		}
	}
	row, err := s.findScanner(ctx, org, str(params, "scanner"))
	if err != nil {
		return nil, err
	}
	body := map[string]any{"customerConfigured": true}
	if dhcp {
		for _, k := range []string{"ipAddress", "subnetMask", "gateway", "primaryDns", "secondaryDns"} {
			body[k] = "dhcpOverride"
		}
		ch.Details = []ChangeDetail{{"Scanner", row.Name}, {"Addressing", "DHCP (no static IP)"}}
	} else {
		for _, f := range []string{"static_ip", "subnet_mask", "gateway", "primary_dns", "secondary_dns"} {
			if v := str(params, f); v != "" && net.ParseIP(v) == nil {
				return nil, fmt.Errorf("%w: %s %q is not an IP address", ErrChangeInvalid, f, v)
			}
		}
		body["ipAddress"], body["subnetMask"], body["gateway"], body["primaryDns"] = str(params, "static_ip"), str(params, "subnet_mask"), str(params, "gateway"), str(params, "primary_dns")
		if v := str(params, "secondary_dns"); v != "" {
			body["secondaryDns"] = v
		}
		ch.Details = []ChangeDetail{{"Scanner", row.Name}, {"Static IP", str(params, "static_ip")}, {"Subnet mask", str(params, "subnet_mask")},
			{"Gateway", str(params, "gateway")}, {"DNS", strings.Join(nonEmpty(str(params, "primary_dns"), str(params, "secondary_dns")), ", ")}}
	}
	ch.Title = "Change network settings of scanner " + row.Name
	ch.Method, ch.Path, ch.Body = "PATCH", "/api/v2/organizations/"+org.ID+"/scanners/"+url.PathEscape(row.ID)+"/network-configuration", body
	ch.Assumptions = []string{"For a physical scanner that has not shipped yet this is the address it is provisioned with; a running scanner is changed from its serial console."}
	return nil, nil
}

func (s *Service) prepareScannerDecommission(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	if miss := missing(params, "scanner"); len(miss) > 0 {
		return miss, nil
	}
	row, err := s.findScanner(ctx, org, str(params, "scanner"))
	if err != nil {
		return nil, err
	}
	ch.Title = "Decommission scanner " + row.Name
	ch.Method, ch.Path, ch.Body = "DELETE", "/api/v2/organizations/"+org.ID+"/scanners/"+url.PathEscape(row.ID), nil
	ch.Details = []ChangeDetail{{"Scanner", row.Name}, {"Type", row.Type}, {"Status", row.Status}, {"Serial", orDefault(row.SerialNumber, "not assigned yet")},
		{"Effect", "Removes the scanner and stops all of its scan schedules."}}
	ch.Assumptions = []string{"Same as Decommission Scanner on the Unified Portal scanner page. It cannot be undone from here."}
	return nil, nil
}

// findSchedule finds a scan schedule by name or id on one scanner, or on any connected scanner.
func (s *Service) findSchedule(ctx context.Context, org upstream.Organization, scanner, want string) (scannerRow, map[string]any, error) {
	rows, err := s.scannerRows(ctx, org)
	if err != nil {
		return scannerRow{}, nil, fmt.Errorf("could not read scanners: %w", err)
	}
	if scanner != "" {
		r, err := s.findScanner(ctx, org, scanner)
		if err != nil {
			return scannerRow{}, nil, err
		}
		rows = []scannerRow{r}
	}
	want = strings.TrimSpace(want)
	for _, r := range rows {
		if !scannerOperational[r.Status] {
			continue
		}
		items, err := s.scannerSchedules(ctx, org, r.ID)
		if err != nil {
			continue
		}
		for _, it := range items {
			if strings.EqualFold(fmt.Sprint(it["id"]), want) || strings.EqualFold(strings.TrimSpace(fmt.Sprint(it["name"])), want) {
				return r, it, nil
			}
		}
	}
	return scannerRow{}, nil, fmt.Errorf("%w: scan schedule %q not found; use get_scanner to list a scanner's schedules", ErrChangeInvalid, want)
}

func (s *Service) prepareScheduleManage(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) ([]string, error) {
	if miss := missing(params, "schedule"); len(miss) > 0 {
		return miss, nil
	}
	row, sched, err := s.findSchedule(ctx, org, str(params, "scanner"), str(params, "schedule"))
	if err != nil {
		return nil, err
	}
	id, name := fmt.Sprint(sched["id"]), fmt.Sprint(sched["name"])
	ident := []ChangeDetail{{"Scan schedule", name}, {"Scanner", row.Name}}
	if kind == ChangeDeleteScanSchedule {
		ch.Title = "Delete scan schedule " + name
		ch.Method, ch.Path = "DELETE", "/api/v1/organizations/"+org.ID+"/scan-schedules/iva"
		ch.Body = map[string]any{"delete": []any{map[string]any{"scannerId": row.ID, "scheduleIds": []string{id}}}}
		ch.Details = ident
		ch.Assumptions = []string{"Same as Delete on the Unified Portal Scan Schedules page; the scanner removes it from its queue."}
		return nil, nil
	}
	resume := yes(params, "resume")
	ch.Title = "Pause scan schedule " + name
	state := "paused (no scans until resumed)"
	if resume {
		ch.Title, state = "Resume scan schedule "+name, "scanning enabled"
	}
	ch.Method, ch.Path = "PUT", "/api/v1/organizations/"+org.ID+"/iva/scan-schedules/disable"
	ch.Body = map[string]any{"disable": []any{map[string]any{"scannerId": row.ID, "scheduleId": id, "scanningDisabled": !resume}}}
	ch.Details = append(ident, ChangeDetail{"New state", state})
	return nil, nil
}

func (s *Service) prepareScanNow(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	if miss := missing(params, "scanner", "hosts"); len(miss) > 0 {
		return miss, nil
	}
	row, err := s.findScanner(ctx, org, str(params, "scanner"))
	if err != nil {
		return nil, err
	}
	if !scannerOperational[row.Status] {
		return nil, fmt.Errorf("%w: scanner %s is %s; it must be connected to scan", ErrChangeInvalid, row.Name, row.Status)
	}
	hosts := list(params, "hosts")
	for _, h := range hosts {
		if net.ParseIP(h) == nil {
			return nil, fmt.Errorf("%w: %q is not an IP address; scan now takes individual host addresses", ErrChangeInvalid, h)
		}
	}
	if len(hosts) > 100 {
		return nil, fmt.Errorf("%w: at most 100 hosts per scan now; use a scan schedule for networks", ErrChangeInvalid)
	}
	ch.Title = fmt.Sprintf("Scan %d host(s) now with %s", len(hosts), row.Name)
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/iva/scan"
	ch.Body = map[string]any{"scans": []any{map[string]any{"scannerId": row.ID, "hosts": hosts}}}
	ch.Details = []ChangeDetail{{"Scanner", row.Name}, {"Hosts", strings.Join(hosts, ", ")}}
	ch.Assumptions = []string{"Same as Scan Now on the Unified Portal. Results appear in Vulnerability Management once the scan finishes."}
	return nil, nil
}

func (s *Service) prepareLogSourceTag(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) ([]string, error) {
	if miss := missing(params, "tag", "log_sources"); len(miss) > 0 {
		return miss, nil
	}
	sources, err := s.up.LogSources(ctx, org.Pod, org.ID)
	if err != nil {
		return nil, fmt.Errorf("could not read log sources: %w", err)
	}
	known := map[string]string{}
	for _, src := range sources {
		known[strings.ToLower(src.Name)] = src.Name
	}
	var names []string
	for _, n := range list(params, "log_sources") {
		exact, ok := known[strings.ToLower(n)]
		if !ok {
			return nil, fmt.Errorf("%w: log source %q not found; use list_log_sources", ErrChangeInvalid, n)
		}
		names = append(names, exact)
	}
	tag := str(params, "tag")
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/log-sources/tag"
	ch.Title = fmt.Sprintf("Tag %d log source(s) %q", len(names), tag)
	if kind == ChangeUntagLogSources {
		ch.Method = "DELETE"
		ch.Title = fmt.Sprintf("Remove tag %q from %d log source(s)", tag, len(names))
	}
	ch.Body = map[string]any{"tag": tag, "logSources": names}
	ch.Details = []ChangeDetail{{"Tag", tag}, {"Log sources", strings.Join(names, ", ")}}
	return nil, nil
}
