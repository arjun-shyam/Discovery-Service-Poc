package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Appliance activation, scanner requests and scan schedules ---
//
// Same Rendall calls as the Unified Portal / Aurora pages:
//   activate_appliance   POST /api/v1/organizations/{org}/sensor/{serial}       (installSensor; sensors, scanners and vLCs)
//   request_scanner      POST /api/v2/organizations/{org}/scanners              (createScannerProfile, physical)
//   create_scan_schedule POST /api/v1/organizations/{org}/iva/{scanner}/scan-schedules (createIvaSchedule)

const (
	ChangeActivateAppliance  = "activate_appliance"
	ChangeRequestScanner     = "request_scanner"
	ChangeCreateScanSchedule = "create_scan_schedule"
)

// Scan schedule limits: the scanner supports ranges up to /16, and one schedule may not
// target more than 65,536 addresses (IVA "Invalid schedule data").
const (
	maxScheduleCIDRMask = 16
	maxScheduleIPs      = 65536
)

// Unified Portal priorities (scan-schedules form-types.ts).
var schedulePriority = map[string]int{"high": 1, "medium": 50, "low": 100}

var scheduleWeekdays = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

func (s *Service) prepareDevices(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	switch kind {
	case ChangeActivateAppliance:
		miss, err = s.prepareActivation(ctx, org, ch, params)
	case ChangeRequestScanner:
		miss, err = s.prepareScannerRequest(ctx, org, ch, params)
	case ChangeCreateScanSchedule:
		miss, err = s.prepareScanSchedule(ctx, org, ch, params)
	default:
		return nil, false, nil
	}
	return miss, true, err
}

func (s *Service) prepareActivation(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	serial := str(params, "serial_number")
	if serial == "" {
		return []string{"serial_number"}, nil
	}
	pending, _, err := s.PendingActivations(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	var found *PendingActivation
	for i, a := range pending.Appliances {
		if strings.EqualFold(a.SerialNumber, serial) {
			found = &pending.Appliances[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: no appliance with serial %q is waiting for activation; use list_pending_activations (it appears after the appliance has connected from its console)", ErrChangeInvalid, serial)
	}
	ch.Title = "Activate " + found.Kind + " " + found.Name
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/sensor/"+url.PathEscape(found.SerialNumber)
	ch.Body = map[string]any{}
	ch.Details = []ChangeDetail{{"Appliance", fmt.Sprintf("%s (%s)", found.Name, found.Kind)}, {"Serial number", found.SerialNumber}, {"Organization", org.Name}}
	if found.Site != "" {
		ch.Details = append(ch.Details, ChangeDetail{"Site", found.Site})
	}
	ch.Assumptions = []string{
		"Same as pressing Activate in Data Collection: the appliance gets its certificates and region, then sets itself up (usually under an hour).",
		"Only the person who set up the appliance can activate it, and they need the Self Activate Appliance permission.",
		"Activation is for this organization; MSPs must be working in the customer's organization.",
	}
	return nil, nil
}

func (s *Service) prepareScannerRequest(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	miss := missing(params, "name", "site", "ship_first_name", "ship_last_name", "ship_email", "ship_phone", "street1", "city", "province_state", "postal_code", "country")
	dhcp := yes(params, "dhcp")
	if !dhcp {
		miss = append(miss, missing(params, "static_ip", "subnet_mask", "gateway", "primary_dns")...)
	}
	// The Unified Portal hides Add New Scanner while Arctic Wolf runs a staff-led onboarding.
	var orgInfo struct {
		OnboardingExperienceActive bool `json:"onboardingExperienceActive"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "", &orgInfo); err == nil && orgInfo.OnboardingExperienceActive {
		return nil, fmt.Errorf("%w: Arctic Wolf is running a guided onboarding for this organization, so physical scanners are requested by your Arctic Wolf team "+
			"(the Unified Portal hides Add Scanner too). Ask your Concierge team, or install a virtual scanner (get_appliance_download appliance=scanner)", ErrChangeInvalid)
	}
	lic, err := s.scannerLicences(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("could not read scanner licences: %w", err)
	}
	left := lic.PhysicalRemaining()
	units := 0
	for _, n := range left {
		units += n
	}
	if units == 0 {
		return nil, fmt.Errorf("%w: no physical scanner licences are left. Virtual scanners are unlimited (get_appliance_download); for another physical scanner, ask the Concierge team for a licence", ErrChangeInvalid)
	}
	if e := str(params, "ship_email"); e != "" {
		if _, err := mail.ParseAddress(e); err != nil {
			return nil, fmt.Errorf("%w: ship_email %q is not a valid email", ErrChangeInvalid, e)
		}
	}
	if !dhcp {
		for _, key := range []string{"static_ip", "subnet_mask", "gateway", "primary_dns", "secondary_dns"} {
			if v := str(params, key); v != "" && net.ParseIP(v).To4() == nil {
				return nil, fmt.Errorf("%w: %s %q must be an IPv4 address", ErrChangeInvalid, key, v)
			}
		}
	}
	var siteUUID, siteName string
	if want := str(params, "site"); want != "" {
		var sites []map[string]any
		if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/sites", &sites); err != nil {
			return nil, fmt.Errorf("could not read sites: %w", err)
		}
		for _, st := range sites {
			if strings.EqualFold(fmt.Sprint(st["name"]), want) || strings.EqualFold(fmt.Sprint(st["uuid"]), want) {
				siteUUID, siteName = fmt.Sprint(st["uuid"]), fmt.Sprint(st["name"])
				break
			}
		}
		if siteUUID == "" {
			return nil, fmt.Errorf("%w: site %q not found; create it first (create_site) or use an exact site name", ErrChangeInvalid, want)
		}
	}
	if len(miss) > 0 {
		return miss, nil
	}
	network := func(key string) string {
		if dhcp {
			return dhcpOverride
		}
		return str(params, key)
	}
	ch.Title = "Request a physical scanner for " + siteName
	ch.Method, ch.Path = "POST", "/api/v2/organizations/"+org.ID+"/scanners"
	// Body as the Unified Portal sends it (device-form-to-scanner-profile.ts).
	ch.Body = map[string]any{
		"name":     str(params, "name"),
		"siteUuid": siteUUID,
		"networkConfiguration": map[string]any{
			"ipAddress": network("static_ip"), "subnetMask": network("subnet_mask"), "gateway": network("gateway"),
			"primaryDns": network("primary_dns"), "secondaryDns": network("secondary_dns"),
		},
		"shippingInfo": map[string]any{
			"first_name": str(params, "ship_first_name"), "last_name": str(params, "ship_last_name"),
			"email_address": str(params, "ship_email"), "phone_number": str(params, "ship_phone"),
			"street1": str(params, "street1"), "street2": str(params, "street2"), "city": str(params, "city"),
			"province_state": str(params, "province_state"), "postal_zip": str(params, "postal_code"), "country": str(params, "country"),
		},
		"technicalRequirements": map[string]any{"customer_configured": false},
		"configuration":         "scanner",
		"scannerStatus":         "awaitingActivation",
		"deploymentID":          "",
		"serialNumber":          "",
		"type":                  "physical",
		"model":                 "scanner200",
		"notes":                 str(params, "notes"),
	}
	networkLine := "No static IP: the scanner uses DHCP"
	if !dhcp {
		networkLine = fmt.Sprintf("IP %s, mask %s, gateway %s, DNS %s", str(params, "static_ip"), str(params, "subnet_mask"), str(params, "gateway"),
			strings.Join(nonEmpty(str(params, "primary_dns"), str(params, "secondary_dns")), ", "))
	}
	ch.Details = []ChangeDetail{
		{"Scanner", fmt.Sprintf("%s (physical, %d licence(s) left before this one)", str(params, "name"), units)},
		{"Site", siteName},
		{"Network", networkLine},
		{"Ship to", fmt.Sprintf("%s %s, %s, %s", str(params, "ship_first_name"), str(params, "ship_last_name"), str(params, "ship_phone"),
			strings.Join(nonEmpty(str(params, "street1"), str(params, "street2"), str(params, "city"), str(params, "province_state"), str(params, "postal_code"), str(params, "country")), ", "))},
	}
	ch.Assumptions = []string{
		"Same request as the Unified Portal Add Scanner page: Arctic Wolf prepares and ships the scanner to this address.",
		"When it arrives, connect port 1 to a switch, power it on and allow the outbound addresses in Resources > Allowlist Requirements.",
		"A physical scanner covers one network; for another network or a cloud network, a virtual scanner is unlimited.",
	}
	return nil, nil
}

func (s *Service) prepareScanSchedule(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	miss := missing(params, "scanner", "name", "targets", "frequency")
	freq := strings.ToLower(str(params, "frequency"))
	switch freq {
	case "", "continuous":
	case "daily", "weekly", "monthly":
		miss = append(miss, missing(params, "start_time_utc")...)
		if freq == "weekly" {
			miss = append(miss, missing(params, "days")...)
		}
		if freq == "monthly" {
			miss = append(miss, missing(params, "day_of_month")...)
		}
	default:
		return nil, fmt.Errorf("%w: frequency must be continuous, daily, weekly or monthly", ErrChangeInvalid)
	}

	targets := list(params, "targets")
	total := 0
	for _, t := range targets {
		n, err := scheduleTargetSize(t)
		if err != nil {
			return nil, err
		}
		total += n
	}
	if total > maxScheduleIPs {
		return nil, fmt.Errorf("%w: these targets cover %d addresses; one schedule may cover at most %d. Split them into several schedules", ErrChangeInvalid, total, maxScheduleIPs)
	}

	priorityName := strings.ToLower(orDefault(str(params, "priority"), "low"))
	priority, okPriority := schedulePriority[priorityName]
	if !okPriority {
		return nil, fmt.Errorf("%w: priority must be high, medium or low", ErrChangeInvalid)
	}
	windowHours := 8
	if v := str(params, "window_hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 24 {
			return nil, fmt.Errorf("%w: window_hours must be 1 to 24", ErrChangeInvalid)
		}
		windowHours = n
	}

	var cron []map[string]any
	if freq != "" && freq != "continuous" && str(params, "start_time_utc") != "" {
		h, m, err := parseClock(str(params, "start_time_utc"))
		if err != nil {
			return nil, err
		}
		base := func() map[string]any {
			return map[string]any{"minute": []int{m}, "hour": []int{h}, "length": windowHours * 60}
		}
		switch freq {
		case "daily":
			cron = []map[string]any{base()}
		case "weekly":
			// IVA uses one entry per weekday (Unified Portal getLegacyWeeklyCron).
			for _, d := range list(params, "days") {
				dow, ok := scheduleWeekdays[strings.ToLower(d)[:min(3, len(d))]]
				if !ok {
					return nil, fmt.Errorf("%w: day %q must be one of mon, tue, wed, thu, fri, sat, sun", ErrChangeInvalid, d)
				}
				e := base()
				e["dayOfWeek"] = []int{dow}
				cron = append(cron, e)
			}
		case "monthly":
			dom, err := strconv.Atoi(str(params, "day_of_month"))
			if err != nil || dom < 1 || dom > 31 {
				return nil, fmt.Errorf("%w: day_of_month must be 1 to 31", ErrChangeInvalid)
			}
			e := base()
			e["dayOfMonth"] = []int{dom}
			cron = []map[string]any{e}
		}
	}

	var scanner scannerRow
	if want := str(params, "scanner"); want != "" {
		r, err := s.findScanner(ctx, org, want)
		if err != nil {
			return nil, err
		}
		if !scannerOperational[r.Status] {
			return nil, fmt.Errorf("%w: scanner %s is %s; schedules can be added once it is connected", ErrChangeInvalid, r.Name, r.Status)
		}
		scanner = r
	}
	if len(miss) > 0 {
		return miss, nil
	}

	enabled := !strings.EqualFold(str(params, "enabled"), "no")
	body := map[string]any{
		"name":             str(params, "name"),
		"description":      str(params, "description"),
		"priority":         priority,
		"scanningDisabled": !enabled,
		"targets":          targets,
		"timezone":         "UTC",
	}
	if cron != nil {
		body["schedule"] = cron
	}
	if yes(params, "discovery_only_in_window") {
		body["scanningOutsideWindowDisabled"] = true
	}
	ch.Title = "Add scan schedule \"" + str(params, "name") + "\" to " + scanner.Name
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/iva/"+url.PathEscape(scanner.ID)+"/scan-schedules"
	ch.Body = body
	when := "Continuously, as fast as the scanner can"
	switch freq {
	case "daily":
		when = fmt.Sprintf("Every day, starting %s UTC, %d-hour window", str(params, "start_time_utc"), windowHours)
	case "weekly":
		when = fmt.Sprintf("Every %s, starting %s UTC, %d-hour window", strings.Join(list(params, "days"), ", "), str(params, "start_time_utc"), windowHours)
	case "monthly":
		when = fmt.Sprintf("Day %s of every month, starting %s UTC, %d-hour window", str(params, "day_of_month"), str(params, "start_time_utc"), windowHours)
	}
	ch.Details = []ChangeDetail{
		{"Scanner", scanner.Name},
		{"Targets", fmt.Sprintf("%s (%d addresses)", strings.Join(targets, ", "), total)},
		{"When", when},
		{"Priority", priorityName},
		{"Scanning", map[bool]string{true: "on", false: "off (saved but not running)"}[enabled]},
	}
	ch.Assumptions = []string{
		"Host discovery (Nmap) keeps running between windows unless discovery_only_in_window is yes; vulnerability scans only start inside the window.",
		"Exclude fragile devices first (printers, medical, VoIP, UPS, ESXi hosts, PLCs); exclusions are set on the scanner's Scan Exclusion tab.",
		"About 540 hosts a day per scanner; aim to cover every host every 10 to 14 days.",
	}
	return nil, nil
}

// scheduleTargetSize validates a scan target (private IPv4, IPv4 range, or CIDR up to /16)
// and returns how many addresses it covers.
func scheduleTargetSize(t string) (int, error) {
	private := func(ip net.IP) bool { return ip != nil && ip.To4() != nil && ip.IsPrivate() }
	switch {
	case strings.Contains(t, "/"):
		ip, n, err := net.ParseCIDR(t)
		if err != nil || ip.To4() == nil {
			return 0, fmt.Errorf("%w: %q is not a valid IPv4 CIDR", ErrChangeInvalid, t)
		}
		ones, _ := n.Mask.Size()
		if ones < maxScheduleCIDRMask {
			return 0, fmt.Errorf("%w: %q is too large; scanners support ranges up to /%d, split it", ErrChangeInvalid, t, maxScheduleCIDRMask)
		}
		if !private(n.IP) {
			return 0, fmt.Errorf("%w: %q is not a private address range; scanners only scan internal networks", ErrChangeInvalid, t)
		}
		return 1 << (32 - ones), nil
	case strings.Contains(t, "-"):
		a, b, _ := strings.Cut(t, "-")
		ipA, ipB := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
		if !private(ipA) || !private(ipB) {
			return 0, fmt.Errorf("%w: %q must be a range of private IPv4 addresses", ErrChangeInvalid, t)
		}
		lo, hi := binary.BigEndian.Uint32(ipA.To4()), binary.BigEndian.Uint32(ipB.To4())
		if hi < lo {
			return 0, fmt.Errorf("%w: %q ends before it starts", ErrChangeInvalid, t)
		}
		return int(hi-lo) + 1, nil
	default:
		if !private(net.ParseIP(t)) {
			return 0, fmt.Errorf("%w: %q must be a private IPv4 address, range or CIDR", ErrChangeInvalid, t)
		}
		return 1, nil
	}
}

func parseClock(v string) (int, int, error) {
	hs, ms, ok := strings.Cut(v, ":")
	h, err1 := strconv.Atoi(hs)
	m, err2 := strconv.Atoi(ms)
	if !ok || err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("%w: start_time_utc must be HH:MM in UTC, e.g. 22:00", ErrChangeInvalid)
	}
	return h, m, nil
}
