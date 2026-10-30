package discovery

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Vulnerability scanners (UC-03 "Scanners", Aurora Vulnerability Management) ---
//
// Same Rendall APIs as the Unified Portal / Aurora Scanners pages (rtkwlf/arcticexperience
// apis/rendall scanner hooks, aurora-ui-platform features/telemetry/src/pages/scanners):
//   GET /api/v1/organizations/{org}/scanners            list with status, serial, site
//   GET /api/v1/organizations/{org}/scanner-summary     counts per status
//   GET /api/v1/organizations/{org}/scanners/{id}       IVA details (connection, settings)
//   GET /api/v1/organizations/{org}/iva/{id}/scan-schedules
//   GET /api/v1/organizations/{org}/scanners/{id}/jobs/issues
// Schedules, exclusions and credentials live in the IVA backend behind Rendall.

// Fleet health buckets, same derivation as the Unified Portal Scanners page.
const (
	HealthUnhealthy      = "unhealthy"
	HealthNeedsAttention = "needsAttention"
	HealthInProgress     = "inProgress"
	HealthHealthy        = "healthy"
)

var scannerHealthBucket = map[string]string{
	"degraded": HealthUnhealthy, "disconnected": HealthUnhealthy, "disabled": HealthUnhealthy,
	"awaitingActivation": HealthNeedsAttention, "misconfigured": HealthNeedsAttention, "staged": HealthNeedsAttention,
	"new": HealthInProgress, "shipped": HealthInProgress, "preparingToShip": HealthInProgress,
	"scanning": HealthHealthy, "idle": HealthHealthy, "connected": HealthHealthy,
}

// scannerOperational are statuses where the scanner talks to Arctic Wolf and has IVA data.
var scannerOperational = map[string]bool{"scanning": true, "idle": true, "connected": true, "misconfigured": true, "disabled": true, "degraded": true, "staged": true}

// scannerNextStep is what the customer should do next for a scanner in this status.
var scannerNextStep = map[string]string{
	"new":                "Arctic Wolf is reviewing the scanner request.",
	"preparingToShip":    "Arctic Wolf is preparing the scanner; it ships soon.",
	"shipped":            "When it arrives: rack it, connect port 1 to a switch, power it on and allow the outbound addresses in Resources > Allowlist Requirements.",
	"awaitingActivation": "The scanner has connected. Activate it (activate_appliance with its serial number); only the person who configured it can activate.",
	"staged":             "Arctic Wolf is finishing the scanner's set-up; this normally takes under an hour.",
	"misconfigured":      "Schedules clash or the deny list blocks every host; review its scan schedules and exclusions.",
	"disabled":           "Host discovery or vulnerability scanning is switched off on this scanner.",
	"degraded":           "Connected but not working as intended; contact the Concierge team.",
	"disconnected":       "Not talking to Arctic Wolf: check power, network and the allowlist, then contact the Concierge team if it stays down.",
}

type ScannerView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Health       string `json:"health"`
	Type         string `json:"type"` // physical | virtual
	Version      string `json:"version,omitempty"`
	IP           string `json:"ip,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	DeploymentID string `json:"deploymentId,omitempty"`
	Site         string `json:"site,omitempty"`
	// Schedules is the number of scan schedules; nil when not read (scanner not operational).
	Schedules *int   `json:"schedules,omitempty"`
	NextStep  string `json:"nextStep,omitempty"`
}

type ScannerList struct {
	Total int `json:"total"`
	// Health is the fleet health (worst bucket present), as on the Scanners page.
	Health   string          `json:"health"`
	ByStatus map[string]int  `json:"byStatus"`
	Licences LicenceProgress `json:"licences"`
	Scanners []ScannerView   `json:"scanners"`
}

type scannerRow struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	Type         string `json:"type"`
	Version      string `json:"version"`
	IP           string `json:"ip"`
	SerialNumber string `json:"serialNumber"`
	DeploymentID string `json:"deploymentID"`
	SiteName     string `json:"siteName"`
}

func fleetHealth(byStatus map[string]int) string {
	present := map[string]bool{}
	for st, n := range byStatus {
		if n > 0 {
			present[scannerHealthBucket[st]] = true
		}
	}
	for _, h := range []string{HealthUnhealthy, HealthNeedsAttention, HealthInProgress} {
		if present[h] {
			return h
		}
	}
	return HealthHealthy
}

func (s *Service) scannerRows(ctx context.Context, org upstream.Organization) ([]scannerRow, error) {
	var page struct {
		Items []scannerRow `json:"items"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/scanners", &page); err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *Service) scannerSchedules(ctx context.Context, org upstream.Organization, scannerID string) ([]map[string]any, error) {
	var page struct {
		Items []map[string]any `json:"items"`
	}
	err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/iva/"+url.PathEscape(scannerID)+"/scan-schedules", &page)
	return page.Items, err
}

// Scanners lists the organization's vulnerability scanners with status, the next step for
// each, scanner licences and (for connected scanners) how many scan schedules they have.
func (s *Service) Scanners(ctx context.Context, orgID string) (ScannerList, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall scanners", "rendall iva scan-schedules", "rendall scanner-license-usage"}, FetchedAt: s.now(),
		UntrustedFields: []string{"scanners[].name", "scanners[].site"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return ScannerList{}, meta, err
	}
	rows, err := s.scannerRows(ctx, org)
	if err != nil {
		return ScannerList{}, meta, fmt.Errorf("could not read scanners: %w", err)
	}
	out := ScannerList{Total: len(rows), ByStatus: map[string]int{}, Scanners: []ScannerView{}}
	for _, r := range rows {
		out.ByStatus[r.Status]++
		v := ScannerView{ID: r.ID, Name: r.Name, Status: r.Status, Health: orDefault(scannerHealthBucket[r.Status], "notAvailable"), Type: r.Type,
			Version: r.Version, IP: r.IP, SerialNumber: r.SerialNumber, DeploymentID: r.DeploymentID, Site: r.SiteName, NextStep: scannerNextStep[r.Status]}
		if scannerOperational[r.Status] && r.ID != "" {
			if items, err := s.scannerSchedules(ctx, org, r.ID); err == nil {
				n := len(items)
				v.Schedules = &n
				if n == 0 && v.Health == HealthHealthy {
					v.NextStep = "Connected but no scan schedules: it only discovers hosts on its own subnet. Add a schedule for each network to scan (create_scan_schedule)."
				}
			} else {
				meta.Notes = append(meta.Notes, fmt.Sprintf("could not read schedules for %s: %v", r.Name, err))
			}
		}
		out.Scanners = append(out.Scanners, v)
	}
	sort.SliceStable(out.Scanners, func(i, j int) bool { return out.Scanners[i].Name < out.Scanners[j].Name })
	out.Health = fleetHealth(out.ByStatus)
	if lic, err := s.scannerLicences(ctx, org); err == nil {
		out.Licences = lic
	} else {
		meta.Notes = append(meta.Notes, "scanner licences unavailable: "+err.Error())
	}
	if out.Total == 0 {
		meta.Notes = append(meta.Notes, "No scanners yet. Physical scanners are requested with prepare_change kind request_scanner; virtual scanners are downloaded (get_appliance_download) and activated.")
	}
	return out, meta, nil
}

type ScannerDetail struct {
	Scanner ScannerView `json:"scanner"`
	// Connection is connected | disconnected (IVA); settings are editable only when connected.
	Connection string `json:"connection,omitempty"`
	// Settings are the scanner's switches and lists from IVA (host identification, deny list…).
	Settings  map[string]any   `json:"settings,omitempty"`
	Schedules []map[string]any `json:"schedules"`
	Issues    []map[string]any `json:"issues"`
}

// Scanner returns one scanner with its IVA settings, scan schedules and recent job issues.
func (s *Service) Scanner(ctx context.Context, orgID, scanner string) (ScannerDetail, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall scanners", "rendall iva"}, FetchedAt: s.now(),
		UntrustedFields: []string{"scanner.name", "scanner.site", "schedules[].name", "schedules[].description", "issues[].description"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return ScannerDetail{}, meta, err
	}
	row, err := s.findScanner(ctx, org, scanner)
	if err != nil {
		return ScannerDetail{}, meta, err
	}
	out := ScannerDetail{Scanner: ScannerView{ID: row.ID, Name: row.Name, Status: row.Status, Health: orDefault(scannerHealthBucket[row.Status], "notAvailable"),
		Type: row.Type, Version: row.Version, IP: row.IP, SerialNumber: row.SerialNumber, DeploymentID: row.DeploymentID, Site: row.SiteName,
		NextStep: scannerNextStep[row.Status]}, Schedules: []map[string]any{}, Issues: []map[string]any{}}
	if !scannerOperational[row.Status] {
		meta.Notes = append(meta.Notes, "The scanner is not connected yet, so it has no schedules or settings.")
		return out, meta, nil
	}
	var details map[string]any
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/scanners/"+url.PathEscape(row.ID), &details); err == nil {
		out.Connection, _ = details["connectionStatus"].(string)
		out.Settings = pickKeys(details, "settings", "denyList", "portBlockRules", "dnsServers", "hostIdentificationScanIntensity",
			"hostIdentificationScanPeriod", "maxConcurrentVulnerabilityScans", "capabilities")
	} else {
		meta.Notes = append(meta.Notes, "scanner settings unavailable: "+err.Error())
	}
	if items, err := s.scannerSchedules(ctx, org, row.ID); err == nil {
		for _, it := range items {
			out.Schedules = append(out.Schedules, pickKeys(it, "id", "name", "description", "scanningEnabled", "status", "frequency", "lastScan", "nextScan", "timezone", "priority", "targets"))
		}
	} else {
		meta.Notes = append(meta.Notes, "scan schedules unavailable: "+err.Error())
	}
	var issues []map[string]any
	after := s.now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/scanners/"+url.PathEscape(row.ID)+"/jobs/issues?after="+url.QueryEscape(after), &issues); err == nil && issues != nil {
		out.Issues = issues
	}
	if len(out.Schedules) == 0 {
		out.Scanner.NextStep = "No scan schedules: add one per network to scan (create_scan_schedule). Start with one or two subnets."
	}
	return out, meta, nil
}

func (s *Service) findScanner(ctx context.Context, org upstream.Organization, want string) (scannerRow, error) {
	rows, err := s.scannerRows(ctx, org)
	if err != nil {
		return scannerRow{}, fmt.Errorf("could not read scanners: %w", err)
	}
	want = strings.TrimSpace(want)
	for _, r := range rows {
		if strings.EqualFold(r.ID, want) || strings.EqualFold(r.SerialNumber, want) || strings.EqualFold(r.DeploymentID, want) || strings.EqualFold(r.Name, want) {
			return r, nil
		}
	}
	return scannerRow{}, fmt.Errorf("%w: scanner %q not found; use list_scanners", ErrChangeInvalid, want)
}

func pickKeys(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// --- Appliances waiting for activation (sensors, scanners, log collectors) ---

type PendingActivation struct {
	Kind         string `json:"kind"` // sensor | scanner (vLCs are listed as sensors)
	Name         string `json:"name"`
	SerialNumber string `json:"serialNumber"`
	Product      string `json:"product,omitempty"`
	Site         string `json:"site,omitempty"`
}

type PendingActivations struct {
	Appliances []PendingActivation `json:"appliances"`
	HowTo      string              `json:"howTo"`
}

// PendingActivations lists virtual appliances that have connected and wait for the
// customer to press Activate (status awaitingActivation).
func (s *Service) PendingActivations(ctx context.Context, orgID string) (PendingActivations, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall sensors", "rendall scanners"}, FetchedAt: s.now(), UntrustedFields: []string{"appliances[].name", "appliances[].site"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return PendingActivations{}, meta, err
	}
	out := PendingActivations{Appliances: []PendingActivation{},
		HowTo: "Activate with prepare_change kind activate_appliance (serial_number). Only the person who set up the appliance can activate it, and they need the Self Activate Appliance permission (primary and secondary contacts have it). A serial number cannot be activated twice."}
	sensors, err := s.allSensors(ctx, org, SensorKindSensor)
	if err != nil {
		meta.Notes = append(meta.Notes, "sensors unavailable: "+err.Error())
	}
	for _, v := range sensors {
		if v.Status == "awaitingActivation" {
			out.Appliances = append(out.Appliances, PendingActivation{Kind: "sensor", Name: v.Name, SerialNumber: v.SerialNumber, Product: v.Product, Site: v.Site})
		}
	}
	rows, err := s.scannerRows(ctx, org)
	if err != nil {
		meta.Notes = append(meta.Notes, "scanners unavailable: "+err.Error())
	}
	for _, r := range rows {
		if r.Status == "awaitingActivation" {
			out.Appliances = append(out.Appliances, PendingActivation{Kind: "scanner", Name: r.Name, SerialNumber: r.SerialNumber, Product: r.Type, Site: r.SiteName})
		}
	}
	return out, meta, nil
}

// --- Virtual appliance download and install guidance ---

type ApplianceDownload struct {
	// URL is a short-lived signed link to the virtual appliance image (VMware/Nutanix OVA).
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// Steps per platform; the same image becomes a vSensor, vScanner or vLC at set-up.
	Platforms []AppliancePlatform `json:"platforms"`
}

type AppliancePlatform struct {
	Platform string   `json:"platform"`
	Steps    []string `json:"steps"`
	Guide    string   `json:"guide"`
}

const docsVirtual = "https://docs.arcticwolf.com/en/sensors-scanners-and-log-collectors"

// ApplianceDownload returns the virtual appliance download link and the install steps for
// each platform, including AWS and Azure (which use an image shared to the customer's cloud
// account instead of a download).
func (s *Service) ApplianceDownload(ctx context.Context, orgID, appliance string) (ApplianceDownload, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall virtualsensor/download", "docs.arcticwolf.com install guides"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return ApplianceDownload{}, meta, err
	}
	role := "Scanner"
	sizing := "8 vCPU, 16 GB RAM, 40 GB disk; do not limit its CPU."
	guide := docsVirtual + "/scanners/aurora-vulnerability-management-scanners/virtual-scanners/install-a-vscanner"
	switch strings.ToLower(appliance) {
	case "sensor", "vsensor":
		role = "Mirroring"
		sizing = "AWNv100: 2 vCPU/8 GB, AWNv200: 8 vCPU/16 GB, AWNv1000: 24 vCPU/48 GB, all 40 GB disk (pick the model you are licensed for)."
		guide = docsVirtual + "/sensors/arctic-wolf-sensors/virtual-sensors/install-a-vsensor"
	case "log_collector", "vlc":
		role = "Log collector"
		guide = docsVirtual + "/sensors/arctic-wolf-sensors/virtual-sensors/install-a-vsensor"
	}
	var dl struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/virtualsensor/download", &dl); err == nil {
		meta.Notes = append(meta.Notes, "The download link is signed and expires; share it only with the person installing the appliance.")
	} else {
		meta.Notes = append(meta.Notes, "download link unavailable ("+err.Error()+"); the customer can download from Resources > Downloads in the portal")
	}
	console := []string{
		"Open the VM console and press Enter three times.",
		"Choose DHCP (with a DHCP reservation) or enter a static IP for the management interface.",
		"Run the connection test; fix the network if a check fails.",
		"Enter a short name and choose \"" + role + "\".",
		"Scan the QR code or open the URL shown (valid 15 minutes) to connect it to Arctic Wolf.",
		"Activate it in the portal (Data Collection) or with activate_appliance.",
	}
	out := ApplianceDownload{URL: dl.URL, SHA256: dl.SHA256, Platforms: []AppliancePlatform{
		{Platform: "VMware vSphere / ESXi / Nutanix", Guide: guide,
			Steps: append([]string{"Download the OVA (Resources > Downloads > VMware/Nutanix, or the link here).", "Deploy OVF template; size: " + sizing}, console...)},
		{Platform: "Microsoft Hyper-V", Guide: guide,
			Steps: append([]string{"Download the Hyper-V image (Resources > Downloads).", "Create the VM; size: " + sizing}, console...)},
		{Platform: "AWS", Guide: guide,
			Steps: append([]string{
				"Give Arctic Wolf your AWS account ID: prepare_change kind connect_cloud_app with type vsensor_ami (no keys or secrets are needed).",
				"Wait up to 24 hours for the private image \"Arctic Wolf Appliance\" to appear in EC2 > AMIs > Private images.",
				"Launch an instance from it in the VPC to cover; size: " + sizing,
			}, console[1:]...)},
		{Platform: "Microsoft Azure", Guide: guide,
			Steps: append([]string{
				"Give Arctic Wolf your Azure subscription ID: prepare_change kind connect_cloud_app with type azure_vm_subid.",
				"Deploy the shared Arctic Wolf image in the virtual network to cover; size: " + sizing,
			}, console[1:]...)},
	}}
	meta.Notes = append(meta.Notes, "Connecting an AWS or Azure account goes through the legacy cloud-sensor path: the signed-in user must be a contact of the organization, and Arctic Wolf opens a ticket to share the image.")
	return out, meta, nil
}

// --- Setup health: is the deployment actually working? ---

type SetupHealth struct {
	Sensors    HealthArea `json:"sensors"`
	Scanners   HealthArea `json:"scanners"`
	LogSources HealthArea `json:"logSources"`
	// Actions lists what needs the customer's attention, most important first.
	Actions []string `json:"actions"`
}

type HealthArea struct {
	Status  string         `json:"status"` // ok | attention | none | unknown
	Counts  map[string]int `json:"counts,omitempty"`
	Summary string         `json:"summary"`
}

// SetupHealth checks that what was set up is working: sensors healthy and activated,
// scanners connected with schedules, log sources parsed and still sending.
func (s *Service) SetupHealth(ctx context.Context, orgID string) (SetupHealth, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall sensors", "rendall scanners", "lss"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return SetupHealth{}, meta, err
	}
	out := SetupHealth{Actions: []string{}}

	if sensors, err := s.allSensors(ctx, org, SensorKindSensor); err != nil {
		out.Sensors = HealthArea{Status: "unknown", Summary: "Sensors could not be read: " + err.Error()}
	} else {
		c := map[string]int{}
		for _, v := range sensors {
			c[v.Status]++
		}
		out.Sensors = HealthArea{Counts: c, Status: "ok"}
		switch {
		case len(sensors) == 0:
			out.Sensors.Status, out.Sensors.Summary = "none", "No sensors yet."
		case c["unhealthy"] > 0:
			out.Sensors.Status = "attention"
			out.Sensors.Summary = fmt.Sprintf("%d of %d sensors are unhealthy (offline or not receiving traffic).", c["unhealthy"], len(sensors))
			out.Actions = append(out.Actions, fmt.Sprintf("Check the %d unhealthy sensor(s): power, network, firewall rules, and that the switch still mirrors traffic to them.", c["unhealthy"]))
		case c["awaitingActivation"] > 0:
			out.Sensors.Status = "attention"
			out.Sensors.Summary = fmt.Sprintf("%d sensor(s) are waiting to be activated.", c["awaitingActivation"])
		default:
			out.Sensors.Summary = fmt.Sprintf("%d sensors, none unhealthy.", len(sensors))
		}
		if c["awaitingActivation"] > 0 {
			out.Actions = append(out.Actions, fmt.Sprintf("Activate %d sensor(s) waiting for activation (list_pending_activations).", c["awaitingActivation"]))
		}
	}

	if list, _, err := s.Scanners(ctx, org.ID); err != nil {
		out.Scanners = HealthArea{Status: "unknown", Summary: "Scanners could not be read: " + err.Error()}
	} else {
		out.Scanners = HealthArea{Counts: list.ByStatus, Status: "ok"}
		noSchedule := 0
		for _, v := range list.Scanners {
			if v.Schedules != nil && *v.Schedules == 0 {
				noSchedule++
			}
		}
		switch {
		case list.Total == 0:
			out.Scanners.Status, out.Scanners.Summary = "none", "No scanners."
		case list.Health == HealthHealthy && noSchedule == 0:
			out.Scanners.Summary = fmt.Sprintf("%d scanner(s), all connected with schedules.", list.Total)
		default:
			out.Scanners.Status = "attention"
			out.Scanners.Summary = fmt.Sprintf("%d scanner(s), fleet health %s, %d without scan schedules.", list.Total, list.Health, noSchedule)
		}
		for _, v := range list.Scanners {
			if v.Health == HealthUnhealthy || v.Status == "awaitingActivation" || (v.Schedules != nil && *v.Schedules == 0) {
				out.Actions = append(out.Actions, "Scanner "+v.Name+": "+v.NextStep)
			}
		}
	}

	if ls, _, err := s.LogSources(ctx, org.ID, LogSourceQuery{Limit: 1}); err != nil {
		out.LogSources = HealthArea{Status: "unknown", Summary: "Log sources could not be read: " + err.Error()}
	} else {
		c := map[string]int{"withParser": ls.Summary.WithParser, "withoutParser": ls.Summary.WithoutParser, "active": ls.Summary.Active, "total": ls.Total}
		out.LogSources = HealthArea{Counts: c, Status: "ok", Summary: fmt.Sprintf("%d log sources: %d parsed, %d without a parser, %d active.", ls.Total, ls.Summary.WithParser, ls.Summary.WithoutParser, ls.Summary.Active)}
		if ls.Total == 0 {
			out.LogSources.Status = "none"
		} else if ls.Summary.WithoutParser > 0 {
			out.LogSources.Status = "attention"
			out.Actions = append(out.Actions, fmt.Sprintf("%d log source(s) have no parser, so no detections run on them: review suggestions (suggest_parser) and confirm a parser.", ls.Summary.WithoutParser))
		}
	}
	return out, meta, nil
}
