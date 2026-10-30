package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Requests to Arctic Wolf and the AD sensor installer (Unified Portal) ---
//
//   request_licences  POST /api/v1/organizations/{org}/tickets — "Request Licenses" on Add Sensor /
//                     Add Scanner. ticketType "deployment" while the organization is onboarding (goes to
//                     the Deployment team), otherwise "sensorCollectorRequestQuote" (goes to the CSM).
//                     (arcticexperience add-sensor-request-form.tsx)
//   ADSensorInstaller POST /api/v1/organizations/{org}/adsensor/download {ip} → signed URL + sha256 of an
//                     Active Directory log collector (NXLog) installer pre-set to forward to that sensor
//                     or vLC (Resources › Downloads › AD Sensor).

const ChangeRequestLicences = "request_licences"

var licenceDevices = map[string]string{
	"physical_sensor": "physical sensor", "virtual_sensor": "virtual sensor (vSensor)", "physical_scanner": "physical scanner",
}

func (s *Service) prepareRequests(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	if kind != ChangeRequestLicences {
		return nil, false, nil
	}
	if miss = missing(params, "device", "quantity"); len(miss) > 0 {
		return miss, true, nil
	}
	device, known := licenceDevices[strings.ToLower(str(params, "device"))]
	if !known {
		return nil, true, fmt.Errorf("%w: device must be physical_sensor, virtual_sensor or physical_scanner (vLCs and virtual scanners are unlimited)", ErrChangeInvalid)
	}
	qty, err := strconv.Atoi(str(params, "quantity"))
	if err != nil || qty < 1 || qty > 50 {
		return nil, true, fmt.Errorf("%w: quantity must be 1 to 50", ErrChangeInvalid)
	}
	var orgInfo struct {
		OnboardingStatus string `json:"onboardingStatus"`
	}
	_ = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "", &orgInfo)
	ticketType, team := "sensorCollectorRequestQuote", "your Customer Success Manager (quote)"
	if orgInfo.OnboardingStatus == "onboarding" {
		ticketType, team = "deployment", "your Arctic Wolf deployment team"
	}
	model := str(params, "model")
	subject := fmt.Sprintf("Licence request: %d × %s", qty, device)
	if model != "" {
		subject += " (" + model + ")"
	}
	desc := fmt.Sprintf("Requested from Aurora.\nDevice: %s\nQuantity: %d", device, qty)
	if model != "" {
		desc += "\nModel: " + model
	}
	if n := str(params, "notes"); n != "" {
		desc += "\n\n" + n
	}
	ch.Title = "Request " + strconv.Itoa(qty) + " more " + device + " licence(s)"
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/tickets"
	ch.Body = map[string]any{"subject": subject, "description": desc, "ticketType": ticketType}
	ch.Details = []ChangeDetail{{"Device", device}, {"Quantity", strconv.Itoa(qty)}, {"Goes to", team}}
	if model != "" {
		ch.Details = append(ch.Details, ChangeDetail{"Model", model})
	}
	ch.Assumptions = []string{"Same as Request Licenses in the Unified Portal; Arctic Wolf replies on the ticket."}
	return nil, true, nil
}

// ADSensorInstaller is the signed download for the Active Directory log collector.
type ADSensorInstaller struct {
	Sensor   string   `json:"sensor"`
	SensorIP string   `json:"sensorIp"`
	URL      string   `json:"url"`
	SHA256   string   `json:"sha256,omitempty"`
	Steps    []string `json:"steps"`
}

// ADSensorInstaller returns the AD sensor installer pre-set to forward Windows event logs to the
// given sensor or vLC (by name, serial, deployment id or IP).
func (s *Service) ADSensorInstaller(ctx context.Context, orgID, sensor string) (ADSensorInstaller, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall sensors", "rendall adsensor/download"}, FetchedAt: s.now(),
		Notes: []string{"The link is signed and expires; give it to the customer as is."}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return ADSensorInstaller{}, meta, err
	}
	rows, err := s.up.Sensors(ctx, org.Pod, org.ID)
	if err != nil {
		return ADSensorInstaller{}, meta, fmt.Errorf("could not read sensors: %w", err)
	}
	var target *upstream.SensorRow
	var withIP []string
	for i, r := range rows {
		if r.IP == "" {
			continue
		}
		withIP = append(withIP, r.Name+" ("+r.IP+")")
		if strings.EqualFold(r.Name, sensor) || strings.EqualFold(r.IP, sensor) || strings.EqualFold(r.DeploymentID, sensor) || strings.EqualFold(r.SerialNumber, sensor) {
			target = &rows[i]
		}
	}
	if target == nil {
		if len(withIP) == 0 {
			return ADSensorInstaller{}, meta, fmt.Errorf("%w: no sensor or vLC with an IP address yet; the AD sensor forwards to one, so set up a vLC first (get_appliance_download appliance=vlc)", ErrChangeInvalid)
		}
		return ADSensorInstaller{}, meta, fmt.Errorf("%w: sensor %q not found; choose one of: %s", ErrChangeInvalid, sensor, strings.Join(withIP, ", "))
	}
	if net.ParseIP(target.IP).To4() == nil {
		return ADSensorInstaller{}, meta, fmt.Errorf("%w: sensor %s has no IPv4 address", ErrChangeInvalid, target.Name)
	}
	var out struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	}
	if err := s.up.RendallOrgPost(ctx, org.Pod, org.ID, "v1", "/adsensor/download", map[string]string{"ip": target.IP}, &out); err != nil {
		return ADSensorInstaller{}, meta, fmt.Errorf("could not get the AD sensor installer: %w", err)
	}
	return ADSensorInstaller{Sensor: target.Name, SensorIP: target.IP, URL: out.URL, SHA256: out.SHA256, Steps: []string{
		"Download the installer on a domain controller (or a server that collects Windows events) and check its SHA-256.",
		"Run it as an administrator; it is already set to forward Windows event logs to " + target.Name + " at " + target.IP + ".",
		"Allow the domain controller to reach " + target.IP + " on the syslog port.",
		"Within a few minutes the domain controller appears as a new log source (list_log_sources new_since_days=1).",
	}}, meta, nil
}

// SourceDetections is what switching a source on gives the customer: the catalog detections that
// run on its parser or integration type ("27 detections switched on").
type SourceDetections struct {
	Parser      string   `json:"parser,omitempty"`
	Integration string   `json:"integration,omitempty"`
	Total       int      `json:"total"`
	Examples    []string `json:"examples"`
	Techniques  []string `json:"mitreTechniques,omitempty"`
}

// DetectionsFor counts detection-catalog detections for a parser and/or integration type.
func (s *Service) DetectionsFor(ctx context.Context, orgID, parser, integration string) (SourceDetections, Meta, error) {
	meta := Meta{Sources: []string{"detection-service /api/v1/detections"}, FetchedAt: s.now()}
	if parser == "" && integration == "" {
		return SourceDetections{}, meta, fmt.Errorf("%w: give a parser (from the log source) or an integration type", ErrChangeInvalid)
	}
	if _, err := s.resolve(ctx, orgID); err != nil {
		return SourceDetections{}, meta, err
	}
	var parsers, sources []string
	if parser != "" {
		parsers = []string{parser}
	}
	if integration != "" {
		sources = []string{integration}
	}
	list, err := s.up.Detections(ctx, parsers, sources, 50)
	if err != nil {
		return SourceDetections{}, meta, fmt.Errorf("detection catalog unavailable: %w", err)
	}
	out := SourceDetections{Parser: parser, Integration: integration, Total: list.Total, Examples: []string{}}
	seen := map[string]bool{}
	for i, d := range list.Data {
		if i < 8 {
			out.Examples = append(out.Examples, d.Name)
		}
		for _, m := range d.Mitres {
			label := strings.TrimSpace(m.ID + " " + m.Name)
			if label != "" && !seen[label] && len(out.Techniques) < 8 {
				seen[label] = true
				out.Techniques = append(out.Techniques, label)
			}
		}
	}
	if list.Total == 0 {
		meta.Notes = append(meta.Notes, "No catalog detections are tagged with this parser or integration; it may use a different name in the catalog.")
	}
	return out, meta, nil
}
