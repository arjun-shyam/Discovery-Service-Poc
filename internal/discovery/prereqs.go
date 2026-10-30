package discovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Prerequisites the Unified Portal enforces before a device or source can be added ---
//
// 1. Permission: the portal hides or disables write actions unless the signed-in user has the
//    feature capability (Rendall GET /api/v1/organizations/{org}/feature-capabilities, e.g.
//    sensor_write, scanner_write, scan_schedules_write, cloud_sensor_write, account_sites_manage,
//    contacts_manage). Checked at prepare time so the customer isn't asked for details first.
// 2. Physical sensor model questions: the Technical Requirements step asks what the licence's model
//    group allows (GET /api/v1/groups/{licence}: deployment, transceiver…) and the model step lists
//    GET /api/v1/groups/{licence}/models.
// 3. Cloud apps: a PREMIUM integration that isn't purchased can't be connected; the portal offers a
//    "Request quote" ticket (ticketType cloudRequestQuote) instead.

// capabilityFor maps a change kind to the feature capability the portal requires for it.
var capabilityFor = map[string]string{
	ChangeCreateSite: "account_sites_manage", ChangeUpdateSite: "account_sites_manage", ChangeDeleteSite: "account_sites_manage",
	ChangeAddContact:    "contacts_manage",
	ChangeRequestSensor: "sensor_write", ChangeMoveSensorSite: "sensor_write", ChangeDecommissionSensor: "sensor_write",
	ChangeRequestScanner: "scanner_write", ChangeUpdateScannerSettings: "scanner_write", ChangeUpdateScannerNetwork: "scanner_write",
	ChangeDecommissionScanner: "scanner_write",
	ChangeCreateScanSchedule:  "scan_schedules_write", ChangePauseScanSchedule: "scan_schedules_write",
	ChangeDeleteScanSchedule: "scan_schedules_write", ChangeScanNow: "scan_schedules_write",
	ChangeConnectCloudApp: "cloud_sensor_write", ChangeUpdateCloudCredentials: "cloud_sensor_write", ChangeRemoveCloudApp: "cloud_sensor_write",
}

var capabilityText = map[string]string{
	"account_sites_manage": "manage sites", "contacts_manage": "manage contacts", "sensor_write": "add or change sensors",
	"scanner_write": "add or change scanners", "scan_schedules_write": "change scan schedules", "cloud_sensor_write": "connect or change cloud apps",
}

// checkPermission returns an error when the signed-in user lacks the capability for kind. If the
// capabilities can't be read, or the key isn't reported, it doesn't block (Rendall still enforces).
func (s *Service) checkPermission(ctx context.Context, org upstream.Organization, kind string) error {
	key, ok := capabilityFor[kind]
	if !ok {
		return nil
	}
	var caps map[string]any
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/feature-capabilities", &caps); err != nil {
		return nil
	}
	if granted, ok := caps[key].(bool); ok && !granted {
		return fmt.Errorf("%w: your Arctic Wolf login isn't allowed to %s for this organization (permission %s). "+
			"Ask your organization's primary contact to do it or to give you that permission", ErrChangeInvalid, capabilityText[key], key)
	}
	return nil
}

// modelQuestion is one Technical Requirements question for a licence's model group.
type modelQuestion struct {
	CapabilityType string `json:"capabilityType"`
	Label          string `json:"label"`
	Required       bool   `json:"required"`
	Options        []struct {
		Value string `json:"value"`
		Label string `json:"label"`
	} `json:"options"`
}

func (q modelQuestion) values() []string {
	out := make([]string, 0, len(q.Options))
	for _, o := range q.Options {
		out = append(out, o.Value)
	}
	return out
}

// sensorModelGroup reads the licence's questions and models. Errors are returned so the caller can
// fall back to the generic questions.
func (s *Service) sensorModelGroup(ctx context.Context, org upstream.Organization, licence string) ([]modelQuestion, []string, error) {
	var group struct {
		Questions []modelQuestion `json:"questions"`
	}
	if err := s.up.RendallGet(ctx, org.Pod, "/api/v1/groups/"+url.PathEscape(licence), &group); err != nil {
		return nil, nil, err
	}
	var models []map[string]any
	_ = s.up.RendallGet(ctx, org.Pod, "/api/v1/groups/"+url.PathEscape(licence)+"/models", &models)
	names := []string{}
	for _, m := range models {
		for _, k := range []string{"value", "model", "name", "id"} {
			if v, ok := m[k].(string); ok && v != "" {
				names = append(names, v)
				break
			}
		}
	}
	return group.Questions, names, nil
}

// validExclusion accepts what the scanner's Scan Exclusion tab accepts: an IP, a CIDR or an a-b range.
func validExclusion(v string) bool { return validSubnetEntry(v) }

// mergeExclusions adds and removes entries from the scanner's deny list.
func mergeExclusions(current []any, add, remove []string) ([]any, []string, error) {
	have := map[string]bool{}
	out := []any{}
	drop := map[string]bool{}
	for _, r := range remove {
		drop[strings.TrimSpace(r)] = true
	}
	var changes []string
	for _, c := range current {
		v := strings.TrimSpace(fmt.Sprint(c))
		if drop[v] {
			changes = append(changes, "remove "+v)
			continue
		}
		have[v] = true
		out = append(out, c)
	}
	for _, a := range add {
		a = strings.TrimSpace(a)
		if !validExclusion(a) {
			return nil, nil, fmt.Errorf("%w: exclusion %q must be an IP, a CIDR like 10.0.5.0/24 or a range like 10.0.5.10-10.0.5.20", ErrChangeInvalid, a)
		}
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			return nil, nil, fmt.Errorf("%w: exclusion %q: only IPv4 is supported", ErrChangeInvalid, a)
		}
		if !have[a] {
			have[a] = true
			out = append(out, a)
			changes = append(changes, "add "+a)
		}
	}
	return out, changes, nil
}
