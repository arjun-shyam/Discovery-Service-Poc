package discovery

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"sort"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Request a physical sensor (UC-03 Site Data Collection "Add Sensors") ---
//
// Same request the Unified Portal Add Sensor wizard sends (rtkwlf/arcticexperience
// features/telemetry/src/pages/sensors/add-sensors-page + use-prepare-sensor-profile-payload):
// Rendall POST /api/v1/organizations/{org}/sensor-profile, which Rendall forwards to the
// Customer Directory (Console) as a physical sensor profile. Arctic Wolf provisions and ships
// the sensor from that profile. Virtual sensors are not requested: the customer downloads and
// activates them.

// cspmAccountFormat are the Unified Portal account id formats for cloud account scan targets.
var cspmAccountFormat = map[string]*regexp.Regexp{
	"aws":   regexp.MustCompile(`^[0-9]{12}$`),
	"gcp":   regexp.MustCompile(`^[a-z][-a-z0-9]{4,28}[a-z0-9]$`),
	"azure": regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`),
}

// sensorDeploymentTypes are the Rendall DeploymentType values the wizard offers.
var sensorDeploymentTypes = map[string]string{
	"mirroring":    "Port mirroring (SPAN) from a switch",
	"internal_tap": "Internal tap, inline behind the firewall",
}

// dhcpOverride is what the Unified Portal sends for every network field when the customer
// has no static IP for the sensor ("Static IP Address Unavailable").
const dhcpOverride = "dhcpOverride"

func (s *Service) prepareSensorRequest(ctx context.Context, org upstream.Organization, ch *Change, params map[string]string) ([]string, error) {
	miss := missing(params, "license", "name", "deployment_type", "site", "ship_first_name", "ship_last_name", "ship_email", "ship_phone",
		"street1", "city", "province_state", "postal_code", "country")
	dhcp := yes(params, "dhcp")
	if !dhcp {
		miss = append(miss, missing(params, "static_ip", "subnet_mask", "gateway", "primary_dns")...)
	}

	licences, err := s.sensorLicences(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("could not read sensor licences: %w", err)
	}
	left := licences.PhysicalRemaining()
	license := strings.ToLower(str(params, "license"))
	if license != "" && left[license] == 0 {
		var models []string
		for m := range left {
			models = append(models, m)
		}
		sort.Strings(models)
		if len(models) == 0 {
			return nil, fmt.Errorf("%w: no physical sensor licences are left to request; contact your Concierge team for more", ErrChangeInvalid)
		}
		return nil, fmt.Errorf("%w: licence %q has no units left; licences with units left: %s", ErrChangeInvalid, license, strings.Join(models, ", "))
	}
	deployment := strings.ToLower(str(params, "deployment_type"))
	if deployment != "" && sensorDeploymentTypes[deployment] == "" {
		return nil, fmt.Errorf("%w: deployment_type must be mirroring or internal_tap", ErrChangeInvalid)
	}
	// The licence's model group decides which deployments, transceivers and models apply, as on the
	// portal's Technical Requirements and Model steps.
	technical := map[string]any{"customer_configured": yes(params, "customer_configured")}
	var groupModels []string
	if license != "" {
		questions, models, gerr := s.sensorModelGroup(ctx, org, license)
		if gerr == nil {
			groupModels = models
			for _, q := range questions {
				field := q.CapabilityType
				if field == "deployment" {
					field = "deployment_type"
				}
				if field == "customer_configured" {
					continue
				}
				val := strings.ToLower(str(params, field))
				if val == "" {
					if q.Required {
						miss = append(miss, field)
					}
					continue
				}
				if allowed := q.values(); len(allowed) > 0 && !contains(allowed, val) {
					return nil, fmt.Errorf("%w: %s %q isn't available for the %s licence; choose one of %s", ErrChangeInvalid, field, val, license, strings.Join(allowed, ", "))
				}
				if field != "deployment_type" {
					technical[field] = val
				}
			}
		}
	}
	if m := strings.ToLower(str(params, "model")); m != "" && len(groupModels) > 0 {
		found := false
		for _, gm := range groupModels {
			if strings.EqualFold(gm, m) {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: model %q isn't part of the %s licence; choose one of %s", ErrChangeInvalid, m, license, strings.Join(groupModels, ", "))
		}
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

	model := strings.ToLower(orDefault(str(params, "model"), license))
	network := func(key string) string {
		if dhcp {
			return dhcpOverride
		}
		return str(params, key)
	}
	technical["deployment_type"] = deployment
	ch.Title = "Request a " + license + " sensor for " + siteName
	ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/sensor-profile"
	ch.Body = map[string]any{
		"shorthand":       str(params, "name"),
		"deployment_type": "physical",
		"notes":           str(params, "notes"),
		"site_uuid":       siteUUID,
		"ip_address":      network("static_ip"),
		"subnet":          network("subnet_mask"),
		"default_gateway": network("gateway"),
		"primary_dns":     network("primary_dns"),
		"secondary_dns":   network("secondary_dns"),
		"shipping_info": map[string]any{
			"first_name": str(params, "ship_first_name"), "last_name": str(params, "ship_last_name"),
			"email_address": str(params, "ship_email"), "phone_number": str(params, "ship_phone"),
			"street1": str(params, "street1"), "street2": str(params, "street2"), "city": str(params, "city"),
			"province_state": str(params, "province_state"), "postal_zip": str(params, "postal_code"), "country": str(params, "country"),
		},
		"required_hardware":      model,
		"configuration":          deployment,
		"technical_requirements": technical,
	}
	networkLine := "No static IP: Arctic Wolf configures it with DHCP"
	if !dhcp {
		networkLine = fmt.Sprintf("IP %s, mask %s, gateway %s, DNS %s", str(params, "static_ip"), str(params, "subnet_mask"), str(params, "gateway"),
			strings.Join(nonEmpty(str(params, "primary_dns"), str(params, "secondary_dns")), ", "))
	}
	ch.Details = []ChangeDetail{
		{"Sensor", fmt.Sprintf("%s (%s licence, %d left before this one)", str(params, "name"), license, left[license])},
		{"Deployment", sensorDeploymentTypes[deployment]},
		{"Site", siteName},
		{"Network", networkLine},
		{"Ship to", fmt.Sprintf("%s %s, %s, %s", str(params, "ship_first_name"), str(params, "ship_last_name"), str(params, "ship_phone"),
			strings.Join(nonEmpty(str(params, "street1"), str(params, "street2"), str(params, "city"), str(params, "province_state"), str(params, "postal_code"), str(params, "country")), ", "))},
	}
	ch.Assumptions = []string{
		"Same request as the Unified Portal Add Sensor page: Arctic Wolf provisions the sensor with these network settings and ships it to this address.",
		"Model defaults to the licence model; Arctic Wolf confirms the exact hardware (for example 10G ports) when provisioning.",
	}
	return nil, nil
}
