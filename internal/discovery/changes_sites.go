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

// --- Sites: add, edit, delete ---
//
// Same form and Rendall calls as the Unified Portal Sites page (rtkwlf/arcticexperience
// features/account/src/pages/sites):
//   create_site  POST   /api/v2/organizations/{org}/sites          (createOrganizationSiteV2)
//   update_site  PUT    /api/v2/organizations/{org}/sites/{uuid}   (updateOrganizationSiteV2, whole site)
//   delete_site  DELETE /api/v2/organizations/{org}/sites/{uuid}   (deleteOrganizationSiteV2)
//
// The form branches like the portal's (use-site-validation-schema.tsx, use-get-site-request.ts):
//   physical_sensor   "Was this site scoped for an Arctic Wolf physical sensor?"
//   essential_log_sources "Are there essential log sources (firewalls, AD) expected from this site?"
//   no physical sensor → virtual_sensor (vsensor | vlc | none); none → log_source_site (forward logs there)
//   physical sensor or essential log sources → AD domain controllers, firewalls, HA type, DNS and
//   DHCP are required ("none" is an answer); neither → those are cleared.

const (
	ChangeUpdateSite = "update_site"
	ChangeDeleteSite = "delete_site"
)

var virtualSensorChoices = []string{"vsensor", "vlc", "none"}

// siteFields are the request fields a site change accepts.
var siteFields = []string{"name", "street", "street2", "city", "state", "postal_code", "country", "time_zone", "ip_subnets",
	"physical_sensor", "essential_log_sources", "virtual_sensor", "log_source_site", "ad_domain_controllers", "firewalls",
	"ha_firewall_type", "dns", "dhcp", "switches", "max_isp_bandwidth_mbps", "client_vpn", "proxy", "auth_8021x",
	"third_party_site", "notes"}

func (s *Service) prepareSiteManage(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) ([]string, error) {
	if miss := missing(params, "site"); len(miss) > 0 {
		return miss, nil
	}
	site, err := s.findSite(ctx, org, str(params, "site"))
	if err != nil {
		return nil, err
	}
	if kind == ChangeDeleteSite {
		var devices []upstream.SensorProfile
		_ = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/sites/"+url.PathEscape(site.UUID)+"/sensors", &devices)
		ch.Title = "Delete site " + site.Name
		ch.Method, ch.Path, ch.Body = "DELETE", "/api/v2/organizations/"+org.ID+"/sites/"+url.PathEscape(site.UUID), nil
		ch.Details = []ChangeDetail{{"Site", site.Name}, {"Time zone", site.TimeZone}}
		if len(devices) > 0 {
			names := make([]string, 0, len(devices))
			for _, d := range devices {
				names = append(names, d.Shorthand)
			}
			ch.Details = append(ch.Details, ChangeDetail{"Devices at this site", strings.Join(names, ", ") + " (move them first with move_sensor_site or update_scanner_settings, or they lose their site)"})
		}
		ch.Assumptions = []string{"Same as Delete on the Unified Portal Sites page. It cannot be undone; the site would have to be added again."}
		return nil, nil
	}

	var cur map[string]any
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/sites/"+url.PathEscape(site.UUID), &cur); err != nil {
		return nil, fmt.Errorf("could not read site %s: %w", site.Name, err)
	}
	changed := false
	for _, f := range siteFields {
		if f != "name" && str(params, f) != "" {
			changed = true
		}
	}
	if str(params, "name") != "" && str(params, "name") != site.Name {
		changed = true
	}
	if !changed {
		return nil, fmt.Errorf("%w: nothing to change; give the fields to update (%s)", ErrChangeInvalid, strings.Join(siteFields, ", "))
	}
	return s.prepareSite(ctx, org, ch, cur, params)
}

// prepareSite builds create_site (cur == nil) or update_site (cur = the site as Rendall has it;
// fields not given keep their current value).
func (s *Service) prepareSite(ctx context.Context, org upstream.Organization, ch *Change, cur map[string]any, params map[string]string) ([]string, error) {
	// Merge: start from the current site's answers, then apply what the customer gave.
	v := map[string]string{}
	if cur != nil {
		for k, val := range siteParamsFrom(cur) {
			v[k] = val
		}
		if fwd, _ := cur["log_source_forward_site"].(string); fwd != "" {
			if st, err := s.findSite(ctx, org, fwd); err == nil {
				v["log_source_site"] = st.Name
			}
		}
	}
	for _, f := range siteFields {
		if val := str(params, f); val != "" {
			v[f] = val
		}
	}

	miss := missing(v, "name", "street", "city", "state", "country", "postal_code", "time_zone", "physical_sensor", "essential_log_sources")
	physical := yes(v, "physical_sensor")
	essential := physical || yes(v, "essential_log_sources")
	virtual := ""
	if str(v, "physical_sensor") != "" && !physical {
		if str(v, "virtual_sensor") == "" {
			miss = append(miss, "virtual_sensor")
		} else {
			got, err := pick(v, "virtual_sensor", virtualSensorChoices)
			if err != nil {
				return nil, err
			}
			virtual = got[0]
		}
	}
	if essential {
		miss = append(miss, missing(v, "ad_domain_controllers", "firewalls", "ha_firewall_type", "dns", "dhcp")...)
	}
	if len(miss) > 0 {
		return miss, nil
	}

	if tz := str(v, "time_zone"); !validTimezone(tz) {
		return nil, fmt.Errorf("%w: time_zone %q is not an IANA zone like America/Toronto", ErrChangeInvalid, tz)
	}
	country := strings.ToUpper(str(v, "country"))
	if !isoCountry.MatchString(country) {
		return nil, fmt.Errorf("%w: country must be a 2-letter ISO code like CA, US or IN", ErrChangeInvalid)
	}
	subnets := list(v, "ip_subnets")
	for _, subnet := range subnets {
		if !validSubnetEntry(subnet) {
			return nil, fmt.Errorf("%w: ip subnet %q must be an IP, a CIDR like 10.0.0.0/24 or a range like 10.0.0.1-10.0.0.50", ErrChangeInvalid, subnet)
		}
	}
	bandwidth, err := nonNegInt(v, "max_isp_bandwidth_mbps")
	if err != nil {
		return nil, err
	}

	// Network answers apply only when the site has a physical sensor or essential log sources.
	adc, ha, proxy := 0, "none", ""
	firewalls, dns, dhcp := []string{}, []string{}, []string{}
	if essential {
		if adc, err = nonNegInt(v, "ad_domain_controllers"); err != nil {
			return nil, err
		}
		if adc > 99 {
			return nil, fmt.Errorf("%w: ad_domain_controllers must be 0 to 99", ErrChangeInvalid)
		}
		got, err := pick(v, "ha_firewall_type", haFirewallOptions)
		if err != nil {
			return nil, err
		}
		ha = got[0]
		firewalls = noneList(v, "firewalls")
		dns, dhcp = noneList(v, "dns"), noneList(v, "dhcp")
		for key, ips := range map[string][]string{"dns": dns, "dhcp": dhcp} {
			for _, ip := range ips {
				if net.ParseIP(ip) == nil {
					return nil, fmt.Errorf("%w: %s server %q must be an IP address (or none)", ErrChangeInvalid, key, ip)
				}
			}
		}
		proxy = str(v, "proxy")
	}

	var forward any
	if !physical && virtual == "none" && str(v, "log_source_site") != "" {
		target, err := s.findSite(ctx, org, str(v, "log_source_site"))
		if err != nil {
			return nil, err
		}
		forward = target.UUID
	}

	body := map[string]any{
		"name": str(v, "name"),
		"address": map[string]any{"street1": str(v, "street"), "street2": str(v, "street2"), "city": str(v, "city"),
			"provinceState": str(v, "state"), "country": country, "postalZip": str(v, "postal_code")},
		"time_zone": str(v, "time_zone"), "ip_subnets": subnets,
		"firewalls": firewalls, "ha_firewall_type": ha, "switches": noneList(v, "switches"),
		"dns": dns, "dhcp": dhcp, "ad_domain_controllers": adc,
		"max_isp_bandwidth_purchased": bandwidth, "client_vpn_services": str(v, "client_vpn"), "proxy": proxy,
		"authentication_server_8021x": str(v, "auth_8021x"), "is_third_party_site": yes(v, "third_party_site"),
		"log_source_forward_site": forward, "notes": str(v, "notes"),
	}
	if !physical {
		body["virtual_sensor_type"] = virtual
	}

	collection := "Arctic Wolf physical sensor"
	if !physical {
		collection = map[string]string{"vsensor": "virtual sensor (vSensor)", "vlc": "virtual log collector (vLC)", "none": "no sensor at this site"}[virtual]
		if forward != nil {
			collection += "; logs forwarded to site " + str(v, "log_source_site")
		}
	}
	ch.Details = []ChangeDetail{
		{"Site name", str(v, "name")},
		{"Address", strings.Join(nonEmpty(str(v, "street"), str(v, "street2"), str(v, "city"), str(v, "state"), str(v, "postal_code"), country), ", ")},
		{"Time zone", str(v, "time_zone")},
		{"Data collection", collection},
		{"Essential log sources (firewalls, AD)", map[bool]string{true: "Yes", false: "No"}[essential]},
	}
	if len(subnets) > 0 {
		ch.Details = append(ch.Details, ChangeDetail{"IP subnets", strings.Join(subnets, ", ")})
	}
	if essential {
		ch.Details = append(ch.Details,
			ChangeDetail{"Firewalls", orNone(strings.Join(firewalls, ", ")) + " (HA: " + ha + ")"},
			ChangeDetail{"DNS / DHCP servers", orNone(strings.Join(dns, ", ")) + " / " + orNone(strings.Join(dhcp, ", "))},
			ChangeDetail{"AD domain controllers", strconv.Itoa(adc)})
	}
	if sw := noneList(v, "switches"); len(sw) > 0 {
		ch.Details = append(ch.Details, ChangeDetail{"Switches", strings.Join(sw, ", ")})
	}
	if bandwidth > 0 {
		ch.Details = append(ch.Details, ChangeDetail{"ISP bandwidth (Mbps)", strconv.Itoa(bandwidth)})
	}
	if extra := nonEmpty(str(v, "client_vpn"), proxy, str(v, "auth_8021x")); len(extra) > 0 {
		ch.Details = append(ch.Details, ChangeDetail{"Client VPN / proxy / 802.1X", orNone(str(v, "client_vpn")) + " / " + orNone(proxy) + " / " + orNone(str(v, "auth_8021x"))})
	}
	if yes(v, "third_party_site") {
		ch.Details = append(ch.Details, ChangeDetail{"Third-party managed", "Yes"})
	}

	if cur == nil {
		ch.Title = "Add site " + str(v, "name")
		ch.Method, ch.Path = "POST", "/api/v2/organizations/"+org.ID+"/sites"
		ch.Assumptions = []string{"Same request as Add Site in the Unified Portal. A physical sensor or scanner is placed at a site, so add the site first."}
	} else {
		uuid, _ := cur["uuid"].(string)
		body["uuid"] = uuid
		ch.Title = "Update site " + str(v, "name")
		ch.Method, ch.Path = "PUT", "/api/v2/organizations/"+org.ID+"/sites/"+url.PathEscape(uuid)
		ch.Assumptions = []string{"Same as Save on the Unified Portal site page. Fields you didn't change keep their current values; the previous values can be put back the same way."}
	}
	ch.Body = body
	return nil, nil
}

// siteParamsFrom turns Rendall's site (OrganizationSiteV2) back into request fields, the way the
// portal fills its edit form (use-get-site-from-response.ts).
func siteParamsFrom(cur map[string]any) map[string]string {
	join := func(k string) string {
		items, _ := cur[k].([]any)
		parts := make([]string, 0, len(items))
		for _, it := range items {
			parts = append(parts, fmt.Sprint(it))
		}
		return strings.Join(parts, ",")
	}
	asStr := func(k string) string {
		if val, ok := cur[k]; ok && val != nil {
			return fmt.Sprint(val)
		}
		return ""
	}
	out := map[string]string{
		"name": asStr("name"), "time_zone": asStr("time_zone"), "ip_subnets": join("ip_subnets"),
		"firewalls": join("firewalls"), "dns": join("dns"), "dhcp": join("dhcp"), "switches": join("switches"),
		"ha_firewall_type": asStr("ha_firewall_type"), "ad_domain_controllers": asStr("ad_domain_controllers"),
		"max_isp_bandwidth_mbps": asStr("max_isp_bandwidth_purchased"), "client_vpn": asStr("client_vpn_services"),
		"proxy": asStr("proxy"), "auth_8021x": asStr("authentication_server_8021x"), "notes": asStr("notes"),
	}
	if b, _ := cur["is_third_party_site"].(bool); b {
		out["third_party_site"] = "yes"
	}
	if addr, ok := cur["address"].(map[string]any); ok {
		for from, to := range map[string]string{"street1": "street", "street2": "street2", "city": "city", "provinceState": "state", "postalZip": "postal_code", "country": "country"} {
			if val, ok := addr[from].(string); ok {
				out[to] = val
			}
		}
	}
	vs, _ := cur["virtual_sensor_type"].(string)
	fwd, _ := cur["log_source_forward_site"].(string)
	if vs != "" || fwd != "" {
		out["physical_sensor"] = "no"
		out["virtual_sensor"] = orDefault(vs, "none")
	} else {
		out["physical_sensor"] = "yes"
	}
	if out["physical_sensor"] == "yes" || fwd != "" || out["firewalls"] != "" || out["dns"] != "" || out["dhcp"] != "" {
		out["essential_log_sources"] = "yes"
	} else {
		out["essential_log_sources"] = "no"
	}
	// An empty list that was saved means the customer answered "none".
	for _, k := range []string{"firewalls", "dns", "dhcp"} {
		if out[k] == "" && out["essential_log_sources"] == "yes" {
			out[k] = "none"
		}
	}
	return out
}

// noneList reads a list field where "none" means an empty list.
func noneList(params map[string]string, key string) []string {
	items := list(params, key)
	if len(items) == 1 && strings.EqualFold(items[0], "none") {
		return []string{}
	}
	return items
}

// validSubnetEntry accepts what the portal accepts: an IP, a CIDR or an a-b range.
func validSubnetEntry(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	if a, b, ok := strings.Cut(v, "-"); ok {
		return net.ParseIP(strings.TrimSpace(a)) != nil && net.ParseIP(strings.TrimSpace(b)) != nil
	}
	return false
}
