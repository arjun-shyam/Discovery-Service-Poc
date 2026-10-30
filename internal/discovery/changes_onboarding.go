package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// Onboarding change kinds. Each one builds the same request the Unified Portal onboarding
// page sends (rtkwlf/arcticexperience features/onboarding + apis/rendall), so a change made
// here is indistinguishable from one made in the portal.
const (
	ChangeSetExecutiveSponsor   = "set_executive_sponsor"
	ChangeSetDeploymentContacts = "set_deployment_contacts"
	ChangeSetEscalationContacts = "set_escalation_contacts"
	ChangeSetEndpointCounts     = "set_endpoint_counts"
	ChangeSetCloudInformation   = "set_cloud_information"
	ChangeSetLocationAlerts     = "set_location_alerts"
	ChangeSetInternetExposure   = "set_internet_exposure"
	ChangeRequestSensor         = "request_sensor"
)

// Option values the Unified Portal cloud information drawer sends.
var (
	microsoftOptions = []string{"global", "gcc", "gcc_high"}
	googleOptions    = []string{"standard_tier", "premium_tier"}
	awsOptions       = []string{"cloud_trail", "guard_duty", "security_hub", "waf"}
	endpointOptions  = []string{"ciscosecure", "crowdstrikecontainment", "crowdstrike", "cylance", "meraki", "microsoftdefender",
		"sentinelone", "sophos", "carbonblack", "webroot", "kaspersky", "paloalto", "symantec", "mcafee", "trendmicro"}
	haFirewallOptions = []string{"none", "active_passive", "active_active", "other_ha"}
	contactRoleFlags  = map[string]string{
		"primary": "primary", "secondary": "secondary", "backup": "secondary", "executive_sponsor": "executiveSponsorManager",
		"distribution_list": "distributionList", "billing": "billing", "networking": "networkingInfrastructure",
		"windows_ad": "serverWindowsAd", "managed_risk": "managedRisk", "managed_awareness": "managedAwareness",
	}
	weekdays   = map[string]string{"mon": "0", "tue": "1", "wed": "2", "thu": "3", "fri": "4", "sat": "5", "sun": "6"}
	isoCountry = regexp.MustCompile(`^[A-Z]{2}$`)
	hostname   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	hhmm       = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
)

// normalise lower-cases, trims and turns spaces/hyphens into underscores ("GCC High" → "gcc_high").
func normalise(v string) string {
	return strings.NewReplacer(" ", "_", "-", "_").Replace(strings.ToLower(strings.TrimSpace(v)))
}

// pick validates a comma-separated list against allowed values (after normalising).
func pick(params map[string]string, key string, allowed []string) ([]string, error) {
	out := []string{}
	for _, raw := range list(params, key) {
		v := normalise(raw)
		v = strings.ReplaceAll(v, "_", "")
		match := ""
		for _, a := range allowed {
			if strings.ReplaceAll(a, "_", "") == v {
				match = a
			}
		}
		if match == "" {
			return nil, fmt.Errorf("%w: %s %q is not one of %s", ErrChangeInvalid, key, raw, strings.Join(allowed, ", "))
		}
		if !contains(out, match) {
			out = append(out, match)
		}
	}
	return out, nil
}

func yes(params map[string]string, key string) bool {
	switch normalise(params[key]) {
	case "yes", "true", "y", "1", "on":
		return true
	}
	return false
}

func nonNegInt(params map[string]string, key string) (int, error) {
	v := str(params, key)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.ReplaceAll(v, ",", ""))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %s must be a whole number", ErrChangeInvalid, key)
	}
	return n, nil
}

// orgContact is a Rendall contact kept as raw JSON so an update sends every field back.
type orgContact map[string]any

func (c orgContact) name() string {
	return strings.TrimSpace(fmt.Sprint(c["firstName"]) + " " + fmt.Sprint(c["lastName"]))
}

func (c orgContact) firstEmail() map[string]any {
	if emails, ok := c["emailAddresses"].([]any); ok && len(emails) > 0 {
		e, _ := emails[0].(map[string]any)
		return e
	}
	return nil
}

func (c orgContact) firstPhone() map[string]any {
	if phones, ok := c["phoneNumbers"].([]any); ok && len(phones) > 0 {
		p, _ := phones[0].(map[string]any)
		if p != nil && fmt.Sprint(p["phone"]) != "" {
			return p
		}
	}
	return nil
}

// findContacts resolves comma-separated contact names (or ids) to the org's contacts, in order.
func (s *Service) findContacts(ctx context.Context, org upstream.Organization, names []string) ([]orgContact, error) {
	var all struct {
		Items []orgContact `json:"items"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/contacts", &all); err != nil {
		return nil, err
	}
	var out []orgContact
	for _, want := range names {
		w := strings.ToLower(strings.TrimSpace(want))
		var found []orgContact
		for _, c := range all.Items {
			if strings.EqualFold(fmt.Sprint(c["id"]), w) || strings.ToLower(c.name()) == w {
				found = append(found, c)
			}
		}
		switch {
		case len(found) == 0:
			return nil, fmt.Errorf("%w: no contact named %q; add the contact first (add_contact) or use get_contacts to find the exact name", ErrChangeInvalid, want)
		case len(found) > 1:
			return nil, fmt.Errorf("%w: %d contacts are named %q; ask which one (use the contact id from get_contacts)", ErrChangeInvalid, len(found), want)
		}
		out = append(out, found[0])
	}
	return out, nil
}

func (s *Service) escalationByType(ctx context.Context, org upstream.Organization, typ string) (rendallEscalationFull, error) {
	var all struct {
		Items []rendallEscalationFull `json:"items"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/escalation-configs", &all); err != nil && !isNotFound(err) {
		return nil, err
	}
	for _, e := range all.Items {
		if contains(escalationTypes(e), typ) {
			return e, nil
		}
	}
	return nil, nil
}

const mspContactsNote = "this organization is managed by an MSP partner, so its contacts are managed by that partner: " +
	"Arctic Wolf does not allow adding contacts here (same rule as the Unified Portal). Ask your MSP partner or your Concierge team to add the contact"

// mspManagedContacts mirrors Rendall's CreateOrgContact rule: an MSP end-customer org (not an MSP,
// has an MSP id, not MSP Plus) cannot add contacts.
func (s *Service) mspManagedContacts(ctx context.Context, org upstream.Organization) (bool, error) {
	var info struct {
		IsMsp   *bool   `json:"isMsp"`
		MspID   *string `json:"mspID"`
		MspPlus bool    `json:"mspPlus"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "", &info); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsMsp != nil && !*info.IsMsp && info.MspID != nil && *info.MspID != "" && !info.MspPlus, nil
}

// prepareOnboarding fills ch for the onboarding kinds. ok is false for kinds it does not handle.
func (s *Service) prepareOnboarding(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	ok = true
	switch kind {
	case ChangeCreateSite:
		miss, err = s.prepareSite(ctx, org, ch, nil, params)
		if err != nil {
			return nil, ok, err
		}

	case ChangeAddContact:
		if managed, e := s.mspManagedContacts(ctx, org); e != nil {
			return nil, ok, e
		} else if managed {
			return nil, ok, fmt.Errorf("%w: %s", ErrChangeInvalid, mspContactsNote)
		}
		miss = missing(params, "first_name", "last_name", "title", "email", "phone", "timezone", "roles")
		email := str(params, "email")
		if email != "" {
			if _, e := mail.ParseAddress(email); e != nil {
				return nil, ok, fmt.Errorf("%w: email %q is not valid", ErrChangeInvalid, email)
			}
			// Rendall CreateOrgContact only accepts addresses on the organization's registered email
			// domains (Customer Directory); check up front so the customer isn't refused after confirming.
			var domains []string
			// Rendall refuses every address when the organization has no registered domains.
			// Rendall refuses every address when the organization has no registered domains. A failed
			// lookup proves nothing, so only a successful, empty answer stops the change here.
			e := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/email-domains", &domains)
			if e != nil {
				log.Printf("add_contact: email-domains lookup failed, skipping the pre-check: %v", e)
			} else if len(domains) == 0 {
				return nil, ok, fmt.Errorf("%w: this organization has no registered email domains, so Arctic Wolf can't add any contact yet. Ask the Concierge Security Team to register your company's email domain, then add the contact", ErrChangeInvalid)
			} else if e == nil {
				at := strings.LastIndex(email, "@")
				domain := strings.ToLower(email[at+1:])
				allowed := false
				for _, d := range domains {
					if strings.EqualFold(strings.TrimSpace(d), domain) {
						allowed = true
					}
				}
				if !allowed {
					return nil, ok, fmt.Errorf("%w: %s isn't on this organization's registered email domains (%s). Use an address on one of them, or ask the Concierge team to add the domain", ErrChangeInvalid, email, strings.Join(domains, ", "))
				}
			}
		}
		if tz := str(params, "timezone"); tz != "" && !validTimezone(tz) {
			return nil, ok, fmt.Errorf("%w: timezone %q is not an IANA zone like America/Toronto", ErrChangeInvalid, tz)
		}
		start, end := orDefault(str(params, "work_start"), "09:00"), orDefault(str(params, "work_end"), "17:00")
		if !hhmm.MatchString(start) || !hhmm.MatchString(end) {
			return nil, ok, fmt.Errorf("%w: working hours must be HH:MM (24h), e.g. 09:00 and 17:00", ErrChangeInvalid)
		}
		var days []string
		for _, d := range list(params, "work_days") {
			n, found := weekdays[strings.ToLower(d)[:min(3, len(d))]]
			if !found {
				return nil, ok, fmt.Errorf("%w: work day %q is not Mon..Sun", ErrChangeInvalid, d)
			}
			days = append(days, n)
		}
		if len(days) == 0 {
			days = []string{"0", "1", "2", "3", "4"}
		}
		flags := map[string]any{"primary": false, "secondary": false, "distributionList": false, "billing": false, "executiveSponsorManager": false,
			"serverWindowsAd": false, "networkingInfrastructure": false, "managedRisk": false, "managedAwareness": false}
		var roleNames []string
		for _, r := range list(params, "roles") {
			flag, found := contactRoleFlags[normalise(r)]
			if !found {
				return nil, ok, fmt.Errorf("%w: role %q is not one of primary, secondary, executive_sponsor, distribution_list, billing, networking, windows_ad", ErrChangeInvalid, r)
			}
			flags[flag] = true
			roleNames = append(roleNames, r)
		}
		contactType := "user"
		if flags["primary"] == true {
			contactType = "primary"
		} else if flags["secondary"] == true {
			contactType = "secondary"
		}
		phoneType := orDefault(normalise(str(params, "phone_type")), "mobile")
		portal := yes(params, "portal_access")
		ch.Title = "Add contact " + str(params, "first_name") + " " + str(params, "last_name")
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/contacts"
		ch.Body = map[string]any{
			"firstName": str(params, "first_name"), "lastName": str(params, "last_name"), "title": str(params, "title"),
			"emailAddresses": []map[string]any{{"email": email, "type": "work"}},
			"phoneNumbers":   []map[string]any{{"phone": str(params, "phone"), "type": phoneType}},
			"work":           map[string]any{"timezone": str(params, "timezone"), "startTime": start + ":00", "endTime": end + ":00", "workDays": strings.Join(days, ",")},
			"contactType":    contactType,
			"access":         map[string]any{"portal": portal, "cyberEssentials": false, "logSearch": false, "activateVlc": false, "managedAwareness": false},
			"contactTypes":   flags,
		}
		ch.Details = []ChangeDetail{{"Name", str(params, "first_name") + " " + str(params, "last_name")}, {"Title", str(params, "title")},
			{"Email", email}, {"Phone", str(params, "phone") + " (" + phoneType + ")"}, {"Roles", strings.Join(roleNames, ", ")},
			{"Working hours", start + "–" + end + " " + str(params, "timezone") + ", days " + orDefault(str(params, "work_days"), "Mon–Fri")},
			{"Portal access", map[bool]string{true: "Yes (invitation sent)", false: "No"}[portal]}}

	case ChangeSetExecutiveSponsor:
		miss = missing(params, "contact")
		if len(miss) > 0 {
			break
		}
		found, e := s.findContacts(ctx, org, []string{str(params, "contact")})
		if e != nil {
			return nil, ok, e
		}
		c := found[0]
		body := map[string]any{}
		for _, k := range []string{"firstName", "lastName", "title", "emailAddresses", "phoneNumbers", "address", "work", "contactType", "access", "contactTypes"} {
			if v, has := c[k]; has && v != nil {
				body[k] = v
			}
		}
		types, _ := body["contactTypes"].(map[string]any)
		next := map[string]any{}
		for k, v := range types {
			next[k] = v
		}
		next["executiveSponsorManager"] = true
		body["contactTypes"] = next
		ch.Title = "Make " + c.name() + " the executive sponsor"
		ch.Method, ch.Path = "PUT", "/api/v1/organizations/"+org.ID+"/contacts/"+fmt.Sprint(c["id"])
		ch.Body = body
		ch.Details = []ChangeDetail{{"Contact", c.name()}, {"Title", fmt.Sprint(c["title"])}, {"New role", "Executive sponsor (contractual issues)"}}
		ch.Assumptions = []string{"Only the executive sponsor flag changes; every other contact field is sent back unchanged."}

	case ChangeSetDeploymentContacts, ChangeSetEscalationContacts:
		miss = missing(params, "contacts")
		if len(miss) > 0 {
			break
		}
		people, e := s.findContacts(ctx, org, list(params, "contacts"))
		if e != nil {
			return nil, ok, e
		}
		var prefs []map[string]any
		var names []string
		for i, c := range people {
			names = append(names, c.name())
			em := c.firstEmail()
			if em == nil {
				return nil, ok, fmt.Errorf("%w: %s has no email address on record", ErrChangeInvalid, c.name())
			}
			typ := "email_to"
			if kind == ChangeSetEscalationContacts && i > 0 {
				typ = "email_cc"
			}
			prefs = append(prefs, map[string]any{"type": typ, "firstName": c["firstName"], "lastName": c["lastName"], "email": em})
			if kind == ChangeSetEscalationContacts {
				if ph := c.firstPhone(); ph != nil {
					prefs = append(prefs, map[string]any{"type": "phone", "firstName": c["firstName"], "lastName": c["lastName"], "phone": ph})
				}
			}
		}
		tiers := []map[string]any{{"tierNumber": 1, "communicationPreferences": prefs}}
		if kind == ChangeSetDeploymentContacts {
			existing, e := s.escalationByType(ctx, org, "onboarding__deployment_comms")
			if e != nil {
				return nil, ok, e
			}
			if existing != nil {
				body := map[string]any{}
				for k, v := range existing {
					body[k] = v
				}
				body["tiers"] = tiers
				ch.Method, ch.Path = "PUT", "/api/v2/organizations/"+org.ID+"/escalation-configs/"+fmt.Sprint(existing["uuid"])
				ch.Body = body
				ch.Assumptions = []string{"Replaces the people on your existing Deployment Communication rule."}
			} else {
				ch.Method, ch.Path = "POST", "/api/v2/organizations/"+org.ID+"/escalation-configs"
				ch.Body = map[string]any{"name": "Deployment Communication", "tiers": tiers,
					"conditions": map[string]any{"type": []map[string]any{{"type": "onboarding__deployment_comms", "displayName": "Deployment Communication"}},
						"priority": []string{"low"}, "sensor": []string{}, "logSource": []string{}},
					"timeType": "any", "shareWithAll": false, "sharedCustomers": []string{}, "excludeFromMsp": false}
			}
			ch.Title = "Set deployment contacts"
			ch.Details = []ChangeDetail{{"Deployment contacts", strings.Join(names, ", ")}, {"They receive", "Deployment-related tickets and tasks"}}
		} else {
			ch.Method, ch.Path = "POST", "/api/v2/organizations/"+org.ID+"/escalation-configs"
			ch.Body = map[string]any{"tiers": tiers, "timeType": "any", "shareWithAll": false, "sharedCustomers": []string{}, "excludeFromMsp": false,
				"conditions": map[string]any{"type": []map[string]any{{"type": "default", "displayName": "Default"}},
					"priority": []string{"low", "medium", "high", "urgent"}, "sensor": []string{}, "logSource": []string{}}}
			ch.Title = "Set escalation contacts"
			order := make([]string, len(names))
			for i, n := range names {
				order[i] = fmt.Sprintf("%d. %s", i+1, n)
			}
			ch.Details = []ChangeDetail{{"Escalate incidents to (in order)", strings.Join(order, "  ")}, {"When", "Any time, all priorities (low to urgent)"},
				{"How", "First person by email (To), others copied; phone where on record"}}
			ch.Assumptions = []string{"Same default rule the Unified Portal onboarding page creates; once submitted, changes go through your Concierge team."}
		}

	case ChangeSetEndpointCounts:
		miss = missing(params, "windows", "mac", "linux", "sysmon_windows")
		win, e1 := nonNegInt(params, "windows")
		mac, e2 := nonNegInt(params, "mac")
		lin, e3 := nonNegInt(params, "linux")
		for _, e := range []error{e1, e2, e3} {
			if e != nil {
				return nil, ok, e
			}
		}
		counts := map[string]any{"windows": win, "mac": mac, "linux": lin, "sysmonWindows": yes(params, "sysmon_windows")}
		var current versioned
		if e := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/endpoint-configuration", &current); e != nil && !isNotFound(e) {
			return nil, ok, e
		}
		if current.Version > 0 {
			ch.Method, ch.Path = "PUT", "/api/v1/organizations/"+org.ID+"/endpoint-configuration/"+orDefault(current.ID, "instance")
			ch.Body = map[string]any{"version": current.Version, "data": map[string]any{"endpointCounts": counts}}
			old, _ := current.Data["endpointCounts"].(map[string]any)
			ch.Assumptions = []string{fmt.Sprintf("Replaces the current estimate (Windows %v, Mac %v, Linux %v, Sysmon %v).", old["windows"], old["mac"], old["linux"], old["sysmonWindows"])}
		} else {
			ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/endpoint-configuration"
			ch.Body = map[string]any{"endpointCounts": counts}
		}
		ch.Title = "Save endpoint estimate for the Arctic Wolf Agent"
		ch.Details = []ChangeDetail{{"Windows endpoints", strconv.Itoa(win)}, {"Mac endpoints", strconv.Itoa(mac)}, {"Linux endpoints", strconv.Itoa(lin)},
			{"Sysmon on all Windows endpoints", map[bool]string{true: "Yes", false: "No"}[yes(params, "sysmon_windows")]}}

	case ChangeSetCloudInformation:
		ms, e := pick(params, "microsoft", microsoftOptions)
		if e != nil {
			return nil, ok, e
		}
		gg, e := pick(params, "google", googleOptions)
		if e != nil {
			return nil, ok, e
		}
		aws, e := pick(params, "aws", awsOptions)
		if e != nil {
			return nil, ok, e
		}
		epp, e := pick(params, "endpoint_solutions", endpointOptions)
		if e != nil {
			return nil, ok, e
		}
		other := str(params, "other_endpoint_solution")
		if len(epp) == 0 && other == "" {
			miss = append(miss, "endpoint_solutions")
		}
		services := []map[string]any{}
		if len(ms) > 0 {
			services = append(services, map[string]any{"cloud_type": "office365", "license_type": ms, "service_type": []string{}})
		}
		if len(gg) > 0 {
			services = append(services, map[string]any{"cloud_type": "gcp", "license_type": gg, "service_type": []string{}})
		}
		if len(aws) > 0 {
			services = append(services, map[string]any{"cloud_type": "aws_cloud", "license_type": []string{}, "service_type": aws})
		}
		data := map[string]any{"cloudServices": services, "endpointSolutions": epp}
		if other != "" {
			data["others"] = other
		}
		var current versioned
		if e := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/cloud-service-configuration", &current); e != nil && !isNotFound(e) {
			return nil, ok, e
		}
		if current.Version > 0 {
			ch.Method, ch.Path = "PUT", "/api/v1/organizations/"+org.ID+"/cloud-service-configuration/"+orDefault(current.ID, "instance")
			ch.Body = map[string]any{"version": current.Version, "data": data}
			ch.Assumptions = []string{"Replaces your current cloud information (" + describeCloudServices(current.Data["cloudServices"]) + "; endpoint security " + joinOr(anyStrings(current.Data["endpointSolutions"]), "none") + ")."}
		} else {
			ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/cloud-service-configuration"
			ch.Body = map[string]any{"data": data}
		}
		ch.Title = "Save cloud information"
		ch.Details = []ChangeDetail{{"Microsoft 365", orNone(strings.Join(ms, ", "))}, {"Google Cloud", orNone(strings.Join(gg, ", "))},
			{"AWS", orNone(strings.Join(aws, ", "))}, {"Endpoint security", orNone(strings.Join(append(epp, other), ", "))}}

	case ChangeSetLocationAlerts:
		approved, denied := list(params, "approved_countries"), list(params, "denied_countries")
		if (len(approved) == 0) == (len(denied) == 0) {
			return nil, ok, fmt.Errorf("%w: give either approved_countries or denied_countries (2-letter ISO codes), not both", ErrChangeInvalid)
		}
		codes, field, label := approved, "approvedCountries", "Approved login countries"
		if len(denied) > 0 {
			codes, field, label = denied, "deniedCountries", "Denied login countries"
		}
		for i, c := range codes {
			codes[i] = strings.ToUpper(c)
			if !isoCountry.MatchString(codes[i]) {
				return nil, ok, fmt.Errorf("%w: %q is not a 2-letter ISO country code", ErrChangeInvalid, c)
			}
		}
		ch.Title = "Set cloud location alerts"
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/configuration-rules/alert"
		ch.Body = map[string]any{field: codes}
		ch.Details = []ChangeDetail{{label, strings.Join(codes, ", ")},
			{"Effect", map[string]string{"approvedCountries": "Cloud sign-ins from any other country raise an alert", "deniedCountries": "Cloud sign-ins from these countries raise an alert"}[field]}}
		var rules map[string]map[string]any
		if e := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/configuration-rules/alert", &rules); e != nil && !isNotFound(e) {
			return nil, ok, e
		}
		ruleID := map[string]string{"approvedCountries": "s10_constants_cloud_services_approved_countries", "deniedCountries": "s10_constants_cloud_services_restricted_countries"}[field]
		ch.Details = append(ch.Details, ChangeDetail{"Current list (will be replaced)", orNone(strings.Join(countryList(rules[ruleID]), ", "))})
		ch.Assumptions = []string{"This list replaces the current list for that alert."}

	case ChangeSetInternetExposure:
		targets := list(params, "public_targets")
		domains := list(params, "email_domains")
		subs, subsErr := s.subscriptions(ctx, org)
		if subsErr == nil && !externalScansAllowed(subs) && len(targets) > 0 {
			return nil, ok, fmt.Errorf("%w: external vulnerability scans are not part of this customer's subscription (Managed Security Awareness only gets account-takeover scans); leave public_targets empty", ErrChangeInvalid)
		}
		if len(targets) > maxScanTargets {
			return nil, ok, fmt.Errorf("%w: %d public targets; the maximum is %d", ErrChangeInvalid, len(targets), maxScanTargets)
		}
		noTargets := len(targets) == 0
		noDomains := len(domains) == 0
		for _, t := range targets {
			if err := validScanTarget(t); err != nil {
				return nil, ok, err
			}
		}
		for _, d := range domains {
			d = strings.ToLower(d)
			if strings.HasPrefix(d, "@") || !hostname.MatchString(d) || strings.HasSuffix(d, "example.com") {
				return nil, ok, fmt.Errorf("%w: email domain %q is not valid (enter just the domain, e.g. company.com)", ErrChangeInvalid, d)
			}
		}
		agreed := yes(params, "agreement")
		if !noTargets && !agreed {
			return nil, ok, fmt.Errorf("%w: the customer must confirm they are permitted to scan these targets and will allowlist Arctic Wolf's scanner source IPs (agreement=yes)", ErrChangeInvalid)
		}
		ch.Title = "Submit internet exposure scan configuration"
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/onboarding-scan-configurations"
		ch.Body = map[string]any{"reach_targets": strings.Join(targets, "\n"), "reach_no_targets": noTargets,
			"fierce_targets": strings.Join(domains, "\n"), "fierce_no_targets": noDomains, "agreement": agreed}
		ch.Details = []ChangeDetail{{"External vulnerability scan targets", orDefault(strings.Join(targets, ", "), "None — I have no public targets")},
			{"Account takeover email domains", orDefault(strings.Join(domains, ", "), "None")},
			{"Scanner source IP allowlist", map[bool]string{true: "Acknowledged", false: "Not needed (no targets)"}[agreed]}}
		ch.Assumptions = []string{"As in the Unified Portal: this is sent to your Concierge team, who set up the scans; afterwards changes go through them."}

	case ChangeRequestSensor:
		m, e := s.prepareSensorRequest(ctx, org, ch, params)
		return m, ok, e

	case ChangeSetLogSourceParser:
		m, e := s.prepareParserChange(ctx, org, ch, params)
		return m, ok, e

	default:
		ok = false
	}
	return miss, ok, nil
}

// Unified Portal limits for external scan targets (scan-configuration-drawer/validation-rules.ts).
const (
	maxScanTargets  = 10000
	maxScanCIDRMask = 21
)

// cloudAccountTarget is a cloud account scan target (CSPM), e.g. aws:123456789012.
var cloudAccountTarget = regexp.MustCompile(`^(aws|gcp|azure):.+$`)

// validScanTarget mirrors the Unified Portal checks: IPv4, IPv4 range, CIDR (max /21),
// hostname, or a cloud account (aws:/gcp:/azure:<id>).
func validScanTarget(t string) error {
	switch {
	case cloudAccountTarget.MatchString(t):
		provider, id, _ := strings.Cut(t, ":")
		if !cspmAccountFormat[provider].MatchString(id) {
			return fmt.Errorf("%w: %q is not a valid %s account id", ErrChangeInvalid, t, provider)
		}
	case strings.Contains(t, "/"):
		ip, n, err := net.ParseCIDR(t)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("%w: %q is not a valid IPv4 CIDR", ErrChangeInvalid, t)
		}
		if ones, _ := n.Mask.Size(); ones < maxScanCIDRMask {
			return fmt.Errorf("%w: %q is too large; the maximum block size is /%d, break it into smaller blocks", ErrChangeInvalid, t, maxScanCIDRMask)
		}
	case strings.Contains(t, "-"):
		a, b, _ := strings.Cut(t, "-")
		if net.ParseIP(strings.TrimSpace(a)).To4() == nil || net.ParseIP(strings.TrimSpace(b)).To4() == nil {
			return fmt.Errorf("%w: %q is not a valid IPv4 range", ErrChangeInvalid, t)
		}
	case net.ParseIP(t) != nil:
		if net.ParseIP(t).To4() == nil {
			return fmt.Errorf("%w: %q: IPv6 is not supported, use IPv4", ErrChangeInvalid, t)
		}
		if strings.HasPrefix(t, "198.51.100.") || strings.HasPrefix(t, "203.0.113.") || strings.HasPrefix(t, "192.0.2.") {
			return fmt.Errorf("%w: %q is an example-only address", ErrChangeInvalid, t)
		}
	default:
		if !hostname.MatchString(strings.ToLower(t)) || strings.HasSuffix(strings.ToLower(t), "example.com") {
			return fmt.Errorf("%w: %q is not a valid hostname, IP or IP range", ErrChangeInvalid, t)
		}
	}
	return nil
}

func nonEmpty(parts ...string) []string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orNone(v string) string { return orDefault(v, "none") }

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// contactWithEmail reports whether the organization already has a contact with this email address.
// Rendall can save a new contact and then fail on a later step (for example the portal invitation),
// so a failed add_contact is checked against the contact list before telling the customer.
func (s *Service) contactWithEmail(ctx context.Context, org upstream.Organization, email string) (orgContact, bool) {
	var all struct {
		Items []orgContact `json:"items"`
	}
	if email == "" || s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/contacts", &all) != nil {
		return nil, false
	}
	for _, c := range all.Items {
		if e := c.firstEmail(); e != nil && strings.EqualFold(fmt.Sprint(e["email"]), email) {
			return c, true
		}
	}
	return nil, false
}
