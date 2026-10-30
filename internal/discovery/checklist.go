package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// The onboarding checklist mirrors the Unified Portal "Organization Overview" onboarding page
// (rtkwlf/arcticexperience features/onboarding): Users, Site Data Collection, Arctic Wolf Agent
// & Sysmon, Cloud Sensors (cloud information, location alerts, connected cloud sensors) and
// Internet Exposure, plus single sign-on. Every value is read live from Rendall (the Unified
// Portal backend) and the onboarding service with the caller's own token. As in the Unified
// Portal, only the sections that apply to the customer's subscriptions are listed (products.go).

// Section status values.
const (
	SectionDone       = "done"
	SectionTodo       = "todo"
	SectionOptional   = "optional"    // nice to have; not counted in percentDone
	SectionArcticWolf = "arctic_wolf" // Arctic Wolf staff complete it (hardware shipping, tickets)
)

type ChecklistSection struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
	// Current holds what Arctic Wolf has on record today for this section.
	Current map[string]any `json:"current,omitempty"`
	// Change is the prepare_change kind that completes or updates this section.
	Change string `json:"change,omitempty"`
	// Why explains in one line why Arctic Wolf asks for it (from the Unified Portal copy).
	Why string `json:"why"`
}

type Checklist struct {
	Organization string             `json:"organization"`
	PercentDone  int                `json:"percentDone"`
	Sections     []ChecklistSection `json:"sections"`
	Products     []string           `json:"purchasedProducts,omitempty"`
	Licences     map[string]int     `json:"hardwareLicences,omitempty"`
	// Subscriptions are the purchased products (Rendall); they decide which sections apply.
	Subscriptions []string `json:"subscriptions,omitempty"`
	// HiddenSections don't apply to this customer's products (or are managed by their MSP).
	HiddenSections  []string          `json:"hiddenSections,omitempty"`
	SensorLicences  *LicenceProgress  `json:"sensorLicences,omitempty"`
	ScannerLicences *LicenceProgress  `json:"scannerLicences,omitempty"`
	OnboardingTeam  map[string]string `json:"onboardingTeam,omitempty"`
	// Handoff is the onboarding service's view of where Arctic Wolf is with this customer.
	Handoff *OnboardingHandoff `json:"handoff,omitempty"`
}

// rendallEscalationFull is an escalation rule with the fields needed to update it.
type rendallEscalationFull map[string]any

// OnboardingHandoff is the onboarding service status (read-only): whether the customer's
// onboarding form is open, kickoff and handoff state, and which sections Arctic Wolf staff
// have finalized (finalizing turns a section into staff tasks).
type OnboardingHandoff struct {
	FormOpen           bool               `json:"formOpen"`
	CustomerCanEdit    bool               `json:"customerCanEdit"`
	KickoffDone        bool               `json:"kickoffDone"`
	HandoffDone        bool               `json:"handoffDone"`
	PartiallyCompleted bool               `json:"partiallyCompleted"`
	ReadyForHandover   bool               `json:"readyForHandover"`
	DataEntryFinalized bool               `json:"dataEntryFinalized"`
	Summary            string             `json:"summary"`
	FinalizedSections  []FinalizedSection `json:"finalizedSections,omitempty"`
}

type FinalizedSection struct {
	Section string `json:"section"`
	When    string `json:"when"`
	By      string `json:"by"`
}

type onboardingStatus struct {
	ExperienceActive bool `json:"onboarding_experience_active"`
	CustomerCanEdit  bool `json:"customer_can_edit_sections"`
	Finalization     any  `json:"finalization"`
	TKOCompleted     bool `json:"tko_completed"`
	HandoffCompleted bool `json:"handoff_completed"`
	Partially        bool `json:"partially_completed"`
	ReadyForHandover bool `json:"ready_for_handover_or_acceptance"`
}

// sectionNames turns onboarding-service section keys into words a customer recognises.
var sectionNames = map[string]string{
	"sites": "Sites", "contacts": "Contacts", "cloud": "Cloud sensors", "cloud_sensor": "Cloud sensors",
	"external": "Internet exposure", "endpoint": "Endpoints and agents", "sensors": "Sensors", "sensor": "Sensors",
	"risk": "Scanners", "risk_scanner": "Scanners", "virtual_sensor": "Virtual sensors", "virtual_scanner": "Virtual scanners",
}

func describeHandoff(h OnboardingHandoff) string {
	switch {
	case h.HandoffDone:
		return "Onboarding handed off: Arctic Wolf has completed setup with you and you are in regular service."
	case h.ReadyForHandover:
		return "Ready for handover: Arctic Wolf is doing the final checks before handing off."
	case h.DataEntryFinalized:
		return "Your onboarding details are with Arctic Wolf; staff are working through the setup tasks."
	case h.FormOpen && h.KickoffDone:
		return "Kickoff done; your onboarding details are still open for you to complete."
	case h.FormOpen:
		return "Onboarding is open: fill in your details, then Arctic Wolf takes it from there."
	default:
		return "The onboarding form is not open for this organization."
	}
}

func escalationTypes(e rendallEscalationFull) []string {
	var out []string
	cond, _ := e["conditions"].(map[string]any)
	types, _ := cond["type"].([]any)
	for _, t := range types {
		if m, ok := t.(map[string]any); ok {
			out = append(out, fmt.Sprint(m["type"]))
		}
	}
	return out
}

func escalationPeople(e rendallEscalationFull) []string {
	var out []string
	tiers, _ := e["tiers"].([]any)
	for _, t := range tiers {
		tm, _ := t.(map[string]any)
		prefs, _ := tm["communicationPreferences"].([]any)
		for _, p := range prefs {
			pm, _ := p.(map[string]any)
			name := strings.TrimSpace(fmt.Sprint(pm["firstName"]) + " " + fmt.Sprint(pm["lastName"]))
			if name == "" || name == "<nil> <nil>" {
				if em, ok := pm["email"].(map[string]any); ok {
					name = maskEmail(fmt.Sprint(em["email"]))
				}
			}
			if name != "" && !contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// countryList extracts ISO codes from a configuration-rules/alert entry's data.
func countryList(rule map[string]any) []string {
	var out []string
	data, _ := rule["data"].([]any)
	for _, d := range data {
		switch v := d.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if c, ok := v["country"]; ok {
				out = append(out, fmt.Sprint(c))
			}
		}
	}
	return out
}

type versioned struct {
	ID      string         `json:"id"`
	Version int            `json:"version"`
	Data    map[string]any `json:"data"`
}

// checklistTTL keeps a computed checklist briefly: the cloud sensor list alone takes ~30 s.
const checklistTTL = 2 * time.Minute

type checklistEntry struct {
	at   time.Time
	list Checklist
}

var (
	checklistMu    sync.Mutex
	checklistCache = map[string]checklistEntry{}
)

// CachedChecklistPercent returns the last computed percentDone for an org (even if stale, so the
// banner never jumps back to a placeholder) and whether it is still fresh.
func CachedChecklistPercent(orgID string) (pct int, found, fresh bool) {
	checklistMu.Lock()
	defer checklistMu.Unlock()
	e, ok := checklistCache[orgID]
	if !ok {
		return 0, false, false
	}
	return e.list.PercentDone, true, time.Since(e.at) <= checklistTTL
}

// invalidateChecklist marks an org's checklist stale after a change (keeps the last percent).
func invalidateChecklist(orgID string) {
	checklistMu.Lock()
	defer checklistMu.Unlock()
	if e, ok := checklistCache[orgID]; ok {
		e.at = time.Time{}
		checklistCache[orgID] = e
	}
}

// OnboardingChecklist reads every customer onboarding section live and says what is done.
func (s *Service) OnboardingChecklist(ctx context.Context, orgID string) (Checklist, Meta, error) {
	list, meta, err := s.onboardingChecklist(ctx, orgID)
	if err == nil {
		checklistMu.Lock()
		checklistCache[orgID] = checklistEntry{at: time.Now(), list: list}
		checklistMu.Unlock()
	}
	return list, meta, err
}

func (s *Service) onboardingChecklist(ctx context.Context, orgID string) (Checklist, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (contacts, escalation-configs, sites, endpoint-configuration, cloud-service-configuration, configuration-rules/alert, onboarding-scan-configurations, cloud sensors, federated-authentication, onboarding-team-contacts)", "onboarding service (products, onboarding status, finalized sections)"},
		FetchedAt:       s.now(),
		UntrustedFields: []string{"sections[].current", "sections[].summary"},
		Notes:           []string{"Mirrors the Unified Portal onboarding page; emails are masked."}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return Checklist{}, meta, err
	}

	var (
		contacts struct {
			Items []rendallContact `json:"items"`
		}
		escalations struct {
			Items []rendallEscalationFull `json:"items"`
		}
		sites      []map[string]any
		endpoint   versioned
		cloudInfo  versioned
		alertRules map[string]map[string]any
		scanConfig map[string]any
		products   map[string]any
		team       map[string]struct{ FirstName, LastName string }
		cloudCount int
		cloudOK    int
		sso        []SSOConnection
		subs       Subscriptions
		mspChild   bool
		sensorLic  LicenceProgress
		scannerLic LicenceProgress
		errs       = map[string]error{}
		mu         sync.Mutex
		wg         sync.WaitGroup
	)
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				errs[name] = err
				mu.Unlock()
			}
		}()
	}
	run("contacts", func() error { return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/contacts", &contacts) })
	run("escalations", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/escalation-configs", &escalations)
	})
	run("sites", func() error { return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/sites", &sites) })
	run("endpoint", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/endpoint-configuration", &endpoint)
	})
	run("cloudInfo", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/cloud-service-configuration", &cloudInfo)
	})
	run("alerts", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/configuration-rules/alert", &alertRules)
	})
	run("scan", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/onboarding-scan-configurations", &scanConfig)
	})
	run("products", func() error { return s.up.OnboardingGet(ctx, org.Pod, org.CustomerID, "v1/products/", &products) })
	var (
		obStatus   onboardingStatus
		obSections map[string]struct {
			Timestamp string `json:"timestamp"`
			UserEmail string `json:"user_email"`
		}
	)
	run("onboardingStatus", func() error {
		return s.up.OnboardingGet(ctx, org.Pod, org.CustomerID, "v1/onboarding-status/", &obStatus)
	})
	run("finalizedSections", func() error {
		return s.up.OnboardingGet(ctx, org.Pod, org.CustomerID, "v2/finalization-section-status/", &obSections)
	})
	run("team", func() error {
		return s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/onboarding-team-contacts", &team)
	})
	run("cloudSensors", func() error {
		rows, err := s.up.CloudSensors(ctx, org.Pod, org.ID)
		cloudCount = len(rows)
		for _, r := range rows {
			if strings.EqualFold(r.Status, "healthy") {
				cloudOK++
			}
		}
		return err
	})
	run("subscriptions", func() error {
		var err error
		subs, err = s.subscriptions(ctx, org)
		return err
	})
	run("msp", func() error {
		var err error
		mspChild, err = s.mspManagedContacts(ctx, org)
		return err
	})
	run("sensorLicences", func() error {
		var err error
		sensorLic, err = s.sensorLicences(ctx, org)
		return err
	})
	run("scannerLicences", func() error {
		var err error
		scannerLic, err = s.scannerLicences(ctx, org)
		return err
	})
	run("sso", func() error {
		var err error
		sso, _, err = s.SSOStatus(ctx, org.ID)
		return err
	})
	wg.Wait()
	for name, e := range errs {
		// A 404 means "nothing configured yet" for the per-customer config items.
		if isNotFound(e) {
			continue
		}
		meta.Notes = append(meta.Notes, name+" unavailable: "+e.Error())
	}

	out := Checklist{Organization: org.Name, Licences: map[string]int{}, OnboardingTeam: map[string]string{}}
	if svcs, ok := products["services"].([]any); ok {
		for _, v := range svcs {
			out.Products = append(out.Products, fmt.Sprint(v))
		}
	}
	if hw, ok := products["hardware_quantity"].(map[string]any); ok {
		for k, v := range hw {
			if n, ok := v.(float64); ok && n > 0 {
				out.Licences[k] = int(n)
			}
		}
	}
	if vs, ok := products["virtual_sensors"].([]any); ok {
		for _, v := range vs {
			out.Licences[fmt.Sprint(v)]++
		}
	}
	if errs["onboardingStatus"] == nil {
		h := OnboardingHandoff{FormOpen: obStatus.ExperienceActive, CustomerCanEdit: obStatus.CustomerCanEdit,
			KickoffDone: obStatus.TKOCompleted, HandoffDone: obStatus.HandoffCompleted, PartiallyCompleted: obStatus.Partially,
			ReadyForHandover: obStatus.ReadyForHandover, DataEntryFinalized: obStatus.Finalization != nil}
		for key, v := range obSections {
			name := sectionNames[key]
			if name == "" {
				name = strings.ReplaceAll(key, "_", " ")
			}
			when := v.Timestamp
			if len(when) >= 10 {
				when = when[:10]
			}
			h.FinalizedSections = append(h.FinalizedSections, FinalizedSection{Section: name, When: when, By: maskEmail(v.UserEmail)})
		}
		sort.Slice(h.FinalizedSections, func(i, j int) bool { return h.FinalizedSections[i].When < h.FinalizedSections[j].When })
		h.Summary = describeHandoff(h)
		out.Handoff = &h
	}
	for role, p := range team {
		if name := strings.TrimSpace(p.FirstName + " " + p.LastName); name != "" {
			out.OnboardingTeam[role] = name
		}
	}

	// --- Users: contacts, communications contacts, escalation contacts ---
	var primary, secondary, sponsors []string
	for _, c := range contacts.Items {
		name := strings.TrimSpace(c.FirstName + " " + c.LastName)
		if c.ContactTypes["primary"] {
			primary = append(primary, name)
		}
		if c.ContactTypes["secondary"] {
			secondary = append(secondary, name)
		}
		if c.ContactTypes["executiveSponsorManager"] {
			sponsors = append(sponsors, name)
		}
	}
	sort.Strings(primary)
	sort.Strings(secondary)
	sort.Strings(sponsors)
	contactSummaryNote := ""
	if mspChild {
		contactSummaryNote = " (contacts are managed by your MSP partner; they cannot be added here)"
	}
	contactStatus := SectionTodo
	if len(primary) > 0 && len(secondary) > 0 {
		contactStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "contacts", Title: "Contacts", Status: contactStatus, Change: ChangeAddContact,
		Summary: fmt.Sprintf("%d contacts: %d primary, %d secondary", len(contacts.Items), len(primary), len(secondary)) + contactSummaryNote,
		Current: map[string]any{"total": len(contacts.Items), "primary": head(primary, 5), "secondary": head(secondary, 5)},
		Why:     "Arctic Wolf needs a primary and a secondary contact to reach your organization for administrative and security matters.",
	})

	var deployment []string
	var hasDefault bool
	var defaultPeople []string
	for _, e := range escalations.Items {
		types := escalationTypes(e)
		if contains(types, "onboarding__deployment_comms") {
			deployment = escalationPeople(e)
		}
		if contains(types, "default") && !hasDefault {
			hasDefault = true
			defaultPeople = escalationPeople(e)
		}
	}
	commsStatus := SectionTodo
	if len(sponsors) > 0 && len(deployment) > 0 {
		commsStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "communications_contacts", Title: "Communications contacts", Status: commsStatus, Change: ChangeSetExecutiveSponsor + " / " + ChangeSetDeploymentContacts,
		Summary: fmt.Sprintf("executive sponsor: %s; deployment contacts: %s", joinOr(sponsors, "none"), joinOr(deployment, "none")),
		Current: map[string]any{"executiveSponsors": head(sponsors, 5), "deploymentContacts": head(deployment, 5)},
		Why:     "An executive sponsor may be contacted for contractual issues; deployment contacts receive deployment tickets and tasks.",
	})
	escStatus := SectionTodo
	if len(escalations.Items) > 0 {
		escStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "escalation_contacts", Title: "Escalation contacts", Status: escStatus, Change: ChangeSetEscalationContacts,
		Summary: fmt.Sprintf("%d escalation rules; default rule: %s", len(escalations.Items), joinOr(defaultPeople, "none")),
		Current: map[string]any{"rules": len(escalations.Items), "defaultRulePeople": head(defaultPeople, 5)},
		Why:     "When the SOC finds an incident, it contacts these people in order, starting with the first responder.",
	})

	// --- Site Data Collection ---
	var siteNames []string
	for _, st := range sites {
		siteNames = append(siteNames, fmt.Sprint(st["name"]))
	}
	siteStatus := SectionTodo
	if len(sites) > 0 {
		siteStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "sites", Title: "Sites", Status: siteStatus, Change: ChangeCreateSite,
		Summary: fmt.Sprintf("%d sites registered", len(sites)),
		Current: map[string]any{"count": len(sites), "examples": head(siteNames, 5)},
		Why:     "Sites tell Arctic Wolf about each physical network (address, subnets, firewalls, DNS/DHCP, domain controllers) so sensors and scanners can be placed and logs understood.",
	})
	if errs["sensorLicences"] == nil {
		out.SensorLicences = &sensorLic
	}
	out.Sections = append(out.Sections, sensorsSection(sensorLic, errs["sensorLicences"]))
	if errs["scannerLicences"] == nil {
		out.ScannerLicences = &scannerLic
	}
	out.Sections = append(out.Sections, scannersSection(scannerLic, errs["scannerLicences"]))

	// --- Arctic Wolf Agent & Sysmon ---
	counts, _ := endpoint.Data["endpointCounts"].(map[string]any)
	agentStatus := SectionTodo
	if endpoint.Version > 0 && counts != nil {
		agentStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "agents", Title: "Arctic Wolf Agent & Sysmon", Status: agentStatus, Change: ChangeSetEndpointCounts,
		Summary: fmt.Sprintf("estimated endpoints: Windows %v, Mac %v, Linux %v; Sysmon on Windows: %v", counts["windows"], counts["mac"], counts["linux"], counts["sysmonWindows"]),
		Current: map[string]any{"endpointCounts": counts, "version": endpoint.Version},
		Why:     "Estimate how many endpoints will run the Arctic Wolf Agent (and whether Sysmon goes on Windows) so coverage can be tracked; then install from Downloads.",
	})

	// --- Cloud Sensors ---
	cloudStatus := SectionTodo
	if cloudInfo.Version > 0 {
		cloudStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "cloud_information", Title: "Cloud information", Status: cloudStatus, Change: ChangeSetCloudInformation,
		Summary: fmt.Sprintf("cloud services: %s; endpoint security: %s", describeCloudServices(cloudInfo.Data["cloudServices"]), joinOr(anyStrings(cloudInfo.Data["endpointSolutions"]), "none")),
		Current: map[string]any{"cloudServices": cloudInfo.Data["cloudServices"], "endpointSolutions": cloudInfo.Data["endpointSolutions"], "others": cloudInfo.Data["others"], "version": cloudInfo.Version},
		Why:     "Which Microsoft, Google and AWS products and which endpoint security tools you use decides which cloud sensors Arctic Wolf deploys.",
	})
	approved := countryList(alertRules["s10_constants_cloud_services_approved_countries"])
	denied := countryList(alertRules["s10_constants_cloud_services_restricted_countries"])
	locStatus := SectionTodo
	if len(approved) > 0 || len(denied) > 0 {
		locStatus = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "location_alerts", Title: "Location alerts", Status: locStatus, Change: ChangeSetLocationAlerts,
		Summary: fmt.Sprintf("approved login countries: %s; denied: %s", joinOr(approved, "none"), joinOr(denied, "none")),
		Current: map[string]any{"approvedCountries": approved, "deniedCountries": denied},
		Why:     "Cloud sign-ins from outside approved countries (or from denied countries) raise an alert.",
	})
	cs := SectionTodo
	if cloudCount > 0 {
		cs = SectionDone
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "cloud_sensors", Title: "Cloud sensors connected", Status: cs, Change: ChangeConnectCloudApp,
		Summary: fmt.Sprintf("%d cloud sensors connected, %d healthy", cloudCount, cloudOK),
		Current: map[string]any{"connected": cloudCount, "healthy": cloudOK},
		Why:     "Connecting each cloud app (with its API credentials) lets Arctic Wolf collect its logs.",
	})

	// --- Internet Exposure ---
	expStatus := SectionTodo
	if len(scanConfig) > 0 {
		expStatus = SectionDone
	}
	expWhy := "Public IPs/domains for External Vulnerability Assessment scans and email domains for account-takeover (dark web) scans."
	if errs["subscriptions"] == nil && !externalScansAllowed(subs) {
		expWhy = "Email domains for account-takeover (dark web) scans. External vulnerability scans are not part of your subscription."
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "internet_exposure", Title: "Internet exposure", Status: expStatus, Change: ChangeSetInternetExposure,
		Summary: describeScanConfig(scanConfig),
		Current: scanConfig,
		Why:     expWhy,
	})

	// --- Arctic Wolf onboarding status (from the onboarding service) ---
	if out.Handoff != nil {
		var done []string
		for _, f := range out.Handoff.FinalizedSections {
			done = append(done, f.Section+" ("+f.When+")")
		}
		out.Sections = append(out.Sections, ChecklistSection{
			ID: "arctic_wolf_onboarding", Title: "Arctic Wolf onboarding status", Status: SectionArcticWolf,
			Summary: out.Handoff.Summary + " Sections finalized by Arctic Wolf: " + joinOr(done, "none yet") + ".",
			Current: map[string]any{"formOpen": out.Handoff.FormOpen, "kickoffDone": out.Handoff.KickoffDone,
				"handoffDone": out.Handoff.HandoffDone, "readyForHandover": out.Handoff.ReadyForHandover,
				"finalizedSections": out.Handoff.FinalizedSections},
			Why: "Shows where Arctic Wolf's own onboarding work stands: kickoff, staff setup tasks and handoff to regular service.",
		})
	}

	// --- Single sign-on (optional) ---
	ssoStatus := SectionOptional
	ssoSummary := "not set up (optional)"
	if len(sso) > 0 {
		ssoStatus = SectionDone
		ssoSummary = fmt.Sprintf("%d SSO connection(s) for %s", len(sso), strings.Join(sso[0].Domains, ", "))
	}
	out.Sections = append(out.Sections, ChecklistSection{
		ID: "single_sign_on", Title: "Single sign-on", Status: ssoStatus, Change: ChangeConfigureSSO, Summary: ssoSummary,
		Why: "Lets your users sign in to the Arctic Wolf portal with your identity provider.",
	})

	// Keep only the sections that apply to the customer's products, like the Unified Portal.
	if errs["subscriptions"] == nil {
		out.Subscriptions = subs.Names()
		visible := visibilityFor(subs, mspChild)
		kept := out.Sections[:0]
		for _, sec := range out.Sections {
			if show, ruled := visible[sec.ID]; ruled && !show {
				out.HiddenSections = append(out.HiddenSections, sec.ID)
				continue
			}
			kept = append(kept, sec)
		}
		out.Sections = kept
	} else {
		meta.Notes = append(meta.Notes, "subscriptions unavailable, so every section is listed; some may not apply to this customer")
	}

	// Same rule as the Unified Portal: each customer section is worth the same share.
	var total, done int
	for _, sec := range out.Sections {
		if sec.Status == SectionOptional || sec.Status == SectionArcticWolf {
			continue
		}
		total++
		if sec.Status == SectionDone {
			done++
		}
	}
	if total > 0 {
		out.PercentDone = (done*100 + total/2) / total
	}
	return out, meta, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "returned 404")
}

func head(list []string, n int) []string {
	if len(list) > n {
		return append(list[:n:n], fmt.Sprintf("+%d more", len(list)-n))
	}
	return list
}

func joinOr(list []string, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(head(list, 3), ", ")
}

func anyStrings(v any) []string {
	var out []string
	if items, ok := v.([]any); ok {
		for _, i := range items {
			out = append(out, fmt.Sprint(i))
		}
	}
	return out
}

func describeCloudServices(v any) string {
	var parts []string
	items, _ := v.([]any)
	for _, i := range items {
		m, _ := i.(map[string]any)
		vals := append(anyStrings(m["license_type"]), anyStrings(m["service_type"])...)
		parts = append(parts, fmt.Sprintf("%v (%s)", m["cloud_type"], strings.Join(vals, ", ")))
	}
	return joinOr(parts, "none")
}

func describeScanConfig(c map[string]any) string {
	if len(c) == 0 {
		return "not submitted"
	}
	var parts []string
	if c["reach_no_targets"] == true {
		parts = append(parts, "no public scan targets")
	} else if t := fmt.Sprint(c["reach_targets"]); t != "" && t != "<nil>" {
		parts = append(parts, "public targets: "+strings.ReplaceAll(t, "\n", ", "))
	}
	if c["fierce_no_targets"] == true {
		parts = append(parts, "no email domains")
	} else if t := fmt.Sprint(c["fierce_targets"]); t != "" && t != "<nil>" {
		parts = append(parts, "email domains: "+strings.ReplaceAll(t, "\n", ", "))
	}
	if c["agreement"] == true {
		parts = append(parts, "scanner allowlist acknowledged")
	}
	return "submitted: " + strings.Join(parts, "; ")
}

// sensorsSection mirrors the Unified Portal "Sensor licenses used" row: done when every licence
// that ships (not vLC, not the free AWN100 vSensor) is in use.
func sensorsSection(p LicenceProgress, err error) ChecklistSection {
	sec := ChecklistSection{ID: "sensors", Title: "Sensors", Change: ChangeRequestSensor,
		Why: "Sensors watch your network traffic and receive logs. Request each physical sensor here (Arctic Wolf ships it to the site); deploy virtual sensors and log collectors yourself from Downloads."}
	if err != nil {
		sec.Status, sec.Summary = SectionTodo, "sensor licences unavailable: "+err.Error()
		return sec
	}
	sec.Status = SectionTodo
	if p.Done() {
		sec.Status = SectionDone
	}
	sec.Summary = fmt.Sprintf("%d of %d sensor licences used", p.Used, p.Total) + licenceLines(p, "free AWN100 vSensor included")
	if left := p.PhysicalRemaining(); len(left) > 0 {
		var parts []string
		for m, n := range left {
			parts = append(parts, fmt.Sprintf("%s ×%d", m, n))
		}
		sort.Strings(parts)
		sec.Summary += ". Physical sensors still to request: " + strings.Join(parts, ", ")
	}
	sec.Current = map[string]any{"used": p.Used, "total": p.Total, "licences": p.Lines, "physicalToRequest": p.PhysicalRemaining()}
	return sec
}

// scannersSection mirrors the Unified Portal "Scanner licenses used" row (Aurora Vulnerability
// Management only): virtual scanners are unlimited, physical scanners have an allotment.
func scannersSection(p LicenceProgress, err error) ChecklistSection {
	sec := ChecklistSection{ID: "scanners", Title: "Vulnerability scanners",
		Why: "Aurora Vulnerability Management scanners scan your internal network. Your IT team installs the scanner (virtual from Downloads, or the shipped physical one); it finds hosts on its own subnet without setup. Exclusions (devices it must never scan), then scan schedules, are set on the scanner in Data Collection › Scanners; Aurora can do both."}
	if err != nil {
		sec.Status, sec.Summary = SectionTodo, "scanner licences unavailable: "+err.Error()
		return sec
	}
	sec.Status = SectionTodo
	if p.Done() {
		sec.Status = SectionDone
	}
	sec.Summary = fmt.Sprintf("%d of %d physical scanner licences used", p.Used, p.Total) + licenceLines(p, "")
	sec.Current = map[string]any{"used": p.Used, "total": p.Total, "licences": p.Lines}
	return sec
}

func licenceLines(p LicenceProgress, freeNote string) string {
	var parts []string
	for _, l := range p.Lines {
		switch {
		case l.Unlimited:
			parts = append(parts, fmt.Sprintf("%s: %d deployed, unlimited", l.Model, l.Used))
		default:
			parts = append(parts, fmt.Sprintf("%s: %d/%d", l.Model, l.Used, l.Quota))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	out := " (" + strings.Join(parts, "; ")
	for _, l := range p.Lines {
		if l.Free > 0 && freeNote != "" {
			out += "; " + freeNote
			break
		}
	}
	return out + ")"
}

// warmInFlight stops repeated progress reads from starting the same background checklist twice.
var warmInFlight sync.Map

// WarmChecklist computes the onboarding checklist in the background with the caller's token,
// so the next progress read has a live percentDone.
func (s *Service) WarmChecklist(ctx context.Context, orgID string) {
	token, err := upstream.TokenFrom(ctx)
	if err != nil {
		return
	}
	if _, busy := warmInFlight.LoadOrStore(orgID, true); busy {
		return
	}
	go func() {
		defer warmInFlight.Delete(orgID)
		bg, cancel := context.WithTimeout(upstream.WithToken(context.Background(), token), 3*time.Minute)
		defer cancel()
		_, _, _ = s.OnboardingChecklist(bg, orgID)
	}()
}
