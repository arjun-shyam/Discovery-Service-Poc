package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Onboarding areas beyond sensors and log sources (UC-03 setup hub) ---
//
// All reads go through Rendall as the signed-in user, the same calls the Aurora and Unified
// portals make. Contact details are masked: the assistant needs who and which role, not the
// full address or number.

type ContactView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Title    string   `json:"title,omitempty"`
	Type     string   `json:"type"`            // primary | secondary | distributionList | user
	Roles    []string `json:"roles,omitempty"` // contactTypes flags that are set
	Email    string   `json:"email,omitempty"` // masked
	Phone    string   `json:"phone,omitempty"` // masked
	Timezone string   `json:"timezone,omitempty"`
	Hours    string   `json:"hours,omitempty"`
}

type EscalationView struct {
	When       string   `json:"when"` // any | during_business_hours | outside_business_hours
	AlertTypes []string `json:"alertTypes,omitempty"`
	Priorities []string `json:"priorities,omitempty"`
	Tiers      int      `json:"tiers"`
	People     []string `json:"people"` // names notified, in tier order
}

type ContactsAndEscalation struct {
	Contacts          []ContactView    `json:"contacts"`
	ContactsTotal     int              `json:"contactsTotal"`
	ByType            map[string]int   `json:"contactsByType"`
	Escalations       []EscalationView `json:"escalations"`
	EscalationsTotal  int              `json:"escalationsTotal"`
	EscalationsByWhen map[string]int   `json:"escalationsByWhen"`
	// OnboardingTeam is the Arctic Wolf project manager and engineer, when assigned.
	OnboardingTeam map[string]string `json:"onboardingTeam,omitempty"`
}

func maskEmail(email string) string {
	user, domain, ok := strings.Cut(email, "@")
	if !ok || user == "" {
		return ""
	}
	return user[:1] + "***@" + domain
}

func maskPhone(phone string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	if len(digits) < 4 {
		return ""
	}
	return "•••" + digits[len(digits)-4:]
}

type rendallContact struct {
	ID             string `json:"id"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	Title          string `json:"title"`
	EmailAddresses []struct {
		Email string `json:"email"`
	} `json:"emailAddresses"`
	PhoneNumbers []struct {
		Phone string `json:"phone"`
	} `json:"phoneNumbers"`
	Work struct {
		Timezone  string `json:"timezone"`
		StartTime string `json:"startTime"`
		EndTime   string `json:"endTime"`
	} `json:"work"`
	ContactType  string          `json:"contactType"`
	ContactTypes map[string]bool `json:"contactTypes"`
}

type rendallEscalation struct {
	TimeType   string `json:"timeType"`
	Conditions struct {
		Type []struct {
			DisplayName string `json:"displayName"`
		} `json:"type"`
		Priority []string `json:"priority"`
	} `json:"conditions"`
	Tiers []struct {
		CommunicationPreferences []struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"communicationPreferences"`
	} `json:"tiers"`
}

func (s *Service) ContactsAndEscalation(ctx context.Context, orgID, nameContains string, limit int) (ContactsAndEscalation, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (contacts, escalation-configs v2, onboarding-team-contacts)"}, FetchedAt: s.now(),
		UntrustedFields: []string{"contacts[].name", "contacts[].title", "escalations[].people"},
		Notes:           []string{"emails and phone numbers are masked"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return ContactsAndEscalation{}, meta, err
	}
	var (
		contacts struct {
			Total int              `json:"total"`
			Items []rendallContact `json:"items"`
		}
		escalations struct {
			Total int                 `json:"total"`
			Items []rendallEscalation `json:"items"`
		}
		team map[string]struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		}
		errs [3]error
		wg   sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		errs[0] = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/contacts", &contacts)
	}()
	go func() {
		defer wg.Done()
		errs[1] = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/escalation-configs", &escalations)
	}()
	go func() {
		defer wg.Done()
		errs[2] = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/onboarding-team-contacts", &team)
	}()
	wg.Wait()
	if errs[0] != nil {
		return ContactsAndEscalation{}, meta, errs[0]
	}

	if limit <= 0 {
		limit = defaultLogSourceLimit
	}
	out := ContactsAndEscalation{ContactsTotal: len(contacts.Items), ByType: map[string]int{}, EscalationsByWhen: map[string]int{}}
	needle := strings.ToLower(strings.TrimSpace(nameContains))
	for _, c := range contacts.Items {
		out.ByType[c.ContactType]++
		name := strings.TrimSpace(c.FirstName + " " + c.LastName)
		if needle != "" && !strings.Contains(strings.ToLower(name), needle) {
			continue
		}
		v := ContactView{ID: c.ID, Name: name, Title: c.Title, Type: c.ContactType, Timezone: c.Work.Timezone}
		if c.Work.StartTime != "" {
			v.Hours = c.Work.StartTime + "-" + c.Work.EndTime
		}
		for role, on := range c.ContactTypes {
			if on {
				v.Roles = append(v.Roles, role)
			}
		}
		sort.Strings(v.Roles)
		if len(c.EmailAddresses) > 0 {
			v.Email = maskEmail(c.EmailAddresses[0].Email)
		}
		if len(c.PhoneNumbers) > 0 {
			v.Phone = maskPhone(c.PhoneNumbers[0].Phone)
		}
		if len(out.Contacts) < limit {
			out.Contacts = append(out.Contacts, v)
		}
	}

	if errs[1] != nil {
		meta.Notes = append(meta.Notes, "escalation rules unavailable: "+errs[1].Error())
	}
	out.EscalationsTotal = len(escalations.Items)
	for _, e := range escalations.Items {
		out.EscalationsByWhen[e.TimeType]++
		if len(out.Escalations) >= limit {
			continue
		}
		v := EscalationView{When: e.TimeType, Priorities: e.Conditions.Priority, Tiers: len(e.Tiers), People: []string{}}
		for _, t := range e.Conditions.Type {
			if len(v.AlertTypes) < 3 {
				v.AlertTypes = append(v.AlertTypes, t.DisplayName)
			}
		}
		for _, tier := range e.Tiers {
			for _, p := range tier.CommunicationPreferences {
				v.People = append(v.People, strings.TrimSpace(p.FirstName+" "+p.LastName))
			}
		}
		out.Escalations = append(out.Escalations, v)
	}
	if out.EscalationsTotal > len(out.Escalations) {
		meta.Notes = append(meta.Notes, fmt.Sprintf("showing %d of %d escalation rules", len(out.Escalations), out.EscalationsTotal))
	}

	if errs[2] == nil {
		out.OnboardingTeam = map[string]string{}
		for role, person := range team {
			if name := strings.TrimSpace(person.FirstName + " " + person.LastName); name != "" {
				out.OnboardingTeam[role] = name
			}
		}
		if len(out.OnboardingTeam) == 0 {
			meta.Notes = append(meta.Notes, "no Arctic Wolf onboarding project manager or engineer is assigned")
		}
	}
	return out, meta, nil
}

// --- Single sign-on ---

type SSOConnection struct {
	Type      string   `json:"type"`
	IssuerURL string   `json:"issuerUrl"`
	Domains   []string `json:"domains"`
	Expires   string   `json:"expires,omitempty"`
	Expired   bool     `json:"expired"`
}

func (s *Service) SSOStatus(ctx context.Context, orgID string) ([]SSOConnection, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (federated-authentication v2)"}, FetchedAt: s.now(),
		Notes: []string{"single sign-on for the Arctic Wolf portals (OIDC); client ids and secrets are not returned"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return nil, meta, err
	}
	var raw struct {
		Results []struct {
			Type       string   `json:"type"`
			IssuerURL  string   `json:"issuerUrl"`
			Domains    []string `json:"domains"`
			ExpiryTime string   `json:"expiryTime"`
		} `json:"results"`
	}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v2", "/federated-authentication", &raw); err != nil {
		return nil, meta, err
	}
	out := make([]SSOConnection, 0, len(raw.Results))
	for _, r := range raw.Results {
		c := SSOConnection{Type: r.Type, IssuerURL: r.IssuerURL, Domains: r.Domains, Expires: r.ExpiryTime}
		if t, err := time.Parse(time.RFC3339, r.ExpiryTime); err == nil && t.Before(s.now()) {
			c.Expired = true
		}
		out = append(out, c)
	}
	return out, meta, nil
}

// --- Agents: what to install ---

type AgentDownloads struct {
	Platforms []struct {
		OS      string `json:"platformOs"`
		Name    string `json:"displayName"`
		Version string `json:"softwareVersion"`
	} `json:"platforms"`
	// DownloadPage is the Aurora page where the signed-in user downloads installers.
	DownloadPage string `json:"downloadPage"`
	Deployment   any    `json:"deployment,omitempty"`
}

func (s *Service) AgentDownloads(ctx context.Context, orgID string) (AgentDownloads, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (agent/platforms, onboarding-agent-overview)"}, FetchedAt: s.now(),
		Notes: []string{"installers are downloaded by the user from the Aurora downloads page; install commands are not available from the API"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return AgentDownloads{}, meta, err
	}
	out := AgentDownloads{DownloadPage: "/" + org.ID + "/resources/downloads"}
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/agent/platforms", &out.Platforms); err != nil {
		return out, meta, err
	}
	if overview, err := s.up.AgentOverview(ctx, org.Pod, org.ID); err == nil {
		out.Deployment = overview
	}
	return out, meta, nil
}

// --- Cloud integrations the customer can connect ---

type IntegrationView struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	License   string `json:"license,omitempty"`
	Purchased bool   `json:"purchased"`
	Connected int    `json:"connected"`
	GuideURL  string `json:"setupGuide,omitempty"`
	// Suggested says why this integration matches the customer's cloud information, if it does.
	Suggested string `json:"suggestedBecause,omitempty"`
	// Fields lists what the credential form asks for (no values); sensitive ones are marked.
	Fields []IntegrationField `json:"fields,omitempty"`
}

type IntegrationField struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Required  bool   `json:"required"`
	Sensitive bool   `json:"sensitive"`
	Input     string `json:"input,omitempty"`
}

func fieldsOf(schema upstream.IntegrationSchema) []IntegrationField {
	required := map[string]bool{}
	for _, r := range schema.Credential.Required {
		required[r] = true
	}
	sensitive := map[string]bool{}
	for _, f := range schema.Credential.SensitiveFields {
		sensitive[f] = true
	}
	fields := make([]IntegrationField, 0, len(schema.Credential.Properties))
	order := map[string]int{}
	for name, p := range schema.Credential.Properties {
		if name == "expiry" {
			continue // optional credential expiry date; not needed to connect
		}
		order[name] = p.Order
		fields = append(fields, IntegrationField{Name: name, Label: p.DisplayName, Required: required[name], Sensitive: sensitive[name], Input: p.InputType})
	}
	sort.Slice(fields, func(i, j int) bool { return order[fields[i].Name] < order[fields[j].Name] })
	return fields
}

// integrationSchemas is cached for an hour: the catalog changes with releases, not per call.
func (s *Service) integrationSchemas(ctx context.Context, org upstream.Organization) ([]upstream.IntegrationSchema, error) {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemas != nil && s.now().Sub(s.schemasAt) < time.Hour {
		return s.schemas, nil
	}
	schemas, err := s.up.IntegrationSchemas(ctx, org.Pod, org.ID)
	if err != nil {
		return nil, err
	}
	s.schemas, s.schemasAt = schemas, s.now()
	return schemas, nil
}

func (s *Service) Integrations(ctx context.Context, orgID, nameContains string, withFields bool) ([]IntegrationView, Meta, error) {
	return s.integrations(ctx, orgID, nameContains, withFields, false)
}

// SuggestedIntegrations lists only the integrations that match the customer's cloud information
// ("here's what your Arctic Wolf team told me you run").
func (s *Service) SuggestedIntegrations(ctx context.Context, orgID string) ([]IntegrationView, Meta, error) {
	return s.integrations(ctx, orgID, "", true, true)
}

func (s *Service) integrations(ctx context.Context, orgID, nameContains string, withFields, suggestedOnly bool) ([]IntegrationView, Meta, error) {
	if s.up.IngestionEnabled() {
		return s.ingestionIntegrations(ctx, orgID, nameContains, withFields, suggestedOnly)
	}
	return s.rendallIntegrations(ctx, orgID, nameContains, withFields, suggestedOnly)
}

// rendallIntegrations is list_cloud_integrations from the Unified Portal catalog (Rendall).
func (s *Service) rendallIntegrations(ctx context.Context, orgID, nameContains string, withFields, suggestedOnly bool) ([]IntegrationView, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (secrets-schema v2, purchased-cloud-sensor-vendors, cloud-sensors)"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return nil, meta, err
	}
	schemas, err := s.integrationSchemas(ctx, org)
	if err != nil {
		return nil, meta, err
	}
	var purchased []string
	_ = s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/purchased-cloud-sensor-vendors", &purchased)
	bought := map[string]bool{}
	for _, p := range purchased {
		bought[p] = true
	}
	connected := map[string]int{}
	if clouds, err := s.allSensors(ctx, org, SensorKindCloud); err == nil {
		for _, c := range clouds {
			if c.Status == "healthy" {
				connected[c.Product]++
			}
		}
	} else {
		meta.Notes = append(meta.Notes, "connected counts unavailable: "+err.Error())
	}

	answers := s.cloudAnswers(ctx, org)
	if suggestedOnly && len(answers) == 0 {
		meta.Notes = append(meta.Notes, "No cloud information on record yet; ask which cloud services and endpoint tools they use (set_cloud_information).")
	}
	needle := strings.ToLower(strings.TrimSpace(nameContains))
	out := []IntegrationView{}
	for _, sc := range schemas {
		if needle != "" && !strings.Contains(strings.ToLower(sc.IntegrationName+" "+sc.DeploymentType), needle) {
			continue
		}
		why := suggestionFor(answers, sc)
		if suggestedOnly && why == "" {
			continue
		}
		v := IntegrationView{Type: sc.DeploymentType, Name: sc.IntegrationName, License: sc.LicenseModel,
			Purchased: bought[sc.DeploymentType] || bought[sc.LicenseName], Connected: connected[sc.DeploymentType], GuideURL: sc.SetupGuideURL, Suggested: why}
		if withFields {
			v.Fields = fieldsOf(sc)
		}
		out = append(out, v)
	}
	if len(out) > 25 && needle == "" {
		meta.Notes = append(meta.Notes, fmt.Sprintf("%d integrations; filter by name to see one with its form fields", len(out)))
	}
	return out, meta, nil
}

// --- Extra setup areas for the hub ---

// moreAreas adds the setup-hub areas beyond sites, sensors, cloud sensors, agents and log
// sources. Areas with no customer-facing API are reported as unknown with the reason.
func (s *Service) moreAreas(ctx context.Context, org upstream.Organization) []AreaStatus {
	areas := make([]AreaStatus, 6)
	var wg sync.WaitGroup
	run := func(i int, fn func() AreaStatus) {
		wg.Add(1)
		go func() { defer wg.Done(); areas[i] = fn() }()
	}
	run(0, func() AreaStatus {
		sso, _, err := s.SSOStatus(ctx, org.ID)
		if err != nil {
			return AreaStatus{Area: "single_sign_on", Status: "unknown", Error: err.Error()}
		}
		return AreaStatus{Area: "single_sign_on", Status: statusFromCount(len(sso)), Summary: map[string]int{"connections": len(sso)}}
	})
	run(1, func() AreaStatus {
		c, _, err := s.ContactsAndEscalation(ctx, org.ID, "", 1)
		if err != nil {
			return AreaStatus{Area: "contacts_and_escalation", Status: "unknown", Error: err.Error()}
		}
		st := "not_started"
		if c.ContactsTotal > 0 {
			st = "in_progress"
			if c.EscalationsTotal > 0 {
				st = "done"
			}
		}
		return AreaStatus{Area: "contacts_and_escalation", Status: st, Summary: map[string]any{"contacts": c.ContactsTotal, "escalationRules": c.EscalationsTotal, "onboardingTeam": c.OnboardingTeam}}
	})
	run(2, func() AreaStatus {
		var summary map[string]any
		if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/scanner-summary", &summary); err != nil {
			return AreaStatus{Area: "scanners", Status: "unknown", Error: err.Error()}
		}
		return summarise("scanners", summary)
	})
	run(3, func() AreaStatus {
		var cfg struct {
			Data map[string]any `json:"data"`
		}
		if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/cloud-service-configuration", &cfg); err != nil {
			return AreaStatus{Area: "what_you_run", Status: "unknown", Error: err.Error()}
		}
		return AreaStatus{Area: "what_you_run", Status: "done", Summary: cfg.Data}
	})
	areas[4] = AreaStatus{Area: "security_policies", Status: "unknown",
		Error: "restricted countries and other policies are not exposed by a customer-facing API yet (onboarding service / XConf)"}
	areas[5] = AreaStatus{Area: "cloud_scanner", Status: "unknown",
		Error: "cloud posture scanner status is served by the health-overview service, not wired into this preview"}
	wg.Wait()
	return areas
}

// --- MFA / mobile-app gate ---

// MFAStatus reports whether the signed-in user has completed MFA / app setup.
// Layer 1: Auth0 amr claim in the bearer JWT ("mfa" present = authenticated with MFA).
// Layer 2: Customer self-reported via the progress store (mfaConfigured flag).
type MFAStatus struct {
	// Configured is true if Layer 1 or Layer 2 confirms MFA is set up.
	Configured bool `json:"configured"`
	// Source is "auth0_amr" | "progress_store" | "not_configured".
	Source string `json:"source"`
}

// CheckMFAStatus returns the MFA gate state for the signed-in user.
// It never fails: network errors and missing claims fall through to "not_configured".
func (s *Service) CheckMFAStatus(ctx context.Context, orgID string) (MFAStatus, Meta) {
	meta := Meta{Sources: []string{"jwt_claims", "discovery (local progress store)"}}

	// Layer 1: decode the JWT payload and read the amr claim.
	if token, err := upstream.TokenFrom(ctx); err == nil {
		if amrOK := jwtHasMFA(token); amrOK {
			return MFAStatus{Configured: true, Source: "auth0_amr"}, meta
		}
	}

	// Layer 2: progress store self-report.
	if s.progress != nil {
		if progress, ok := s.progress.GetProgress(orgID); ok && progress.MFAConfigured {
			return MFAStatus{Configured: true, Source: "progress_store"}, meta
		}
	}

	return MFAStatus{Configured: false, Source: "not_configured"}, meta
}

// jwtHasMFA returns true when the JWT payload's amr claim contains "mfa".
// The JWT is not verified here (it was already verified by the Auth0 JWKS check upstream);
// we only decode the claims to read amr.
func jwtHasMFA(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		AMR []string `json:"amr"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	for _, method := range claims.AMR {
		if strings.EqualFold(method, "mfa") {
			return true
		}
	}
	return false
}
