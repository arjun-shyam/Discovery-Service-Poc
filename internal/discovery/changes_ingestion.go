package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Cloud apps through the ingestion orchestrator (Aurora Integrations) ---
//
// Aurora's Integrations page connects and changes cloud apps through the ingestion orchestrator
// (rtkwlf/ingestion-orchestrator api/openapi.yaml), so going the same way keeps one state: the same
// catalog (licensed, schema form), health with a call to action (UPDATE_CREDENTIALS, FINISH_SETUP…)
// and the SETUP_COMPLETE flag behind "Resume Setup" (aurora-ui-platform#2342).
//   connect_cloud_app        POST   /customers/{org}/integration/{type}/sensor            {name, credential}
//   update_cloud_credentials PUT    /customers/{org}/integration/{type}/sensor/{sensor_id} {name, credential}
//   remove_cloud_app         DELETE /customers/{org}/integration/{type}/sensor/{sensor_id}
// The orchestrator checks the credentials while provisioning, so a wrong secret comes back as the
// apply error (the "Test" step).

const serviceIngestion = "ingestion"

type ingestionIntegration struct {
	Type           string `json:"integration_type"`
	Name           string `json:"display_name"`
	GuideURL       string `json:"setup_guide_url"`
	ConnectionType string `json:"connection_type"`
	LicenseModel   string `json:"license_model"`
	Licensed       bool   `json:"licensed"`
	Schema         struct {
		Properties map[string]struct {
			DisplayName string `json:"displayName"`
			Order       int    `json:"order"`
			InputType   string `json:"inputType"`
			Required    bool   `json:"required"`
			Sensitive   bool   `json:"sensitive"`
			Editable    *bool  `json:"editable"`
		} `json:"properties"`
	} `json:"credential_schema"`
}

func (i ingestionIntegration) fields() []IntegrationField {
	out := []IntegrationField{}
	order := map[string]int{}
	for name, p := range i.Schema.Properties {
		if name == "expiry" {
			continue
		}
		order[name] = p.Order
		out = append(out, IntegrationField{Name: name, Label: orDefault(p.DisplayName, name), Required: p.Required, Sensitive: p.Sensitive, Input: p.InputType})
	}
	sort.Slice(out, func(a, b int) bool { return order[out[a].Name] < order[out[b].Name] })
	return out
}

type ingestionDeployment struct {
	ID             string `json:"deployment_id"`
	Type           string `json:"integration_type"`
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	ConnectionType string `json:"connection_type"`
	ExtendedHealth struct {
		State    string `json:"state"`
		Statuses []struct {
			Status       string `json:"status"`
			Severity     string `json:"severity"`
			CallToAction string `json:"call_to_action"`
		} `json:"statuses"`
	} `json:"extended_health"`
}

func (s *Service) ingestionCatalog(ctx context.Context, org upstream.Organization) ([]ingestionIntegration, error) {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if c, ok := s.ingestionCache[org.ID]; ok && s.now().Sub(c.at) < time.Hour {
		return c.items, nil
	}
	var items []ingestionIntegration
	if err := s.up.IngestionDo(ctx, "GET", org.Pod, "/customers/"+url.PathEscape(org.ID)+"/available-integrations", nil, &items); err != nil {
		return nil, err
	}
	if s.ingestionCache == nil {
		s.ingestionCache = map[string]ingestionCatalogEntry{}
	}
	s.ingestionCache[org.ID] = ingestionCatalogEntry{items: items, at: s.now()}
	return items, nil
}

type ingestionCatalogEntry struct {
	items []ingestionIntegration
	at    time.Time
}

func (s *Service) ingestionIntegration(ctx context.Context, org upstream.Organization, typ string) (ingestionIntegration, error) {
	items, err := s.ingestionCatalog(ctx, org)
	if err != nil {
		return ingestionIntegration{}, fmt.Errorf("could not read the integration catalog: %w", err)
	}
	for _, it := range items {
		if strings.EqualFold(it.Type, typ) {
			return it, nil
		}
	}
	return ingestionIntegration{}, fmt.Errorf("%w: unknown integration type %q; use list_cloud_integrations", ErrChangeInvalid, typ)
}

func (s *Service) ingestionDeployments(ctx context.Context, org upstream.Organization) ([]ingestionDeployment, error) {
	var out []ingestionDeployment
	err := s.up.IngestionDo(ctx, "GET", org.Pod, "/customers/"+url.PathEscape(org.ID)+"/sensors", nil, &out)
	return out, err
}

// ingestionUsable says whether the ingestion orchestrator serves this org for this user. A 403
// (the gateway or orchestrator refusing this login) falls back to the Unified Portal path.
func (s *Service) ingestionUsable(ctx context.Context, org upstream.Organization) bool {
	if !s.up.IngestionEnabled() {
		return false
	}
	_, err := s.ingestionCatalog(ctx, org)
	var ue *upstream.Error
	if errors.As(err, &ue) && (ue.Status == 403 || ue.Status == 401 || ue.Status == 404) {
		return false
	}
	return true
}

// prepareIngestion handles the cloud-app kinds when the ingestion orchestrator is configured.
func (s *Service) prepareIngestion(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	if kind != ChangeConnectCloudApp && kind != ChangeUpdateCloudCredentials && kind != ChangeRemoveCloudApp {
		return nil, false, nil
	}
	if !s.ingestionUsable(ctx, org) {
		return nil, false, nil
	}
	switch kind {
	case ChangeConnectCloudApp:
		if miss = missing(params, "type", "name"); len(miss) > 0 {
			return miss, true, nil
		}
		it, err := s.ingestionIntegration(ctx, org, str(params, "type"))
		if errors.Is(err, ErrChangeInvalid) {
			// Not an Aurora Integrations type (e.g. the AWS / Azure appliance VM accounts
			// vsensor_ami, azure_vm_subid): those are Unified Portal cloud sensors.
			return nil, false, nil
		}
		if err != nil {
			return nil, true, err
		}
		if !it.Licensed && !strings.EqualFold(it.LicenseModel, "INCLUDED") {
			return nil, true, fmt.Errorf("%w: %s isn't licensed for this organization (%s), so it can't be connected yet. Offer to request a quote (prepare_change request_cloud_quote {type: %s})", ErrChangeInvalid, it.Name, strings.ToLower(it.LicenseModel), it.Type)
		}
		if it.ConnectionType == "WEBHOOK" {
			return nil, true, fmt.Errorf("%w: %s is a webhook integration: connecting it returns a webhook URL and token that must be shown once on the Aurora Integrations page (Add), not in chat", ErrChangeInvalid, it.Name)
		}
		credential := map[string]any{}
		for _, f := range it.fields() {
			ch.SecureFields = append(ch.SecureFields, SecureField{Name: f.Name, Label: f.Label, Required: f.Required, Sensitive: f.Sensitive, Input: f.Input})
			credential[f.Name] = redactedSecret
		}
		ch.Title = "Connect " + it.Name + " (" + str(params, "name") + ")"
		ch.service = serviceIngestion
		ch.Method, ch.Path = "POST", "/customers/"+org.ID+"/integration/"+url.PathEscape(it.Type)+"/sensor"
		ch.Body = map[string]any{"name": str(params, "name"), "credential": credential}
		ch.Details = []ChangeDetail{{"Integration", it.Name}, {"Name in Arctic Wolf", str(params, "name")}, {"Setup guide", it.GuideURL}}
		if exp := str(params, "expiry"); exp != "" {
			t, err := time.Parse("2006-01-02", exp)
			if err != nil || !t.After(s.now()) {
				return nil, true, fmt.Errorf("%w: expiry must be a future date like 2027-06-30 (when these credentials stop working)", ErrChangeInvalid)
			}
			credential["expiry"] = t.UTC().Format(time.RFC3339)
			ch.Details = append(ch.Details, ChangeDetail{"Credentials expire", exp + " (Arctic Wolf warns before then)"})
		}
		ch.Assumptions = []string{"Same as Add on the Aurora Integrations page. Arctic Wolf checks the credentials while connecting; if they're wrong, the reason comes back and nothing is created."}
		return nil, true, nil

	case ChangeUpdateCloudCredentials, ChangeRemoveCloudApp:
		if miss = missing(params, "cloud_app"); len(miss) > 0 {
			return miss, true, nil
		}
		deps, err := s.ingestionDeployments(ctx, org)
		if err != nil {
			return nil, true, fmt.Errorf("could not read cloud apps: %w", err)
		}
		want := str(params, "cloud_app")
		var dep *ingestionDeployment
		for i, d := range deps {
			if strings.EqualFold(d.ID, want) || strings.EqualFold(d.Name, want) || strings.EqualFold(d.DisplayName, want) {
				dep = &deps[i]
			}
		}
		if dep == nil {
			return nil, true, fmt.Errorf("%w: cloud app %q not found; use list_cloud_apps", ErrChangeInvalid, want)
		}
		path := "/customers/" + org.ID + "/integration/" + url.PathEscape(dep.Type) + "/sensor/" + url.PathEscape(dep.ID)
		ident := []ChangeDetail{{"Cloud app", orDefault(dep.Name, dep.DisplayName)}, {"Integration", dep.Type}, {"Health", orDefault(dep.ExtendedHealth.State, "unknown")}}
		ch.service = serviceIngestion
		if kind == ChangeRemoveCloudApp {
			ch.Title = "Remove cloud app " + orDefault(dep.Name, dep.DisplayName)
			ch.Method, ch.Path, ch.Body = "DELETE", path, nil
			ch.Details = append(ident, ChangeDetail{"Effect", "Arctic Wolf stops collecting this app's logs and deletes its stored credentials"})
			ch.Assumptions = []string{"Same as Delete on the Aurora Integrations page. To undo, connect the app again."}
			return nil, true, nil
		}
		it, err := s.ingestionIntegration(ctx, org, dep.Type)
		if err != nil {
			return nil, true, err
		}
		credential := map[string]any{}
		for _, f := range it.fields() {
			ch.SecureFields = append(ch.SecureFields, SecureField{Name: f.Name, Label: f.Label, Required: f.Required, Sensitive: f.Sensitive, Input: f.Input})
			credential[f.Name] = redactedSecret
		}
		ch.Title = "Update credentials for " + orDefault(dep.Name, dep.DisplayName)
		ch.Method, ch.Path = "PUT", path
		ch.Body = map[string]any{"name": orDefault(dep.Name, dep.DisplayName), "credential": credential}
		ch.Details = append(ident, ChangeDetail{"Setup guide", it.GuideURL})
		ch.Assumptions = []string{"Same as Update credentials on the Aurora Integrations page. Arctic Wolf checks the new credentials; health updates within minutes."}
		return nil, true, nil
	}
	return nil, false, nil
}

// CloudApp is a connected cloud app with its health and what the customer should do next.
type CloudApp struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Integration string   `json:"integration"`
	Connection  string   `json:"connectionType,omitempty"`
	Health      string   `json:"health"`
	Actions     []string `json:"actions,omitempty"`
}

var callToAction = map[string]string{
	"UPDATE_CREDENTIALS":            "credentials are failing: update them (update_cloud_credentials)",
	"UPDATE_TOKEN":                  "the token needs renewing (update_cloud_credentials)",
	"FINISH_SETUP":                  "setup isn't finished: resume it (update_cloud_credentials, or Resume Setup on the Integrations page)",
	"CHECK_CLOUD_APP_CONFIGURATION": "check the app's configuration in the vendor console (setup guide)",
	"UPGRADE_CLOUD_APP_LICENSE":     "the vendor licence doesn't include the needed logs: upgrade it with the vendor",
	"CONTACT_ARCTIC_WOLF":           "Arctic Wolf needs to look at it: contact the Concierge team",
}

// CloudApps lists the organization's cloud apps from the ingestion orchestrator with health and the
// next step for each, as on the Aurora Integrations page.
func (s *Service) CloudApps(ctx context.Context, orgID string) ([]CloudApp, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "ingestion-orchestrator sensors"}, FetchedAt: s.now(), UntrustedFields: []string{"[].name"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return nil, meta, err
	}
	if !s.ingestionUsable(ctx, org) {
		// Unified Portal path: Rendall cloud sensors (health = status, no call to action).
		rows, err := s.up.CloudSensors(ctx, org.Pod, org.ID)
		if err != nil {
			return nil, meta, fmt.Errorf("could not read cloud apps: %w", err)
		}
		meta.Sources = []string{"eloc", "rendall cloud-sensors"}
		out := []CloudApp{}
		for _, r := range rows {
			app := CloudApp{ID: r.DeploymentID, Name: r.Name, Integration: orDefault(r.Type, r.Vendor), Health: r.Status}
			if r.Status == "invalidCredentials" {
				app.Actions = []string{callToAction["UPDATE_CREDENTIALS"]}
			}
			out = append(out, app)
		}
		return out, meta, nil
	}
	deps, err := s.ingestionDeployments(ctx, org)
	if err != nil {
		return nil, meta, fmt.Errorf("could not read cloud apps: %w", err)
	}
	out := []CloudApp{}
	for _, d := range deps {
		app := CloudApp{ID: d.ID, Name: orDefault(d.Name, d.DisplayName), Integration: d.Type, Connection: d.ConnectionType, Health: orDefault(d.ExtendedHealth.State, "unknown")}
		for _, st := range d.ExtendedHealth.Statuses {
			if a := callToAction[st.CallToAction]; a != "" && !contains(app.Actions, a) {
				app.Actions = append(app.Actions, a)
			}
		}
		out = append(out, app)
	}
	return out, meta, nil
}

// ingestionIntegrations is list_cloud_integrations from the Aurora Integrations catalog.
func (s *Service) ingestionIntegrations(ctx context.Context, orgID, nameContains string, withFields, suggestedOnly bool) ([]IntegrationView, Meta, error) {
	if org, err := s.resolve(ctx, orgID); err == nil && !s.ingestionUsable(ctx, org) {
		return s.rendallIntegrations(ctx, orgID, nameContains, withFields, suggestedOnly)
	}
	meta := Meta{Sources: []string{"eloc", "ingestion-orchestrator available-integrations, sensors", "rendall cloud-service-configuration"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return nil, meta, err
	}
	items, err := s.ingestionCatalog(ctx, org)
	if err != nil {
		return nil, meta, fmt.Errorf("could not read the integration catalog: %w", err)
	}
	connected := map[string]int{}
	if deps, err := s.ingestionDeployments(ctx, org); err == nil {
		for _, d := range deps {
			connected[d.Type]++
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
	for _, it := range items {
		if it.ConnectionType == "ACTIVE_RESPONSE" || it.ConnectionType == "SYSLOG" {
			continue // response connectors and syslog sources aren't cloud log apps
		}
		if needle != "" && !strings.Contains(strings.ToLower(it.Name+" "+it.Type), needle) {
			continue
		}
		why := suggestionForName(answers, it.Name+" "+it.Type)
		if suggestedOnly && why == "" {
			continue
		}
		v := IntegrationView{Type: it.Type, Name: it.Name, License: it.LicenseModel, Purchased: it.Licensed || strings.EqualFold(it.LicenseModel, "INCLUDED"),
			Connected: connected[it.Type], GuideURL: it.GuideURL, Suggested: why}
		if withFields {
			v.Fields = it.fields()
		}
		out = append(out, v)
	}
	// Unified Portal-only cloud sensors (AWS / Azure appliance VM accounts…) are listed too.
	if rendall, _, err := s.rendallIntegrations(ctx, orgID, nameContains, withFields, suggestedOnly); err == nil {
		have := map[string]bool{}
		for _, v := range out {
			have[strings.ToLower(v.Type)] = true
		}
		for _, v := range rendall {
			if !have[strings.ToLower(v.Type)] {
				out = append(out, v)
			}
		}
	}
	if len(out) > 25 && needle == "" && !suggestedOnly {
		meta.Notes = append(meta.Notes, fmt.Sprintf("%d integrations; filter by name to see one with its form fields", len(out)))
		out = out[:25]
	}
	return out, meta, nil
}
