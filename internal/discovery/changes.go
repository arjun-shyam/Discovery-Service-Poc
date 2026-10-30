package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Prepared changes (UC-03 "do it for me", ask before acting) ---
//
// The assistant never writes directly. prepare_change builds the exact Rendall request a
// change would send and returns it for the customer to confirm on a card; apply_change runs
// it only after that confirmation. apply_change sends the real request to Rendall once the
// customer confirms. Secret values (client secrets, API keys)
// never pass through the model: the confirm card posts them straight to this service, which
// keeps them in memory only and never returns them.

const (
	ChangeCreateSite      = "create_site"
	ChangeAddContact      = "add_contact"
	ChangeConfigureSSO    = "configure_sso"
	ChangeConnectCloudApp = "connect_cloud_app"
	changeTTL             = time.Hour
)

// Change status values.
const (
	ChangePrepared      = "prepared"            // waiting for the customer's confirmation
	ChangeNeedsSecrets  = "needs_secure_fields" // the confirm card must collect secret fields first
	ChangeDryRunNotSent = "dry_run_not_sent"    // confirmed, validated, deliberately not sent (legacy; left for reference)
	ChangeApplied       = "applied"             // sent to Arctic Wolf and accepted
	ChangeFailed        = "failed"              // sent but rejected by upstream
	ChangeCancelled     = "cancelled"
	redactedSecret      = "••••••"
)

var (
	ErrChangeNotFound = errors.New("change not found or expired")
	ErrChangeInvalid  = errors.New("change is not valid")
)

// ChangeDetail is one human-readable line on the confirm card.
type ChangeDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SecureField is a field the confirm card collects directly from the customer.
type SecureField struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
	// Sensitive fields are entered as passwords; all secure fields bypass the chat.
	Sensitive bool   `json:"sensitive"`
	Input     string `json:"input,omitempty"`
	Provided  bool   `json:"provided"`
}

type Change struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Status  string         `json:"status"`
	Title   string         `json:"title"`
	Details []ChangeDetail `json:"details"`
	Method  string         `json:"method"`
	Path    string         `json:"path"`
	// Body is the request body with secret values redacted.
	Body         map[string]any `json:"body"`
	SecureFields []SecureField  `json:"secureFields,omitempty"`
	Assumptions  []string       `json:"assumptions,omitempty"`
	DryRun       bool           `json:"dryRun"`
	CreatedAt    time.Time      `json:"createdAt"`
	AppliedAt    *time.Time     `json:"appliedAt,omitempty"`
	// Error is Arctic Wolf's reason when a confirmed change was rejected.
	Error string `json:"error,omitempty"`
	// Reference is a record created for the change (e.g. the support ticket URL).
	Reference string `json:"reference,omitempty"`
	// Outcome is a one-line result for the customer, for changes with more than one step.
	Outcome string `json:"outcome,omitempty"`

	orgID   string
	service string // "" = Rendall; "ingestion" = ingestion orchestrator
	secrets map[string]string
	parser  *parserTarget
}

type changeStore struct {
	mu sync.Mutex
	m  map[string]*Change
}

func newChangeID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "chg_" + hex.EncodeToString(b)
}

func (c *changeStore) put(ch *Change) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*Change{}
	}
	for id, old := range c.m {
		if time.Since(old.CreatedAt) > changeTTL {
			delete(c.m, id)
		}
	}
	c.m[ch.ID] = ch
}

// with runs fn on the stored change for this org under the store lock.
func (c *changeStore) with(orgID, id string, fn func(*Change) error) (Change, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[id]
	if !ok || ch.orgID != orgID || time.Since(ch.CreatedAt) > changeTTL {
		return Change{}, ErrChangeNotFound
	}
	if err := fn(ch); err != nil {
		return *ch, err
	}
	return *ch, nil
}

func str(params map[string]string, key string) string { return strings.TrimSpace(params[key]) }

func list(params map[string]string, key string) []string {
	out := []string{}
	for _, part := range strings.Split(params[key], ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func missing(params map[string]string, keys ...string) []string {
	var out []string
	for _, k := range keys {
		if str(params, k) == "" {
			out = append(out, k)
		}
	}
	return out
}

func validTimezone(tz string) bool {
	_, err := time.LoadLocation(tz)
	return tz != "" && err == nil
}

// PrepareChange builds a change for the customer to confirm. params are plain strings;
// list values are comma separated. Nothing is sent.
func (s *Service) PrepareChange(ctx context.Context, orgID, kind string, params map[string]string) (Change, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall api_spec (request shape)"}, FetchedAt: s.now(),
		UntrustedFields: []string{"details[].value", "body"},
		Notes:           []string{"Preview: nothing has been sent yet. Show the customer the card and wait for them to confirm."}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return Change{}, meta, err
	}
	ch := &Change{ID: newChangeID(), Kind: kind, Status: ChangePrepared, DryRun: false, CreatedAt: s.now(), orgID: org.ID, secrets: map[string]string{}}
	if err := s.checkPermission(ctx, org, kind); err != nil {
		return Change{}, meta, err
	}
	miss, handled, err := s.prepareOnboarding(ctx, org, ch, kind, params)
	if err == nil && !handled {
		miss, handled, err = s.prepareDevices(ctx, org, ch, kind, params)
	}
	if err == nil && !handled {
		miss, handled, err = s.prepareManage(ctx, org, ch, kind, params)
	}
	if err == nil && !handled {
		miss, handled, err = s.prepareIngestion(ctx, org, ch, kind, params)
	}
	if err == nil && !handled {
		miss, handled, err = s.prepareCloud(ctx, org, ch, kind, params)
	}
	if err == nil && !handled {
		miss, handled, err = s.prepareRequests(ctx, org, ch, kind, params)
	}
	if err == nil && !handled {
		miss, handled, err = s.prepareCSPM(ctx, org, ch, kind, params)
	}
	if err != nil {
		return Change{}, meta, err
	}
	switch {
	case handled:
	case kind == ChangeConfigureSSO:
		miss = missing(params, "issuer_url", "client_id", "domains")
		if u, err := url.Parse(str(params, "issuer_url")); str(params, "issuer_url") != "" && (err != nil || u.Scheme != "https") {
			return Change{}, meta, fmt.Errorf("%w: issuer_url must be an https URL", ErrChangeInvalid)
		}
		ch.Title = "Turn on single sign-on for " + strings.Join(list(params, "domains"), ", ")
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/federated-authentication"
		ch.Body = map[string]any{"issuerUrl": str(params, "issuer_url"), "clientId": str(params, "client_id"), "clientSecret": redactedSecret, "domainNames": list(params, "domains")}
		ch.SecureFields = []SecureField{{Name: "clientSecret", Label: "Client secret", Required: true, Sensitive: true}}
		ch.Details = []ChangeDetail{{"Identity provider", str(params, "issuer_url")}, {"Client ID", str(params, "client_id")}, {"Email domains", strings.Join(list(params, "domains"), ", ")}}

	case kind == ChangeConnectCloudApp:
		// TODO(citl): once CITL is running, high-risk cloud-app connections (e.g. CrowdStrike,
		// M365) should route through CITL for out-of-band approval before calling ApplyChange.
		// Flow: PrepareChange → POST http://127.0.0.1:8080/v1/aurora/requests with callback_url
		// pointing at Discovery's /v1/orgs/{org}/changes/{id}/callback → CITL notifies approver
		// (Slack, mobile, or aurora_portal) → on approval Discovery calls ApplyChange internally.
		miss = missing(params, "type", "name")
		var schema *upstream.IntegrationSchema
		if t := str(params, "type"); t != "" {
			schemas, err := s.integrationSchemas(ctx, org)
			if err != nil {
				return Change{}, meta, err
			}
			for i := range schemas {
				if schemas[i].DeploymentType == t {
					schema = &schemas[i]
				}
			}
			if schema == nil {
				return Change{}, meta, fmt.Errorf("%w: unknown integration type %q; use list_cloud_integrations", ErrChangeInvalid, t)
			}
			if strings.EqualFold(schema.LicenseModel, "PREMIUM") && !s.cloudPurchased(ctx, org, *schema) {
				return Change{}, meta, fmt.Errorf("%w: %s is a premium integration this organization hasn't purchased, so it can't be connected yet. "+
					"Offer to request a quote (prepare_change request_cloud_quote {type: %s}); Arctic Wolf replies on the ticket", ErrChangeInvalid, schema.IntegrationName, schema.DeploymentType)
			}
		}
		ch.Title = "Connect " + str(params, "name")
		ch.Method, ch.Path = "POST", "/api/v2/organizations/"+org.ID+"/cloud-sensors"
		secrets := map[string]any{}
		if schema != nil {
			ch.Title = "Connect " + schema.IntegrationName + " (" + str(params, "name") + ")"
			for _, f := range fieldsOf(*schema) {
				// Every credential field is collected on the secure card, sensitive or not.
				ch.SecureFields = append(ch.SecureFields, SecureField{Name: f.Name, Label: f.Label, Required: f.Required, Sensitive: f.Sensitive, Input: f.Input})
				secrets[f.Name] = redactedSecret
			}
			ch.Details = []ChangeDetail{{"Integration", schema.IntegrationName}, {"Name in Arctic Wolf", str(params, "name")}, {"Setup guide", schema.SetupGuideURL}}
		}
		ch.Body = map[string]any{"name": str(params, "name"), "type": str(params, "type"), "secrets": secrets}
		if exp := str(params, "expiry"); exp != "" {
			t, err := time.Parse("2006-01-02", exp)
			if err != nil || !t.After(s.now()) {
				return Change{}, meta, fmt.Errorf("%w: expiry must be a future date like 2027-06-30 (when these credentials stop working)", ErrChangeInvalid)
			}
			ch.Body["expiry"] = t.UTC().Format(time.RFC3339)
			ch.Details = append(ch.Details, ChangeDetail{"Credentials expire", exp + " (Arctic Wolf warns before then)"})
		}
		ch.Assumptions = []string{"Credentials are checked by the integration itself after the cloud sensor is created; its health shows in Cloud sensors."}

	default:
		return Change{}, meta, fmt.Errorf("%w: unknown kind %q (create_site, add_contact, set_executive_sponsor, set_deployment_contacts, set_escalation_contacts, set_endpoint_counts, set_cloud_information, set_location_alerts, set_internet_exposure, request_sensor, request_scanner, activate_appliance, create_scan_schedule, configure_sso, connect_cloud_app, set_log_source_parser, move_sensor_site, decommission_sensor, update_scanner_settings, update_scanner_network, decommission_scanner, pause_scan_schedule, delete_scan_schedule, scan_now, tag_log_sources, untag_log_sources, update_site, delete_site, request_cloud_quote, update_cloud_credentials, remove_cloud_app, request_licences, connect_cloud_scanner, remove_cloud_scanner)", ErrChangeInvalid, kind)
	}
	if len(miss) > 0 {
		return Change{}, meta, fmt.Errorf("%w: missing %s; ask the customer for them (an aurora-form works well)", ErrChangeInvalid, strings.Join(miss, ", "))
	}
	if len(ch.SecureFields) > 0 {
		ch.Status = ChangeNeedsSecrets
	}
	s.changes.put(ch)
	return *ch, meta, nil
}

// SetChangeSecrets stores secure-card values for a change. Values stay in memory only and
// are never returned; unknown field names are rejected.
func (s *Service) SetChangeSecrets(ctx context.Context, orgID, id string, values map[string]string) (Change, Meta, error) {
	meta := Meta{Sources: []string{"secure card"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return Change{}, meta, err
	}
	ch, err := s.changes.with(org.ID, id, func(ch *Change) error {
		if ch.Status != ChangeNeedsSecrets && ch.Status != ChangePrepared {
			return fmt.Errorf("%w: change is %s", ErrChangeInvalid, ch.Status)
		}
		known := map[string]int{}
		for i, f := range ch.SecureFields {
			known[f.Name] = i
		}
		for name, value := range values {
			i, ok := known[name]
			if !ok {
				return fmt.Errorf("%w: %q is not a field of this change", ErrChangeInvalid, name)
			}
			if strings.TrimSpace(value) != "" {
				ch.secrets[name] = value
				ch.SecureFields[i].Provided = true
			}
		}
		for _, f := range ch.SecureFields {
			if f.Required && !f.Provided {
				return nil // still waiting for required fields
			}
		}
		ch.Status = ChangePrepared
		return nil
	})
	return ch, meta, err
}

// GetChange returns a change (secrets redacted) for the confirm card.
func (s *Service) GetChange(ctx context.Context, orgID, id string) (Change, Meta, error) {
	meta := Meta{Sources: []string{"prepared changes"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return Change{}, meta, err
	}
	ch, err := s.changes.with(org.ID, id, func(*Change) error { return nil })
	return ch, meta, err
}

// parseRendallPath extracts the API version, orgID and suffix from a prepared change path
// like /api/v2/organizations/{uuid}/sites → version="v2", orgID="{uuid}", suffix="/sites".
func parseRendallPath(path string) (version, orgID, suffix string, ok bool) {
	// path is /api/{version}/organizations/{uuid}{suffix}
	prefix := "/api/"
	if !strings.HasPrefix(path, prefix) {
		return
	}
	rest := path[len(prefix):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return
	}
	version = rest[:slash]
	rest = rest[slash+1:] // "organizations/{uuid}{suffix}"
	if !strings.HasPrefix(rest, "organizations/") {
		return
	}
	rest = rest[len("organizations/"):]
	slash = strings.Index(rest, "/")
	if slash < 0 {
		orgID = rest
		suffix = ""
	} else {
		orgID = rest[:slash]
		suffix = rest[slash:]
	}
	ok = true
	return
}

// ApplyChange sends a confirmed change to Arctic Wolf.
func (s *Service) ApplyChange(ctx context.Context, orgID, id string, cancel bool) (Change, Meta, error) {
	meta := Meta{Sources: []string{"prepared changes", "rendall"}, FetchedAt: s.now()}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return Change{}, meta, err
	}

	// First pass: validate state and mark in-flight (cancel handled inline).
	var snapshot Change
	snapshot, err = s.changes.with(org.ID, id, func(ch *Change) error {
		switch {
		case cancel:
			ch.Status = ChangeCancelled
			return nil
		case ch.Status == ChangeNeedsSecrets:
			var waiting []string
			for _, f := range ch.SecureFields {
				if f.Required && !f.Provided {
					waiting = append(waiting, f.Label)
				}
			}
			sort.Strings(waiting)
			return fmt.Errorf("%w: waiting for the secure card: %s", ErrChangeInvalid, strings.Join(waiting, ", "))
		case ch.Status != ChangePrepared:
			return fmt.Errorf("%w: change is already %s", ErrChangeInvalid, ch.Status)
		}
		return nil
	})
	if err != nil || snapshot.Status == ChangeCancelled {
		return snapshot, meta, err
	}

	snapshot, _ = s.changes.with(org.ID, id, func(ch *Change) error { return nil })
	if snapshot.Kind == ChangeSetLogSourceParser {
		ref, outcome, applyErr := s.applyParserChange(ctx, org, snapshot)
		ch, _ := s.changes.with(org.ID, id, func(ch *Change) error {
			now := s.now()
			ch.AppliedAt = &now
			ch.Reference, ch.Outcome = ref, outcome
			if applyErr != nil {
				ch.Status, ch.Error = ChangeFailed, applyErr.Error()
				return nil
			}
			ch.Status = ChangeApplied
			return nil
		})
		if applyErr != nil {
			log.Printf("apply_change %s %s failed: %v", ch.ID, ch.Kind, applyErr)
			return ch, meta, nil
		}
		invalidateChecklist(org.ID)
		meta.Notes = []string{outcome}
		return ch, meta, nil
	}

	// Build the body with real secret values merged in (never mutate ch.Body which the card shows).
	sendBody := make(map[string]any, len(snapshot.Body))
	for k, v := range snapshot.Body {
		sendBody[k] = v
	}
	// Cloud apps nest credentials under "secrets" (Rendall) or "credential" (ingestion
	// orchestrator); others (configure_sso clientSecret) are top-level fields.
	nestedKey := ""
	for _, k := range []string{"secrets", "credential"} {
		if _, ok := sendBody[k].(map[string]any); ok {
			nestedKey = k
		}
	}
	if nestedKey == "" {
		for name, secret := range snapshot.secrets {
			sendBody[name] = secret
		}
	} else {
		inner := sendBody[nestedKey].(map[string]any)
		merged := make(map[string]any, len(inner))
		for k, v := range inner {
			if v == redactedSecret {
				continue // a field left empty on the card isn't sent
			}
			merged[k] = v
		}
		for name, secret := range snapshot.secrets {
			merged[name] = secret
		}
		sendBody[nestedKey] = merged
	}

	if snapshot.service == serviceIngestion || snapshot.service == serviceCMS {
		var body any = sendBody
		if snapshot.Body == nil {
			body = nil
		}
		var sendErr error
		if snapshot.service == serviceCMS {
			sendErr = s.up.CMSDo(ctx, snapshot.Method, org.Pod, snapshot.Path, body, nil)
		} else {
			sendErr = s.up.IngestionDo(ctx, snapshot.Method, org.Pod, snapshot.Path, body, nil)
		}
		ch, _ := s.changes.with(org.ID, id, func(ch *Change) error {
			now := s.now()
			ch.AppliedAt = &now
			if sendErr != nil {
				ch.Status, ch.Error = ChangeFailed, sendErr.Error()
				return nil
			}
			ch.Status = ChangeApplied
			return nil
		})
		if sendErr != nil {
			log.Printf("apply_change %s %s %s %s failed: %v", ch.ID, ch.Kind, ch.Method, ch.Path, sendErr)
			meta.Notes = []string{"Arctic Wolf returned an error; nothing was changed. If it is about the credentials, the customer can fix them and try again."}
			return ch, meta, nil
		}
		invalidateChecklist(org.ID)
		meta.Notes = []string{"Change sent to Arctic Wolf and accepted. Next: tell the customer what it switched on (get_detections_for_source integration=<type>)."}
		return ch, meta, nil
	}

	version, pathOrgID, suffix, pathOK := parseRendallPath(snapshot.Path)
	if !pathOK {
		return snapshot, meta, fmt.Errorf("change has invalid path %q", snapshot.Path)
	}
	_ = pathOrgID // path already carries the org from PrepareChange; use org.Pod for routing

	var sendErr error
	switch snapshot.Method {
	case "POST":
		sendErr = s.up.RendallOrgPost(ctx, org.Pod, org.ID, version, suffix, sendBody, nil)
	case "PUT":
		sendErr = s.up.RendallOrgPut(ctx, org.Pod, org.ID, version, suffix, sendBody, nil)
	case "PATCH", "DELETE":
		var body any = sendBody
		if snapshot.Body == nil {
			body = nil
		}
		sendErr = s.up.RendallOrgDo(ctx, snapshot.Method, org.Pod, org.ID, version, suffix, body, nil)
	default:
		sendErr = fmt.Errorf("unsupported method %q", snapshot.Method)
	}

	// Rendall may save a contact and then fail on a later step; check before reporting a failure.
	savedDespiteError := ""
	if sendErr != nil && snapshot.Kind == ChangeAddContact {
		if email := contactEmailOf(snapshot.Body); email != "" {
			if _, found := s.contactWithEmail(ctx, org, email); found {
				savedDespiteError = sendErr.Error()
				log.Printf("apply_change %s add_contact: Rendall returned an error but the contact exists: %v", snapshot.ID, sendErr)
				sendErr = nil
			}
		}
	}

	var ch Change
	ch, err = s.changes.with(org.ID, id, func(ch *Change) error {
		now := s.now()
		if savedDespiteError != "" {
			ch.Outcome = "The contact was added. Arctic Wolf reported an error after saving it (" + savedDespiteError + "), so check the contact's portal invitation and details."
		}
		if sendErr != nil {
			ch.Status = ChangeFailed
			ch.AppliedAt = &now
			ch.Error = sendErr.Error()
			return nil
		}
		ch.Status = ChangeApplied
		ch.AppliedAt = &now
		return nil
	})
	if sendErr != nil {
		log.Printf("apply_change %s %s %s %s failed: %v", snapshot.ID, snapshot.Kind, snapshot.Method, snapshot.Path, sendErr)
		meta.Notes = []string{"Arctic Wolf returned an error; the change was not applied."}
		if strings.Contains(sendErr.Error(), "must be a contact of the organization") {
			meta.Notes = append(meta.Notes, "Arctic Wolf only accepts this from a person listed as a contact of the organization. Ask a customer contact to do it, or have them add you as a contact first.")
		}
		return ch, meta, nil
	}
	invalidateChecklist(orgID)
	invalidateChecklist(org.ID)
	meta.Notes = []string{"Change sent to Arctic Wolf and accepted."}
	return ch, meta, err
}

// contactEmailOf returns the work email from an add_contact request body.
func contactEmailOf(body any) string {
	b, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	if emails, ok := b["emailAddresses"].([]map[string]any); ok && len(emails) > 0 {
		return fmt.Sprint(emails[0]["email"])
	}
	return ""
}
