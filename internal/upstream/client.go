// Package upstream calls existing Arctic Wolf services on behalf of the signed-in user.
// Every call forwards the caller's own Auth0 bearer token; this service never holds a
// service credential, so it can only see what the user can see.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds the upstream endpoints. RendallURLTemplate contains one %s for the pod (e.g. "us001").
type Config struct {
	ElocURL            string
	RendallURLTemplate string
	// ASAURLTemplate is production ASA behind the gateway; %s = pod.
	ASAURLTemplate string
	// LSSURLTemplate is the Log Source Service inside the pod's VPC; %s = pod. Reachable from
	// a laptop only on the Production employee VPN. Empty disables LSS (Rendall is used).
	LSSURLTemplate string
	// OnboardingURLTemplate is the onboarding service (onboarding-go) inside the pod's VPC; %s = pod.
	// Same network rules as LSS. Empty disables it.
	OnboardingURLTemplate string
	// LSOURLTemplate is the Log Source Orchestrator behind the managed API gateway; %s = pod.
	// Empty means LSO isn't available and parser changes go to Arctic Wolf staff as a ticket.
	LSOURLTemplate string
	// IngestionURLTemplate is the ingestion orchestrator (Aurora Integrations) behind the managed
	// gateway, including /api/v1; %s = pod. Empty disables it (cloud apps use Rendall cloud sensors).
	IngestionURLTemplate string
	// CMSURLTemplate is the Credential Management Service behind the managed gateway (cloud scanner /
	// CSPM accounts, as the Unified Portal Cloud Scanners page); %s = pod. Empty disables it.
	CMSURLTemplate string
	// DetectionURL is the detection catalog (detection-service) behind the global managed gateway.
	DetectionURL string
	Timeout      time.Duration
}

// Client is a thin read-only HTTP client for ELOC, Rendall and LSS.
type Client struct {
	cfg  Config
	http *http.Client
	// lss fails fast when the VPC isn't reachable (VPN off) so callers can fall back.
	lss *http.Client
}

func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	lssTransport := http.DefaultTransport.(*http.Transport).Clone()
	lssTransport.DialContext = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
		lss:  &http.Client{Timeout: cfg.Timeout, Transport: lssTransport},
	}
}

// Error is returned when an upstream answers with a non-2xx status.
type Error struct {
	Service string
	Status  int
	Body    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s returned %d: %s", e.Service, e.Status, e.Body)
}

// ErrNoToken is returned when the caller did not supply a bearer token.
var ErrNoToken = errors.New("missing bearer token")

type tokenKey struct{}

// WithToken stores the caller's bearer token (without the "Bearer " prefix) in ctx.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

func tokenFrom(ctx context.Context) (string, error) {
	t, _ := ctx.Value(tokenKey{}).(string)
	if t == "" {
		return "", ErrNoToken
	}
	return t, nil
}

// TokenFrom is the exported variant for packages outside upstream that need to read the
// caller's bearer token from the context (e.g. to decode claims without an outbound call).
func TokenFrom(ctx context.Context) (string, error) { return tokenFrom(ctx) }

func (c *Client) getJSON(ctx context.Context, service, rawURL string, out any) error {
	return c.getJSONWith(ctx, c.http, service, rawURL, out)
}

func (c *Client) getJSONWith(ctx context.Context, hc *http.Client, service, rawURL string, out any) error {
	token, err := tokenFrom(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", service, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("%s read failed: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Service: service, Status: resp.StatusCode, Body: truncate(string(body), 300)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s returned unexpected JSON: %w", service, err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- ELOC (global): which organizations the user can see, and their pod ---

type Organization struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CustomerID string `json:"customerID"`
	Pod        string `json:"pod"`
}

func (c *Client) Organizations(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	err := c.getJSON(ctx, "eloc", strings.TrimRight(c.cfg.ElocURL, "/")+"/api/v1/organizations", &orgs)
	return orgs, err
}

// --- Rendall (per pod) ---

func (c *Client) rendall(pod, path string) (string, error) {
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return "", fmt.Errorf("invalid pod %q", pod)
	}
	base := c.cfg.RendallURLTemplate
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	return strings.TrimRight(base, "/") + path, nil
}

func (c *Client) rendallGet(ctx context.Context, pod, path string, out any) error {
	u, err := c.rendall(pod, path)
	if err != nil {
		return err
	}
	return c.getJSON(ctx, "rendall", u, out)
}

func (c *Client) rendallMutate(ctx context.Context, method, pod, path string, body, out any) error {
	u, err := c.rendall(pod, path)
	if err != nil {
		return err
	}
	token, err := tokenFrom(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("rendall: marshal body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rendall request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("rendall read failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("rendall %s %s → %d: %s", method, u, resp.StatusCode, truncate(string(respBody), 300))
		return &Error{Service: "rendall", Status: resp.StatusCode, Body: truncate(string(respBody), 300)}
	}
	log.Printf("rendall %s %s → %d: %s", method, u, resp.StatusCode, truncate(string(respBody), 200))
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("rendall returned unexpected JSON: %w", err)
		}
	}
	return nil
}

// RendallOrgPost POSTs to a versioned org path (e.g. /api/v2/organizations/{id}/sites).
func (c *Client) RendallOrgPost(ctx context.Context, pod, orgID, version, suffix string, body, out any) error {
	path := "/api/" + version + "/organizations/" + url.PathEscape(orgID) + suffix
	return c.rendallMutate(ctx, http.MethodPost, pod, path, body, out)
}

// RendallOrgPut PUTs to a versioned org path.
func (c *Client) RendallOrgPut(ctx context.Context, pod, orgID, version, suffix string, body, out any) error {
	path := "/api/" + version + "/organizations/" + url.PathEscape(orgID) + suffix
	return c.rendallMutate(ctx, http.MethodPut, pod, path, body, out)
}

// RendallGet GETs a Rendall path that isn't under an organization (e.g. /api/v1/groups/{group}).
func (c *Client) RendallGet(ctx context.Context, pod, path string, out any) error {
	return c.rendallGet(ctx, pod, path, out)
}

// RendallOrgDo sends any method (PATCH, DELETE…) to a versioned org path. A nil body sends none.
func (c *Client) RendallOrgDo(ctx context.Context, method, pod, orgID, version, suffix string, body, out any) error {
	path := "/api/" + version + "/organizations/" + url.PathEscape(orgID) + suffix
	return c.rendallMutate(ctx, method, pod, path, body, out)
}

func orgPath(orgID, suffix string) string {
	return "/api/v1/organizations/" + url.PathEscape(orgID) + suffix
}

func orgPathV2(orgID, suffix string) string {
	return "/api/v2/organizations/" + url.PathEscape(orgID) + suffix
}

type Site struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	TimeZone string `json:"time_zone"`
	Address  any    `json:"address,omitempty"`
}

func (c *Client) Sites(ctx context.Context, pod, orgID string) ([]Site, error) {
	var sites []Site
	err := c.rendallGet(ctx, pod, orgPathV2(orgID, "/sites"), &sites)
	return sites, err
}

type SensorProfile struct {
	UUID           string `json:"uuid"`
	Shorthand      string `json:"shorthand"`
	Deployment     any    `json:"deployment"`
	DeploymentType string `json:"deployment_type"`
	IPAddress      string `json:"ip_address"`
	SiteUUID       string `json:"site_uuid"`
}

func (c *Client) SiteSensors(ctx context.Context, pod, orgID, siteUUID string) ([]SensorProfile, error) {
	var sensors []SensorProfile
	err := c.rendallGet(ctx, pod, orgPathV2(orgID, "/sites/"+url.PathEscape(siteUUID)+"/sensors"), &sensors)
	return sensors, err
}

// LogSource is Rendall's customer-facing view of an LSS record. Rendall drops suggested
// parsers, volume, deployment and sample lines; Parsers holds tags of the configured parser.
type LogSource struct {
	Name     string    `json:"name"`
	LastSeen time.Time `json:"lastSeen"`
	Timezone string    `json:"timezone"`
	Parsers  []string  `json:"parsers"`
	Tags     []string  `json:"tags"`
}

func (c *Client) LogSources(ctx context.Context, pod, orgID string) ([]LogSource, error) {
	var ls []LogSource
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/log-sources"), &ls)
	return ls, err
}

// --- LSS (per pod, inside the VPC): the full log source records Rendall trims ---

// LSSRecord is one LSS log source record. LSS keys records by (deployment, name), so the
// same source arriving on two sensors is two records.
type LSSRecord struct {
	Name                string    `json:"name"`
	Deployment          string    `json:"deployment"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
	HasConfiguredParser bool      `json:"has_configured_parser"`
	ConfiguredParser    *string   `json:"configured_parser"`
	ConfiguredTimezone  *string   `json:"configured_timezone"`
	SuggestedParsers    []string  `json:"suggested_parsers"`
	IsActive            bool      `json:"is_active"`
	LogSourceVolume     *int64    `json:"log_source_volume"`
	DeprecatedBy        *string   `json:"deprecated_by"`
}

// ErrOnboardingDisabled is returned when no onboarding service endpoint is configured.
var ErrOnboardingDisabled = errors.New("onboarding service endpoint not configured")

// OnboardingGet reads from the onboarding service (onboarding-go) for a customer (the ELOC
// customerID, e.g. "baconsecurity"), with the caller's own token. path is relative to
// /api/, e.g. "v1/products/".
func (c *Client) OnboardingGet(ctx context.Context, pod, customerID, path string, out any) error {
	if c.cfg.OnboardingURLTemplate == "" {
		return ErrOnboardingDisabled
	}
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return fmt.Errorf("invalid pod %q", pod)
	}
	version, rest, _ := strings.Cut(path, "/")
	u := strings.TrimRight(fmt.Sprintf(c.cfg.OnboardingURLTemplate, pod), "/") + "/api/" + version + "/" + url.PathEscape(customerID) + "/" + rest
	return c.getJSONWith(ctx, c.lss, "onboarding", u, out)
}

// ErrLSSDisabled is returned when no LSS endpoint is configured.
var ErrLSSDisabled = errors.New("lss endpoint not configured")

// LSSLogSources returns every LSS record for a customer (the ELOC customerID, e.g.
// "baconsecurity"). Same call Rendall makes, with the caller's own token.
func (c *Client) LSSLogSources(ctx context.Context, pod, customerID string) ([]LSSRecord, error) {
	if c.cfg.LSSURLTemplate == "" {
		return nil, ErrLSSDisabled
	}
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return nil, fmt.Errorf("invalid pod %q", pod)
	}
	base := c.cfg.LSSURLTemplate
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	var recs []LSSRecord
	err := c.getJSONWith(ctx, c.lss, "lss", strings.TrimRight(base, "/")+"/customers/"+url.PathEscape(customerID)+"/", &recs)
	return recs, err
}

// SensorRow is one physical/virtual/VLC sensor from Rendall's sensor list.
type SensorRow struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	DeploymentID string `json:"deploymentID"`
	SerialNumber string `json:"serialNumber"`
	Status       string `json:"status"` // new | healthy | unhealthy | preparingToShip | staged | shipped | awaitingActivation
	Product      string `json:"product"`
	Model        string `json:"model"`
	Config       string `json:"config"`
	IP           string `json:"ip"`
	SiteName     string `json:"siteName"`
	ShippedDate  string `json:"shippedDate"`
}

// Sensors lists the org's sensors with their status (about 12 s for a large org).
func (c *Client) Sensors(ctx context.Context, pod, orgID string) ([]SensorRow, error) {
	var page struct {
		Items []SensorRow `json:"items"`
	}
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/sensors"), &page)
	return page.Items, err
}

// CloudSensorRow is one cloud sensor (integration). Its credential block is not decoded.
type CloudSensorRow struct {
	Name         string `json:"name"`
	DeploymentID string `json:"deploymentID"`
	Status       string `json:"status"` // healthy | unhealthy | invalidCredentials | pendingCustomerConfig | …
	Vendor       string `json:"vendor"`
	Type         string `json:"type"`
}

// CloudSensors lists the org's cloud sensors with their status (can take 30-40 s).
func (c *Client) CloudSensors(ctx context.Context, pod, orgID string) ([]CloudSensorRow, error) {
	var page struct {
		Items []CloudSensorRow `json:"items"`
	}
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/cloud-sensors"), &page)
	return page.Items, err
}

// LSSExampleLines returns the sample lines LSS kept when it identified a source on one
// sensor (deployment). Instant, and present even when the raw archive has nothing.
func (c *Client) LSSExampleLines(ctx context.Context, pod, deployment, source string) ([]string, error) {
	if c.cfg.LSSURLTemplate == "" {
		return nil, ErrLSSDisabled
	}
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return nil, fmt.Errorf("invalid pod %q", pod)
	}
	base := c.cfg.LSSURLTemplate
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	var out struct {
		Lines []string `json:"lines"`
	}
	path := "/deployments/" + url.PathEscape(deployment) + "/sources/" + url.PathEscape(source) + "/example-log-lines/"
	err := c.getJSONWith(ctx, c.lss, "lss", strings.TrimRight(base, "/")+path, &out)
	return out.Lines, err
}

// RendallOrgGet reads one organization-scoped Rendall resource, e.g. version "v1" and
// suffix "/contacts" for /api/v1/organizations/{org}/contacts.
func (c *Client) RendallOrgGet(ctx context.Context, pod, orgID, version, suffix string, out any) error {
	path := orgPath(orgID, suffix)
	if version == "v2" {
		path = orgPathV2(orgID, suffix)
	}
	return c.rendallGet(ctx, pod, path, out)
}

// IntegrationSchema is one connectable cloud integration from Rendall's secrets-schema:
// the credential form the customer fills in to connect it.
type IntegrationSchema struct {
	DeploymentType  string `json:"deployment_type"`
	IntegrationName string `json:"integration_name"`
	SetupGuideURL   string `json:"setup_guide_url"`
	LicenseModel    string `json:"license_model"`
	LicenseName     string `json:"license_name"`
	Credential      struct {
		Required        []string `json:"required"`
		SensitiveFields []string `json:"sensitiveFields"`
		Properties      map[string]struct {
			Type        string `json:"type"`
			DisplayName string `json:"displayName"`
			Order       int    `json:"order"`
			InputType   string `json:"inputType"`
		} `json:"properties"`
	} `json:"credential_schema"`
}

// IntegrationSchemas lists every cloud integration the org can connect (≈650 KB with logos;
// the logos are not decoded).
func (c *Client) IntegrationSchemas(ctx context.Context, pod, orgID string) ([]IntegrationSchema, error) {
	var out []IntegrationSchema
	err := c.rendallGet(ctx, pod, orgPathV2(orgID, "/secrets-schema"), &out)
	return out, err
}

// Summaries are passed through as generic maps: their shapes are counts by status.

func (c *Client) SensorSummary(ctx context.Context, pod, orgID string) (map[string]any, error) {
	var m map[string]any
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/sensor-summary"), &m)
	return m, err
}

func (c *Client) CloudSensorSummary(ctx context.Context, pod, orgID string) (map[string]any, error) {
	var m map[string]any
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/cloud-sensor-summary"), &m)
	return m, err
}

func (c *Client) AgentOverview(ctx context.Context, pod, orgID string) (map[string]any, error) {
	var m map[string]any
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/onboarding-agent-overview"), &m)
	return m, err
}

// --- Raw Log Search (Rendall → Scrounger): raw lines as they arrived, before parsing ---

// RawLogRow is one raw line from the archive.
type RawLogRow struct {
	Timestamp  string `json:"timestamp"`
	Deployment string `json:"deployment"`
	Host       string `json:"host"`
	Body       string `json:"body"`
}

type LogSearch struct {
	ID      string `json:"id"`
	Percent int    `json:"percent"`
	Count   int    `json:"count"`
	Failed  bool   `json:"failed"`
}

// CreateLogSearch starts an archive search job. It appears in the org's search history.
func (c *Client) CreateLogSearch(ctx context.Context, pod, orgID, query string, start, end time.Time) (LogSearch, error) {
	var out LogSearch
	body := map[string]any{
		"query":          query,
		"startTime":      start.UTC().Format(time.RFC3339),
		"endTime":        end.UTC().Format(time.RFC3339),
		"caseSensitive":  false,
		"logSourcesTags": map[string]any{}, // required by Rendall
	}
	u, err := c.rendall(pod, orgPath(orgID, "/logsearch"))
	if err != nil {
		return out, err
	}
	err = c.postJSON(ctx, "rendall-logsearch", u, body, &out)
	return out, err
}

func (c *Client) GetLogSearch(ctx context.Context, pod, orgID, id string) (LogSearch, error) {
	var out struct {
		Search LogSearch `json:"search"`
	}
	err := c.rendallGet(ctx, pod, orgPath(orgID, "/logsearch/"+url.PathEscape(id)), &out)
	return out.Search, err
}

func (c *Client) LogSearchResults(ctx context.Context, pod, orgID, id string, page int) ([]RawLogRow, error) {
	var rows []RawLogRow
	err := c.rendallGet(ctx, pod, orgPath(orgID, fmt.Sprintf("/logsearch/%s/results?page=%d", url.PathEscape(id), page)), &rows)
	return rows, err
}

func (c *Client) postJSON(ctx context.Context, service, rawURL string, in, out any) error {
	token, err := tokenFrom(ctx)
	if err != nil {
		return err
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", service, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("%s read failed: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Service: service, Status: resp.StatusCode, Body: truncate(string(body), 300)}
	}
	return json.Unmarshal(body, out)
}

// --- Data Explorer (Rendall → Query Broker): counts over parsed events ---

// QueryResponse is the subset of a Query Broker response the service reads.
type QueryResponse struct {
	Rows  [][]any `json:"rows"`
	Total int     `json:"total"`
}

// GroupCount runs a count query over parsed events grouped by the given fields.
func (c *Client) GroupCount(ctx context.Context, pod, orgID string, fields []string, start, end time.Time, limit int) (QueryResponse, error) {
	columns := make([]map[string]any, 0, len(fields)+1)
	for _, f := range fields {
		columns = append(columns, map[string]any{"field": map[string]string{"name": f}})
	}
	columns = append(columns, map[string]any{"operation": map[string]string{"operator": "count", "alias": "count"}})
	body := map[string]any{
		"start": start.UTC().Format(time.RFC3339),
		"end":   end.UTC().Format(time.RFC3339),
		"limit": limit,
		"total": true,
		"query": map[string]any{"query": map[string]any{
			"source":  "axes_observations",
			"columns": columns,
			"orderBy": []map[string]any{{"on": map[string]any{"field": map[string]string{"name": "count"}}, "order": "desc"}},
		}},
	}
	var out QueryResponse
	u, err := c.rendall(pod, orgPath(orgID, "/data-explorer/analyzed-logs"))
	if err != nil {
		return out, err
	}
	err = c.postJSON(ctx, "rendall-data-explorer", u, body, &out)
	return out, err
}

// --- Production ASA (the assistant the Unified Portal uses), called as the user ---

// AskASA sends one question to production ASA in the Unified Portal context, with the same
// feature flags the Unified Portal chatbot sends, and returns the streamed answer as text.
func (c *Client) AskASA(ctx context.Context, pod, orgID, question string) (string, error) {
	token, err := tokenFrom(ctx)
	if err != nil {
		return "", err
	}
	if c.cfg.ASAURLTemplate == "" {
		return "", errors.New("ASA URL not configured")
	}
	base := c.cfg.ASAURLTemplate
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	body, _ := json.Marshal(map[string]any{
		"contextInfo": map[string]any{
			"organizationId": orgID,
			"contextType":    "UP",
			"invocationURL":  "https://dashboard.arcticwolf.com/" + url.PathEscape(orgID),
			"asaFeatureConfig": map[string]bool{
				"sonnet_4_5": true, "up_expert": true, "aw_mcp_server": true,
				"disable_thinking_block": true, "security_journey": true, "threat_bulletin": true,
			},
		},
		"messages": []map[string]string{{"role": "user", "text": question}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/converse-stream", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("asa request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Service: "asa", Status: resp.StatusCode, Body: truncate(string(raw), 300)}
	}
	var answer strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		payload, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
		if !ok {
			continue
		}
		var event struct {
			Text string `json:"text"`
		}
		if json.Unmarshal([]byte(payload), &event) == nil {
			answer.WriteString(event.Text)
		}
	}
	return stripThinking(answer.String()), nil
}

// stripThinking removes <thinking>/<internal_thinking> blocks ASA may include.
func stripThinking(text string) string {
	for _, tag := range []string{"thinking", "internal_thinking"} {
		for {
			start := strings.Index(text, "<"+tag+">")
			if start < 0 {
				break
			}
			end := strings.Index(text[start:], "</"+tag+">")
			if end < 0 {
				text = text[:start]
				break
			}
			text = text[:start] + text[start+end+len(tag)+3:]
		}
	}
	return strings.TrimSpace(text)
}

// --- Tickets (Rendall) ---

// TicketInput is Rendall's createTicket body (a Zendesk ticket on the customer's behalf).
type TicketInput struct {
	Subject     string   `json:"subject"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// CreateTicket opens a support ticket for the organization as the caller and returns its id.
func (c *Client) CreateTicket(ctx context.Context, pod, orgID string, in TicketInput) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.RendallOrgPost(ctx, pod, orgID, "v1", "/tickets", in, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("rendall created a ticket but returned no id")
	}
	return out.ID, nil
}

// --- Log Source Orchestrator ---

// ErrLSODisabled is returned when no LSO endpoint is configured.
var ErrLSODisabled = errors.New("log source orchestrator not configured")

// LSOEnabled reports whether parser changes can be saved through LSO.
func (c *Client) LSOEnabled() bool { return c.cfg.LSOURLTemplate != "" }

// LSOUpdateLogSource saves a log source's parser/timezone through LSO
// (PUT /api/v1/customers/{customer}/deployments/{deployment}/log-sources/{source}/), which
// writes the deployment's XConf logsource item. reason and ticket become XConf's X-Reason and
// X-Ticket. Uses the caller's own token.
func (c *Client) LSOUpdateLogSource(ctx context.Context, pod, customerUUID, deploymentID, source string, body any, reason, ticket string) error {
	if c.cfg.LSOURLTemplate == "" {
		return ErrLSODisabled
	}
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return fmt.Errorf("invalid pod %q", pod)
	}
	token, err := tokenFrom(ctx)
	if err != nil {
		return err
	}
	base := c.cfg.LSOURLTemplate
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	u := strings.TrimRight(base, "/") + "/api/v1/customers/" + url.PathEscape(customerUUID) +
		"/deployments/" + url.PathEscape(deploymentID) + "/log-sources/" + url.PathEscape(source) + "/"
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Reason", reason)
	if ticket != "" {
		req.Header.Set("X-Ticket", ticket)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("log source orchestrator request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Service: "log source orchestrator", Status: resp.StatusCode, Body: truncate(string(respBody), 300)}
	}
	return nil
}

// DetectionList is one page of the detection catalog.
type DetectionList struct {
	Total int `json:"total"`
	Data  []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Mitres []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"mitres"`
	} `json:"data"`
}

// Detections lists catalog detections that run on any of the given parsers or log source types
// (detection-service GET /api/v1/detections), with the caller's token.
func (c *Client) Detections(ctx context.Context, parsers, logSources []string, limit int) (DetectionList, error) {
	var out DetectionList
	if c.cfg.DetectionURL == "" {
		return out, errors.New("detection catalog not configured")
	}
	q := url.Values{}
	for _, p := range parsers {
		q.Add("parsers", p)
	}
	for _, l := range logSources {
		q.Add("logSources", l)
	}
	q.Set("limit", strconv.Itoa(limit))
	err := c.getJSON(ctx, "detection-service", strings.TrimRight(c.cfg.DetectionURL, "/")+"/api/v1/detections?"+q.Encode(), &out)
	return out, err
}

// IngestionEnabled reports whether cloud apps go through the ingestion orchestrator.
func (c *Client) IngestionEnabled() bool { return c.cfg.IngestionURLTemplate != "" }

// IngestionDo calls the ingestion orchestrator (path under /api/v1, e.g. /customers/{uuid}/sensors)
// with the caller's token. A nil body sends none; out may be nil.
func (c *Client) IngestionDo(ctx context.Context, method, pod, path string, body, out any) error {
	if c.cfg.IngestionURLTemplate == "" {
		return errors.New("ingestion orchestrator not configured")
	}
	return c.gatewayDo(ctx, "ingestion-orchestrator", c.cfg.IngestionURLTemplate, method, pod, path, body, out)
}

// CMSEnabled reports whether cloud scanner (CSPM) accounts are available.
func (c *Client) CMSEnabled() bool { return c.cfg.CMSURLTemplate != "" }

// CMSDo calls the Credential Management Service (path from /api/v1/...) with the caller's token.
func (c *Client) CMSDo(ctx context.Context, method, pod, path string, body, out any) error {
	if c.cfg.CMSURLTemplate == "" {
		return errors.New("credential management service not configured")
	}
	return c.gatewayDo(ctx, "credential-management-service", c.cfg.CMSURLTemplate, method, pod, path, body, out)
}

// gatewayDo sends one JSON request to a managed-gateway service with the caller's token.
func (c *Client) gatewayDo(ctx context.Context, service, template, method, pod, path string, body, out any) error {
	if pod == "" || strings.ContainsAny(pod, "/.:?#") {
		return fmt.Errorf("invalid pod %q", pod)
	}
	token, err := tokenFrom(ctx)
	if err != nil {
		return err
	}
	base := template
	if strings.Contains(base, "%s") {
		base = fmt.Sprintf(base, pod)
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%s: marshal body: %w", service, err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", service, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("%s read failed: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		msg := truncate(string(respBody), 300)
		if json.Unmarshal(respBody, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		return &Error{Service: service, Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%s returned unexpected JSON: %w", service, err)
		}
	}
	return nil
}
