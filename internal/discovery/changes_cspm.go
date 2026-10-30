package discovery

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Cloud scanner (CSPM) accounts: AWS, Azure, Google Cloud ---
//
// Same calls as the Unified Portal Cloud Scanners page (arcticexperience features/cloud-scanners),
// which talks to the Credential Management Service with the user's token (MAPIG capability
// credential_manage):
//   schemas  GET    /api/v1/schemas?serviceName=cspm      → prod_cspm_aws / prod_cspm_azure / prod_cspm_gcp
//   list     GET    /api/v1/organizations/{org}/credentials/metadata
//   add      POST   /api/v1/organizations/{org}/credentials {credential, schemaType, integrationInstanceId}
//   remove   DELETE /api/v1/organizations/{org}/credentials/{id}
// integrationInstanceId is the AWS account id, Azure subscription id or GCP project id.

const (
	ChangeConnectCloudScanner = "connect_cloud_scanner"
	ChangeRemoveCloudScanner  = "remove_cloud_scanner"
	serviceCMS                = "cms"
)

var cspmSchemaType = regexp.MustCompile(`^(?:prod|test)?_?(cspm_(aws|azure|gcp))$`)

// cspmInstanceField is the credential field that identifies the cloud account (portal rule).
var cspmInstanceField = map[string]string{"aws": "account_id", "azure": "subscription_id", "gcp": "project_id"}

var cspmProviderName = map[string]string{"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud"}

type cmsSchema struct {
	SchemaType      string   `json:"schemaType"`
	IntegrationName string   `json:"integrationName"`
	Required        []string `json:"required"`
	SensitiveFields []string `json:"sensitiveFields"`
	Properties      map[string]struct {
		DisplayName string `json:"displayName"`
		Order       int    `json:"order"`
		InputType   string `json:"inputType"`
		Description string `json:"description"`
	} `json:"properties"`
}

func (c cmsSchema) provider() string {
	if m := cspmSchemaType.FindStringSubmatch(c.SchemaType); m != nil {
		return m[2]
	}
	return ""
}

// cspmSchemas returns the production CSPM schemas by provider.
func (s *Service) cspmSchemas(ctx context.Context, org upstream.Organization) (map[string]cmsSchema, error) {
	var all []cmsSchema
	if err := s.up.CMSDo(ctx, "GET", org.Pod, "/api/v1/schemas?serviceName=cspm", nil, &all); err != nil {
		return nil, err
	}
	out := map[string]cmsSchema{}
	for _, sc := range all {
		if p := sc.provider(); p != "" && !strings.HasPrefix(sc.SchemaType, "test") {
			out[p] = sc
		}
	}
	return out, nil
}

// CloudScannerAccount is one connected cloud account for posture scanning.
type CloudScannerAccount struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Ticket   string `json:"ticket,omitempty"`
}

// CloudScannerAccounts lists the organization's CSPM accounts and which providers can be added.
func (s *Service) CloudScannerAccounts(ctx context.Context, orgID string) (map[string]any, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "credential-management-service (cspm)"}, FetchedAt: s.now(), UntrustedFields: []string{"accounts[].account"}}
	if !s.up.CMSEnabled() {
		return nil, meta, fmt.Errorf("cloud scanner accounts aren't available here (credential management service not configured)")
	}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return nil, meta, err
	}
	var list struct {
		Data []struct {
			ID                    string `json:"id"`
			SchemaType            string `json:"schemaType"`
			IntegrationInstanceID string `json:"integrationInstanceId"`
			ZendeskTicketID       string `json:"zendeskTicketId"`
		} `json:"data"`
	}
	if err := s.up.CMSDo(ctx, "GET", org.Pod, "/api/v1/organizations/"+url.PathEscape(org.ID)+"/credentials/metadata", nil, &list); err != nil {
		return nil, meta, fmt.Errorf("could not read cloud scanner accounts: %w", err)
	}
	accounts := []CloudScannerAccount{}
	for _, d := range list.Data {
		m := cspmSchemaType.FindStringSubmatch(d.SchemaType)
		if m == nil {
			continue
		}
		accounts = append(accounts, CloudScannerAccount{ID: d.ID, Provider: cspmProviderName[m[2]], Account: d.IntegrationInstanceID, Ticket: d.ZendeskTicketID})
	}
	providers := []string{}
	if schemas, err := s.cspmSchemas(ctx, org); err == nil {
		for p := range schemas {
			providers = append(providers, p)
		}
		sort.Strings(providers)
	}
	return map[string]any{"accounts": accounts, "canAdd": providers}, meta, nil
}

func (s *Service) prepareCSPM(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	switch kind {
	case ChangeConnectCloudScanner:
		if !s.up.CMSEnabled() {
			return nil, true, fmt.Errorf("%w: cloud scanner accounts aren't available here", ErrChangeInvalid)
		}
		provider := strings.ToLower(str(params, "provider"))
		if provider == "google" || provider == "google_cloud" {
			provider = "gcp"
		}
		idField := cspmInstanceField[provider]
		if miss = missing(params, "provider"); len(miss) > 0 {
			return miss, true, nil
		}
		if idField == "" {
			return nil, true, fmt.Errorf("%w: provider must be aws, azure or gcp", ErrChangeInvalid)
		}
		if miss = missing(params, "account"); len(miss) > 0 {
			return []string{"account (" + idField + ")"}, true, nil
		}
		account := str(params, "account")
		if !cspmAccountFormat[provider].MatchString(account) {
			return nil, true, fmt.Errorf("%w: %q isn't a valid %s %s", ErrChangeInvalid, account, cspmProviderName[provider], strings.ReplaceAll(idField, "_", " "))
		}
		schemas, err := s.cspmSchemas(ctx, org)
		if err != nil {
			return nil, true, fmt.Errorf("could not read cloud scanner forms: %w", err)
		}
		sc, found := schemas[provider]
		if !found {
			return nil, true, fmt.Errorf("%w: %s cloud scanning isn't offered for this organization", ErrChangeInvalid, cspmProviderName[provider])
		}
		sensitive := map[string]bool{}
		for _, f := range sc.SensitiveFields {
			sensitive[f] = true
		}
		required := map[string]bool{}
		for _, f := range sc.Required {
			required[f] = true
		}
		credential := map[string]any{idField: account}
		names := make([]string, 0, len(sc.Properties))
		for name := range sc.Properties {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return sc.Properties[names[i]].Order < sc.Properties[names[j]].Order })
		for _, name := range names {
			if name == idField {
				continue
			}
			p := sc.Properties[name]
			// Role ARNs, tenant/client ids, keys and service-account files go on the secure card.
			ch.SecureFields = append(ch.SecureFields, SecureField{Name: name, Label: orDefault(p.DisplayName, name), Required: required[name], Sensitive: sensitive[name], Input: p.InputType})
			credential[name] = redactedSecret
		}
		ch.Title = "Add " + cspmProviderName[provider] + " account " + account + " to cloud scanning"
		ch.service = serviceCMS
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/credentials"
		ch.Body = map[string]any{"credential": credential, "schemaType": sc.SchemaType, "integrationInstanceId": account}
		ch.Details = []ChangeDetail{{"Cloud", cspmProviderName[provider]}, {"Account", account}, {"What it does", "Arctic Wolf scans this cloud account's configuration for risky settings (CSPM); findings appear in Exposure Management"}}
		ch.Assumptions = []string{"Same as Add Account on the Unified Portal Cloud Scanners page. First create the read-only role or service account in the cloud console as the setup guide describes."}
		return nil, true, nil

	case ChangeRemoveCloudScanner:
		if miss = missing(params, "account"); len(miss) > 0 {
			return miss, true, nil
		}
		res, _, err := s.CloudScannerAccounts(ctx, org.ID)
		if err != nil {
			return nil, true, err
		}
		for _, a := range res["accounts"].([]CloudScannerAccount) {
			if strings.EqualFold(a.Account, str(params, "account")) || a.ID == str(params, "account") {
				ch.Title = "Remove " + a.Provider + " account " + a.Account + " from cloud scanning"
				ch.service = serviceCMS
				ch.Method, ch.Path, ch.Body = "DELETE", "/api/v1/organizations/"+org.ID+"/credentials/"+url.PathEscape(a.ID), nil
				ch.Details = []ChangeDetail{{"Cloud", a.Provider}, {"Account", a.Account}, {"Effect", "Arctic Wolf stops scanning this account and deletes its stored credentials"}}
				ch.Assumptions = []string{"Same as Remove on the Unified Portal Cloud Scanners page. To undo, add the account again."}
				return nil, true, nil
			}
		}
		return nil, true, fmt.Errorf("%w: cloud scanner account %q not found; use list_cloud_scanner_accounts", ErrChangeInvalid, str(params, "account"))
	}
	return nil, false, nil
}
