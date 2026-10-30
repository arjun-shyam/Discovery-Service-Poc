package discovery

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- Cloud apps after the first connection (Unified Portal Cloud Sensors page) ---
//
//   request_cloud_quote      POST   /api/v1/organizations/{org}/tickets {ticketType: cloudRequestQuote}  (Request quote, premium not purchased)
//   update_cloud_credentials PUT    /api/v1/organizations/{org}/customer-credential/{deploymentId}       (putCustomerCredential)
//   remove_cloud_app         DELETE /api/v1/organizations/{org}/customer-credential/{deploymentId}       (deleteCustomerCredential)

const (
	ChangeRequestCloudQuote      = "request_cloud_quote"
	ChangeUpdateCloudCredentials = "update_cloud_credentials"
	ChangeRemoveCloudApp         = "remove_cloud_app"
)

// cloudPurchased says whether a premium integration is on the organization's purchased list.
func (s *Service) cloudPurchased(ctx context.Context, org upstream.Organization, schema upstream.IntegrationSchema) bool {
	var purchased []string
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/purchased-cloud-sensor-vendors", &purchased); err != nil {
		return true // can't tell: let Arctic Wolf decide
	}
	for _, p := range purchased {
		if p == schema.DeploymentType || (schema.LicenseName != "" && p == schema.LicenseName) {
			return true
		}
	}
	return false
}

func (s *Service) schemaByType(ctx context.Context, org upstream.Organization, typ string) (upstream.IntegrationSchema, error) {
	schemas, err := s.integrationSchemas(ctx, org)
	if err != nil {
		return upstream.IntegrationSchema{}, err
	}
	for _, sc := range schemas {
		if strings.EqualFold(sc.DeploymentType, typ) {
			return sc, nil
		}
	}
	return upstream.IntegrationSchema{}, fmt.Errorf("%w: unknown integration type %q; use list_cloud_integrations", ErrChangeInvalid, typ)
}

func (s *Service) findCloudApp(ctx context.Context, org upstream.Organization, want string) (upstream.CloudSensorRow, error) {
	rows, err := s.up.CloudSensors(ctx, org.Pod, org.ID)
	if err != nil {
		return upstream.CloudSensorRow{}, fmt.Errorf("could not read cloud sensors: %w", err)
	}
	for _, r := range rows {
		if strings.EqualFold(r.Name, want) || strings.EqualFold(r.DeploymentID, want) {
			return r, nil
		}
	}
	return upstream.CloudSensorRow{}, fmt.Errorf("%w: cloud app %q not found; use list_sensors kind=cloud", ErrChangeInvalid, want)
}

func (s *Service) prepareCloud(ctx context.Context, org upstream.Organization, ch *Change, kind string, params map[string]string) (miss []string, ok bool, err error) {
	switch kind {
	case ChangeRequestCloudQuote:
		if miss = missing(params, "type"); len(miss) > 0 {
			return miss, true, nil
		}
		sc, err := s.schemaByType(ctx, org, str(params, "type"))
		if err != nil {
			return nil, true, err
		}
		subject := "Quote request: " + sc.IntegrationName + " monitoring"
		desc := "Requested from Aurora. The customer would like to add " + sc.IntegrationName + " (" + sc.DeploymentType + ") monitoring."
		if n := str(params, "notes"); n != "" {
			desc += "\n\n" + n
		}
		ch.Title = "Request a quote for " + sc.IntegrationName
		ch.Method, ch.Path = "POST", "/api/v1/organizations/"+org.ID+"/tickets"
		ch.Body = map[string]any{"subject": subject, "description": desc, "ticketType": "cloudRequestQuote"}
		ch.Details = []ChangeDetail{{"Integration", sc.IntegrationName}, {"What happens", "A quote request ticket goes to your Arctic Wolf team; they reply on the ticket"}}
		return nil, true, nil

	case ChangeUpdateCloudCredentials, ChangeRemoveCloudApp:
		if miss = missing(params, "cloud_app"); len(miss) > 0 {
			return miss, true, nil
		}
		app, err := s.findCloudApp(ctx, org, str(params, "cloud_app"))
		if err != nil {
			return nil, true, err
		}
		path := "/api/v1/organizations/" + org.ID + "/customer-credential/" + url.PathEscape(app.DeploymentID)
		ident := []ChangeDetail{{"Cloud app", app.Name}, {"Vendor", app.Vendor}, {"Status", app.Status}}
		if kind == ChangeRemoveCloudApp {
			ch.Title = "Remove cloud app " + app.Name
			ch.Method, ch.Path, ch.Body = "DELETE", path, nil
			ch.Details = append(ident, ChangeDetail{"Effect", "Arctic Wolf stops collecting this app's logs and deletes its stored credentials"})
			ch.Assumptions = []string{"Same as Delete on the Unified Portal Cloud Sensors page; Arctic Wolf may process it as a request. To undo, connect the app again with connect_cloud_app."}
			return nil, true, nil
		}
		sc, err := s.schemaByType(ctx, org, orDefault(app.Type, app.Vendor))
		if err != nil {
			return nil, true, err
		}
		secrets := map[string]any{}
		for _, f := range fieldsOf(sc) {
			// Every credential field is re-entered on the secure card; nothing passes through chat.
			ch.SecureFields = append(ch.SecureFields, SecureField{Name: f.Name, Label: f.Label, Required: f.Required, Sensitive: f.Sensitive, Input: f.Input})
			secrets[f.Name] = redactedSecret
		}
		ch.Title = "Update credentials for " + app.Name
		ch.Method, ch.Path = "PUT", path
		ch.Body = map[string]any{"name": app.Name, "type": sc.DeploymentType, "secrets": secrets}
		ch.Details = append(ident, ChangeDetail{"Setup guide", sc.SetupGuideURL})
		ch.Assumptions = []string{"Same as editing the account on the Unified Portal Cloud Sensors page. Arctic Wolf checks the new credentials; status shows in Cloud sensors."}
		return nil, true, nil
	}
	return nil, false, nil
}
