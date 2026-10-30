package discovery

import (
	"context"
	"sort"

	"github.com/notxdr/discovery-service/internal/upstream"
)

// --- What the customer bought decides which onboarding sections apply ---
//
// Mirrors the Unified Portal onboarding page (rtkwlf/arcticexperience
// packages/utils/src/onboarding/visibility-config.ts and
// features/onboarding/src/components/site-card/{sensors,scanners}-section.tsx): sections are
// shown per Rendall subscription, and sensors / scanners count as done when every licence
// that is not unlimited (or free) is used.

// Subscriptions is the subset of Rendall GET /api/v1/organizations/{org}/subscriptions
// (SubscriptionDetail) the onboarding page reads.
type Subscriptions struct {
	MDR                     bool `json:"managedDetectionResponse"`
	ManagedRisk             bool `json:"managedRisk"` // Aurora Vulnerability Management (AVM)
	ManagedAwareness        bool `json:"managedAwareness"`
	ManagedAwarenessPlus    bool `json:"managedAwarenessPlus"`
	IRJumpstart             bool `json:"irJumpstart"`
	IRRetainer              bool `json:"incidentResponseRetainer"`
	CSPMAws                 bool `json:"cspmAws"`
	CSPMAzure               bool `json:"cspmAzure"`
	CSPMGcp                 bool `json:"cspmGcp"`
	AuroraProtect           bool `json:"auroraProtect"`
	AuroraEndpointDefense   bool `json:"auroraEndpointDefense"`
	AuroraEndpointAssurance bool `json:"auroraEndpointAssurance"`
	AuroraEngine            bool `json:"auroraEngine"`
}

func (s Subscriptions) ma() bool { return s.ManagedAwareness || s.ManagedAwarenessPlus }
func (s Subscriptions) edr() bool {
	return s.AuroraProtect || s.AuroraEndpointDefense || s.AuroraEndpointAssurance || s.AuroraEngine
}
func (s Subscriptions) ir() bool   { return s.IRJumpstart || s.IRRetainer }
func (s Subscriptions) cspm() bool { return s.CSPMAws || s.CSPMAzure || s.CSPMGcp }

// Names lists the purchased products in words a customer recognises.
func (s Subscriptions) Names() []string {
	var out []string
	for _, p := range []struct {
		on   bool
		name string
	}{
		{s.MDR, "Managed Detection and Response"}, {s.ManagedRisk, "Aurora Vulnerability Management"},
		{s.ma(), "Managed Security Awareness"}, {s.edr(), "Aurora Endpoint"}, {s.ir(), "Incident Response"},
		{s.cspm(), "Cloud Security Posture Management"},
	} {
		if p.on {
			out = append(out, p.name)
		}
	}
	return out
}

// Visibility is which onboarding sections apply, keyed by checklist section id.
type Visibility map[string]bool

// visibilityFor applies the Unified Portal rules. mspChild hides contacts (the parent MSP
// manages them), as the Unified Portal does so those customers can reach 100%.
func visibilityFor(s Subscriptions, mspChild bool) Visibility {
	users := s.MDR || s.ManagedRisk || s.ma() || s.edr() || s.ir()
	mdrOrMR := s.MDR || s.ManagedRisk
	return Visibility{
		"contacts":                users && !mspChild,
		"communications_contacts": users,
		"escalation_contacts":     users,
		"sites":                   mdrOrMR,
		"sensors":                 s.MDR,
		"scanners":                s.ManagedRisk,
		"agents":                  mdrOrMR,
		"cloud_information":       s.MDR,
		"location_alerts":         s.MDR,
		"cloud_sensors":           s.MDR,
		"internet_exposure":       mdrOrMR || s.ma(),
	}
}

// externalScansAllowed says whether External Vulnerability Assessment targets apply; customers
// with only Managed Security Awareness get account-takeover scans only.
func externalScansAllowed(s Subscriptions) bool { return s.MDR || s.ManagedRisk }

func (s *Service) subscriptions(ctx context.Context, org upstream.Organization) (Subscriptions, error) {
	var out Subscriptions
	err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/subscriptions", &out)
	return out, err
}

// --- Licences (Rendall license-usage / scanner-license-usage) ---

type quota struct {
	Quota int `json:"quota"`
	Used  int `json:"used"`
}

type licenceUsage struct {
	Quotas map[string]quota `json:"quotas"`
}

// LicenceLine is one licence model with how many are used.
type LicenceLine struct {
	Model     string `json:"model"`
	Quota     int    `json:"quota"`
	Used      int    `json:"used"`
	Unlimited bool   `json:"unlimited,omitempty"`
	Free      int    `json:"free,omitempty"` // complimentary units not counted towards progress
	Virtual   bool   `json:"virtual,omitempty"`
}

// LicenceProgress is the Unified Portal's sensors/scanners progress: used vs total over the
// licences that are neither unlimited nor free.
type LicenceProgress struct {
	Used  int           `json:"used"`
	Total int           `json:"total"`
	Lines []LicenceLine `json:"licences"`
}

func (p LicenceProgress) Done() bool { return p.Used >= p.Total }

// Physical returns licence models with units left that ship as hardware.
func (p LicenceProgress) PhysicalRemaining() map[string]int {
	out := map[string]int{}
	for _, l := range p.Lines {
		if !l.Virtual && !l.Unlimited && l.Quota > l.Used {
			out[l.Model] = l.Quota - l.Used
		}
	}
	return out
}

var (
	// Sensors: vanilla/vsensor are hidden, vlc is unlimited, one AWN100 vSensor comes free
	// with every MDR deal (sensors-section.tsx).
	sensorLicenceHidden    = map[string]bool{"vanilla": true, "vsensor": true}
	sensorLicenceUnlimited = map[string]bool{"vlc": true}
	sensorLicenceFree      = map[string]int{"awnv100": 1}
	virtualSensorModels    = map[string]bool{"awnv100": true, "awnv200": true, "awnv1000": true, "vanilla": true, "vsensor": true}
	// Scanners: virtual scanners are unlimited (scanners-section.tsx).
	scannerLicenceUnlimited = map[string]bool{"virtual": true}
)

func licenceProgress(u licenceUsage, hidden, unlimited map[string]bool, free map[string]int, virtual func(string) bool) LicenceProgress {
	var p LicenceProgress
	for model, q := range u.Quotas {
		if hidden[model] || (!unlimited[model] && q.Quota <= 0) {
			continue
		}
		line := LicenceLine{Model: model, Quota: q.Quota, Used: q.Used, Unlimited: unlimited[model], Free: free[model], Virtual: virtual(model)}
		p.Lines = append(p.Lines, line)
		if line.Unlimited {
			continue
		}
		total := max(0, q.Quota-line.Free)
		p.Total += total
		p.Used += min(q.Used, total)
	}
	sort.Slice(p.Lines, func(i, j int) bool { return p.Lines[i].Model < p.Lines[j].Model })
	return p
}

func (s *Service) sensorLicences(ctx context.Context, org upstream.Organization) (LicenceProgress, error) {
	var u licenceUsage
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/license-usage", &u); err != nil {
		return LicenceProgress{}, err
	}
	return licenceProgress(u, sensorLicenceHidden, sensorLicenceUnlimited, sensorLicenceFree,
		func(m string) bool { return virtualSensorModels[m] || m == "vlc" }), nil
}

func (s *Service) scannerLicences(ctx context.Context, org upstream.Organization) (LicenceProgress, error) {
	var u licenceUsage
	if err := s.up.RendallOrgGet(ctx, org.Pod, org.ID, "v1", "/scanner-license-usage", &u); err != nil {
		return LicenceProgress{}, err
	}
	return licenceProgress(u, nil, scannerLicenceUnlimited, nil, func(m string) bool { return m == "virtual" }), nil
}
