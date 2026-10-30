package discovery

import "testing"

func TestVisibilityForMatchesUnifiedPortal(t *testing.T) {
	maOnly := visibilityFor(Subscriptions{ManagedAwareness: true}, false)
	for id, want := range map[string]bool{"contacts": true, "internet_exposure": true, "sites": false, "sensors": false, "scanners": false, "agents": false, "cloud_sensors": false} {
		if maOnly[id] != want {
			t.Errorf("MA only: %s = %v, want %v", id, maOnly[id], want)
		}
	}
	avm := visibilityFor(Subscriptions{ManagedRisk: true}, false)
	if !avm["scanners"] || avm["sensors"] || avm["cloud_information"] || !avm["sites"] {
		t.Errorf("AVM only: got %v", avm)
	}
	mdrMSP := visibilityFor(Subscriptions{MDR: true}, true)
	if mdrMSP["contacts"] || !mdrMSP["escalation_contacts"] || !mdrMSP["sensors"] || mdrMSP["scanners"] {
		t.Errorf("MDR MSP child: got %v", mdrMSP)
	}
	if externalScansAllowed(Subscriptions{ManagedAwarenessPlus: true}) || !externalScansAllowed(Subscriptions{MDR: true}) {
		t.Error("external scans: MA-only must be false, MDR true")
	}
}

func TestSensorLicenceProgress(t *testing.T) {
	u := licenceUsage{Quotas: map[string]quota{
		"awnv100": {Quota: 1, Used: 1}, // free with MDR: not counted
		"vlc":     {Quota: 0, Used: 3}, // unlimited
		"vsensor": {Quota: 5, Used: 0}, // hidden
		"awn201":  {Quota: 2, Used: 1}, // one left to request
		"awn101":  {Quota: 0, Used: 0}, // no quota: hidden
	}}
	p := licenceProgress(u, sensorLicenceHidden, sensorLicenceUnlimited, sensorLicenceFree,
		func(m string) bool { return virtualSensorModels[m] || m == "vlc" })
	if p.Used != 1 || p.Total != 2 || p.Done() {
		t.Fatalf("progress = %d/%d done=%v, want 1/2 not done", p.Used, p.Total, p.Done())
	}
	left := p.PhysicalRemaining()
	if len(left) != 1 || left["awn201"] != 1 {
		t.Fatalf("physical remaining = %v, want awn201:1", left)
	}
	if len(p.Lines) != 3 {
		t.Fatalf("lines = %v, want awn201, awnv100, vlc", p.Lines)
	}
}

func TestScannerLicenceProgressVirtualUnlimited(t *testing.T) {
	p := licenceProgress(licenceUsage{Quotas: map[string]quota{"virtual": {Quota: 0, Used: 2}}}, nil, scannerLicenceUnlimited, nil,
		func(m string) bool { return m == "virtual" })
	if p.Total != 0 || !p.Done() {
		t.Fatalf("virtual-only scanners = %d/%d, want 0/0 done", p.Used, p.Total)
	}
}

func TestValidScanTarget(t *testing.T) {
	for _, ok := range []string{"8.8.8.0/21", "8.8.8.8", "8.8.8.1-8.8.8.9", "vpn.acme.io", "aws:123456789012", "gcp:my-project-1", "azure:0f8fad5b-d9cb-469f-a165-70867728950e"} {
		if err := validScanTarget(ok); err != nil {
			t.Errorf("%s: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"8.8.0.0/20", "aws:123", "gcp:A", "azure:nope", "2001:db8::1"} {
		if err := validScanTarget(bad); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}
