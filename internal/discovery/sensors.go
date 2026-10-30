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

// --- Sensors and cloud sensors with status (UC-03 "which sensors need attention?") ---
//
// Rendall lists every sensor with a status but not the reason it is unhealthy; health
// details live in gto-health-check, which has no customer-facing API yet.

const (
	SensorKindSensor = "sensor" // physical, virtual and VLC sensors
	SensorKindCloud  = "cloud"  // cloud sensors (API integrations)
	sensorTTL        = 5 * time.Minute
)

type SensorView struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// Sensor is the deployment id; log sources reference it as their sensor.
	Sensor string `json:"sensor,omitempty"`
	// SerialNumber identifies the appliance for activation (activate_appliance).
	SerialNumber string `json:"serialNumber,omitempty"`
	// Product is physical | virtual | vlc for sensors, the vendor for cloud sensors.
	Product     string `json:"product,omitempty"`
	Model       string `json:"model,omitempty"`
	IP          string `json:"ip,omitempty"`
	Site        string `json:"site,omitempty"`
	ShippedDate string `json:"shippedDate,omitempty"`
	// LastLogSeen is the newest last-seen time of any log source on this sensor (LSS).
	LastLogSeen *time.Time `json:"lastLogSeen,omitempty"`
	LogSources  int        `json:"logSources,omitempty"`
}

type SensorQuery struct {
	Kind         string // sensor | cloud | "" (both)
	Status       string // exact status, e.g. unhealthy, invalidCredentials
	NameContains string
	SiteContains string
	Limit        int // default 25, max 200
}

type SensorList struct {
	Total    int `json:"total"`
	Matched  int `json:"matched"`
	Returned int `json:"returned"`
	// ByStatus counts every sensor of the requested kind(s) per kind and status.
	ByStatus map[string]map[string]int `json:"byStatus"`
	Sensors  []SensorView              `json:"sensors"`
}

func (s *Service) Sensors(ctx context.Context, orgID string, q SensorQuery) (SensorList, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall"}, FetchedAt: s.now(), UntrustedFields: []string{"sensors[].name", "sensors[].site"},
		Notes: []string{"status only: the reason a sensor is unhealthy is not available from customer-facing APIs yet"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return SensorList{}, meta, err
	}
	kinds := []string{SensorKindSensor, SensorKindCloud}
	if q.Kind == SensorKindSensor || q.Kind == SensorKindCloud {
		kinds = []string{q.Kind}
	}

	all := make([][]SensorView, len(kinds))
	errs := make([]error, len(kinds))
	var wg sync.WaitGroup
	// Log sources per sensor say when each sensor last delivered logs (LSS only).
	var sources []LogSourceView
	var sourcesOrigin string
	wg.Add(1)
	go func() {
		defer wg.Done()
		sources, sourcesOrigin, _, _, _ = s.allLogSources(ctx, org)
	}()
	for i, kind := range kinds {
		wg.Add(1)
		go func(i int, kind string) {
			defer wg.Done()
			all[i], errs[i] = s.allSensors(ctx, org, kind)
		}(i, kind)
	}
	wg.Wait()

	out := SensorList{ByStatus: map[string]map[string]int{}}
	var views []SensorView
	for i, kind := range kinds {
		if errs[i] != nil {
			if len(kinds) == 1 {
				return SensorList{}, meta, errs[i]
			}
			meta.Notes = append(meta.Notes, fmt.Sprintf("%s sensors unavailable: %v", kind, errs[i]))
			continue
		}
		counts := map[string]int{}
		for _, v := range all[i] {
			counts[v.Status]++
		}
		out.ByStatus[kind] = counts
		views = append(views, all[i]...)
	}
	out.Total = len(views)
	if sourcesOrigin == "lss" {
		views = withLastLog(views, sources)
		meta.Sources = append(meta.Sources, "lss (last log per sensor)")
	}

	name := strings.ToLower(strings.TrimSpace(q.NameContains))
	site := strings.ToLower(strings.TrimSpace(q.SiteContains))
	matched := make([]SensorView, 0, len(views))
	for _, v := range views {
		if q.Status != "" && !strings.EqualFold(v.Status, q.Status) {
			continue
		}
		if name != "" && !strings.Contains(strings.ToLower(v.Name), name) {
			continue
		}
		if site != "" && !strings.Contains(strings.ToLower(v.Site), site) {
			continue
		}
		matched = append(matched, v)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLogSourceLimit
	}
	limit = min(limit, maxLogSourceLimit)
	out.Matched = len(matched)
	out.Sensors = matched[:min(limit, len(matched))]
	out.Returned = len(out.Sensors)
	if out.Returned < out.Matched {
		meta.Notes = append(meta.Notes, fmt.Sprintf("showing %d of %d matches; narrow with filters or raise limit", out.Returned, out.Matched))
	}
	return out, meta, nil
}

// withLastLog copies views, adding when each sensor last delivered any log source.
func withLastLog(views []SensorView, sources []LogSourceView) []SensorView {
	type stat struct {
		last  time.Time
		count int
	}
	bySensor := map[string]stat{}
	for _, src := range sources {
		st := bySensor[src.Sensor]
		st.count++
		if src.LastSeen.After(st.last) {
			st.last = src.LastSeen
		}
		bySensor[src.Sensor] = st
	}
	out := make([]SensorView, len(views))
	for i, v := range views {
		if st, ok := bySensor[v.Sensor]; ok && v.Sensor != "" {
			last := st.last
			v.LastLogSeen, v.LogSources = &last, st.count
		}
		out[i] = v
	}
	return out
}

// WarmSensors fetches sensor lists in the background so a later list_sensors is fast.
func (s *Service) WarmSensors(ctx context.Context, org upstream.Organization) {
	for _, kind := range []string{SensorKindSensor, SensorKindCloud} {
		go func(kind string) { _, _ = s.allSensors(context.WithoutCancel(ctx), org, kind) }(kind)
	}
}

// allSensors returns one kind of sensor for the org, cached for sensorTTL (cloud sensors
// take 30-40 s for large orgs).
func (s *Service) allSensors(ctx context.Context, org upstream.Organization, kind string) ([]SensorView, error) {
	e := s.sensors.entry(org.ID + "|" + kind)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.views != nil && s.now().Sub(e.at) < sensorTTL {
		return e.views, nil
	}
	var views []SensorView
	switch kind {
	case SensorKindSensor:
		rows, err := s.up.Sensors(ctx, org.Pod, org.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			views = append(views, SensorView{Kind: kind, Name: r.Name, Status: r.Status, Sensor: r.DeploymentID, SerialNumber: r.SerialNumber,
				Product: r.Product, Model: r.Model, IP: r.IP, Site: r.SiteName, ShippedDate: r.ShippedDate})
		}
	case SensorKindCloud:
		rows, err := s.up.CloudSensors(ctx, org.Pod, org.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			views = append(views, SensorView{Kind: kind, Name: r.Name, Status: r.Status, Sensor: r.DeploymentID, Product: r.Vendor})
		}
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	if views == nil {
		views = []SensorView{}
	}
	e.views, e.at = views, s.now()
	return views, nil
}

type sensorEntry struct {
	mu    sync.Mutex
	views []SensorView
	at    time.Time
}

type sensorCache struct {
	mu sync.Mutex
	m  map[string]*sensorEntry
}

func (c *sensorCache) entry(key string) *sensorEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*sensorEntry{}
	}
	e, ok := c.m[key]
	if !ok {
		e = &sensorEntry{}
		c.m[key] = e
	}
	return e
}

// --- Where to send syslog (UC-02 "point your firewall at the sensor") ---

// SyslogPort is a documented syslog listener on Arctic Wolf sensors and vLCs.
type SyslogPort struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Use       string `json:"use"`
	Doc       string `json:"doc"`
}

// sensorSyslogPorts come from Arctic Wolf's syslog configuration guides (Confluence
// 6883049722: sensor IP, port 514, standard syslog, no secure transmission; 3100443051 and
// 5031595461: TLS syslog on 6514 with the sensor certificate).
var sensorSyslogPorts = []SyslogPort{
	{Port: 514, Transport: "udp or tcp", Use: "standard syslog (default; turn off the device's own 'secure transmission')", Doc: "Confluence 6883049722"},
	{Port: 6514, Transport: "tcp+tls", Use: "secure syslog, only when the device must use TLS (uses the sensor certificate)", Doc: "Confluence 3100443051"},
}

type SyslogDestination struct {
	// Source is the log source the destination was found for (empty when asked by sensor).
	Source      string       `json:"source,omitempty"`
	Sensor      SensorView   `json:"sensor"`
	Destination string       `json:"destination"` // the sensor IP the device should send to
	Ports       []SyslogPort `json:"ports"`
	// OtherSourcesOnSensor counts other sources arriving on this sensor in the last 24 h,
	// a quick sign the sensor itself is receiving syslog.
	OtherSourcesOnSensor int `json:"otherSourcesOnSensorLast24h"`
}

// SyslogDestination finds the sensor a device should send syslog to: the sensor a log source
// already arrives on (source), or a sensor by deployment id or name (sensor).
func (s *Service) SyslogDestination(ctx context.Context, orgID, source, sensor string) (SyslogDestination, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "rendall (sensors)", "lss (log sources)", "arctic wolf syslog guides"}, FetchedAt: s.now(),
		UntrustedFields: []string{"sensor.name", "sensor.site", "source"}}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return SyslogDestination{}, meta, err
	}
	sources, origin, _, _, _ := s.allLogSources(ctx, org)
	out := SyslogDestination{Ports: sensorSyslogPorts}

	deployment := strings.TrimSpace(sensor)
	if source != "" {
		if origin != "lss" {
			return out, meta, fmt.Errorf("finding a source's sensor needs LSS, which is unreachable; ask which sensor or site instead")
		}
		var last time.Time
		for _, v := range sources {
			if strings.EqualFold(v.Name, source) && v.LastSeen.After(last) {
				last, deployment, out.Source = v.LastSeen, v.Sensor, v.Name
			}
		}
		if out.Source == "" {
			return out, meta, fmt.Errorf("log source %q: %w", source, ErrNotFound)
		}
	}
	if deployment == "" {
		return out, meta, fmt.Errorf("give a log source or a sensor")
	}

	sensors, err := s.allSensors(ctx, org, SensorKindSensor)
	if err != nil {
		return out, meta, err
	}
	if origin == "lss" {
		sensors = withLastLog(sensors, sources)
	}
	needle := strings.ToLower(deployment)
	found := false
	for _, v := range sensors {
		if strings.EqualFold(v.Sensor, deployment) || (out.Source == "" && strings.Contains(strings.ToLower(v.Name), needle)) {
			out.Sensor, found = v, true
			break
		}
	}
	if !found {
		return out, meta, fmt.Errorf("sensor %q: %w", deployment, ErrNotFound)
	}
	out.Destination = out.Sensor.IP

	dayAgo := s.now().Add(-24 * time.Hour)
	for _, v := range sources {
		if v.Sensor == out.Sensor.Sensor && !strings.EqualFold(v.Name, out.Source) && v.LastSeen.After(dayAgo) {
			out.OtherSourcesOnSensor++
		}
	}
	if out.Destination == "" {
		meta.Notes = append(meta.Notes, "this sensor has no IP on record; ask Arctic Wolf support for its log collection address")
	}
	if out.Sensor.Status != "healthy" {
		meta.Notes = append(meta.Notes, "sensor status is "+out.Sensor.Status+": fix the sensor before expecting logs")
	}
	meta.Notes = append(meta.Notes, "ports are Arctic Wolf's documented sensor syslog listeners, not read from this sensor's config")
	return out, meta, nil
}
