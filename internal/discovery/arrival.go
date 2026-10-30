package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// --- "I'll confirm when packets arrive" (UC-03 syslog step) ---
//
// After the customer points a device at a sensor or vLC, the Log Source Service records the new
// source (name = sending host or IP, per deployment) when its first lines arrive. WatchForLogs reads
// LSS directly (not the 5-minute cache) every few seconds until the source shows up or the wait ends.

// LogArrival is the outcome of one watch.
type LogArrival struct {
	Arrived   bool           `json:"arrived"`
	Source    *LogSourceView `json:"source,omitempty"`
	WaitedSec int            `json:"waitedSeconds"`
	NextStep  string         `json:"nextStep"`
}

const (
	maxArrivalWait  = 90 * time.Second
	arrivalInterval = 10 * time.Second
)

// WatchForLogs waits up to waitSec (max 90) for a source matching source (name or IP, contains) on
// the given sensor (deployment id, optional) to be seen by LSS.
func (s *Service) WatchForLogs(ctx context.Context, orgID, source, sensor string, waitSec int) (LogArrival, Meta, error) {
	meta := Meta{Sources: []string{"eloc", "lss (live, not cached)"}, FetchedAt: s.now(), UntrustedFields: []string{"source.name"}}
	source, sensor = strings.ToLower(strings.TrimSpace(source)), strings.ToLower(strings.TrimSpace(sensor))
	if source == "" {
		return LogArrival{}, meta, fmt.Errorf("%w: give the device's IP or hostname as source", ErrChangeInvalid)
	}
	org, err := s.resolve(ctx, orgID)
	if err != nil {
		return LogArrival{}, meta, err
	}
	wait := time.Duration(waitSec) * time.Second
	if wait <= 0 || wait > maxArrivalWait {
		wait = maxArrivalWait
	}
	start := s.now()
	for {
		recs, err := s.up.LSSLogSources(ctx, org.Pod, org.CustomerID)
		if err != nil {
			return LogArrival{}, meta, fmt.Errorf("can't check arrivals: the Log Source Service is unreachable (%v); check again later or look in list_log_sources", err)
		}
		for _, v := range fromLSS(recs) {
			if strings.Contains(strings.ToLower(v.Name), source) && (sensor == "" || strings.Contains(strings.ToLower(v.Sensor), sensor)) {
				v := v
				invalidateLogSources(s, org.ID)
				next := "Logs are arriving. Next: confirm its parser (suggest_parser / set_log_source_parser)."
				if v.ParserStatus == ParserConfigured {
					next = "Logs are arriving and already parsed by " + v.Parser + "; detections run on them."
				}
				return LogArrival{Arrived: true, Source: &v, WaitedSec: int(s.now().Sub(start).Seconds()), NextStep: next}, meta, nil
			}
		}
		if s.now().Sub(start)+arrivalInterval > wait {
			break
		}
		select {
		case <-ctx.Done():
			return LogArrival{}, meta, ctx.Err()
		case <-time.After(arrivalInterval):
		}
	}
	return LogArrival{Arrived: false, WaitedSec: int(s.now().Sub(start).Seconds()),
		NextStep: "Nothing yet. Usually the first lines arrive within a few minutes of the device being pointed at the sensor. " +
			"Check: the device sends to the sensor IP and port from get_syslog_destination, the firewall between them allows it, and the device's logging is on. Offer to check again."}, meta, nil
}

// invalidateLogSources drops the cached source list so the next read includes the new source.
func invalidateLogSources(s *Service, orgID string) {
	e := s.logSources.entry(orgID)
	e.mu.Lock()
	e.views = nil
	e.mu.Unlock()
}
