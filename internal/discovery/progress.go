package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// knownAreas is the full set of onboarding areas used to compute PercentDone.
var knownAreas = []string{
	"sites",
	"single_sign_on",
	"contacts_and_escalation",
	"what_you_run",
	"sensors",
	"scanners",
	"cloud_sensors",
	"agents",
	"log_sources",
	"security_policies",
	"cloud_scanner",
}

// OnboardingProgress captures what the customer has done and their last conversation state.
// It is stored per-org (not per-user): onboarding is a team activity.
type OnboardingProgress struct {
	OrgID string `json:"orgId"`
	// Areas maps each setup area to one of: "not_started" | "in_progress" | "done" | "skipped".
	Areas map[string]string `json:"areas"`
	// CurrentArea is the area currently in progress (may be empty).
	CurrentArea string `json:"currentArea,omitempty"`
	// ConversationID is the ASA conversation thread for the onboarding session.
	ConversationID string `json:"conversationId,omitempty"`
	// Notes holds per-area free-text left by the customer or agent.
	Notes     map[string]string `json:"notes,omitempty"`
	UpdatedAt time.Time         `json:"updatedAt"`
	// MFAConfigured is set to true when the customer self-reports that they have installed
	// the Arctic Wolf mobile app and configured 2FA. Layer-2 fallback: Layer 1 is the amr
	// claim in the Auth0 JWT, which is authoritative when present.
	MFAConfigured bool `json:"mfaConfigured,omitempty"`
	// PercentDone is derived on read; not stored.
	PercentDone int `json:"percentDone"`
}

// OnboardingProgressUpdate carries the fields the API caller may change.
type OnboardingProgressUpdate struct {
	Areas          map[string]string `json:"areas,omitempty"`
	CurrentArea    string            `json:"currentArea,omitempty"`
	ConversationID string            `json:"conversationId,omitempty"`
	Notes          map[string]string `json:"notes,omitempty"`
	// MFAConfigured, when true, records that the customer confirmed app + 2FA setup.
	// A pointer so that omitting the field (nil) leaves any existing value unchanged.
	MFAConfigured *bool `json:"mfaConfigured,omitempty"`
}

// ErrInvalidOrgID is returned when an empty or invalid org id is given to the progress store.
var ErrInvalidOrgID = errors.New("org id must be non-empty")

// ProgressStore is a file-backed, thread-safe per-org onboarding progress store.
type ProgressStore struct {
	dataDir string
	mu      sync.RWMutex
	cache   map[string]OnboardingProgress
	locks   map[string]*sync.Mutex
	locksMu sync.Mutex
}

// NewProgressStore creates a store that persists under dataDir/progress/.
// Existing files are loaded on construction.
func NewProgressStore(dataDir string) (*ProgressStore, error) {
	dir := filepath.Join(dataDir, "progress")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("progress store: create dir %s: %w", dir, err)
	}
	store := &ProgressStore{
		dataDir: dataDir,
		cache:   map[string]OnboardingProgress{},
		locks:   map[string]*sync.Mutex{},
	}
	if err := store.load(dir); err != nil {
		return nil, err
	}
	return store, nil
}

// load reads all *.json files in dir into the cache (best-effort; corrupt files are skipped).
func (store *ProgressStore) load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // empty dir is fine
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var progress OnboardingProgress
		if err := json.Unmarshal(data, &progress); err != nil {
			continue
		}
		if progress.OrgID != "" {
			store.cache[progress.OrgID] = progress
		}
	}
	return nil
}

// orgLock returns the per-org mutex, creating it on first use.
func (store *ProgressStore) orgLock(orgID string) *sync.Mutex {
	store.locksMu.Lock()
	defer store.locksMu.Unlock()
	lock, ok := store.locks[orgID]
	if !ok {
		lock = &sync.Mutex{}
		store.locks[orgID] = lock
	}
	return lock
}

// GetProgress returns the saved progress for orgID, or (zero, false) if none exists.
func (store *ProgressStore) GetProgress(orgID string) (OnboardingProgress, bool) {
	store.mu.RLock()
	progress, ok := store.cache[orgID]
	store.mu.RUnlock()
	if !ok {
		return OnboardingProgress{}, false
	}
	progress.PercentDone = computePercent(progress.Areas)
	return progress, true
}

// PutProgress writes progress to the store. orgID must be non-empty.
func (store *ProgressStore) PutProgress(progress OnboardingProgress) error {
	if strings.TrimSpace(progress.OrgID) == "" {
		return ErrInvalidOrgID
	}
	orgLock := store.orgLock(progress.OrgID)
	orgLock.Lock()
	defer orgLock.Unlock()

	// Zero out derived field before persisting.
	toWrite := progress
	toWrite.PercentDone = 0

	data, err := json.MarshalIndent(toWrite, "", "  ")
	if err != nil {
		return fmt.Errorf("progress store: marshal: %w", err)
	}
	dir := filepath.Join(store.dataDir, "progress")
	path := filepath.Join(dir, progress.OrgID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("progress store: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("progress store: rename: %w", err)
	}

	store.mu.Lock()
	store.cache[progress.OrgID] = progress
	store.mu.Unlock()
	return nil
}

func computePercent(areas map[string]string) int {
	if len(areas) == 0 {
		return 0
	}
	done := 0
	for _, area := range knownAreas {
		status := areas[area]
		if status == "done" || status == "skipped" {
			done++
		}
	}
	return (done * 100) / len(knownAreas)
}

// --- Service methods ---

// GetOnboardingProgress returns the saved progress for an org, or a fresh empty progress.
func (s *Service) GetOnboardingProgress(_ context.Context, orgID string) (OnboardingProgress, error) {
	if s.progress == nil {
		return emptyProgress(orgID), nil
	}
	progress, ok := s.progress.GetProgress(orgID)
	if !ok {
		return emptyProgress(orgID), nil
	}
	return progress, nil
}

// PutOnboardingProgress merges the update into the saved progress and persists it.
func (s *Service) PutOnboardingProgress(_ context.Context, orgID string, update OnboardingProgressUpdate) (OnboardingProgress, error) {
	if strings.TrimSpace(orgID) == "" {
		return OnboardingProgress{}, ErrInvalidOrgID
	}
	if s.progress == nil {
		return OnboardingProgress{}, errors.New("progress store not available")
	}
	existing, _ := s.progress.GetProgress(orgID)
	merged := mergeProgress(existing, orgID, update)
	merged.UpdatedAt = time.Now()
	if err := s.progress.PutProgress(merged); err != nil {
		return OnboardingProgress{}, err
	}
	merged.PercentDone = computePercent(merged.Areas)
	return merged, nil
}

func emptyProgress(orgID string) OnboardingProgress {
	areas := make(map[string]string, len(knownAreas))
	for _, area := range knownAreas {
		areas[area] = "not_started"
	}
	return OnboardingProgress{OrgID: orgID, Areas: areas, PercentDone: 0}
}

func mergeProgress(existing OnboardingProgress, orgID string, update OnboardingProgressUpdate) OnboardingProgress {
	merged := existing
	merged.OrgID = orgID
	if merged.Areas == nil {
		merged.Areas = make(map[string]string, len(knownAreas))
		for _, area := range knownAreas {
			merged.Areas[area] = "not_started"
		}
	}
	for area, status := range update.Areas {
		merged.Areas[area] = status
	}
	if update.CurrentArea != "" {
		merged.CurrentArea = update.CurrentArea
	}
	if update.ConversationID != "" {
		merged.ConversationID = update.ConversationID
	}
	if len(update.Notes) > 0 {
		if merged.Notes == nil {
			merged.Notes = map[string]string{}
		}
		for key, value := range update.Notes {
			merged.Notes[key] = value
		}
	}
	if update.MFAConfigured != nil {
		merged.MFAConfigured = *update.MFAConfigured
	}
	return merged
}
