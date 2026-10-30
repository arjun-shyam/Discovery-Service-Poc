// Package api exposes the discovery service over HTTP. Read-only in this version.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/notxdr/discovery-service/internal/discovery"
	"github.com/notxdr/discovery-service/internal/mcp"
	"github.com/notxdr/discovery-service/internal/upstream"
)

// checklistInFlight stops page loads from starting the same background checklist twice.
var checklistInFlight sync.Map

type envelope struct {
	Data any            `json:"data"`
	Meta discovery.Meta `json:"meta"`
}

type errorBody struct {
	Error string `json:"error"`
}

// NewRouter wires the routes. Every /v1 route requires the caller's bearer token,
// which is forwarded unchanged to upstream services.
func NewRouter(svc *discovery.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /v1/orgs", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.FindOrganizations(r.Context(), r.URL.Query().Get("name"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/setup/status", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.SetupStatus(r.Context(), r.PathValue("org"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/sites", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.SitesWithSensors(r.Context(), r.PathValue("org"), r.URL.Query().Get("name"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/sensors", withToken(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		data, meta, err := svc.Sensors(r.Context(), r.PathValue("org"), discovery.SensorQuery{
			Kind: q.Get("kind"), Status: q.Get("status"), NameContains: q.Get("name"), SiteContains: q.Get("site"), Limit: limit,
		})
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/log-sources", withToken(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		query := discovery.LogSourceQuery{NameContains: q.Get("name"), Parser: q.Get("parser"), Sensor: q.Get("sensor")}
		if q.Get("unrecognised") == "true" { // older name for parser=none
			query.Parser = discovery.ParserNone
		}
		query.NewSinceDays, _ = strconv.Atoi(q.Get("newSinceDays"))
		query.Limit, _ = strconv.Atoi(q.Get("limit"))
		data, meta, err := svc.LogSources(r.Context(), r.PathValue("org"), query)
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/log-sources/{name}/samples", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.Samples(r.Context(), r.PathValue("org"), r.PathValue("name"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/log-sources/{name}/suggestions", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.Suggestions(r.Context(), r.PathValue("org"), r.PathValue("name"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/log-sources/{name}/preview", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.Preview(r.Context(), r.PathValue("org"), r.PathValue("name"), r.URL.Query().Get("parser"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/parsers/{parser}/activity", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.ParserActivity(r.Context(), r.PathValue("org"), r.PathValue("parser"))
		respond(w, data, meta, err)
	}))
	// Confirm card: read a prepared change, and send secure fields straight here (never via chat).
	mux.HandleFunc("GET /v1/orgs/{org}/changes/{id}", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.GetChange(r.Context(), r.PathValue("org"), r.PathValue("id"))
		respond(w, data, meta, err)
	}))
	mux.HandleFunc("POST /v1/orgs/{org}/changes/{id}/secrets", withToken(func(w http.ResponseWriter, r *http.Request) {
		var values map[string]string
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&values); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "body must be a JSON object of strings"})
			return
		}
		data, meta, err := svc.SetChangeSecrets(r.Context(), r.PathValue("org"), r.PathValue("id"), values)
		respond(w, data, meta, err)
	}))
	// MFA / mobile-app gate: returns whether the signed-in user has MFA configured.
	mux.HandleFunc("GET /v1/orgs/{org}/mfa/status", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta := svc.CheckMFAStatus(r.Context(), r.PathValue("org"))
		writeJSON(w, http.StatusOK, envelope{Data: data, Meta: meta})
	}))
	mux.HandleFunc("GET /v1/orgs/{org}/onboarding/checklist", withToken(func(w http.ResponseWriter, r *http.Request) {
		data, meta, err := svc.OnboardingChecklist(r.Context(), r.PathValue("org"))
		respond(w, data, meta, err)
	}))
	// Onboarding progress — GET returns current state (empty struct for new orgs); PUT merges.
	mux.HandleFunc("GET /v1/orgs/{org}/onboarding/progress", withToken(func(w http.ResponseWriter, r *http.Request) {
		org := r.PathValue("org")
		data, err := svc.GetOnboardingProgress(r.Context(), org)
		if err != nil {
			respond(w, nil, discovery.Meta{}, err)
			return
		}
		// percentDone comes from the live onboarding checklist (same rule as the Unified
		// Portal); compute it in the background on a cache miss so this call stays fast.
		sources := []string{"discovery (local progress store)"}
		pct, found, fresh := discovery.CachedChecklistPercent(org)
		if found {
			data.PercentDone = pct
			sources = append(sources, "live onboarding checklist")
		}
		if !fresh {
			bg := upstream.WithToken(context.Background(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if _, busy := checklistInFlight.LoadOrStore(org, true); !busy {
				go func() {
					defer checklistInFlight.Delete(org)
					ctx, cancel := context.WithTimeout(bg, 3*time.Minute)
					defer cancel()
					_, _, _ = svc.OnboardingChecklist(ctx, org)
				}()
			}
		}
		writeJSON(w, http.StatusOK, envelope{Data: data, Meta: discovery.Meta{Sources: sources}})
	}))
	mux.HandleFunc("PUT /v1/orgs/{org}/onboarding/progress", withToken(func(w http.ResponseWriter, r *http.Request) {
		var update discovery.OnboardingProgressUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&update); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid JSON body"})
			return
		}
		data, err := svc.PutOnboardingProgress(r.Context(), r.PathValue("org"), update)
		if err != nil {
			respond(w, nil, discovery.Meta{}, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope{Data: data, Meta: discovery.Meta{Sources: []string{"discovery (local progress store)"}}})
	}))
	// CITL callback: fired by citl-local when a customer approves/rejects an action.
	// The request comes from CITL itself (no user bearer token), so we don't use withToken here.
	mux.HandleFunc("POST /v1/orgs/{org}/changes/{id}/callback", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Approved bool   `json:"approved"`
			ActedBy  string `json:"acted_by"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid JSON body"})
			return
		}
		log.Printf("citl callback: org=%s change=%s approved=%v by=%s", r.PathValue("org"), r.PathValue("id"), body.Approved, body.ActedBy)
		// For now just acknowledge; a future iteration will auto-apply on approval.
		writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
	})
	// MCP endpoint for ASA (streamable HTTP). Same tools, same token pass-through.
	mux.Handle("/mcp", mcp.Handler(svc))
	return mux
}

func withToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || strings.TrimSpace(token) == "" {
			writeJSON(w, http.StatusUnauthorized, errorBody{Error: "missing bearer token"})
			return
		}
		next(w, r.WithContext(upstream.WithToken(r.Context(), strings.TrimSpace(token))))
	}
}

func respond(w http.ResponseWriter, data any, meta discovery.Meta, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, envelope{Data: data, Meta: meta})
		return
	}
	var upErr *upstream.Error
	switch {
	case errors.Is(err, discovery.ErrChangeInvalid):
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: err.Error()})
	case errors.Is(err, discovery.ErrNotFound), errors.Is(err, discovery.ErrChangeNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{Error: err.Error()})
	case errors.Is(err, upstream.ErrNoToken):
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: err.Error()})
	case errors.As(err, &upErr) && (upErr.Status == http.StatusUnauthorized || upErr.Status == http.StatusForbidden):
		writeJSON(w, upErr.Status, errorBody{Error: upErr.Service + " refused the request for this user"})
	default:
		log.Printf("upstream error: %v", err)
		writeJSON(w, http.StatusBadGateway, errorBody{Error: "an upstream service failed; see server log"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
