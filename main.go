// Discovery service POC: the onboarding facade from the Aurora SecOps architecture.
// Read-only. Forwards the caller's own token to existing services; holds no secrets.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/notxdr/discovery-service/internal/api"
	"github.com/notxdr/discovery-service/internal/discovery"
	"github.com/notxdr/discovery-service/internal/parser"
	"github.com/notxdr/discovery-service/internal/upstream"
)

func main() {
	addr := env("DISCOVERY_ADDR", "127.0.0.1:8090")
	cfg := upstream.Config{
		ElocURL:            env("ELOC_URL", "https://eloc.managedgw.global-prod.arcticwolf.net"),
		RendallURLTemplate: env("RENDALL_URL_TEMPLATE", "https://rendall.managedgw.%s-prod.arcticwolf.net"),
		ASAURLTemplate:     env("ASA_URL_TEMPLATE", "https://ai-security-assistant.managedgw.%s-prod.arcticwolf.net"),
		// In-VPC; reachable from a laptop only on the Production employee VPN. "off" disables.
		LSSURLTemplate: lssURL(env("LSS_URL_TEMPLATE", "https://lss.logsource.prod.%s-prod.rtkwlf.io")),
		// In-VPC like LSS: the onboarding service (purchased products, licences, onboarding status).
		OnboardingURLTemplate: lssURL(env("ONBOARDING_URL_TEMPLATE", "https://onboarding-eks.onboarding.prod.%s-prod.rtkwlf.io")),
		// Log Source Orchestrator via the managed API gateway; %s = pod. Off by default: LSO's
		// write API is PR rtkwlf/log-source-orchestrator#55 and LSO isn't in every pod yet.
		LSOURLTemplate: lssURL(env("LSO_URL_TEMPLATE", "off")),
		// Ingestion orchestrator (Aurora Integrations): cloud apps connect, resume and change here,
		// so Aurora's Integrations page shows the same state. "off" falls back to Rendall cloud sensors.
		IngestionURLTemplate: lssURL(env("INGESTION_URL_TEMPLATE", "https://ingestion-orchestrator-prod.managedgw.%s-prod.arcticwolf.net/api/v1")),
		// Credential Management Service: cloud scanner (CSPM) accounts, like the Unified Portal.
		CMSURLTemplate: lssURL(env("CMS_URL_TEMPLATE", "https://credentialmanagementservice.managedgw.%s-prod.arcticwolf.net")),
		// Detection catalog behind the global managed gateway (host unverified until the first live call).
		DetectionURL: env("DETECTION_URL", "https://detection-service.managedgw.global-prod.arcticwolf.net"),
		Timeout:      durationEnv("UPSTREAM_TIMEOUT", 120*time.Second),
	}

	log.Printf("upstreams: eloc=%s rendall=%s lss=%s onboarding=%s", cfg.ElocURL, cfg.RendallURLTemplate, cfg.LSSURLTemplate, cfg.OnboardingURLTemplate)

	runner := parser.Runner{Dir: env("PARSER_RUNNER_DIR", "../parser-runner")}
	log.Printf("parser runner: %s", runner.Dir)

	origins := strings.Split(env("DISCOVERY_CORS_ORIGINS", "http://localhost:3000"), ",")
	handler := api.WithRequestLog(api.WithCORS(api.NewRouter(discovery.New(upstream.New(cfg), runner)), origins))
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("discovery service listening on http://%s", addr)
	log.Fatal(server.ListenAndServe())
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func lssURL(v string) string {
	if v == "off" {
		return ""
	}
	return v
}
