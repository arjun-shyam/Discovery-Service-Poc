# Discovery service (POC)

The onboarding facade from the Aurora SecOps architecture (the only "New" box). It combines existing services into the answers the Aurora setup hub and ASA need for UC-02 / UC-03.

**Status:** local POC, read-only, not pushed anywhere. Plan: `../../research/17_poc_end_to_end.md`.

## Rules
- Forwards the **caller's own Auth0 token** to upstream services. Holds no service credential, so it can only see what the user can see.
- **Read-only.** No writes to any system.
- Every answer carries `meta`: which services it came from (`sources`), when it was fetched (`fetchedAt`), whether it's faked (`stubbed`, `stubReason`), and which fields hold untrusted text (`untrustedFields`), so an AI treats log text as data, not instructions.

## Endpoints
| Endpoint | What it answers | Built on |
|---|---|---|
| `GET /v1/orgs?name=bacon` | Find an organization the user can see, with its pod | ELOC |
| `GET /v1/orgs/{org}/setup/status` | Setup hub: sites, sensors, cloud sensors, agents, log sources, each with a status | Rendall |
| `GET /v1/orgs/{org}/sites?name=topeka` | "I added logs to the Topeka sensor": matching sites and their sensors | Rendall |
| `GET /v1/orgs/{org}/log-sources?unrecognised=true` | Logs we can't read yet | Rendall → LSS |
| `GET /v1/orgs/{org}/log-sources/{name}/samples` | Real raw lines for one source + which sensor (deployment). Window: 24 h ending 2 h ago (archive lags). Cached 30 min | Rendall → Scrounger (Raw Log Search) |
| `GET /v1/orgs/{org}/log-sources/{name}/suggestions` | **Real** parser suggestions: LSS's own Identifier runs every identifiable parser (239) on ≤10 real lines; ranked by fields extracted, then LSS score | samples + `../parser-runner` |
| `GET /v1/orgs/{org}/log-sources/{name}/preview?parser=X` | **Real** preview: raw line next to the fields that parser extracts | samples + `../parser-runner` |

## Known gaps (found while building)
- Rendall's customer view of log sources has only `name, lastSeen, timezone, parsers (tags), tags`. It drops `suggested_parsers`, `has_configured_parser`, volume, deployment (sensor) and sample lines. So:
  - we can't tell parsed from unparsed sources: `parserStatus` is `configured` only when Rendall shows a parser tag, else `unknown` (on Bacon 706 of 846 are untagged, including clearly parsed ones like Google Workspace);
  - the list is per organization, not per sensor;
  Fix for the unparsed flag: extend Rendall's `/log-sources` response (Rendall already receives `has_configured_parser` from LSS). Suggestions and preview no longer need it (see parser runner).
- First call for a source takes ~75 s (raw log search job); later calls use the cache (~1 s). Each new search appears in the org's raw log search history.
- Setup status rules are heuristics over counts; real rules belong to the onboarding service.

## Parser runner (`../parser-runner`)
Python 3.12 venv running the **real** code: `rtklss.identification.suggest.Identifier` + `parse.base.CustomerStreamParserEngine` from `repos/awn`, with a carser bundle built from `repos/parse_and_detect` using the same file filter as `build_scripts/jenkins/update_carsers.sh`. Setup notes: `../parser-runner/README.md`.

## Run
```sh
# Against prod with your own token (read-only). Keep the token in a git-ignored file; never paste it in chat.
go run -buildvcs=false .
curl -H "Authorization: Bearer $(cat .token)" 'http://127.0.0.1:8090/v1/orgs?name=bacon'
```
Env: `DISCOVERY_ADDR` (default `127.0.0.1:8090`), `ELOC_URL`, `RENDALL_URL_TEMPLATE` (`%s` = pod), `UPSTREAM_TIMEOUT` (default `90s`; Bacon log sources are slow).

## Test
```sh
go test ./...   # unit tests use a fake upstream; the service itself only talks to real services
```
