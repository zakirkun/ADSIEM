# PROJECT KNOWLEDGE BASE

**Generated:** 2026-10-20
**Commit:** c7824c6
**Branch:** nightmare-c0de

## OVERVIEW

Modular SIEM platform: Go endpoint agent (Linux + Windows) → FastAPI ingest → Python/Redis-Streams detection worker → React SOC dashboard, backed by PostgreSQL + Elasticsearch, deployed via Docker Compose.

## STRUCTURE

```
.
├── agent/          # Go endpoint agent — Linux (eBPF/FIM/firewall) + Windows (event log/plugins)
├── server-api/     # FastAPI REST API + agent ingest + WebSocket alert push
├── worker/         # Python async detection pipeline (worker/worker/** — package nested one level down)
├── dashboard/      # React 18 + Vite + Tailwind SPA
├── rules/          # 105 Sigma YAML rules — seeded to DB on worker start
├── decoders/       # 80 regex/kv YAML decoders — seeded to DB on worker start
├── db/init.sql     # Postgres schema bootstrap (23 tables; extensions, roles, users, agents, ...)
├── nginx/          # Reverse proxy + TLS term (nginx.conf dev, nginx.dev.conf, nginx.prod.conf)
├── tests/          # pytest by service + sigmahq/ windows/ sim/ harnesses
├── sim/            # demo lab: agent-demo VM (vulnerable app) + attacker container
├── searxng/        # settings.yml for the search backend behind the AI assistant
├── docs/           # PROJECT_OVERVIEW.md, llm-gateway-spec.md, superpowers/ plans
└── docker-compose.yml (+ .dev / .prod overrides)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Agent main loop, wiring of every subsystem | `agent/cmd/agent/main.go` | enroll → tailer → config watch → hygiene → FIM → firewall → flows → procexec → netwatch → heartbeat → sender |
| Log tailing w/ glob + rotation + copytruncate | `agent/internal/tailer/tailer.go` | entries encoded `logType\x00rawMessage`; `Decode()` reverses it |
| eBPF process-exec / network | `agent/internal/procexec/`, `agent/internal/netwatch/` | both `.bpf.c` must be clang-compiled before Go build |
| Windows event log | `agent/internal/winevent/` | `eventlog:<Channel>` log sources via `EvtSubscribe` |
| API app + router registration | `server-api/app/main.py` | 40 route modules; all listed in one `for router in [...]` loop at EOF |
| Auth / RBAC / group scoping | `server-api/app/core/deps.py` | `require_permission()`, `get_scoped_group()`, `fetch_scoped()`, `assert_group_access()` |
| ORM models (all of them) | `server-api/app/models/models.py` | single 38 KB module |
| Pydantic schemas (all of them) | `server-api/app/schemas/schemas.py` | single 27 KB module |
| Detection pipeline entry | `worker/worker/main.py` | `asyncio.gather()` launches 19 supervised loops |
| Stream consume → decode → sigma → alert | `worker/worker/consumer.py` | DLQ at `{REDIS_STREAM_KEY}:failed`, retried every 300s |
| Rule seeding | `worker/worker/seeder.py` | seeds `rules/` + `decoders/` into DB, new titles only |
| Case grouping (one attacker = one case) | `worker/worker/case_grouping.py` | IOC-keyed campaigns; hosts/users are never keys |
| SOAR playbooks | `worker/worker/soar_engine.py` | triggered from alert creation |
| UEBA | `worker/worker/ueba/` | Isolation Forest scorer + trainer + explain + loops |
| Threat intel providers | `worker/worker/ti/providers/` | abuseipdb, virustotal, shodan, otx, greynoise, urlhaus, geoip, whois, base |
| Dashboard routes | `dashboard/src/App.tsx` | 34 `<Route>` entries, 30 pages; role gating nested `<ProtectedRoute minRole=...>` |
| Dashboard API client | `dashboard/src/api/client.ts` | axios; token from `stores/auth.ts` |
| Postgres schema | `db/init.sql` | `pgcrypto` + `vector` extensions enabled |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `main` | func | `agent/cmd/agent/main.go` | agent entry — bootstraps every subsystem |
| `Enroll` | func | `agent/internal/enrollment/enrollment.go` | first-run enroll; retries w/ exponential backoff |
| `Tail` / `Decode` | func | `agent/internal/tailer/tailer.go` | log tailing + entry codec |
| `lifespan` | func | `server-api/app/main.py:445` | one-replica-at-a-time migrations via `pg_advisory_lock(727501001)` |
| `get_current_user` / `require_permission` / `get_scoped_group` / `fetch_scoped` / `get_agent` | func | `server-api/app/core/deps.py` | auth + RBAC + group filter + scoped load + agent-token auth |
| `Agent` | model | `server-api/app/models/models.py` | most-referenced model across route modules |
| `main` | func | `worker/worker/main.py` | worker entry — seeds, loads engines, gathers 19 loops |
| `consume_loop` / `process_message` / `load_engines` | func | `worker/worker/consumer.py` | stream ingest → decode → sigma → alert (no tests) |
| `next_concurrency` | func | `worker/worker/adaptive.py` | AIMD consume concurrency from stream lag + cgroup CPU/mem |
| `App` | func | `dashboard/src/App.tsx:39` | route table + auth rehydrate |

## CONVENTIONS

- **Python**: async-first (SQLAlchemy `AsyncSession`, `redis.asyncio`). Structured logging via `structlog` only — no `print`. `pytest` `asyncio_mode = auto`, so `async def test_*` needs no decorator.
- **Two DBs, two purposes**: Postgres = config/metadata (rules, alerts, cases, users); Elasticsearch = raw + decoded events. Writes go to both.
- **Group scoping is mandatory**: non-superadmin queries filter by `group_id`. Single-resource routes use `fetch_scoped()` (404, never 403 — do not confirm another tenant's object exists).
- **Rules/decoders are data**: add YAML files to `rules/` / `decoders/` — seeding is idempotent by `title`/`name`, so DB edits are never clobbered. `process_creation` rules use Sigma field names (`Image`, `CommandLine`), everything else ECS dotted fields (`event.action`, `source.ip`).
- **Agent→server contract**: log ingest `POST /api/ingest/log`; FIM `POST /api/fim`; heartbeat drives live log-source/FIM-path updates and task dispatch; flows long-poll `/api/agent/flows/poll`.
- **Dashboard**: Vite + TS strict; hooks in `src/hooks/` wrap TanStack Query; server state via react-query, auth via zustand. Path alias `@/` → `src/`.
- **Routers must be registered** in the `main.py` list or they 404 silently.

## ANTI-PATTERNS (THIS PROJECT)

- **NEVER commit real secrets**: `JWT_SECRET`, `POSTGRES_PASSWORD`, `AGENT_ENROLLMENT_TOKEN`, `NINEROUTER_*`, `SEARXNG_SECRET`. Defaults (`admin`/`admin123`) are dev-only.
- **NEVER point the agent at `http://`**: nginx 301-redirects to HTTPS and Go downgrades POST→GET on 301, turning every ingest into a 405. Always `https://`.
- **NEVER ship a self-signed cert without SAN + `basicConstraints = CA:TRUE`** — plain `openssl req -x509 -subj "/CN=..."` breaks agent TLS verification and `update-ca-trust` silently drops it.
- **Do not add `CREATE TABLE` to `db/init.sql` for new features** — API startup runs `Base.metadata.create_all` plus `_migrate_*` helpers; add a migration helper instead. (`init.sql`'s 23 tables are the bootstrap floor, not the schema of record.)
- **Do not run migrations without the advisory lock** (`_STARTUP_LOCK_KEY = 727501001`) — concurrent replicas deadlock on `ALTER TABLE`.
- **eBPF/FIM/firewall/netwatch failures must degrade gracefully** (warn, don't crash) — they need root + BTF kernel and are optional by design.
- **Do not use `as any` / `@ts-ignore`** in dashboard; do not silence type errors in Python either.

## UNIQUE STYLES

- **Worker package nesting**: code lives in `worker/worker/` (repo dir = image root, inner dir = importable package). `worker/tests/` is a *third* layer.
- Two-DB writes plus best-effort side effects: UEBA scoring is wrapped in `try/except` and explicitly "never blocks the main pipeline".
- Service tiers split as `docker-compose.yml` (base) + `.dev` (hot reload, 5432/6379/9200/5173 exposed, HTTP:80) + `.prod` (2× server-api, 2× worker, resource limits, TLS; `agent-demo` behind `profiles: ["demo"]`).
- Agent's in-memory buffer re-queues on 5xx and drops on 4xx with an error log — deliberate.
- Repository-local docs are mixing English/Indonesian (`docs/PROJECT_OVERVIEW.md`, `prompt.md`) — leave as-is.

## COMMANDS

```bash
# Dev stack (hot reload, HTTP:80, DB ports exposed)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

# Prod stack (replicas + limits + TLS)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Tests — Python (importlib mode is required; see pytest.ini)
pytest                                   # all suites
pytest tests/server-api tests/worker     # per-service
pytest worker/tests                      # worker extras
# Tests — Go agent (go.work spans ./agent + ./tests/agent)
go test ./tests/agent/...
# Tests — dashboard
cd dashboard && npm run build            # tsc -b && vite build (no unit runner configured)

# Agent build (Makefile runs the bpf target first; outputs bin/siem-agent)
cd agent && make build VERSION=1.8.0     # bpf → go build; needs clang
# Manual equivalent (note the two DIFFERENT -I roots):
cd agent
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I internal -c internal/netwatch/bpf/netwatch.bpf.c \
  -o internal/netwatch/bpf/netwatch.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I internal/procexec/bpf/include \
  -c internal/procexec/bpf/execve.bpf.c \
  -o internal/procexec/bpf/execve.bpf.o
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=1.8.0" -o bin/siem-agent ./cmd/agent/

# Agent release (tag-triggered CI)
git tag agent-v1.8.0 && git push origin agent-v1.8.0   # .github/workflows/agent-release.yml
```

## NOTES

- 42 LSP servers configured, 5 installed (`gopls`, `ruff`, `rust`, `dart`, `prisma`). Python gets `ruff` only (no pyright/basedpyright); TypeScript, YAML and Dockerfile servers are **missing** — so dashboard/TS and `rules/*.yaml` edits get no diagnostics. `dashboard` has zero test runner; `npm run build` is its only gate.
- **Build artifacts are gitignored, not committed**: `agent/bin/`, `agent/dist/`, `dashboard/dist/`, `*.deb`. Only `agent/internal/procexec/bpf/include/bpf/vmlinux.h` is a committed generated header. A stale local `dist/` will not reflect source changes.
- `rules/` (105) and `decoders/` (80) counts change; treat as data, not constants.
- Postgres runs `pgvector/pgvector:pg16` (vector search for RAG over cases/SOPs/knowledge); `fastembed` model is baked into the worker image by `worker/bake_embedding_model.py`.
- `9router` (LLM router) and `searxng` back the AI SOC assistant and AI investigations; `package-builder` (`agent/Dockerfile.packages`) is a one-shot job that builds `.deb`/`.rpm`/Windows zip at `agent/VERSION` and copies them to the `agent_packages` volume for the dashboard to serve.
- **CI exists and is meaningful**: `.github/workflows/ci.yml` runs pytest (with a Postgres service), Go tests + Windows vet/build, and the dashboard build; `sigmahq-compat.yml` replays SigmaHQ regression samples (PR + weekly); `windows-agent.yml` builds/installs the MSI on a real Windows runner; `agent-release.yml` handles tagging.
