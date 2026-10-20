# SERVER-API (FastAPI)

REST API + agent ingest + WebSocket alert push. Async SQLAlchemy (`asyncpg`), Postgres; Elasticsearch for event queries. Runs 2 replicas in prod. 40 route modules.

## STRUCTURE

```
server-api/app/
├── main.py              # FastAPI app, lifespan (migrations), router list at EOF (:499)
├── api/routes/          # 40 route modules — one file per domain
├── core/                # deps.py (RBAC/scoping), database.py, security.py, config.py,
│                        # es_client.py, llm_client.py, llm_gateway.py, sigma.py,
│                        # query_builder.py, url_guard.py, limiter.py, geoip.py
├── artifacts/           # 32 built-in live-response artifact YAMLs (Linux.*, Windows.*, Generic.*)
├── models/models.py     # ALL ORM models, single 38 KB module
├── schemas/schemas.py   # ALL Pydantic schemas, single 27 KB module
└── services/            # assistant, assistant_tools, investigator, ingest, audit,
                         # flow_artifacts, agent_tamper, report_pdf, sigmahq, knowledge_schema, ...
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Register a new router | `app/main.py:499` `for router in [...]` | **must** be added or it 404s silently |
| Startup migrations | `app/main.py:445` `lifespan` | `Base.metadata.create_all` + `_migrate_*` under `pg_advisory_lock(727501001)` |
| Auth / token decode | `app/core/deps.py:17` `get_current_user` | HTTPBearer; token `type` must be `"access"` |
| Permission gate | `app/core/deps.py:40` `require_permission("x:y")` | superadmin bypasses; else check role.permissions set |
| Group scoping (list queries) | `app/core/deps.py:51` `get_scoped_group` | returns `None` for superadmin, else `user.group_id` |
| Group scoping (single resource) | `app/core/deps.py:65` `fetch_scoped` | **use this instead of `db.get()`** — raises 404 for another tenant's row |
| Post-load ownership check | `app/core/deps.py:56` `assert_group_access` | 404, never 403 — do not confirm existence |
| Agent-token auth | `app/core/deps.py:90` `get_agent` | header `X-Agent-Token`, compared by `hash_token` |
| Agent log ingest | `app/api/routes/ingest.py` | `POST /api/ingest/log` |
| Router name collisions | `app/main.py` imports | Aliased `cases_router`, `hunts_router`, `settings_router`, `fleet_router`, `artifacts_router`, `agent_flows_router`, ... |
| WebSocket push | `app/api/routes/ws.py` + `_ws_redis_listener` in main | Redis pubsub channel `ws:alerts` |
| Live-response flows | `app/api/routes/flows.py`, `app/services/flow_artifacts.py` | artifacts compile to plugin calls; rows filtered server-side by each source's Sigma `detection`; agents long-poll `/api/agent/flows/poll` (woken via Redis `siem:flowq:<agent>`) |
| Plugin allowlist | `app/services/flow_artifacts.py` `PLUGINS` | must stay in sync with `agent/internal/task/plugins.go` |
| AI case investigation | `app/services/investigator.py` | collection-only by design: no isolate/kill/quarantine/block tool; `AI.*` artifact names; `read_file` refused on credential stores; group-scoped even for superadmin |
| AI assistant | `app/services/assistant.py`, `assistant_tools.py` | read-only tool surface — no settings/users/webhook access |
| Agent tamper signals | `app/services/agent_tamper.py` | heartbeat integrity deltas → agent-health events |
| Shared Sigma/decoder engines | `server-api/Dockerfile:21` (+ `Dockerfile.dockerignore`) | build context is the **repo root**; `worker/worker/{sigma_engine,sigma_logsource,decoder_engine,agent_health,knowledge_query}.py` are copied in, not duplicated |

## CONVENTIONS

- **Route module shape**: usually `router = APIRouter(prefix="/api/<domain>", tags=["<domain>"])`. Some modules omit the prefix and declare full paths per-decorator (`agents.py`, `cases.py`, `fim.py`, `hunts.py`, `hygiene.py`, `settings.py`, `sop.py`, `system.py`, `ueba.py`, `ws.py`, `investigations.py`) — match the file you're editing.
- **Every route** takes `db: Annotated[AsyncSession, Depends(get_db)]` and a `Depends(...)` guard — never a bare public route.
- **Single-resource routes use `fetch_scoped()`** (34 call sites across 7 modules); list routes filter with `get_scoped_group()`. Never a bare `db.get()` on a group-owned model.
- **Audit logging is a BackgroundTask**: `background.add_task(audit_log, db, user.id, "action", "entity", id)` — do not `await` it inline.
- **Rate limits** via `slowapi`: `@limiter.limit("5/minute")` on auth endpoints.
- **Decoder/rule YAML is validated on write** (`_validate_decoder_yaml`) — regex needs `pattern`, type ∈ `regex|kv`.
- Decoder *test* route imports `worker.decoder_engine` directly — a cross-service import that works because both live in the same repo (and the Dockerfile copies it in).
- **Outbound URLs go through `url_guard.py`** (SSRF): private/loopback/link-local blocked unless `ALLOW_PRIVATE_WEBHOOK_TARGETS=true`.

## ANTI-PATTERNS

- **Do not add a new table via `db/init.sql`** — use `Base.metadata.create_all` + a `_migrate_*` helper called from `lifespan`.
- **Do not bypass group scoping** on any list/fetch of agents, alerts, cases, logs, FIM — cross-group leakage is a security bug. `AUDIT.md` C-1 documents what happens when it is.
- **Do not add routers outside the `main.py` list**, and do not rename a router import without updating the alias there.
- **Do not `await` an `audit_log`** — it's designed as a background task.
- **Do not raise raw `Exception`** for client errors; use `HTTPException` with the right status (422 for YAML validation, 403 for RBAC, 409 for duplicates).
- **Do not duplicate `sigma_engine.py`/`decoder_engine.py` here** — the Dockerfile copies them from `worker/worker/`. Edit the worker copy.
