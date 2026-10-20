# WORKER (Python detection pipeline)

Async consumer of the Redis stream. **Package nesting is deliberate**: repo dir `worker/` is the Docker image root, `worker/worker/` is the importable package, `worker/tests/` is a third layer. Runs 2 replicas in prod.

## STRUCTURE

```
worker/worker/
├── main.py            # entry — asyncio.gather() of 19 supervised loops + health server (:8001)
├── consumer.py        # stream consume → decode → sigma → alert; DLQ retry; hot reload
├── adaptive.py        # AIMD consume concurrency from stream lag + cgroup CPU/mem
├── decoder_engine.py  # regex + kv YAML decoders
├── sigma_engine.py    # rule match + threshold + suppression (Redis-backed); compiled-rule cache
├── sigma_logsource.py # log_type (+ Windows Channel/EventID) → Sigma product/service/category, field aliases
├── alert_manager.py   # alert creation + webhook fire
├── case_grouping.py   # which case an alert joins (IOC-keyed campaigns, digest cases, merge/link)
├── seeder.py          # seed rules/ + decoders/ into DB (new titles only, per-item SAVEPOINT)
├── soar_engine.py     # playbook execution
├── stream_maintenance.py # re-queue dead-consumer pending, drop idle consumers, XTRIM processed
├── maintenance.py     # daily retention purge (ES logs, closed alerts)
├── rag.py / rag_indexer.py / knowledge.py / knowledge_query.py  # pgvector RAG + knowledge base
├── llm_client.py / llm_gateway.py / ai_analyst.py / ai_consumer.py / ai_queue.py
├── graph/             # triage_graph.py, chat_model.py, checkpoint.py (LangGraph-style triage)
├── hunter.py / hunt_scheduler.py / campaign_analyzer.py / fleet_correlation.py
├── agent_monitor.py / agent_health.py   # agent offline/tamper detection as log events
├── report_sender.py / email_sender.py / webhook_sender.py / url_guard.py / web_fetch.py
├── ueba/              # features.py, scorer.py (Isolation Forest), explain.py, trainer.py, model_codec.py, loops.py
├── ti/                # aggregator.py, extractor.py, mitre.py, iocs.py
│   └── providers/     # abuseipdb, virustotal, shodan, otx, greynoise, urlhaus, geoip, whois, base
├── models.py          # worker-side ORM (separate from server-api's models.py)
└── config.py          # all env vars (DATABASE_URL, REDIS_*, CONSUME_*, NINEROUTER_*, ...)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add a background loop | `worker/worker/main.py` `asyncio.gather(...)` | 19 `_supervise(...)` entries — add here or it never runs |
| Message lifecycle | `worker/worker/consumer.py:72` `process_message` | decode → ES index → sigma → `create_alert` → UEBA (best-effort) |
| Batch + concurrency | `worker/worker/consumer.py:179` `consume_loop` | splits a batch into per-source groups; groups run concurrently, a group stays in stream order; `Semaphore(state["concurrency"])` |
| Adaptive concurrency | `worker/worker/adaptive.py` `next_concurrency` | AIMD: `+2` while lag high and CPU<85%/mem<80%, `-1` when caught up, halve at mem≥90%. Bounded by `CONSUME_CONCURRENCY_MIN/MAX` (4/16), max capped by DB pool (25) |
| DLQ behaviour | `consumer.py:207` `dlq_retry_loop` | failed msgs at `{REDIS_STREAM_KEY}:failed`, re-injected every **300s**, batch 50 |
| Engine hot-reload | `consumer.py:232` `reload_loop` | interval from `RELOAD_INTERVAL` env (default 60s) |
| Stream hygiene | `worker/worker/stream_maintenance.py` | every minute: re-queues pending from dead consumers, removes idle consumers, trims processed entries (unbounded stream previously crash-looped Redis) |
| Health/metrics | `main.py` `HealthHandler` | `/health`, `/metrics` on port 8001 |
| Case assignment rules | `worker/worker/case_grouping.py` | attacker IOCs are the keys; hosts/users never are; no-IOC alerts join the campaign on their host; failed-only brute force → one digest case per group per day |
| Rule/decoder seeding | `worker/worker/seeder.py` | idempotent by `title`/`name`; per-item SAVEPOINT (replica race safe) |
| Sigma threshold/suppression state | Redis | expect Redis to be required for sigma, not just the stream |
| Worker DB session | `worker/worker/database.py` `AsyncSessionLocal` | worker has its own engine, separate from server-api |
| Agent tamper events | `worker/worker/agent_health.py` | emits `event=agent_stopped/agent_offline/agent_integrity_changed` into the log stream; decoded by `decoders/siem_agent.yaml`, alerted by `rules/siem_agent_*.yaml` |

## CONVENTIONS

- **`structlog` JSON only**; configured in `main.py` from `LOG_LEVEL`. No `print`, no stdlib logging.
- **Best-effort side effects never block the pipeline**: UEBA scoring is wrapped in `try/except` with a warning and continues — replicate that pattern for enrichment.
- **Every message is `xack`'d** even on failure (then copied to the DLQ) so the pending-entries list doesn't grow.
- **Ordering is per source, not global**: entries from one source IP/host stay in order; different sources are processed concurrently. Don't add a global lock that serializes them.
- **Cross-service import is normal**: `worker.decoder_engine` is imported by server-api's decoder-test route — keep the module import-safe (no side effects at import).
- **Prometheus counters** are module-level in `consumer.py`/`adaptive.py`; add new metrics next to the relevant loop.
- **Loop supervision**: `_supervise(name, factory)` restarts a loop with backoff if it raises out of its body — a loop that returns cleanly is a bug.

## ANTI-PATTERNS

- **Do not assume Elasticsearch is optional** — `ensure_es_index` runs at startup and every processed message writes there. Postgres alone won't produce a working event view.
- **Do not do blocking I/O** in a loop (no `requests`, no `time.sleep`) — this is a single event loop shared by 19 loops; a blocking call stalls ingest for every loop.
- **Do not scatter `except Exception: pass`** — the worker's established style is log the exception via structlog at `warning`/`error` then continue (see `process_message` UEBA block).
- **Do not edit rule/decoder YAML logic here** — `rules/` and `decoders/` are data, seeded by `seeder.py`; DB rows are never overwritten for existing titles.
- **Do not import server-api modules** into the worker; the two services share only the DB and Redis, and their `models.py` files are intentionally separate.
- **Do not raise `CONSUME_CONCURRENCY_MAX` past the DB pool size** (25) — each concurrent group can hold a connection.
