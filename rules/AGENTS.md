# RULES (Sigma detection content — YAML data)

Seeded into Postgres on worker startup by `worker/worker/seeder.py`. Seeding is idempotent by `title`: rows for existing titles are never overwritten, so dashboard edits survive redeploys. Adding a file is the deployment mechanism — there is no build step.

Current count: **105 rule files** (treat as data; it changes). A file may hold several rules separated by `---` (base + correlation).

## RULE SHAPE

Standard Sigma. Two field vocabularies — pick the right one for the logsource:

| Logsource | Field style | Examples |
|---|---|---|
| `process_creation` | **Sigma native** | `Image`, `CommandLine`, `ParentImage`, `User`, `ProcessId`, `ParentProcessId` |
| everything else | **ECS dotted** | `event.action`, `user.name`, `source.ip` |

- `process_creation` rules are fed by the Go agent's eBPF monitor (decoded by `decoders/linux_process_exec.yaml`) and by Windows 4688/Sysmon; they use Sigma field names so public **SigmaHQ `process_creation` rules drop in unmodified**.
- Non-`process_creation` rules must match the field names a decoder actually emits — an unmatched `selection` key means the rule silently never fires.
- Families present: linux auth/priv-esc, web (SQLi/XSS/SSRF/SSTI/deserialization/log4shell/spring4shell/shellshock), firewall (FortiGate), Windows (security/sysmon), persistence (cron/systemd/sudoers/SSH-key), mining/exfil/C2, agent tamper (`siem_agent_*.yaml`).

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Seeding logic / idempotency key | `worker/worker/seeder.py` | per-title SAVEPOINT; safe across 2 replicas |
| Field names a rule can match | the decoder with the same `log_type` in `decoders/` | rule selection keys must exist in decoded output |
| Which logsource an event maps to | `worker/worker/sigma_logsource.py` | log_type → Sigma product/service/category + field aliases |
| Dashboard rule editor | `dashboard/src/pages/RulesPage.tsx` | YAML write → Test → Save |
| SigmaHQ bulk import | `dashboard/src/components/SigmaHQImportModal.tsx`, `server-api/app/services/sigmahq.py` | |
| Regression harness | `tests/sigmahq/run.sh` + `.github/workflows/sigmahq-compat.yml` | replays SigmaHQ samples on PR + weekly |

## ENGINE SUPPORT (`worker/worker/sigma_engine.py`)

- **Matching:** case-insensitive by default (`|cased` opts out), `*`/`?` wildcards (`\*` = literal star, `\\*` = backslash + wildcard), list-of-maps selections, `keywords` (searched against `raw_message`).
- **Modifiers:** `contains` `startswith` `endswith` `all` `re` (+ `i` `m` `s`) `cidr` `lt` `lte` `gt` `gte` `exists` `cased` `fieldref` `base64` `base64offset` `wide`/`utf16le` `utf16be` `utf16` `windash`. `field: null` matches a missing field.
- **Condition:** `and`/`or`/`not`, parentheses, `1 of sel_*`, `all of them`, `N of x` (selections starting with `_` are excluded from `them`). `| count()` aggregations are not supported — use a correlation rule or `threshold`.
- **Correlation rules (Sigma v2):** `type: event_count | value_count | temporal`, referencing rules by `name`, `id` or `title`; `group-by`, `timespan`, `condition` (`gt`/`gte`/`eq`). `generate` defaults to `false`, which silences the referenced rules' own alerts.
- **Logsource routing:** a rule only runs against events whose derived product/service/category match — a `windows/process_creation` rule never sees an SSH line.
- Anything the engine can't evaluate is **rejected at load** and logged as `sigma_rule_rejected` — check worker logs after adding a rule.

## CONVENTIONS

- **Filename** = snake_case describing the behaviour (`ssh_brute_force.yaml`, `kernel_module_suspicious.yaml`).
- **`log_type` must match a decoder's** (`linux_auth`, `syslog`, `linux_process_exec`, `nginx_access`, `fortigate_traffic`, `windows_security`, ...). A typo means zero matches for that source.
- **Rules are detection only** — response actions belong in SOAR playbooks (`worker/worker/soar_engine.py`), not rule YAML.
- **Group by a field the decoder emits**; for free-text syslog, prefer a regex-derived field over a raw kv key.

## ANTI-PATTERNS

- **Do not rename an existing rule `title`** to "update" it — seeding keys on `title`, so a rename creates a duplicate rule and leaves the old one active.
- **Do not mix field vocabularies** — using `Image` in an ECS-logsource rule (or `event.action` in a `process_creation` rule) makes it dead.
- **Do not put logic in these files** — they are pure content, no scripts, no `CREATE TABLE`-style config.
- **Do not assume an edited DB row is permanent** — only *new* titles are seeded; edit YAML and bump the title, or edit in the dashboard and accept it lives only in the DB.
- **Do not add a rule without checking it fires** — use the dashboard Test action or `tests/sigmahq/run.sh`; a rejected rule is only visible in worker logs.
