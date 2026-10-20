# DECODERS (log-line parsers — YAML data)

Seeded into Postgres on worker startup by `worker/worker/seeder.py`, idempotent by `name`. A decoder turns one raw log line into the dotted ECS-ish fields Sigma rules match on. Adding a file is the deployment mechanism — there is no build step.

Current count: **80 decoder files** — 43 `regex`, 37 `kv` (treat as data; it changes).

## TWO TYPES

**regex** — named capture groups → output fields:
```yaml
name: linux_auth_failed
log_type: linux_auth          # must match an agent logs[].type
type: regex
priority: 10                  # lower = tried first
enabled: true
pattern: 'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip           # output_field: capture_group
  user.name: user
  source.port: port
```

**kv** — `key=value` / `key="quoted"` lines (what eBPF process-exec and the Windows agent emit):
```yaml
name: my_kv_decoder
log_type: some_log_type
type: kv
priority: 10
fields:
  event.action: action        # output_field: kv_key
static_fields:
  event.category: network
```

## LOG_TYPES IN USE

| Family | log_types |
|---|---|
| Linux auth/syslog | `linux_auth`, `syslog`, `linux_audit`, `postfix` |
| Linux eBPF | `linux_process_exec`, `linux_network_connect`, `linux_network_accept`, `linux_network_bind`, `linux_network_snapshot`, `linux_dns_query`, `linux_iptables` |
| Web | `nginx_access`, `nginx_access_combined`, `nginx_error`, `apache_access` |
| Firewall | `fortigate_traffic` (plus admin/vpn/utm/event variants) |
| Windows | `windows_security`, `windows_system`, `windows_application`, `windows_powershell`, `windows_sysmon` |
| Platform | `siem_agent` (agent tamper/health events) |

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Decoder execution | `worker/worker/decoder_engine.py` | regex then kv by `priority`; `_parse_kv` is reused by `sigma_logsource.py` |
| Which logsource a decoded event maps to | `worker/worker/sigma_logsource.py` | derives `<product>_<service>` from log_type, aliases Sigma field names |
| Agent side that emits `log_type` | `agent/internal/tailer/` (fixed + glob) and `agent/internal/winevent/format.go` | `logs[].type` in `config.yaml` |
| Windows line format contract | `agent/internal/winevent/format.go` | `EventID=<id> Channel="..." Key="value" ...`; change it **and** `win_*.yaml` together |
| Dashboard decoder editor | `dashboard/src/pages/DecodersPage.tsx` | YAML write → Test → Save |
| Server-side validation | `server-api/app/api/routes/decoders.py` `_validate_decoder_yaml` | rejects non-`regex|kv`, regex without `pattern` |
| Decoder test endpoint | `POST /api/decoders/test` | imports `worker.decoder_engine` |
| Regression samples | `tests/worker/test_windows_decoding.py`, `test_web_payload_decoding.py` | pin real lab lines |

## CONVENTIONS

- **`log_type` must exactly match an agent `logs[].type`** — a typo means zero decodes for that source, silently.
- **`priority` orders evaluation** — put narrow/high-confidence decoders lower; the generic `*_generic.yaml` fallbacks go last.
- **Output field names are the Sigma contract** — dotted ECS for non-`process_creation` rules; keep them consistent across decoders that share a log_type.
- **`static_fields` for constants** (e.g. `event.category: network`) instead of repeating them in every rule.
- **A file per log source family**, not per rule — several `win_security_46xx.yaml` files each target one EventID.

## ANTI-PATTERNS

- **Do not change a decoder's output field names** without grepping `rules/` for the old name — every rule matching it goes dead with no error.
- **Do not rename an existing decoder `name`** to "update" it — seeding keys on `name`, so a rename creates a duplicate and leaves the old one active.
- **Do not edit `winevent.FormatXML` without the `win_*.yaml` decoders** — they are one contract; `tests/agent/winevent_format_test.go` and `tests/worker/test_windows_decoding.py` pin it.
- **Do not rely on `enabled: false` to retire a decoder** — it stays seeded; disable it in the dashboard or delete the file and remove the row.
- **Do not add a `type` the engine doesn't implement** — only `regex` and `kv` exist.
