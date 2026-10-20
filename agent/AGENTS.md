# AGENT (Go endpoint agent)

Cross-platform: **Linux** (eBPF process/network, FIM, nftables firewall, local detection) and **Windows** (event log, PowerShell live-response). Single binary, `CGO_ENABLED=0`. Module path `github.com/siem-platform/agent`.

**Versioning has two sources**: `make build` / release workflows take `VERSION=...` (→ `-X main.Version`), while `agent/Dockerfile.packages` (the dashboard's package-builder) reads the tracked `agent/VERSION` file — currently `1.8.0`. Bump both when releasing.

## STRUCTURE

```
agent/
├── cmd/agent/
│   ├── main.go              # entry — wires every subsystem in sequence
│   ├── configure*.go        # -configure CLI (linux/other/windows variants)
│   └── service_windows.go   # SCM service install/uninstall (SIEMAgent)
├── cmd/winevent-fmt/        # dev tool: render event XML the way winevent.FormatXML does
├── internal/
│   ├── config/              # YAML load/save + fsnotify watcher (bootstrap fields only)
│   ├── enrollment/          # first-run enroll → writes agent_id/token back to config.yaml
│   ├── tailer/              # log tailing (fixed + glob), rotation + copytruncate detect
│   ├── buffer/              # in-memory queue + disk spill of undelivered entries
│   ├── client/              # HTTP client (PostWithRetry / Post)
│   ├── heartbeat/           # 30s loop: log sources + FIM paths + task dispatch + integrity hash
│   ├── fim/                 # fsnotify watcher, SHA256, 2s debounce, 50-event batch
│   ├── hygiene/             # OS/patch/ports/disk snapshots (linux + windows collectors)
│   ├── procexec/            # eBPF execve monitor (bpf/ has .c + vendored headers)
│   ├── netwatch/            # eBPF connect/accept/bind/DNS + `ss` snapshot fallback
│   ├── detect/              # local threshold engine: keeps blocking when the server is down
│   ├── firewall/            # nftables gate: rule model, anti-lockout guard, engine
│   ├── winevent/            # Windows EvtSubscribe + FormatXML (`eventlog:<Channel>` sources)
│   └── task/                # live response: collectors, flows/plugins, yara, firewall, quarantine
└── packaging/               # build-deb.sh, build-rpm.sh, build-msi.ps1, build-windows.sh, systemd unit, .spec, .wxs
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Startup order / what runs | `cmd/agent/main.go` `run` | enroll (if no token) → tailer mgr → config watch → hygiene → FIM → firewall engine → flows → procexec → netwatch → heartbeat → sender |
| Sender backoff semantics | `cmd/agent/main.go` `senderLoop` | `>=500` re-queues entry; `>=300` logs + drops |
| Uninstall gate | `cmd/agent/main.go` `-verify-uninstall` | exits 0 only if `-token`/`$SIEM_UNINSTALL_TOKEN` matches the agent's uninstall token; used by MSI and deb/rpm removal |
| Anti-tamper | `internal/config` `AntiTamperConfig`, `internal/heartbeat` `Integrity` | service-lock hardening + binary/config SHA256 reported every 5 min; a change without a version bump is tampering |
| Log-line codec | `internal/tailer/tailer.go` `encode`/`Decode` | `logType + "\x00" + rawMessage` |
| Glob rotation + copytruncate | `internal/tailer/tailer.go` `tailGlob`, `rewindIfTruncated` | first sight → seek EOF; new rotated file → read from start; same-inode truncation → rewind to 0 |
| Rebuild BPF objects | `internal/procexec/bpf/execve.bpf.c`, `internal/netwatch/bpf/netwatch.bpf.c` | `go:embed`'d, **build fails without them**; `.o` files are gitignored |
| Network telemetry | `internal/netwatch/netwatch.go` | connect/accept/bind/DNS → `linux_network_*`; needs tracefs + CAP_SYS_ADMIN |
| Netwatch fallback | `internal/netwatch/fallback.go` | `ss -tunapH` every 10s when eBPF cannot attach |
| Local detection engine | `internal/detect/detect.go` | sliding window + cooldown + block caps; emits `local_detection` |
| Local rule set | `internal/detect/defaults.go` | ssh_bruteforce, port_scan, webshell_upload — all disabled by default |
| Offline spill | `internal/buffer/spill.go` | undelivered entries to disk; replayed on boot **and** on reconnect |
| Firewall rule engine | `internal/firewall/engine.go` | nft backend + guard + JSON state; degrades to noop |
| Anti-lockout rules | `internal/firewall/guard.go` | refuses blocks covering SIEM IP / gateway / loopback |
| Firewall task handlers | `internal/task/firewall.go` | block_ip, unblock_ip, isolate_host, firewall_list, firewall_flush |
| Live-response collectors | `internal/task/collectors.go` | process_list, netstat, persistence_check, users_list, dmesg_tail, open_files, file_list, file_get |
| Live-response flows | `internal/task/flow.go` | long-polls `/api/agent/flows/poll`, runs sources sequentially, 500-row batches to `/update`, enforces timeout/max_rows, honours server cancel; a plugin ignoring ctx is abandoned after 5s |
| Flow plugins (Linux) | `internal/task/plugins.go` | registry must match `PLUGINS` in `server-api/app/services/flow_artifacts.py`; glob/hash/yara never enter `/proc` `/sys` `/dev` unless the root is inside them (`/proc/kmsg` reads block forever) |
| Flow plugins (Windows) | `internal/task/plugins_windows.go`, `plugins_windows_extra.go`, `plugins_eventlog.go` | PowerShell replacements + `winevent.Query` (validated args → XPath) |
| Response actions | `internal/task/response.go`, `response_handlers.go`, `quarantine.go` | operator-approved kill/quarantine/pull-file; `integrity.go` = self-integrity task |
| YARA scans | `internal/task/yara.go` | |
| Windows event log ingest | `internal/winevent/format.go` + `subscribe_windows.go` | one line per event: `EventID=<id> Channel="..." Key="value" ...` |

## CONVENTIONS

- **`log/slog` only** (JSON handler) — no `fmt.Println`, no `log` stdlib package.
- **Everything degrades gracefully**: procexec, FIM, firewall, netwatch all `slog.Warn` and continue when unavailable — never `os.Exit` on those paths.
- **eBPF needs tracefs mounted**: containers do not mount it, and without it both procexec and netwatch fail with "neither debugfs nor tracefs are mounted". `agent/demo/entrypoint.sh` mounts it best-effort (and a host that forbids it just loses eBPF); production hosts normally already have it.
- **netwatch drops its own process** (`comm=agent`). The agent's ingest traffic is one connect per shipped event; emitting it created a ~97k event/min feedback loop that buried real activity and built a 270k-deep Redis backlog.
- **BPF include roots differ per object**: `netwatch.bpf.c` uses `-I internal`; `execve.bpf.c` uses `-I internal/procexec/bpf/include`. The Makefile owns this — do not "unify" them.
- **Firewall fails open, not dead**: without `nft` or `CAP_NET_ADMIN` the engine swaps to a noop backend, reports `degraded` in `firewall_list`, and the agent keeps collecting. `SIEM_FW_DRY_RUN=1` forces that path and lists the commands it would have run.
- **Every firewall mutation is an event**: apply/remove/isolate/reject are pushed into the log buffer as `firewall_gate`, so they land in Elasticsearch like any other telemetry.
- **nft element syntax needs braces**: `add element ... set { <key> timeout 30s }`. Without the braces nft parses `timeout` as the next element and fails — `nftApplyArgv` owns that formatting.
- **Local rules must group by a regex, not a kv field, for syslog sources.** `auth.log` and Apache `access.log` are free text — `GroupBy: "host"` silently never matches and the rule looks installed but dead. `GroupExpr` exists for exactly this; `internal/detect/defaults_test.go` pins the patterns against real lab lines.
- **Local detection observes before delivery**, in `senderLoop`, so it keeps working while the server is unreachable. Moving that call onto the success path silently disables offline detection.
- **Local blocks reuse the firewall guard**: a rule that would block the SIEM IP, gateway or loopback is refused and the detection records `block_error` instead of blocking.
- **Undelivered entries are spilled to disk** and replayed both at boot and when a send succeeds after a failure; without the reconnect replay they stay stranded until restart.
- **Config mutation is write-back**: after successful enrollment the agent rewrites `config.yaml`; log sources/FIM paths are then server-driven, not config-driven.
- **Buffer contract**: `Pop()` returns `(entry, ok)`; sender must re-`Push` on 5xx.
- Deps are deliberately minimal (`cilium/ebpf`, `fsnotify`, `yaml.v3`). Firewall shells out to `nft`, no netlink library.

## ANTI-PATTERNS

- **Do not hardcode `http://`** for `server.url` — the 301→405 downgrade trap in root AGENTS.md hits every agent ingest.
- **Do not add a `User=` hardening to the shipped systemd unit** without accepting that firewall and eBPF fail closed — the platform expects root.
- **Do not import `slices`/`maps` into `internal/firewall`** — it compiles under the module's Go directive and needs no generics.
- **Do not read guarded state with `RLock` and then call `Guard.Gateway()` inside it** — `Gateway()` takes the write lock to cache, and re-entering deadlocks (regression-tested in `engine_test.go`).
- **Do not commit `.bpf.o` files or new large binaries**; `include/bpf/vmlinux.h` is the only committed generated header. `agent/bin/` and `agent/dist/` are gitignored.
- **`make build` compiles the eBPF objects first** (target `bpf`, requires `clang`; fails with a clear message if absent). `make package-deb`/`package-rpm` depend on it too.
- **Windows/macOS hosts can still `go build ./...`** for editing; `hygiene/collector*.go` and `procexec/*.go` use `//go:build linux` with a no-op stub elsewhere.

## WINDOWS

- Same binary, `GOOS=windows` (`packaging/build-windows.sh` → zip with `install.ps1`/`uninstall.ps1`/`config.yaml`; `build-msi.ps1` + `siem-agent.wxs` → MSI). Runs as the `SIEMAgent` service (`cmd/agent/service_windows.go`; `-install`/`-uninstall`), config and `agent.log` in `%ProgramData%\SIEMAgent`.
- Event logs: a log source path `eventlog:<channel>` (e.g. `eventlog:Security`) is read via `EvtSubscribe` (`internal/winevent`), future events only. Each event becomes one `EventID=<id> Channel="..." Key="value" ...` line — the contract for the `decoders/win_*.yaml` kv decoders; change `winevent.FormatXML` and those decoders together (`tests/agent/winevent_format_test.go`, `tests/worker/test_windows_decoding.py`).
- Live response: `plugins_windows.go` replaces pslist/netstat/users/persistence with PowerShell (`Get-CimInstance`, `Get-NetTCPConnection`, ...); `plugins_windows_extra.go` adds info (registry), eventlog (`winevent.Query`: channel + event_ids + hours, XPath built from validated args in `plugins_eventlog.go`), services and programs — used by the `Windows.*` artifacts in `server-api/app/artifacts/`. dmesg/open_files are unsupported. `tests/windows/smoke-msi.ps1` runs a flow with every Windows plugin on a real runner.
- Isolation/block-IP use `netsh advfirewall` rules named `SIEM-*` (`isolation_windows.go`, `firewall_native_windows.go`); the nft engine has no Windows backend.
- No eBPF/process-exec stream and no package hygiene on Windows — use Sysmon (`eventlog:Microsoft-Windows-Sysmon/Operational`) or 4688 for process creation.
