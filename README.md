<div align="center">

# satpam-agent

**Web server file scanner — deploy once per host**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Tests](https://img.shields.io/badge/tests-48%20passing-brightgreen?style=flat-square)](#testing)
[![No CGO](https://img.shields.io/badge/CGO-disabled-blue?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)](#)

</div>

---

## Overview

satpam-agent runs on each web server. It fetches YARA detection rules from satpam-server, scans local directories with a concurrent worker pool, and reports every match back — tagged with the agent's identity so findings are always traceable to a specific host.

```
satpam-server                     satpam-agent (this)
      │                                  │
      │◀── GET /v1/rules ───────────────│  fetch rules + scan config
      │                                  │
      │                           walk /var/www/html
      │                           match rules (N workers)
      │                                  │
      │◀── POST /v1/findings ───────────│  { agent_id: "web-prod-01", ... }
```

---

## Features

- 🔍 **Pure-Go YARA engine** — no libyara, no CGO, single static binary
- 🏷️ **Agent identity** — every finding carries the agent's hostname or custom `-id`
- ⚡ **Concurrent scanning** — configurable worker pool with buffer reuse via `sync.Pool`
- 🔄 **Auto rule updates** — fetches fresh rules from the server on every scan cycle
- 🛡️ **Zero local config** — scan paths and extensions are served centrally

---

## Quick Start

```bash
go build -o satpam-agent .

./satpam-agent \
  -server   http://192.168.1.10:8080 \
  -id       web-prod-01 \
  -interval 5m \
  -workers  4
```

**One-shot mode** (for cron/CI):

```bash
./satpam-agent -server http://192.168.1.10:8080 -interval 0
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `http://localhost:8080` | satpam-server base URL |
| `-id` | system hostname | Agent identity recorded with every finding |
| `-interval` | `5m` | Time between scans — `0` to run once and exit |
| `-workers` | `4` | Parallel file-scan goroutines |

---

## Files

| File | Responsibility |
|------|---------------|
| `main.go` | CLI flags, signal handling, scan scheduler |
| `yara.go` | Pure-Go YARA parser — literals, hex, regex, nocase, condAll/condAny |
| `scanner.go` | Directory walker with concurrent worker pool |
| `client.go` | HTTP client — `fetchRules`, `reportFindings` with agent_id injection |

---

## Testing

```bash
go test ./... -v
```

```
--- PASS: TestIntegration_MaliciousFile_AlertsWithAgentID (0.01s)
--- PASS: TestIntegration_AgentID_RecordedByServer        (0.01s)
--- PASS: TestIntegration_MultipleShells_AllAlerted        (0.01s)
--- PASS: TestIntegration_CleanDirectory_NoAlerts          (0.01s)
ok  github.com/patra/satpam-agent  0.958s
```

**48 tests** across parser, scanner, client, and full end-to-end integration — no external services needed, uses an in-process mock server.

| File | Tests | Covers |
|------|------:|--------|
| `yara_test.go` | 21 | Parser: literals, hex, regex, nocase, condAll, escape sequences |
| `scanner_test.go` | 14 | Ext filter, dir exclusion, empty files, cancellation, workers |
| `client_test.go` | 9 | Fetch rules, POST findings, agent_id presence, error handling |
| `integration_test.go` | 6 | Full pipeline: file detected → alert with correct agent identity |

---

📖 [How to Run](how-to-run.md) · 🏗️ [Architecture](arch.md) · ⬅️ [Back to root](../README.md)
