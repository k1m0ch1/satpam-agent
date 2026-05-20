# Architecture — satpam-agent

## Responsibility

satpam-agent runs on each web server, fetches detection rules from satpam-server, scans local files, and reports matches back — tagged with the agent's identity so the server knows which host each finding came from.

## Scan Cycle

```
main (ticker or one-shot)
        │
        ▼
runScan(ctx, client, workers)
        │
        ├─ fetchRules(ctx)
        │    GET /v1/rules → RuleSet{ YARARules, ScanConfig }
        │
        ├─ ParseRules(YARARules)
        │    → []*Rule  (compiled patterns + condition)
        │
        ├─ NewScanner(rules, ScanConfig, workers)
        │    pre-build extSet, skipSet
        │    init sync.Pool of []byte buffers
        │
        ├─ Scanner.Scan(ctx)
        │    ┌── goroutine: walk ─────────────────────────┐
        │    │  WalkDir each path                         │
        │    │  skip dirs in skipSet                      │
        │    │  send path if ext in extSet → files chan   │
        │    └────────────────────────────────────────────┘
        │    ┌── N worker goroutines ─────────────────────┐
        │    │  path ← files chan                         │
        │    │  buf  ← sync.Pool                          │
        │    │  read file (capped at maxFileMB)           │
        │    │  lower = bytes.ToLower(data)  ← once/file  │
        │    │  for rule in rules:                        │
        │    │    rule.Match(data, lower) → Finding?      │
        │    │  finding → out chan                        │
        │    │  buf  → sync.Pool                          │
        │    └────────────────────────────────────────────┘
        │    collect []Finding from out chan
        │
        └─ if findings > 0:
             reportFindings(ctx, findings)
             POST /v1/findings  ← [{ agent_id, rule_name, ... }]
```

## Components

### yara.go — Pure-Go YARA Parser

No CGO. No libyara. Parses a superset of YARA text sufficient for the bundled rules.

**`ParseRules(text)`** uses a line-by-line `bufio.Scanner`:
- Finds `rule <Name>` declarations
- Reads `meta:`, `strings:`, `condition:` sections
- Compiles each `$id = "..."`, `$id = /regex/`, `$id = { hex }` into a `pattern` struct
- Sets `condType` to `condAll` if the condition line contains `"all of"`, else `condAny`

**`Rule.Match(data, lower []byte)`**:
- `condAny` — returns on the first matching pattern
- `condAll` — requires all patterns to match; captures `matchedOn` and `snippet` from the first hit only

`lower` is `bytes.ToLower(data)` computed **once per file** by the caller (`scanFile`) and passed to every rule — avoids O(rules × file_size) allocations.

### scanner.go — Worker Pool

`NewScanner` pre-builds two lookup maps at construction time so walk/scan hot paths are O(1):

```go
extSet  map[string]bool  // ".php" → true
skipSet map[string]bool  // "vendor" → true  (lowercased)
```

`sync.Pool` holds `[]byte` buffers of size `maxFileMB`. Each worker borrows one buffer for its lifetime and returns it on exit — zero heap allocations in steady state.

Channel sizing (`workers * 4`) keeps the producer (walk) from blocking while workers are busy, and keeps workers from blocking while the collector is draining.

### client.go — HTTP Client

`serverClient` holds the server base URL and the **agent ID** — a string set once at startup (`-id` flag, defaulting to `os.Hostname()`).

`reportFindings` maps `[]Finding` → `[]reportedFinding`, injecting `AgentID` into every entry before serialisation. The server never trusts agent-supplied timestamps; it stamps `CreatedAt` itself.

## Identity Model

```
Agent starts with -id web-prod-01
        │
        └─ stored in serverClient.agentID
               │
               └─ injected into every reportedFinding.AgentID
                        │
                        └─ POST /v1/findings
                                 │
                                 └─ stored verbatim in Finding.AgentID
                                          │
                                          └─ returned by GET /v1/findings
```

Operators can filter findings by `agent_id` to scope detections to a specific host.

## YARA Constructs Supported

| Construct | Example |
|-----------|---------|
| Literal | `$s1 = "eval("` |
| Literal + nocase | `$s1 = "eval(" nocase` |
| Hex bytes | `$h1 = { 65 76 61 6C }` |
| Regex | `$r1 = /shell_exec\s*\(/` |
| Regex + nocase / `i` flag | `$r1 = /pattern/ nocase` |
| Any condition (default) | `any of them` |
| All condition | `all of them` |
| Meta: description, severity | parsed into `Rule` struct |

Unsupported constructs (imports, `at`, `in`, modules) are silently skipped — the parser never errors on unknown syntax.

## Test Coverage

```
yara_test.go         21 tests  parser correctness, escape sequences, hex, regex, condAll
scanner_test.go      14 tests  extension filter, dir exclusion, empty/missing files, concurrency
client_test.go        9 tests  fetch rules, report findings, agent_id in payload, error cases
integration_test.go   6 tests  full pipeline: file → scan → POST findings with correct agent_id
```

Integration tests use `net/http/httptest` — no real server needed. Test fixtures use a synthetic marker string (`SATPAM_UNIT_TEST_CANARY_XZ42`) instead of real malware patterns so Windows Defender does not block the source files during compilation.
