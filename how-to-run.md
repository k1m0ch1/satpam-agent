# How to Run — satpam-agent

## Prerequisites

- Go 1.22 or later
- A running satpam-server reachable from this host

## Build

```bash
cd satpam-agent
go build -o satpam-agent .
```

On Windows: produces `satpam-agent.exe`.

## Run

```bash
./satpam-agent \
  -server   http://<server-ip>:8080 \
  -id       web-prod-01 \
  -interval 5m \
  -workers  4
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `http://localhost:8080` | satpam-server base URL |
| `-id` | system hostname | Agent identifier recorded with every finding — use something that identifies the host (e.g. `web-prod-01`, FQDN, IP) |
| `-interval` | `5m` | Time between scans. Set to `0` to run once and exit. |
| `-workers` | `4` | Parallel file-scan goroutines |

The agent fetches scan paths and extensions from the server on every cycle, so no local scan config is needed.

## One-shot / Cron Mode

```bash
./satpam-agent -server http://192.168.1.10:8080 -id $(hostname) -interval 0
```

Add to crontab:

```cron
0 * * * * /usr/local/bin/satpam-agent -server http://192.168.1.10:8080 -interval 0
```

## Run as a systemd Service (Linux)

```ini
# /etc/systemd/system/satpam-agent.service
[Unit]
Description=Satpam security agent
After=network.target

[Service]
ExecStart=/usr/local/bin/satpam-agent -server http://192.168.1.10:8080 -id %H -interval 5m -workers 4
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now satpam-agent
```

## Run the Tests

```bash
cd satpam-agent
go test ./... -v
```

48 tests across four files. No external services required — integration tests use an in-process mock satpam-server.

```
--- PASS: TestIntegration_MaliciousFile_AlertsWithAgentID
--- PASS: TestIntegration_AgentID_RecordedByServer
--- PASS: TestIntegration_MultipleShells_AllAlerted
...
ok  github.com/patra/satpam-agent
```

## Notes

- The agent runs as the OS user that starts it. For full coverage of `/var/www`, run as `www-data` or `root` depending on your web server ownership.
- Files larger than `max_file_size_mb` (set in server config) are skipped silently.
- If the server is unreachable, the scan cycle logs an error and retries on the next interval — the agent does not crash.
