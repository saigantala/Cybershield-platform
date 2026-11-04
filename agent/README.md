# CyberShield Endpoint Monitoring Agent

The **CyberShield Endpoint Monitoring Agent** is a lightweight, cross-platform telemetry sensor designed for zero-trust endpoint visibility, real-time device health monitoring, and network flow ingestion into the CyberShield SOC platform.

---

## Capabilities

- **Real-Time Host Metrics**: CPU load, RAM utilization, Disk capacity, and interface status.
- **Network Flow Telemetry**: Active TCP/UDP socket connections, protocols (HTTP, HTTPS, DNS, SSH, Postgres), and traffic directions.
- **Mutual Authentication**: Registers via standard HTTPS REST API and communicates using high-entropy `cs_mon_...` API keys (`X-Agent-Key` header).
- **Automated Reconnect & Recovery**: Robust network retry logic with exponential backoff.
- **Zero External Dependencies Required**: Built with Python 3 standard library; automatically uses `psutil` if installed for higher resolution.

---

## Quick Start

### 1. Requirements
- Python 3.8+ (Windows, Linux, macOS)
- Network connectivity to CyberShield API server (default `http://localhost:8000/api/v1`)
- (Optional) `pip install psutil` for high-resolution hardware counters

### 2. Enrollment

Enroll the agent against your CyberShield instance:

```bash
# Automatic enrollment using current system profile
python agent/cybershield_agent.py --enroll --server-url http://localhost:8000/api/v1

# Authenticated enrollment under specific organization
python agent/cybershield_agent.py --enroll --server-url http://localhost:8000/api/v1 --auth-token <SUPABASE_JWT_TOKEN>
```

Upon successful registration, credentials are saved to `agent/.agent_config.json`:
- `agent_id`: Assigned UUID
- `api_key`: One-time generated secret key (`cs_mon_...`)
- `organization_id`: Bound organization

### 3. Running the Agent Daemon

```bash
# Run as continuous background daemon with 30-second interval
python agent/cybershield_agent.py --interval 30

# Test run: send a single telemetry heartbeat and exit
python agent/cybershield_agent.py --once
```

---

## Command-Line Options

| Argument | Description | Default |
|---|---|---|
| `--enroll` | Enrolls this endpoint with the CyberShield management API | `False` |
| `--server-url` | Base URL of CyberShield API | `http://localhost:8000/api/v1` |
| `--auth-token` | Bearer JWT token for authenticated enrollment | `None` |
| `--org-id` | Target Organization UUID | `None` |
| `--agent-id` | Override Agent UUID if previously registered | Loaded from config |
| `--api-key` | Agent secret API key (`X-Agent-Key`) | Loaded from config |
| `--interval` | Heartbeat telemetry interval in seconds | `30` |
| `--once` | Send one telemetry report and exit | `False` |
| `--config-file` | Path to agent credentials JSON file | `agent/.agent_config.json` |
| `--verbose` | Enable debug logging | `False` |

---

## Operating System Service Setup

### Linux (Systemd)

Create `/etc/systemd/system/cybershield-agent.service`:

```ini
[Unit]
Description=CyberShield Endpoint Monitoring Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cybershield/agent
ExecStart=/usr/bin/python3 /opt/cybershield/agent/cybershield_agent.py --interval 30
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cybershield-agent
```

### Windows (Task Scheduler or NSSM)

Using NSSM (Non-Sucking Service Manager):
```cmd
nssm install CyberShieldAgent "C:\Python311\python.exe" "C:\CyberShield\agent\cybershield_agent.py --interval 30"
nssm start CyberShieldAgent
```
