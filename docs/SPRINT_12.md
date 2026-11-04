# CyberShield – Sprint 12: Advanced Network Monitoring & Real-Time SOC

## Overview
Sprint 12 introduces enterprise network traffic telemetry, host resource health metrics, authorized fleet agent enrollment, and a deterministic rule-based anomaly detection engine into the CyberShield platform. It features a dedicated **Real-Time SOC Command Center** (`/soc-monitoring`), interactive traffic analytics (`/network-monitoring`), fleet device health inventory (`/device-health`), anomaly triage drawers (`/network-anomalies`), agent credential management (`/monitoring-agents`), and detection policy tuning (`/monitoring-rules`).

---

## 1. System Architecture

```
+---------------------------------------------------------------------------------------------------+
|                                  CyberShield SOC Web Frontend                                     |
|  /soc-monitoring  |  /network-monitoring  |  /device-health  |  /network-anomalies  |  /agents     |
+---------------------------------------------------------------------------------------------------+
                                         |  ▲ (Supabase Realtime Channel & Polling Fallback)
                                         v  |
+---------------------------------------------------------------------------------------------------+
|                                    FastAPI Backend (v1)                                           |
|                                                                                                   |
|   +-----------------------+   +-----------------------+   +----------------------------------+    |
|   |   MonitoringService   |   |   AnomalyEngine       |   |       TrafficAnalytics           |    |
|   |  • Agent Registry     |   |  • Traffic Spikes     |   |  • Protocol Breakdown (HTTPS/TCP)|    |
|   |  • SHA-256 Key Auth   |   |  • Unexpected Ports   |   |  • Top Talkers (IP Volume)       |    |
|   |  • Rate Limiting      |   |  • Outbound C2 Check  |   |  • Destination Ports             |    |
|   |  • Host Metrics Eval  |   |  • Event Deduplication|   |  • Bandwidth Trajectory          |    |
|   +-----------------------+   +-----------------------+   +----------------------------------+    |
+---------------------------------------------------------------------------------------------------+
                  ▲ (X-Agent-Key Header)                                  |
                  |                                                       v
+------------------------------------+          +---------------------------------------------------+
|    Authorized Fleet Probes         |          |          Supabase PostgreSQL Schema               |
|  • Linux Ubuntu / Debian Probes    |          |  monitoring_agents     | monitoring_sessions      |
|  • Metadata Only (No Payloads)     |          |  network_telemetry     | device_health_metrics    |
|  • Heartbeat & Rolling Ingress     |          |  network_anomalies     | monitoring_rules         |
+------------------------------------+          |  monitoring_events     | monitoring_rule_history  |
                                                +---------------------------------------------------+
```

---

## 2. Real-Time SOC Dashboard (`/soc-monitoring`)

A single-pane-of-glass operations console engineered for 24/7 Tier 1/2 SOC operators:
- **Connection Status Pill**: Dynamically displays `Connected` (active SSE channel), `Reconnecting` (transient packet loss), or `Disconnected` with automated polling fallback.
- **Worker Daemon Monitor**: Status indicator confirming backend daemon process state.
- **Top 5 Operational KPIs**:
  1. *Network Health Status* (`Healthy`, `Degraded`, `Critical`).
  2. *Active Enrolled Agents* (Online vs Registered fleet size).
  3. *Active Anomalies* (Live unmitigated behavioral triggers).
  4. *Open Alerts* (Correlated incident alarms).
  5. *Bandwidth Throughput* (Real-time kbps and packet rates).
- **Live Security Event Feed**: Auto-scrolling, deduplicated stream of network, authentication, and scanner events.
- **Throughput Area Graph**: Real-time ingress vs egress curve.
- **Agent Host Health Cards**: CPU, memory, and disk utilization gauges for authorized sensors.

---

## 3. Network Traffic Analytics (`/network-monitoring`)

Collects strictly authorized packet flow metadata without payload interception:
- **Protocol Distribution**: Breakdown of observed transport and application protocols (HTTPS, TCP, UDP, DNS, SSH, etc.).
- **Top Talkers**: Rank-ordered communicating devices sorted by total transferred bytes and packet count.
- **Top Ingress/Egress Ports**: Service profiling across port numbers (443, 80, 5432, 22, 53, etc.).
- **Throughput Volume Trend**: Multi-point observation window with selectable time ranges (15m, 1h, 6h, 24h).
- **Data Export**: Direct CSV export of flow records for forensic analysis.

---

## 4. Device Health & Host Telemetry (`/device-health`)

Combines asset management with agent-reported host metrics:
- **Health States**: `Healthy`, `Warning`, `Critical`, `Offline`, `Unknown`.
  - `Critical`: CPU &ge; 90%, RAM &ge; 90%, or Disk &ge; 95%.
  - `Warning`: CPU &ge; 75%, RAM &ge; 75%, or Disk &ge; 85%.
  - `Healthy`: Standard operational thresholds.
- **Anti-Hallucination Guardrail**: Remote device CPU/memory is **never** fabricated. Assets lacking an installed agent are clearly classified as `Agent Not Installed` / `Host Telemetry Unprobed` with `Unknown` health.

---

## 5. Rule-Based Anomaly Detection (`/network-anomalies`)

Transparent, explainable heuristic detection rules:
1. `traffic_spike`: Rapid flow volume exceeding configured threshold (&ge; 5MB within 60s).
2. `unexpected_port`: Ingress on restricted or high-risk offensive ports (`4444`, `1337`, `6667`, `31337`, `8888`, `3389`).
3. `suspicious_outbound`: Egress connections directed at external listener ports.
4. `connection_failure_burst`: Burst of failed/unanswered connection attempts.
5. `new_device`: First-seen unregistered IP address.
6. `ioc_traffic_match`: Flows to/from known adversary IOCs from Threat Intelligence.

### Anomaly Investigation Drawer
Provides interactive modal inspection of:
- Evidentiary packet metadata (JSON format).
- Confidence percentage (80–95%).
- Prescribed investigation checklist (non-disruptive, advisory-only).
- Status workflow: `Open` &rarr; `Investigating` &rarr; `Resolved` &rarr; `Dismissed`.

---

## 6. Monitoring Agent Architecture (`/monitoring-agents`)

A secure, optional sensor probe architecture:
- **Cryptographic Registration**: On enrollment, generates high-entropy key `cs_mon_<uuid_hex>`.
- **One-Way Storage**: Only the SHA-256 hash (`hashlib.sha256`) is stored on the backend. Raw key is revealed only once during registration.
- **Agent Header Authentication**: Ingests telemetry via `X-Agent-Key` HTTP header.
- **Rate-Limiting**: Enforces max 120 submissions per minute per agent.
- **Privacy Assurance**: Agents collect only transport metadata (IPs, ports, protocols, byte counts) and local host resource metrics. Payloads, session tokens, passwords, and message contents are excluded by design.

---

## 7. FastApi REST Endpoints

| Category | Endpoint | Method | Role / Auth |
|---|---|---|---|
| Monitoring | `/api/v1/monitoring/status` | GET | Authenticated User |
| Monitoring | `/api/v1/monitoring/events` | GET | Authenticated User |
| Monitoring | `/api/v1/monitoring/agents` | GET | Authenticated User |
| Monitoring | `/api/v1/monitoring/agents/register` | POST | Analyst / Admin |
| Monitoring | `/api/v1/monitoring/telemetry` | POST | `X-Agent-Key` or Bearer Token |
| Monitoring | `/api/v1/monitoring/telemetry` | GET | Authenticated User |
| Device Health | `/api/v1/monitoring/device-health` | GET | Authenticated User |
| Device Health | `/api/v1/monitoring/device-health/{asset_id}` | GET | Authenticated User |
| Rules | `/api/v1/monitoring/rules` | GET | Authenticated User |
| Rules | `/api/v1/monitoring/rules` | POST | Analyst / Admin |
| Rules | `/api/v1/monitoring/rules/{id}` | PATCH | Analyst / Admin |
| Network | `/api/v1/network/traffic` | GET | Authenticated User |
| Network | `/api/v1/network/protocols` | GET | Authenticated User |
| Network | `/api/v1/network/top-talkers` | GET | Authenticated User |
| Network | `/api/v1/network/anomalies` | GET | Authenticated User |

---

## 8. Automated Test Suite

All 111 backend automated tests passing across Sprints 1–12 in **2.51s**:
```bash
cd backend
.venv\Scripts\pytest -q
# Result: 111 passed, 299 warnings in 2.51s
```

Frontend type safety completely clean with **0 errors**:
```bash
cd apps/web
npx tsc --noEmit
# Result: Exit code 0
```
