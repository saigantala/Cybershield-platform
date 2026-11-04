# CyberShield V1.0 – Live Data & Telemetry Architecture

**Document Version:** 1.0.0-PROD  
**Architecture Date:** November 4, 2026  
**Auditor Roles:** Principal Cybersecurity Architect, Distributed Systems Engineer, Database Architect  
**Objective:** Specification of the end-to-end data processing pipeline connecting physical endpoints, network probes, live threat feeds, and external SIEMs to the CyberShield SOC dashboard.

---

## 1. High-Level Data Flow Pipeline

The CyberShield live data architecture operates across seven discrete stages:

```
[ Data Sources ]
  - Endpoint Agents (Windows/Linux)
  - Authorized Network Discovery (Nmap/ARP)
  - Remote Threat Feeds (CISA KEV, URLhaus, MalwareBazaar, NVD)
  - SIEM / Syslog Forwarders (Wazuh, Splunk, Webhooks)
  - Internal Platform Audit Events
        │
        ▼
[ Ingestion & Collector Gateway ]
  - FastAPI `/api/v1/monitoring/telemetry`
  - Agent Token / HMAC-SHA256 Authentication
  - Sliding-Window Rate Limiting (120 req/min per agent)
  - Strict Request Size & SSRF Guardrails
        │
        ▼
[ Validation & Normalization Layer ]
  - Pydantic v2 Schema Enforcement
  - IP, MAC, CIDR, Port & Hash Syntax Validation
  - Privacy Stripping (Zero payload storage; headers & flow counters only)
  - Data Provenance Injection (`organization_id`, `collected_at`, `is_synthetic`)
        │
        ▼
[ Queue & Asynchronous Processing ]
  - Redis 7 In-Memory Message Broker
  - Celery Background Workers (Dedicated queues: `discovery`, `telemetry`, `intel`)
  - Exponential Backoff Retries & Dead-Letter Queue Handling
  - Deduplication & Idempotency Key Validation
        │
        ▼
[ PostgreSQL Storage & Multi-Tenancy ]
  - Supabase PostgreSQL with 100% Row Level Security (RLS)
  - B-Tree & GIN Indexes on IP, Hash, Domain, and Timestamp Columns
  - Partitioned Telemetry Buffers & Automated Data Retention Policies
        │
        ▼
[ Real-Time Correlation & Detection Engine ]
  - Rule-Based Event Correlation (Agent Inactive, New Unknown Asset, IOC Match)
  - Machine Learning Anomaly Detection (Isolation Forest on Flow Telemetry)
  - Alert Generation with Severity (`Critical`, `High`, `Medium`, `Low`, `Info`)
  - Incident Creation & Playbook Triggering
        │
        ▼
[ Live Delivery & SOC Dashboard ]
  - WebSockets / Server-Sent Events (SSE) / Resilient Polling Fallback (5s)
  - Dynamic Posture Scoring & MTTD/MTTR Calculation
  - Data Freshness Gauges & Stale Data Warnings
  - Clean Empty States with Guided Action Cards
```

---

## 2. Ingestion & Collector Specification

### 2.1 Endpoint Monitoring Agent Ingress
* **Endpoint:** `POST /api/v1/monitoring/agents/telemetry`
* **Authentication:** Custom Bearer token (`Authorization: Bearer cs_mon_<secret_hex>`). The token is validated against the stored SHA-256 hash using constant-time comparison (`hmac.compare_digest`).
* **Rate Limiting:** Sliding-window rate limiter restricting submissions to **120 requests per minute** per agent ID.
* **Payload Structure:**
  ```json
  {
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "timestamp": "2026-11-04T13:25:00Z",
    "host_metrics": {
      "cpu_utilization_pct": 24.5,
      "memory_utilization_pct": 68.2,
      "disk_utilization_pct": 52.1,
      "uptime_seconds": 184500,
      "network_interface_status": "Up"
    },
    "network_flows": [
      {
        "interface": "eth0",
        "source_ip": "192.168.1.15",
        "destination_ip": "1.1.1.1",
        "protocol": "UDP",
        "source_port": 54122,
        "destination_port": 53,
        "packet_count": 4,
        "byte_count": 312,
        "direction": "outbound"
      }
    ]
  }
  ```

### 2.2 Network Discovery Sweep Ingress
* **Endpoint:** `POST /api/v1/scans`
* **Trigger:** Dispatched via Celery worker (`run_authorized_discovery.delay`).
* **Execution:**
  1. Re-verifies approved RFC 1918 scope ownership in PostgreSQL.
  2. Executes native `nmap` process if binary is detected on host.
  3. If Nmap is missing, executes native asynchronous Python socket probes across top service ports and queries local OS ARP table (`arp -a`).
  4. Feeds open ports, MAC OUIs, and banners into `DeviceClassifier`.
  5. Ingests responsive hosts into `assets` with `discovery_method = 'automatic'`.

### 2.3 Threat Intelligence Feed Synchronizer
* **Endpoint:** `POST /api/v1/threat-intelligence/feeds/{feed_id}/sync`
* **Workers:** Celery periodic beat tasks or manual operator trigger.
* **Connectors:**
  * **CISA KEV:** Fetches `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`.
  * **URLhaus:** Fetches `https://urlhaus.abuse.ch/downloads/json_recent/`.
  * **MalwareBazaar:** Queries `https://mb-api.abuse.ch/api/v1/`.
  * **NVD CVE API:** Queries `https://services.nvd.nist.gov/rest/json/cves/2.0` with throttling.

---

## 3. Data Provenance & Synthetic Separation Model

Every security observable entering CyberShield is stamped with immutable provenance metadata:

| Column | Data Type | Purpose | Production Requirement |
| :--- | :--- | :--- | :--- |
| `organization_id` | UUID | Strict tenant boundary isolation | Enforced by Postgres RLS |
| `source_system` | TEXT | Identifier of reporting collector (`agent-01`, `nmap`, `urlhaus`) | Mandatory |
| `collected_at` | TIMESTAMPTZ | Exact UTC timestamp of collection | Mandatory |
| `is_synthetic` | BOOLEAN | Distinguishes demo/test seeds from real live observations | Default `FALSE` |
| `confidence` | INTEGER | Heuristic confidence rating (0 to 100%) | Mandatory |
| `evidence` | JSONB | Raw supporting proof (banners, hashes, socket responses) | Mandatory |

### Synthetic Data Quarantine Rule
* Production queries (`/api/v1/dashboard/overview`, `/api/v1/assets`, `/api/v1/alerts`) must append `WHERE is_synthetic = FALSE` by default.
* Synthetic or sample records will ONLY be returned when the request explicitly specifies `include_demo=true`.
* The UI displays a vibrant orange **SYNTHETIC** badge on any record carrying `is_synthetic = TRUE`.

---

## 4. Real-Time Event Correlation & Alert Rules

Incoming telemetry flows and host metrics pass through the real-time correlation engine in `backend/app/threat_intelligence/correlation.py`:

```
Incoming Stream ──► [ Deduplication Window (5 min) ]
                            │
                            ▼
                    [ Detection Rule Matcher ]
                            ├─ Rule 1: Agent Heartbeat Timeout (>90s) ──► Alert: "Agent Offline" (High)
                            ├─ Rule 2: Unassessed IP on Network       ──► Alert: "New Device" (Medium)
                            ├─ Rule 3: Flow Dest IP in URLhaus IOCs   ──► Alert: "C2 Traffic Match" (Critical)
                            ├─ Rule 4: Host CPU/RAM > 95%             ──► Alert: "Resource Exhaustion" (Warning)
                            └─ Rule 5: Critical CVE Detected in Scan  ──► Alert: "Exploitable Vuln" (Critical)
                            │
                            ▼
                    [ Alert Deduplication & Cooldown ]
                            │
                            ▼
                    [ Supabase Realtime Broadcast ] ──► Live SOC Dashboard
```

---

## 5. Live Dashboard Delivery & Freshness Indicators

The Next.js frontend delivers real-time updates through:
1. **WebSocket / Supabase Realtime Listener:** Listens on `realtime:public:alerts` and `realtime:public:security_events` filtered by `organization_id`.
2. **Resilient Polling Fallback:** If WebSocket connection drops or firewall blocks WS upgrades, an automatic 5-second polling interval retrieves delta updates.
3. **Data Freshness Indicator:**
   * **🟢 Live (< 15s ago):** All collectors reporting normally.
   * **🟡 Stale (15s – 2m ago):** Telemetry delayed; connection throttling active.
   * **🔴 Disconnected (> 2m ago):** Backend unreachable; displaying cached state.
4. **Actionable Empty States:**
   * Zero assets registered $\rightarrow$ Render "Run Network Discovery" card.
   * Zero agents reporting $\rightarrow$ Render "Download Monitoring Agent" card with generated token.
   * Zero threat intel $\rightarrow$ Render "Sync Public Feeds" card.
