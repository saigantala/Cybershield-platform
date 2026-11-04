# CyberShield V1.0 – Real-World Implementation & Execution Plan

**Document Version:** 1.0.0-PROD  
**Plan Date:** November 4, 2026  
**Auditor Roles:** Principal Software Architect, Senior Full-Stack Engineer, Lead DevSecOps Architect  
**Objective:** Step-by-step engineering roadmap to transform CyberShield from simulated placeholders to a functional, real-world cybersecurity operations platform in an alive, verified state.

---

## 1. Implementation Philosophy & Rules of Engagement

1. **Never Break Working Code:** Build upon existing architecture without rewriting functional modules.
2. **Preserve Premium SOC Design System:** All UI enhancements must adhere to the Dark Glassmorphism aesthetic (`#080D18`, `#0B1220`, `#111C2D`, `#162338`).
3. **Honest Data Presentation:** Never display hardcoded mock metrics as real telemetry. When no real data exists, present an informative Empty State with clear onboarding action buttons.
4. **Keep the Project Alive:** Ensure dev servers (FastAPI port 8000, Next.js port 3000) remain running and accessible on localhost throughout and following implementation.
5. **Least Privilege & Safe Boundaries:** Scanning restricted to authorized RFC 1918 private scopes and loopback; no arbitrary shell execution or destructive exploitation.

---

## 2. Phase-by-Phase Execution Plan

### Phase 1: Repository Audit & Removal of Misleading Mock Production Data
* **Objectives:**
  1. Complete repository inspection and publish architectural deliverables.
  2. Eliminate hardcoded initial metrics in frontend dashboards (`total: 248`, `critical: 8`).
  3. Replace static fallback tables (`RecentFindingsTable`, `RecentScansTable`, `ActiveIncidentsWidget`, `VulnerabilityCharts`) with live API connections and clean Empty States.
  4. Tag synthetic records with `is_synthetic = True` and render visual **SYNTHETIC** badges.
* **Target Files:**
  * `apps/web/app/(dashboard)/page.tsx`
  * `apps/web/components/dashboard/RecentFindingsTable.tsx`
  * `apps/web/components/dashboard/RecentScansTable.tsx`
  * `apps/web/components/dashboard/ActiveIncidentsWidget.tsx`
  * `apps/web/components/dashboard/VulnerabilityCharts.tsx`
  * `apps/web/app/(dashboard)/topology/page.tsx`
* **Verification:** Dashboard displays `0` counts and clean actionable empty states when database is empty.

---

### Phase 2: Database & Backend Integration Validation
* **Objectives:**
  1. Ensure schema supports live data provenance: `is_synthetic` column on `assets`, `vulnerability_findings`, `threat_indicators`, `security_events`, `alerts`, `incidents`.
  2. Implement SQLite/Postgres fallback persistence for `SupabaseService` so data persists across backend restarts even when cloud Supabase credentials are absent.
  3. Verify RLS policies on all extended columns.
* **Target Files:**
  * `supabase/migrations/`
  * `backend/app/services/supabase_service.py`
* **Verification:** Backend restarts retain dynamically registered assets and enrolled agents.

---

### Phase 3: Real Network Discovery Engine
* **Objectives:**
  1. Maintain Nmap binary execution when installed.
  2. Implement a **Native Python Asynchronous TCP & ARP Discovery Engine** as fallback when Nmap binary is absent:
     - Asynchronous port scan across top service ports (80, 443, 22, 53, 3000, 8000, 5432, 3389, 445, 8080).
     - Local ARP cache inspection (`arp -a`) to discover real MAC addresses and IP mappings.
     - Reverse DNS lookup (`socket.gethostbyaddr`) for hostnames.
     - HTTP/SSH socket banner grabbing.
     - Device classification via `DeviceClassifier`.
  3. Re-verify RFC 1918 scope validation (reject public IPs).
  4. Detect asset state changes between scans.
* **Target Files:**
  * `backend/app/services/nmap_scanner.py`
  * `backend/app/services/device_classifier.py`
  * `backend/app/workers/tasks.py`
* **Verification:** Scanning `127.0.0.1/32` or local gateway discovers actual listening ports (8000, 3000) with 0 simulated Cisco devices.

---

### Phase 4: Authenticated Endpoint Monitoring Agent
* **Objectives:**
  1. Author a standalone, cross-platform Python agent script: `agent/cybershield_agent.py`.
  2. Collect real host metrics:
     - CPU utilization % (`psutil.cpu_percent`)
     - Memory utilization % (`psutil.virtual_memory`)
     - Disk utilization % (`psutil.disk_usage`)
     - Network interface stats (`psutil.net_io_counters`)
     - Host uptime (`psutil.boot_time`)
     - OS and hostname (`platform.platform`, `socket.gethostname`)
  3. Implement agent enrollment flow:
     - Generate registration token `cs_mon_...` via `POST /api/v1/monitoring/agents/register`.
     - Store token securely in local agent config (`agent_config.json`).
  4. Stream real telemetry every 30s to `POST /api/v1/monitoring/agents/telemetry`.
  5. In-memory queue buffering (up to 500 items) with backoff retry on connection drop.
  6. Frontend UI display at `/device-health` and `/monitoring-agents` showing live online status and metrics.
* **Target Files:**
  * `agent/cybershield_agent.py` (New File)
  * `agent/README.md` (New File)
  * `backend/app/services/monitoring_service.py`
  * `apps/web/app/(dashboard)/monitoring-agents/page.tsx`
  * `apps/web/app/(dashboard)/device-health/page.tsx`
* **Verification:** Running `python agent/cybershield_agent.py` against localhost updates the dashboard with live CPU/RAM metrics within 30 seconds.

---

### Phase 5: Real Vulnerability Scanner Integration
* **Objectives:**
  1. Integrate real Nmap service version detection strings into CVE lookup.
  2. Implement honest Greenbone/OpenVAS connector reporting `IMPLEMENTED_NOT_CONFIGURED` when no GVM daemon is reachable, with instructions to launch via Docker.
  3. Implement honest OWASP ZAP connector reporting `IMPLEMENTED_NOT_CONFIGURED` when no ZAP daemon is reachable.
  4. Correlate discovered open service banners against known NVD/CISA KEV CVEs without fabricating findings.
  5. Finding deduplication and audit trail tracking.
* **Target Files:**
  * `backend/app/scanners/openvas_scanner.py`
  * `backend/app/scanners/zap_scanner.py`
  * `backend/app/services/cve_service.py`
* **Verification:** Vulnerability findings page reflects only verifiable CVE matches from open service banners.

---

### Phase 6: Live Threat Intelligence Feed Synchronization
* **Objectives:**
  1. Connect CISA KEV feed to live remote URL `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`.
  2. Connect abuse.ch URLhaus feed to live remote URL `https://urlhaus.abuse.ch/downloads/json_recent/`.
  3. Connect abuse.ch MalwareBazaar to live API `https://mb-api.abuse.ch/api/v1/`.
  4. Implement real IOC matching engine comparing live discovered assets and agent flows against threat indicators.
  5. Expiration, deduplication, and source attribution.
* **Target Files:**
  * `backend/app/threat_intelligence/feed_manager.py`
  * `backend/app/threat_intelligence/correlation.py`
  * `apps/web/app/(dashboard)/threat-intelligence/page.tsx`
* **Verification:** Triggering feed sync downloads real live threat indicators into `threat_indicators` table.

---

### Phase 7: Real Security Event Collection & Normalization
* **Objectives:**
  1. Unify incoming events from agents, scans, threat matches, and audit logs into a normalized pipeline.
  2. Schema enforcement: `organization_id`, `source`, `category`, `severity`, `timestamp`, `src_ip`, `dst_ip`, `asset_id`, `details`.
  3. Event ingestion API endpoint with deduplication and search.
* **Target Files:**
  * `backend/app/api/routes/security_events.py`
  * `backend/app/services/supabase_service.py`
  * `apps/web/app/(dashboard)/security-monitoring/page.tsx`
* **Verification:** Agent heartbeats and scan runs generate real normalized security events in the event ledger.

---

### Phase 8: Operational Alert & Incident Detection Rules
* **Objectives:**
  1. Implement operational detection rules:
     - **Rule 1: Agent Heartbeat Expired (>90s)** $\rightarrow$ Alert: `Agent Offline` (High)
     - **Rule 2: Unassessed Host Discovered on Network** $\rightarrow$ Alert: `New Device Detected` (Medium)
     - **Rule 3: Live Flow Destination Matches Malicious IOC** $\rightarrow$ Alert: `Malicious Traffic Detected` (Critical)
     - **Rule 4: Host CPU/RAM > 95%** $\rightarrow$ Alert: `Resource Exhaustion Anomaly` (Warning)
     - **Rule 5: Exploitable CISA KEV Vulnerability Identified** $\rightarrow$ Alert: `Known Exploited Vuln Found` (Critical)
  2. Alert triage lifecycle: `New` $\rightarrow$ `Investigating` $\rightarrow$ `Escalated` $\rightarrow$ `Resolved`.
  3. Incident creation and escalation with NIST SP 800-61r2 playbook assignment.
* **Target Files:**
  * `backend/app/threat_intelligence/correlation.py`
  * `backend/app/api/routes/alerts.py`
  * `backend/app/api/routes/incidents.py`
  * `apps/web/app/(dashboard)/alerts/page.tsx`
* **Verification:** Stopping the endpoint agent triggers an automated `Agent Offline` alert in the alert queue.

---

### Phase 9: Real-Time SOC Dashboard & Freshness Indicators
* **Objectives:**
  1. Update `/` and `/soc-monitoring` to render real data queries only.
  2. Implement polling fallback (5s) for live event feed updates.
  3. Add visual Data Freshness Indicator:
     - 🟢 **LIVE (< 15s ago)**
     - 🟡 **STALE (15s – 2m)**
     - 🔴 **DISCONNECTED (> 2m)**
  4. Render high-impact Empty States with quick-action cards when data is zero.
  5. Transform network discovery results into dynamic React Flow nodes in `/topology`.
* **Target Files:**
  * `apps/web/app/(dashboard)/page.tsx`
  * `apps/web/app/(dashboard)/soc-monitoring/page.tsx`
  * `apps/web/app/(dashboard)/topology/page.tsx`
* **Verification:** Dashboard updates dynamically when background events or agent heartbeats occur.

---

### Phase 10: SIEM Connectors & Grounded AI Analysis
* **Objectives:**
  1. Build functional HTTP connectors for Slack, Microsoft Teams, and Generic HMAC Webhooks.
  2. Provide clean configuration and test connection modals for Wazuh, Splunk HEC, and Microsoft Sentinel.
  3. Connect Google Gemini 1.5 Pro with prompt shielding, evidence attribution, and clear offline status indicator.
* **Target Files:**
  * `backend/app/services/integrations_service.py`
  * `backend/app/ai/alert_analyzer.py`
  * `apps/web/app/(dashboard)/integrations/page.tsx`
* **Verification:** Dispatched test webhook reaches target endpoint; AI explanations reference real event evidence.

---

### Phase 11: End-to-End Verification & Real Data Validation
* **Objectives:**
  1. Run full automated test suite (`pytest -q`).
  2. Run frontend typecheck (`tsc --noEmit`).
  3. Execute live lab validation:
     - Register user and organization.
     - Run network discovery on `127.0.0.1/32` or local subnet.
     - Run endpoint agent on host machine.
     - Synchronize live CISA KEV and URLhaus feeds.
     - Verify real alert generation on agent stop.
     - Verify real-time dashboard presentation.
  4. Publish `docs/REAL_INTEGRATION_TEST_RESULTS.md` and `docs/V1_REAL_WORLD_RELEASE_READINESS.md`.
* **Target Files:**
  * `docs/REAL_INTEGRATION_TEST_RESULTS.md`
  * `docs/V1_REAL_WORLD_RELEASE_READINESS.md`
* **Verification:** 100% test pass rate, 0 compilation errors, alive servers on ports 8000 and 3000.
