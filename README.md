<<<<<<< HEAD
# CyberShield – Intelligent Network Security Monitoring & Vulnerability Assessment Platform

[![Next.js](https://img.shields.io/badge/Next.js-14.2-black)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Python_3.13-009688)](https://fastapi.tiangolo.com/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL_RLS-3ECF8E)](https://supabase.com/)
[![React Flow](https://img.shields.io/badge/React_Flow-Topology-FF0072)](https://reactflow.dev/)
[![Security](https://img.shields.io/badge/SOC-Dark_Glassmorphism-3B82F6)]()

CyberShield is an enterprise-grade multi-organization cybersecurity platform designed to help security teams discover network assets, assess vulnerabilities, identify exposed services, monitor security events, manage incidents, and generate compliance reports.

---

## 📁 Monorepo Structure

```
CyberShield/
├── apps/
│   ├── web/            # Next.js 14 SOC Dark Glassmorphism Web App
│   └── mobile/         # Expo React Native App (Sprint 8)
├── backend/            # FastAPI REST API & Scanner Orchestrator
├── packages/
│   └── shared-types/   # Shared TypeScript Domain Definitions
├── supabase/
│   ├── migrations/     # PostgreSQL RLS Schema (20 tables)
│   └── seed.sql        # Development Data Seed
├── infrastructure/     # Dockerfiles and compose setups
└── docs/               # System Architecture & API specifications
```

---

## 🚀 Quickstart: Sprint 0 SOC Dashboard

### 1. Install Dependencies
From the repository root:
```bash
npm install
```

### 2. Run the Next.js SOC Web Application
```bash
npm run dev
```

Visit **http://localhost:3000** in your browser.

---

## 🛡️ Key Features Implemented in Sprint 0

- **Premium SOC Dark Glassmorphism**: Tailored for 24/7 Security Operations Centers with dark surfaces, glowing severity badges, and Inter typography.
- **Tenant Workspace Switching**: Seamlessly manage multiple organizations (e.g. Nexus Defense Group vs. Aegis FinTech Labs).
- **Security Posture Score**: Algorithmic index evaluating unmitigated criticals, CVSS 3.1 severity, and CISA KEV tags.
- **Asset Inventory & Evidence**: Categorized register of servers, routers, workstations, IoT hardware, and CCTV cameras with classification confidence percentages.
- **Interactive Network Topology**: Visualized device relationship graph powered by React Flow with real-time node inspection.
- **Scan Center**: Orchestrate Network Discovery, OpenVAS Vulnerability Audits, and OWASP ZAP Web Baselines with live log output.
- **Incident Response & Security Operations (Sprint 8)**:
  - Unified Incident Management with sequential identifiers (`CS-YYYY-XXXXXX`), severity levels, priorities (`P1`–`P4`), and 8-phase lifecycle state machine (`New` &rarr; `Acknowledged` &rarr; `Investigating` &rarr; `Containment` &rarr; `Eradication` &rarr; `Recovery` &rarr; `Resolved` &rarr; `Closed`).
  - Multi-tab Incident Investigation Workspace (`/incidents/[incidentId]`) with 8 analytical sub-views (Overview, Alerts & Events, Assets & Indicators, MITRE ATT&CK, Evidence Vault, Response Playbooks, Approvals, Timeline & Notes).
  - MITRE ATT&CK Enterprise Matrix v15.1 Integration & Technique Mapping with confidence ratings and analyst rationale.
  - Evidence Management Vault with automatic SHA-256 calculation, strict 25MB limits, and executable upload rejection (`.exe`, `.sh`, `.bat`, etc.).
  - Response Playbooks Catalog (4 standard procedures + custom SOPs) with interactive step progress tracking and analyst attribution.
  - Human-in-the-Loop Response Approval Workflow (`/response-requests`) with mandatory decision justification notes for disruptive containment actions.
  - Incident Case Export in JSON and CSV formats.
- **Threat Intelligence & Security Monitoring (Sprint 7)**:
  - Authoritative IOC Hub supporting IPv4, IPv6, Domain, URL, MD5, SHA1, and SHA256 observable formats.
  - External threat feed manager integrating CISA KEV, abuse.ch URLhaus, abuse.ch MalwareBazaar, and AlienVault OTX with scheduled caching and health tracking.
  - High-throughput normalized security event telemetry ingestion with automatic data sanitization and tenant isolation.
  - Real-time Event Correlation Engine evaluating 5 core detection scenarios (Brute Force Anomaly, Threat Indicator Match, CISA KEV Exposure, Asset Activity Spikes, Repeated Suspicious Events).
  - SOC Alert Queue with complete triage lifecycle (`New`, `Investigating`, `Escalated`, `Resolved`, `False Positive`), mandatory resolution justification, analyst assignment, and incident linking.
  - Configurable Detection Rules catalog with threshold and sliding time-window tuning.
- **Vulnerability Management & Triage (Sprint 6)**:
  - Unified vulnerability assessment engine integrating NVD 2.0 CVE intelligence and the CISA Known Exploited Vulnerabilities (KEV) catalog.
  - Multi-engine scanner abstraction (`BaseScanner`, `MockVulnerabilityScanner`, `OpenVASScanner`, `ZapScanner`, `FindingNormalizer`).
  - Transparent, auditable prioritization score separating official CVSS base scores from weaponization context.
  - Strict remediation lifecycles (`Open`, `Acknowledged`, `In Progress`, `Resolved`, `Accepted Risk`, `False Positive`) with mandatory justification enforcement.
- **Authorized Network Discovery & Scope Governance (Sprint 5)**:
  - RFC 1918 private IPv4 subnet boundaries, public IP rejection, multi-signal heuristic device classification, and grounded Layer 3 topology.
- **Incident Room**: Rapid triage, analyst assignment, evidence recording, and resolution notes.
- **Final Integration, End-to-End Testing & Enterprise Release Preparation (Sprint 20)**:
  - Centralized Enterprise Release Readiness Dashboard (`/release-readiness`) providing an authoritative audit gate evaluating build safety, 215 regression tests, database migrations, authentication, multi-tenancy, and container hardening.
  - End-to-End Workflow Verification covering 11 critical paths from onboarding, asset discovery, and vulnerability triage to AI investigations, SOAR playbooks, and digital forensics.
  - Complete Enterprise Documentation Suite including Final Architecture (`docs/FINAL_ARCHITECTURE.md`), Database Architecture (`docs/DATABASE_ARCHITECTURE.md`), Installation Guide (`docs/INSTALLATION.md`), Deployment Guide (`docs/DEPLOYMENT_GUIDE.md`), and Testing Guide (`docs/TESTING_GUIDE.md`).
  - Transparent security engine classification explicitly distinguishing verified sensors (Scapy, CISA KEV, URLhaus, Forensics) from mock and externally configured engines.
- **Advanced Security Validation, Penetration Testing & Continuous Security Assurance (Sprint 19)**:
  - Centralized Continuous Security Assurance Center (`/security-assurance`) providing real-time deterministic posture evaluation, decoupled risk scores (0–100), automated test coverage %, and OWASP/ASVS compliance tracking.
  - 17-Component Security Architecture Assessment (`docs/SECURITY_ASSESSMENT.md`) evaluating Next.js frontend, FastAPI backend, Supabase PostgreSQL, Redis caching, Celery workers, container runtimes, and Zero Trust access policies.
  - OWASP Top 10:2021 & ASVS 4.0 Verification Matrix (`/security-assurance/application`) with interactive assessment dispatching, category filters, and test evidence drawers.
  - Automated API Security Validation & Fuzzing Suite (`/security-assurance/api`) validating BOLA cross-tenant boundaries, BFLA Viewer mutation guards, JWT signature tampering/expiration, SQL/Command injection safety, Zero Trust AAL2 step-up enforcement, and rate limiting.
  - Software Supply Chain & SBOM Auditing (`/security-assurance/dependencies`) powered by automated `pip-audit` and `npm audit` integrations with CVE identifiers and upgrade recommendations.
  - Container Runtime & Image Security Inspector (`/security-assurance/containers`) auditing image vulnerabilities and CIS Docker Benchmark hardening (non-root execution, minimal distroless/slim base images).
  - Unified Vulnerability & Findings Center (`/security-assurance/findings`) with complete finding lifecycles (`open`, `acknowledged`, `in_progress`, `fixed`, `accepted_risk`, `false_positive`, `verified`), analyst collaboration notes, and formal risk acceptance exception workflows.
  - Historical Posture Trend Tracking & Export Center (`/security-assurance/history`) supporting verified JSON and CSV report downloads.
  - Scanner Orchestration & Governance (`/security-assurance/settings`) managing automated assessment schedules, approved target scopes, and exception policies.
- **Enterprise Identity, SSO, MFA & Zero Trust Security Architecture (Sprint 18)**:
  - Multi-Factor Authentication (MFA) Center (`/settings/mfa`): RFC 6238 TOTP enrollment with dynamic scalable SVG QR code, 160-bit Base32 secret keys, drift-window tolerance (+/- 30s), brute-force rate-limiting lockout (5 failures per 15 min triggers 429), and single-use SHA-256 hashed recovery code vaults (`CS-XXXX-XXXX`) with TOTP-verified rotation.
  - Enterprise Single Sign-On (SSO) Center (`/settings/sso`): Centralized federation for Microsoft Entra ID (Azure AD), Okta, Google Workspace, and generic OIDC 1.0 / SAML 2.0 with masked secret protection (`••••••••••••`), live discovery connection testing, and DNS TXT token domain verification.
  - Active Session Security & Device Management (`/settings/sessions`): Continuous device fingerprinting (Desktop, Mobile, Tablet, OS, Browser, IP, Location), impossible travel & geographic jump anomaly detection, individual session revocation, and emergency "Revoke All Other Sessions" killswitch.
  - Zero Trust Access Policies & Microsegmentation (`/identity/access-policies`): Fail-closed continuous server-side ABAC authorization engine enforcing Authentication Assurance Levels (`aal2`), organization-wide MFA mandates, CIDR network boundaries, and an interactive Zero Trust Policy Simulator.
  - Immutable Identity Audit Log (`/identity/audit`): Forensic event ledger tracking logins, MFA challenges, step-up requests, IdP modifications, and access denials with strict cryptographic credential redaction.
  - Account Hardening & Posture Dashboard (`/settings/security`): 0-100 Security Score gauge, AAL indicator, and actionable security posture recommendations.
- **Advanced Threat Hunting & Digital Forensics (Sprint 17)**:
  - Centralized Advanced Threat Hunting Center (`/threat-hunting`) providing proactive hypothesis-driven telemetry interrogation, adversary behavior correlation, and IOC discovery.
  - Threat Hunting Investigation Case Files (`/threat-hunting/cases` & `/threat-hunting/cases/[caseId]`) with sequential numbering (`TH-YYYY-XXXXX`), objectives, hypotheses, findings logs, and strict separation between confirmed facts (`is_confirmed: true`) and analyst hypotheses.
  - Structured Query Engine (`/threat-hunting/search`) supporting parameterized filtering (`source_ip`, `destination_ip`, `port`, `protocol`, `asset_id`, `event_category`, `severity`, `ioc_value`, `detection_rule`, `time_range`), AND/OR logic gates, saved searches, pagination, query history, and CSV export.
  - Multi-Type IOC Deep Correlation Console (`/threat-hunting/ioc-investigation`) analyzing IPv4, IPv6, Domain, URL, MD5, SHA-1, and SHA-256 against threat intelligence feeds, alerts, assets, and incidents—with mandatory safety guard ensuring unknown indicators are labeled `unknown_unverified` and never assumed safe.
  - Digital Forensics Workspace (`/forensics` & `/forensics/cases/[caseId]`) managing formal case files (`FOR-YYYY-XXXXX`), investigation objectives, assigned investigators, target host roles (`compromised_target`, `pivot_host`, `command_control_hop`, `unauthorized_scanner`, `witness_system`), and analyst case notes.
  - Digital Evidence Vault (`/forensics/evidence`) with bit-stream preservation, category classification (logs, PCAP flows, memory dumps, disk artifacts, reports), automated SHA-256/MD5 hashing, and derivation tracking.
  - Tamper-Evident Cryptographic Chain of Custody powered by sequential SHA-256 hash chaining ($\text{SHA256}(\text{previous\_hash} : \text{evidence\_id} : \text{actor} : \text{action} : \text{timestamp} : \text{metadata})$), immutable append-only logs, and real-time cryptographic verification (`verify-chain`).
  - Safe Static Artifact Analysis Engine executing safe log AST normalization, regex IOC extraction, and PCAP header parsing with strictly zero binary or script execution within a 25MB boundary.
  - Forensic Timeline Reconstruction (`/forensics/timeline`) aggregating events chronologically across 8 security sources (auth, network, assets, vulnerabilities, threat intel, alerts, incidents, evidence custody) with interactive inspection and CSV export.
  - Standardized 14-Section Forensic Report Generation (`/forensics/reports`) compiling evidentiary case files, chain of custody verification statements, confirmed facts vs hypotheses, MITRE ATT&CK mapping, and remediation guidance into verifiable JSON and Markdown deliverables.
- **Production Hardening, Performance Optimization & DevSecOps (Sprint 16)**:
  - System Health & Fleet Observability Dashboard (`/system-health`) providing real-time subsystem diagnostics (PostgreSQL, Redis, Celery, Storage, Integrations), process uptime, and host telemetry (CPU, RAM, Disk).
  - Production Readiness Audit Dashboard (`/admin/production-readiness`) tracking 12 automated criteria across Configuration, DB Governance, Auth, Security, Backup, and DevSecOps with honest verification classifications.
  - Defense-in-Depth Runtime Security: Content Security Policy, HTTP security response headers (HSTS, DENY, nosniff), adaptive sliding-window rate limiting (120 req/min general, 15 req/min auth), and 25MB request size limits.
  - Request Correlation Tracing: Unique `X-Request-ID` and `X-Correlation-ID` header generation and propagation across distributed services and logs.
  - Sensitive Data Redaction: Automated log filter scrubbers masking passwords, bearer tokens, and secrets from application logs.
  - Hardened Non-Root Containers: Multi-stage Dockerfiles executing as unprivileged user `appuser` (UID 1001), health probes, dropped capabilities (`cap_drop: ALL`), and production compose profile (`docker-compose.prod.yml`).
  - Automated DevSecOps Workflows: GitHub Actions CI/CD (`ci.yml`), Gitleaks secret detection, Trivy vulnerability audits, CodeQL SAST (`security.yml`), and Dependabot patching (`dependabot.yml`).
  - Disaster Recovery Architecture: Automated daily backups, WAL point-in-time recovery (PITR) guide, and RPO (<1h) / RTO (<30m) documentation.
- **Enterprise Integrations & External Security Ecosystem (Sprint 15)**:
  - Centralized Integration Center (`/integrations`) with category filtering, live connection status pills, health scoring, and direct sync triggers.
  - Connector Catalog Marketplace (`/integrations/available`) supporting 8 categories: SIEM (Splunk HEC, Microsoft Sentinel, Elastic ECS, Wazuh), Communication (Slack, MS Teams, SMTP Email), Threat Intel (CISA KEV, AlienVault OTX, URLhaus), Cloud Security (AWS CloudTrail/GuardDuty, Azure Defender, Google Cloud SCC), and Webhooks.
  - Connector Setup & Credentials Drawer (`/integrations/configure/[id]`) with SSRF-protected endpoint validation, write-only AES-256 encrypted credential storage, and live round-trip latency testing.
  - Outbound Webhook Management (`/integrations/webhooks`) featuring HMAC-SHA256 signature generation (`CyberShield-Signature`), replay skew protection (<300s), strict SSRF blocking (127.0.0.1, localhost, 169.254.169.254, RFC 1918 subnets), secret rotation, delivery attempt logs, and one-click delivery replay.
  - Delivery Audit Trail (`/integrations/logs`) tracking chronological event dispatches, HTTP status code badges, latencies, and payload summaries.
  - Integration Health & SLA Monitor (`/integrations/health`) monitoring 24h delivery success rates, transport latencies, and provider availability rankings.
- **AI Threat Detection & Predictive Security Intelligence (Sprint 14)**:
  - Centralized threat detection engine analyzing network monitoring, asset discovery, auth events, and threat intel feeds.
  - Machine learning anomaly detection powered by `scikit-learn` Isolation Forest with calibrated anomaly scores and confidence metrics.
  - User and Asset Behavior Analytics (UEBA) calculating rolling 14-day asset baselines and standard deviation exceedance.
  - AI Threat Investigation Assistant (`/ai-threat-investigation`) providing grounded answers with telemetry evidence citations, uncertainty disclosures, and recommended investigative actions without hallucination.
  - Detection Rule Management (`/ai-detection/rules`) supporting statistical thresholds, behavioral deviation gates, and IOC matching.
  - Investigation Workspace (`/ai-detection/investigations`) for triage, analyst disposition notes, and true/false-positive feedback.
  - ML Model Registry (`/ai-detection/models`) tracking evaluation metrics (Precision, Recall, F1) and version revision history.
  - Predictive Threat Risk Scoring (`/ai-detection/risk-analysis`) projecting asset risk scores (0–100), trajectories, and contributing factors.
- **Security Orchestration, Automation & Response (SOAR - Sprint 13)**:
  - Centralized SOAR Automation Engine with automated event triggers (`new_critical_alert`, `new_high_vulnerability`, `suspicious_network_activity`, `threat_intel_ioc_match`, `repeated_auth_failures`, `unauthorized_asset_detected`, `manual_investigation`).
  - Interactive Visual Playbook Builder (`/soar/playbooks/new`) supporting 13 modular action step types (`trigger`, `condition`, `severity_check`, `asset_lookup`, `threat_intel_lookup`, `vulnerability_lookup`, `create_incident`, `add_incident_note`, `assign_analyst`, `send_notification`, `request_approval`, `generate_report`, `end_workflow`).
  - Human-in-the-Loop Approval Gates (`/soar/approvals`) enforcing mandatory analyst authorization before executing disruptive containment actions (`asset_isolation`, `account_suspension`, `firewall_rule_review`, `block_indicator`).
  - 5 Pre-Seeded Standard Security Playbooks (Suspicious Login Response, Malware Alert Investigation, Vulnerability Escalation, Suspicious Network Traffic & C2, Phishing Triage).
  - Execution History & Step-by-Step Audit Timeline (`/soar/executions` and `/soar/executions/[id]`) with input/output payloads and redacted console logs.
  - SOAR Automation Analytics (`/soar/analytics`) monitoring response velocity (MTTE in ms), daily execution trends, and SOC time savings.
  - Multi-Channel Notification Engine (`/soar/notifications`) supporting In-App, Email, and Webhook dispatch testing.
- **Advanced Network Monitoring & Real-Time SOC (Sprint 12)**:
  - Real-Time SOC Command Center (`/soc-monitoring`) with connection status pill (Connected / Reconnecting / Disconnected), live security event stream, and operational KPIs.
  - Authorized Network Traffic Analytics (`/network-monitoring`) capturing flow metadata, protocol breakdown (HTTPS, TCP, UDP, DNS, SSH), Top Talkers, and bandwidth trajectory.
  - Device Health & Host Telemetry Inventory (`/device-health`) with states (`Healthy`, `Warning`, `Critical`, `Offline`, `Unknown`) distinguishing real agent-monitored metrics from unmonitored assets.
  - Rule-Based Anomaly Detection Engine (`/network-anomalies`) evaluating traffic spikes, high-risk ports, suspicious egress, and IOC matches with an interactive Investigation Drawer.
  - Lightweight Monitoring Agent Architecture (`/monitoring-agents`) with token generation (`cs_mon_...`), one-way SHA-256 storage, and curl installer snippets.
  - Monitoring Policy Configuration (`/monitoring-rules`) for tuning evaluation thresholds, severities, and time windows.
- **Advanced Reporting, Compliance & Posture Management (Sprint 11)**:
  - Multi-Framework Compliance Module supporting NIST CSF 2.0, CIS Controls v8, OWASP Top 10:2021, and ISO/IEC 27001:2022 with domain tracking and control lifecycles (`Not Assessed`, `Partially Implemented`, `Implemented`, `Not Applicable`).
  - Cryptographic Evidence Vault with automated SHA-256 calculation, mime validation rejecting executable extensions (`.exe`, `.sh`, `.bat`, etc.), and 25MB file limits.
  - Advanced Reporting Engine supporting 7 core categories (Vulnerability Assessment, Asset Inventory, Incident Summary, Threat Intelligence, Compliance Assessment, Security Posture, Executive Summary) with pure-Python PDF 1.4 document compilation and RFC 4180 CSV export.
  - Deterministic Security Posture Score calculation (0–100) with category pillar health, risk factor deductions, and proactive remediation recommendations.
  - Dedicated Executive Dashboard (`/executive-dashboard`) providing C-level metrics, historical posture area graphs, framework compliance comparison, and Top 5 Security Risks.
- **Enterprise SaaS & Multi-Tenancy (Sprint 10)**:
  - Multi-tenant organization isolation enforced at the PostgreSQL RLS layer with workspace switching.
  - Centralized RBAC (`OWNER`, `ADMIN`, `ANALYST`, `VIEWER`) with strict last-owner demotion/removal protection.
  - Team onboarding workflows with tokenized invitations and automatic seat quota guards.
  - 3-tier subscription billing engine (`Free Starter`, `Professional SOC`, `Enterprise Defense`) with metered quotas for assets, seats, monthly scans, and AI requests.
  - Programmatic API Key Management with SHA-256 cryptographic hashing, prefix tracking (`cs_live_...`), and one-time secret reveals.
  - Platform Admin Control Center (`/platform-admin`) strictly decoupled from tenant owner roles for global health monitoring, cross-tenant auditing, and organization workspace suspension/reactivation.
- **AI-Powered SOC Assistant & Advanced Analytics (Sprint 9)**:
  - Grounded AI Assistant with multi-provider abstraction (Mock, OpenAI, Google Gemini).
  - Security guardrails enforcing prompt-injection defenses, credential leakage prevention, and tenant boundary confinement.
  - Autonomous Alert AI Analyzer, Incident Summarizer, and Remediation Advisor.
  - Deterministic Security Analytics Engine calculating Posture Scores, MTTD/MTTR operational velocities, and vulnerability distributions.
- **Compliance & Executive Reports**: Audit-ready report generation for ISO 27001, SOC 2, and executive leadership.
- **Immutable Audit Trail**: Append-only log recording logins, scan dispatches, and status modifications.

---

## 🧪 Automated Testing

### Backend Unit & Integration Tests (215/215 passing):
```bash
cd backend
.venv\Scripts\pytest -q
```

### Frontend Type Safety Verification (0 errors):
```bash
cd apps/web
npx tsc --noEmit
```
- **Role-Based Access Control (RBAC)**: Centralized matrix defining Owner, Admin, Analyst, and Viewer permissions with platform admin segregation.
=======
# Cybershield-platform
>>>>>>> 91cbde4085bfe755372ebdb5ae47b9f01633ebbe
