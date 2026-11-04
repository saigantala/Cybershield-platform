# CyberShield – Complete API Documentation (REST v1)

All routes are mounted under the base path `/api/v1` and documented interactively via OpenAPI at `/api/v1/docs` and Redoc at `/api/v1/redoc`.

---

## 1. 34 Mounted API Routers Summary

| Router Prefix | Tag | Description |
|---|---|---|
| `/health` | System Health | Liveness, readiness, Redis ping, and subsystem status. |
| `/auth` | Authentication | Login, registration, token refresh, and user profile. |
| `/scopes` | Scope Governance | RFC 1918 authorized CIDR subnet boundaries. |
| `/assets` | Asset Management | Multi-signal heuristic device inventory and tags. |
| `/scans` | Network Discovery | Port scanning, OS detection, and scan history. |
| `/vulnerabilities`| Vulnerability Engine | CVSS v3.1 calculation, NVD CVE mapping, remediation. |
| `/threat-intelligence` | Threat Intel | IOC indicators, CISA KEV feeds, and URLhaus. |
| `/security-events`| Security Telemetry | Normalized event ingestion and correlation. |
| `/alerts` | Alert Center | SOC alert triage, investigation, and escalation. |
| `/detection-rules`| Detection Rules | Sliding-window threshold tuning and behavioral rules. |
| `/incidents` | Incident Response | Case management and MITRE ATT&CK technique mapping. |
| `/attack` | MITRE ATT&CK | Enterprise Matrix v15.1 tactic and technique matrix. |
| `/evidence` | Evidence Vault | SHA-256 evidence hashing and upload vault. |
| `/playbooks` | Response SOPs | Interactive incident response playbooks. |
| `/response-requests` | Approvals | Human-in-the-loop disruptive action approval gates. |
| `/ai` | AI SOC Assistant | Grounded conversational assistant and alert summarizer. |
| `/analytics` | SOC Analytics | MTTE/MTTD operational velocity and posture analytics. |
| `/organizations` | Multi-Tenancy | Tenant workspace switching and organization settings. |
| `/team` | Team & RBAC | Member role management and last-owner lockout block. |
| `/subscriptions` | SaaS Billing | Quota management, plans, and usage limits. |
| `/api-keys` | API Keys | SHA-256 hashed API keys with prefix tracking. |
| `/platform-admin` | Platform Admin | Cross-tenant auditing and platform health. |
| `/compliance` | Compliance | NIST CSF 2.0, CIS v8, and ISO 27001 assessments. |
| `/reports` | Executive Reports | Pure-Python PDF 1.4 compilation and CSV export. |
| `/monitoring` | Agent Fleet | Lightweight agent tokens and host metrics collection. |
| `/network` | Traffic Analytics | Packet metadata extraction and protocol breakdown. |
| `/soar` | SOAR Engine | Automated workflow execution and approval gates. |
| `/ai-detection` | AI Threat Detection | Isolation Forest ML anomaly scoring and UEBA. |
| `/integrations` | External Connectors| SIEM webhooks, Slack, Splunk HEC, and logs. |
| `/system-health` | Host Observability| CPU, RAM, disk, and container subsystem telemetry. |
| `/threat-hunting` | Threat Hunting | Hypothesis-driven structured query engine and IOCs. |
| `/forensics` | Digital Forensics | NIST SP 800-86 cases, evidence, and custody chain. |
| `/identity` | Zero Trust & MFA | RFC 6238 TOTP, AAL2 step-up, and SSO federation. |
| `/security-assurance` | Pentest & Posture | Automated API security suite, SBOM, and findings. |
| `/release-readiness` | Release Audit | Enterprise release gate and multi-factor readiness. |
