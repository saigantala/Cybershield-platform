# CyberShield – Sprint 11: Advanced Reporting, Compliance & Security Posture Management

## Overview
Sprint 11 delivers an enterprise-grade reporting and governance engine for CyberShield. It equips SecOps teams, compliance officers, and executive leadership with automated compliance auditing against premier cybersecurity frameworks, deterministic security posture scoring, tamper-evident cryptographic evidence storage, auditable document export (PDF 1.4 and RFC 4180 CSV), and an interactive C-level executive briefing dashboard.

---

## 1. Architecture & Capabilities

```
+-------------------------------------------------------------------------------+
|                       CyberShield Executive & SOC UI                          |
|  /compliance  |  /compliance/frameworks  |  /reports  |  /executive-dashboard |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                        FastAPI Backend Engine (v1)                            |
|                                                                               |
|   +-----------------------+  +-----------------------+  +------------------+  |
|   |   ComplianceService   |  |     PostureService    |  |    PDF/CSV Export|  |
|   |  • Framework Registry |  |  • 0-100 Score Calc   |  |  • Pure-Python   |  |
|   |  • Control Assessment |  |  • 5 Pillar Breakdown |  |    PDF 1.4 Engine|  |
|   |  • Evidence Vault     |  |  • Risk Factor Engine |  |  • RFC 4180 CSV  |  |
|   |    (SHA-256 / Filter) |  |  • Exec Summary API   |  |  • 7 Categories  |  |
|   +-----------------------+  +-----------------------+  +------------------+  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                        Supabase PostgreSQL RLS Schema                         |
|  compliance_frameworks | compliance_controls   | compliance_assessments       |
|  compliance_evidence   | security_reports      | report_schedules             |
|  posture_score_history | (Tenant Isolated via organization_id RLS)            |
+-------------------------------------------------------------------------------+
```

---

## 2. Multi-Framework Compliance Module

CyberShield models four major compliance frameworks natively with domain mappings, control specifications, implementation guidelines, and assessment lifecycles:

1. **NIST Cybersecurity Framework (CSF) 2.0**:
   - Domains: Govern (`GV`), Identify (`ID`), Protect (`PR`), Detect (`DE`), Respond (`RS`), Recover (`RC`).
   - Grounded controls for access control (`PR.AC-1`), continuous monitoring (`DE.CM-1`), vulnerability management (`ID.RA-1`), and incident handling (`RS.MA-1`).
2. **CIS Controls v8**:
   - Mapped across Implementation Groups (IG1, IG2, IG3).
   - Core controls for inventory of enterprise assets (`1.1`), software assets (`2.1`), continuous vulnerability management (`7.1`), and audit log management (`8.2`).
3. **OWASP Top 10:2021**:
   - Broken Access Control (`A01:2021`), Cryptographic Failures (`A02:2021`), Injection (`A03:2021`), Insecure Design (`A04:2021`), Security Misconfiguration (`A05:2021`), Vulnerable Components (`A06:2021`), and SSRF (`A10:2021`).
4. **ISO/IEC 27001:2022**:
   - Annex A Controls spanning Information Security Policies (`A.5.1`), Threat Intelligence (`A.5.7`), Access Control (`A.8.2`), Management of Technical Vulnerabilities (`A.8.8`), and Incident Response (`A.5.24`).

### Assessment Workflow
- Status lifecycle: `Not Assessed` &rarr; `Partially Implemented` &rarr; `Implemented` &rarr; `Not Applicable`.
- Control owner assignment, target review dates, compliance score weighting, and auditable implementation notes.
- Framework adherence percentage formula:
  $$\text{Completion \%} = \frac{\text{Implemented} + (0.5 \times \text{Partially Implemented})}{\text{Total Applicable Controls}} \times 100$$

---

## 3. Compliance Evidence Vault

The evidence vault preserves auditable artifacts proving control implementation:
- **Cryptographic Hash Verification**: Backend automatically calculates SHA-256 digest on upload (`hashlib.sha256`) and records file byte size.
- **Malicious Upload Mitigation**: Strictly denies executable and script extensions (`.exe`, `.bat`, `.cmd`, `.sh`, `.ps1`, `.msi`, `.dll`, `.vbs`, etc.).
- **Size Bounds**: Enforces 25MB maximum file size ceiling.
- **Auditable Association**: Binds evidence directly to control identifiers and assessments with analyst attribution and tenant isolation.

---

## 4. Advanced Security Reporting Engine

Supports automated document compilation across **7 essential categories**:
1. `vulnerability_assessment`: Technical CVE findings, CVSS v3.1 metrics, CISA KEV tags, PoC references & patch advisories.
2. `asset_inventory`: Discovered IP addresses, MAC identifiers, open ports, services, OS classifications & subnets.
3. `incident_summary`: Incident timeline, severity triage, MTTA/MTTR metrics, playbook execution & containment status.
4. `threat_intelligence`: Active indicators of compromise (IOCs), adversary reputation scores & threat actor attribution.
5. `compliance_assessment`: Framework control statuses, evidence references & audit gap analysis.
6. `security_posture`: Quantitative risk scorecard, 5-pillar breakdown & proactive remediation priorities.
7. `executive_summary`: Board-level briefing with overall risk classification, KPIs, and executive action recommendations.

### Pure-Python PDF 1.4 Builder (`PDFDocumentBuilder`)
- Generates 100% standards-compliant PDF 1.4 binary documents directly without external pip dependencies.
- Features: CyberShield header branding, confidentiality classification banners, executive metric summary boxes, structured tables with column widths, page numbers (`Page X of Y`), and digital verification stamps.

### RFC 4180 CSV Engine (`CSVReportBuilder`)
- Generates machine-readable tabular exports with proper quoting, header definitions, and formatting for ingestion into external SIEM or BI tooling.

---

## 5. Deterministic Security Posture Scoring (0–100)

CyberShield evaluates organizational security posture with complete mathematical transparency, separating CVSS base severity from internal posture calculations:

### Scoring Formula
$$\text{Score} = \min\Big(100, \max\big(0, 100 - \sum \text{Deductions}\big)\Big)$$

- **Critical CVEs**: $-10$ pts per open critical finding (capped at $-30$).
- **CISA KEV Exploits**: $-8$ pts per actively exploited vulnerability (capped at $-24$).
- **High Severity CVEs**: $-4$ pts per finding (capped at $-20$).
- **Uncontained Incidents**: $-6$ pts per active high/critical incident (capped at $-18$).
- **Unverified Perimeter Scopes**: $-5$ pts.
- **Compliance Gap Factor**: $+0.2 \times (\text{Framework Adherence \%} - 50)$.

### Risk Classification Thresholds:
- **85 – 100**: `Hardened` (Minimal exposure, proactive controls verified)
- **70 – 84**: `Low Risk` (Operational controls active, routine remediation)
- **50 – 69**: `Moderate Risk` (Action required on identified vulnerabilities)
- **30 – 49**: `High Risk` (Critical exposures or uncontained incidents present)
- **0 – 29**: `Critical Risk` (Immediate containment and executive intervention required)

---

## 6. Dedicated Executive Dashboard (`/executive-dashboard`)

A modern, high-level view engineered specifically for CISOs, CIOs, and executive leadership:
- **Date Range Telemetry**: 7-day, 30-day, and 90-day observation windows.
- **Executive Security Score Hero**: Large illuminated score gauge with trend indicator (`+4 pts vs prior period`).
- **5 Category Pillars**: Vulnerability Mgmt, Perimeter Hardening, Incident Readiness, Threat Intelligence, and Regulatory Compliance.
- **Key Executive KPIs**: Critical CVE count, High-Risk Asset count, Open Incidents with MTTR, Compliance %, Remediation SLA adherence %.
- **Interactive Visualizations (Recharts)**: Historical posture score trajectory area chart and Multi-Framework compliance vs target bar chart.
- **Top 5 Security Risks**: Weaponization-ranked threat vectors featuring CVE IDs, CVSS scores, affected assets, and CISA KEV active exploitation indicators.
- **Prioritized Strategic Decisions**: Board-ready remediation recommendations with ROI impact projections.
- **One-Click Export**: Immediate generation and export of the signed Executive PDF briefing.

---

## 7. Frontend Architecture (Next.js 14 SOC UI)

| Route | Functionality |
|---|---|
| `/compliance` | Multi-framework overview, overall completion gauge, domain readiness, quick actions |
| `/compliance/frameworks` | Framework selector, control search, domain filters, status badges, expandible requirements |
| `/compliance/assessments` | Control assessment modal, status selector, owner assignment, target date, audit notes |
| `/compliance/evidence` | Evidence vault, SHA-256 verification hash, file size bounds, mime filter, delete modal |
| `/reports` | 7 report category cards, live document preview modal, PDF & CSV export, history table |
| `/executive-dashboard` | C-Level briefing, posture gauge, 5 pillar health, trend graphs, top 5 risks, strategic actions |

---

## 8. Verification & Test Suite

All 103 backend automated tests passing in **2.48s**:
```bash
cd backend
.venv\Scripts\pytest -q
# Result: 103 passed, 267 warnings in 2.48s
```

Frontend type safety completely clean with **0 errors**:
```bash
cd apps/web
npx tsc --noEmit
# Result: Exit code 0
```
