# CyberShield Sprint 6: Vulnerability Assessment Engine

## 1. Overview & Architecture

CyberShield Sprint 6 delivers an enterprise vulnerability assessment engine designed to audit network services, identify exposed Common Vulnerabilities and Exposures (CVEs), correlate threat intelligence with CISA's Known Exploited Vulnerabilities (KEV) catalog, calculate auditable risk prioritization scores, and manage the remediation lifecycle within a unified Security Operations Center (SOC).

```
                      +------------------------------------+
                      |    Next.js SOC Frontend (/vulnerabilities) |
                      +-----------------+------------------+
                                        | (Bearer JWT)
                                        v
                      +------------------------------------+
                      |       FastAPI Gateway (v1)         |
                      |   /api/v1/vulnerabilities/*        |
                      +--------+------------------+--------+
                               |                  |
           +-------------------+                  +-------------------+
           |                                                          |
           v                                                          v
+-----------------------+                                  +---------------------+
|  Supabase PostgreSQL  |                                  |   Celery Workers    |
| - vulnerability_scans |                                  |  & Redis Broker     |
| - vulnerability_finds |                                  +----------+----------+
| - remediation_history |                                             |
| - Row Level Security  |                                             |
+-----------------------+                                             |
                                                                      v
                                                    +---------------------------------+
                                                    |    Scanner Abstraction Layer    |
                                                    |  (backend/app/scanners/)        |
                                                    | - BaseScanner Interface         |
                                                    | - MockVulnerabilityScanner      |
                                                    | - OpenVASScanner (GMP Engine)   |
                                                    | - ZapScanner (Passive Baseline) |
                                                    | - FindingNormalizer             |
                                                    +----------------+----------------+
                                                                     |
                                             +-----------------------+-----------------------+
                                             |                                               |
                                             v                                               v
                                   +-------------------+                           +-------------------+
                                   | NVD 2.0 CVE Intel |                           |  CISA KEV Catalog |
                                   | Rate-limited      |                           | Weaponization     |
                                   | Cached Advisories |                           | Indicators        |
                                   +-------------------+                           +-------------------+
```

---

## 2. Database Schema & Migrations

Migration: `supabase/migrations/20261031_sprint6_vulnerability_engine.sql`

### Tables Created:
1. `vulnerability_scans`:
   - `id`: UUID primary key
   - `organization_id`: UUID references `organizations(id)`
   - `scan_scope_id`: UUID references `scan_scopes(id)`
   - `scan_type`: `mock`, `openvas`, `zap_baseline`, `comprehensive`
   - `scanner_name`: Name of scanner engine invoked
   - `status`: `queued`, `running`, `completed`, `failed`, `cancelled`
   - `total_assets`: Responsive targets assessed
   - `total_findings`: Identified vulnerabilities
   - `error_message`: Diagnostic failure logs

2. `vulnerability_findings`:
   - `id`: UUID primary key
   - `organization_id`: UUID references `organizations(id)`
   - `scan_id`: UUID references `vulnerability_scans(id)`
   - `asset_id`: UUID references `assets(id)`
   - `title`: Vulnerability advisory headline
   - `description`: Technical vulnerability overview
   - `cve_id`: Normalized CVE identifier (e.g. `CVE-2024-21762`)
   - `cvss_score`: Official base CVSS score (0.0 – 10.0)
   - `cvss_version`: CVSS metric version (default `3.1`)
   - `severity`: Standardized rating (`Critical`, `High`, `Medium`, `Low`, `Informational`)
   - `prioritization_score`: CyberShield contextual risk rating (0.0 – 100.0)
   - `affected_service` & `affected_version`: Software components identified
   - `evidence`: Proof-of-concept capture
   - `remediation`: Vendor mitigation guidance
   - `reference_urls`: Authoritative external security advisories
   - `is_kev`: Boolean weaponization indicator
   - `kev_metadata`: CISA KEV due dates, vendor project, ransomware usage
   - `status`: `Open`, `Acknowledged`, `In Progress`, `Resolved`, `Accepted Risk`, `False Positive`
   - **Constraint**: `UNIQUE(asset_id, cve_id, title)` for duplicate prevention.

3. `vulnerability_references`:
   - External advisory links tied to specific findings.

4. `remediation_history`:
   - Audit trail capturing `previous_status`, `new_status`, `notes`, `changed_by`, and `created_at`.

### Row Level Security (RLS) Policies:
- Strict multi-tenant isolation based on `organization_members(organization_id)`.
- Viewers have read-only access.
- Analysts, Admins, and Owners have scan creation and remediation update privileges.

---

## 3. Scanner Abstraction Layer

Located in `backend/app/scanners/`:

1. `BaseScanner` (`base.py`):
   - `check_health()`: Diagnostic probe of daemon connectivity and authentication.
   - `run_assessment(targets, options)`: Non-destructive assessment pipeline.
   - `cancel_assessment(task_id)`: Cooperative job cancellation.

2. `MockVulnerabilityScanner` (`mock_scanner.py`):
   - Deterministic offline scanner for CI/CD, development, and unit testing.
   - Accurately correlates real CVEs (Fortinet SSL-VPN RCE `CVE-2024-21762`, OpenSSH regreSSHion `CVE-2024-6387`, SSH Terrapin `CVE-2023-48795`, HSTS missing headers) to asset traits.

3. `OpenVASScanner` (`openvas_scanner.py`):
   - Greenbone Management Protocol (GMP) client.
   - Safe execution against approved targets without destructive exploit scripts.

4. `ZapScanner` (`zap_scanner.py`):
   - OWASP ZAP API integration strictly using safe baseline and passive scan rules.
   - Active attack plugins, fuzzers, and brute-force modules are strictly forbidden and disabled.

5. `FindingNormalizer` (`normalizer.py`):
   - Canonicalizes raw scanner inputs into standardized CyberShield records.
   - Enforces CVSS boundary clamping, severity title-casing, CVE regex extraction, and reference hygiene.

---

## 4. Threat Intelligence Integrations

### NVD CVE Intelligence (`backend/app/services/cve_service.py`):
- Connects to official NIST NVD API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
- Supports optional `NVD_API_KEY` with rate limiting throttling (0.6s interval with key, 6.0s without).
- 24-hour in-memory cache to minimize external network latency.
- Protects against uncertain banner guessing: requires explicit software version strings before correlating product CVEs.

### CISA KEV Catalog (`backend/app/services/kev_service.py`):
- Automatically ingests CISA's official Known Exploited Vulnerabilities catalog.
- Flags actively weaponized vulnerabilities with `is_kev=True`.
- Ingests remediation due dates, vendor projects, and known ransomware campaign linkages.
- **Important**: KEV membership indicates active threat actor exploitation in the wild, *not* proof that an individual tenant host has been compromised.

---

## 5. Auditable Risk Prioritization Engine

Located in `backend/app/services/risk_scoring.py`:

To prevent ambiguity, official metrics and CyberShield calculated scores are kept in separate fields:
- `cvss_score`: Official base CVSS score (0.0 to 10.0)
- `severity`: Official severity category (`Critical`, `High`, `Medium`, `Low`, `Informational`)
- `is_kev`: Known exploited flag
- `prioritization_score`: CyberShield computed priority (0.0 to 100.0)

### Prioritization Formula:
$$\text{prioritization\_score} = \min(100.0, \text{round}((\text{cvss\_score} \times 7.0) + \text{kev\_boost} + \text{asset\_boost}, 1))$$

- **Base CVSS Weight**: `cvss_score * 7.0` (contributes up to 70.0 points)
- **Weaponization Context (CISA KEV)**: `+25.0 points` if actively exploited in the wild.
- **Critical Asset Context**: `+5.0 points` if target asset is marked `Critical`.

*Example*: A CVSS 7.5 vulnerability weaponized in CISA KEV on an enterprise firewall yields:
$(7.5 \times 7.0) + 25.0 + 5.0 = 82.5 / 100$, appropriately prioritizing it above an unweaponized CVSS 9.2 vulnerability on an isolated desktop ($(9.2 \times 7.0) = 64.4 / 100$).

---

## 6. API Reference

All endpoints require verified Supabase Bearer JWTs and enforce tenant isolation:

| Method | Endpoint | Description | Required Role |
|---|---|---|---|
| `GET` | `/api/v1/vulnerabilities/overview` | Summary counts, severity breakdown, top affected assets | Any Member |
| `GET` | `/api/v1/vulnerabilities/findings` | Filtered, searchable, paginated findings | Any Member |
| `GET` | `/api/v1/vulnerabilities/findings/{id}` | Single finding with evidence & remediation | Any Member |
| `PATCH` | `/api/v1/vulnerabilities/findings/{id}` | Update status or notes | Analyst / Admin / Owner |
| `GET` | `/api/v1/vulnerabilities/scans` | List vulnerability assessment runs | Any Member |
| `POST` | `/api/v1/vulnerabilities/scans` | Launch assessment with scope check | Analyst / Admin / Owner |
| `GET` | `/api/v1/vulnerabilities/scans/{id}` | Scan live status and progress | Any Member |
| `POST` | `/api/v1/vulnerabilities/scans/{id}/cancel` | Cancel running assessment | Analyst / Admin / Owner |
| `GET` | `/api/v1/vulnerabilities/cves/{cve_id}` | Retrieve NVD CVE intelligence | Any Member |
| `GET` | `/api/v1/vulnerabilities/kev` | Query CISA KEV catalog | Any Member |
| `GET` | `/api/v1/vulnerabilities/assets/{id}` | Asset-correlated vulnerabilities | Any Member |
| `POST` | `/api/v1/vulnerabilities/findings/{id}/remediation` | Submit formal status transition | Analyst / Admin / Owner |
| `GET` | `/api/v1/vulnerabilities/findings/{id}/history` | Remediation history audit trail | Any Member |

---

## 7. Environment Variables

Documented in `backend/.env.example`:

```bash
# NVD CVE Intelligence
NVD_API_KEY=your-nvd-api-key-here
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
KEV_CATALOG_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# Greenbone OpenVAS Engine
OPENVAS_HOST=localhost
OPENVAS_PORT=9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=your-openvas-password

# OWASP ZAP Baseline Engine
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=your-zap-api-key

# Scanner Guardrails
SCANNER_TIMEOUT_SECONDS=1800
```

---

## 8. Verification & Test Suite

To run the complete automated test suite (all 47 tests across Sprints 2–6):

```bash
cd backend
.venv\Scripts\pytest -v
```

### Verified Test Cases:
1. `test_cve_response_parsing`: Standardized parsing of NVD 2.0 payloads.
2. `test_cvss_severity_mapping`: Mathematical mapping and auditable prioritization scoring.
3. `test_cisa_kev_matching`: Correct detection of weaponized CVEs and ransomware tags.
4. `test_duplicate_finding_prevention_and_sync`: Ingestion idempotency on `(asset_id, cve_id, title)`.
5. `test_missing_service_version_safe_correlation`: Defensive suppression on uncertain banners.
6. `test_invalid_asset_id_rejected`: 404 rejection on cross-tenant or missing assets.
7. `test_unapproved_scan_scope_rejected`: 400 rejection for scopes in `Pending` state.
8. `test_expired_scan_scope_rejected`: 400 rejection for expired authorizations.
9. `test_unauthorized_organization_access_rejected`: 403 enforcement on unauthorized tenants.
10. `test_viewer_cannot_launch_scan`: RBAC enforcement blocking viewers from scanning.
11. `test_viewer_cannot_update_remediation`: RBAC enforcement blocking viewers from modifying status.
12. `test_remediation_justification_required`: HTTP 422 rejection when `Accepted Risk` or `False Positive` lacks justification.
13. `test_scanner_timeout_handling`: Graceful handling of worker timeout exceptions.
14. `test_scanner_failure_handling`: Resilient error logging on worker exceptions.
15. `test_vulnerability_scan_cancellation`: Cooperative cancellation of active assessments.
16. `test_vulnerabilities_overview_and_inventory`: Overview metrics and filtered inventory queries.
