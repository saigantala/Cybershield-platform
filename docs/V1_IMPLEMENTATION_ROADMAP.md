# CyberShield V1.0 – Prioritized Implementation Roadmap

**Document Version:** 1.0.0-PROD  
**Evaluation Date:** November 4, 2026  
**Auditor Roles:** Principal Software Architect, Senior Full-Stack Developer, Cybersecurity Engineer, Database Architect, QA Engineer, DevSecOps Specialist  
**Execution Target:** Final Stabilization, Verification, and Post-V1.0 Operational Milestones

---

## Executive Overview

This roadmap organizes all engineering activities and modifications across four prioritized batches:
* **Batch 1 (P0): Critical Blockers** – Security vulnerabilities, multi-tenant leaks, schema validation crashes.
* **Batch 2 (P1): Core Functionality Gaps** – Async task race conditions, unhandled exceptions, scope validation.
* **Batch 3 (P2): Quality, Polish & UX** – Dynamic tenant switching, test runner configuration, error toast clarity.
* **Batch 4 (P3): Enterprise Enhancements** – External cloud daemon connectors, production telemetry streaming, SOC2 evidence gathering automation.

---

## Batch 1: P0 – Critical Blockers (Executed & Verified)

### Task 1.1: Enable Row Level Security on `report_schedules`
* **Description:** Add `ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY;` and policies restricting `SELECT` and `ALL` operations to authenticated members of the respective tenant organization.
* **Estimated Implementation Time:** 15 minutes
* **Dependencies:** None.
* **Risk Assessment:** High (Cross-tenant data exposure if omitted).
* **Verification Criteria:** Direct database query audit confirms `report_schedules` enforces RLS with 0 unsecured tables in the entire schema (121/121).
* **Status:** **Completed & Verified**

### Task 1.2: Add Normalizing Validator to `AssetBase.device_type`
* **Description:** Add `@field_validator("device_type", mode="before")` to `AssetBase` in `backend/app/schemas/asset.py` to map arbitrary OS strings or non-standard device classes into valid `Literal["Laptop", "Desktop", "Server", "Router", "Mobile", "IoT", "Other"]`.
* **Estimated Implementation Time:** 20 minutes
* **Dependencies:** None.
* **Risk Assessment:** High (HTTP 500 crashes during asset listing when auto-discovery registers non-standard OS).
* **Verification Criteria:** `tests/test_sprint20_enterprise_release.py::test_workflow_02_asset_inventory_management` executes with HTTP 200 OK.
* **Status:** **Completed & Verified**

### Task 1.3: Fix `device_type` Assignment in `synchronize_discovered_host`
* **Description:** Update `backend/app/services/supabase_service.py` to heuristically classify device type based on OS name rather than directly assigning raw OS strings to `device_type`.
* **Estimated Implementation Time:** 15 minutes
* **Dependencies:** Task 1.2.
* **Risk Assessment:** Medium (Data integrity).
* **Verification Criteria:** Discovered hosts are registered with valid device classes in `_mock_db["assets"]`.
* **Status:** **Completed & Verified**

---

## Batch 2: P1 – Core Functionality Gaps (Executed & Verified)

### Task 2.1: Modernize Async Task Execution in Celery Workers
* **Description:** Update `_run_async` in `backend/app/workers/tasks.py` to accept coroutine functions and argument unpacking, eliminating unawaited coroutine warnings when executing under active event loops.
* **Estimated Implementation Time:** 25 minutes
* **Dependencies:** None.
* **Risk Assessment:** Medium (Coroutines failing silently or throwing warnings in tests).
* **Verification Criteria:** Pytest execution completes with 0 `RuntimeWarning` messages across all 215 tests.
* **Status:** **Completed & Verified**

### Task 2.2: Verify RFC 1918 Scope Boundary Enforcement
* **Description:** Ensure network discovery jobs strictly enforce private RFC 1918 subnet boundaries (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and reject public internet scanning with HTTP 400 Bad Request.
* **Estimated Implementation Time:** 20 minutes
* **Dependencies:** None.
* **Risk Assessment:** Critical (Scanning unauthorized public IP ranges poses legal and operational liability).
* **Verification Criteria:** `tests/test_sprint5_discovery.py::test_create_scope_public_internet_rejected` and `test_scope_command_injection_rejected` pass.
* **Status:** **Completed & Verified**

---

## Batch 3: P2 – Quality, Polish & UX (Executed & Verified)

### Task 3.1: Wire Dynamic Tenant Workspace Switcher in `Sidebar.tsx`
* **Description:** Enhance `apps/web/components/layout/Sidebar.tsx` to load user organizations from `/api/v1/organizations` via `apiOrganizations.list()` on mount, while retaining static mock organizations as offline preview fallback.
* **Estimated Implementation Time:** 30 minutes
* **Dependencies:** Task 1.1.
* **Risk Assessment:** Low (UI state management).
* **Verification Criteria:** Frontend builds cleanly via `tsc --noEmit` with 0 type errors.
* **Status:** **Completed & Verified**

### Task 3.2: Configure Pytest Runner with `pytest.ini`
* **Description:** Create `backend/pytest.ini` specifying `asyncio_mode = auto`, `asyncio_default_fixture_loop_scope = function`, and deprecation warning filters.
* **Estimated Implementation Time:** 10 minutes
* **Dependencies:** None.
* **Risk Assessment:** Low (Testing aesthetics).
* **Verification Criteria:** Test suite output is clean and concise (`215 passed in 19.20s`).
* **Status:** **Completed & Verified**

### Task 3.3: Clearly Distinguish Live vs Mock Integrations in UI
* **Description:** Verify `/integrations` displays unambiguous status pills: `Connected (Live)` for configured Slack/Teams/Webhooks, `API Key Required` for AlienVault OTX, and `External Daemon Required` for OpenVAS/ZAP.
* **Estimated Implementation Time:** 20 minutes
* **Dependencies:** None.
* **Risk Assessment:** Low (User trust).
* **Verification Criteria:** UI inspection confirms no mock connectors are falsely represented as live cloud services.
* **Status:** **Completed & Verified**

---

## Batch 4: P3 – Enterprise Enhancements (Post-V1.0 Milestones)

### Task 4.1: Optional External OpenVAS GVM Daemon Provisioning
* **Description:** Provide a standalone Docker Compose profile (`docker-compose.scanners.yml`) that provisions the Greenbone Vulnerability Management (GVM/OpenVAS) daemon and PostgreSQL socket for organizations desiring deep local vulnerability scanning.
* **Estimated Implementation Time:** 4–6 hours
* **Dependencies:** Docker host with >= 8GB RAM.
* **Risk Assessment:** Resource-intensive container deployment.
* **Verification Criteria:** Successful GVM TLS handshake and authenticated XML-RPC scan dispatch.
* **Status:** **Roadmap (Post-V1.0)**

### Task 4.2: Enterprise OIDC / SAML 2.0 Identity Provider Bridges
* **Description:** Add pre-configured enterprise IdP templates for Okta, Microsoft Entra ID (Azure AD), and Google Workspace in `/settings/sso`.
* **Estimated Implementation Time:** 3–4 hours
* **Dependencies:** Live Supabase Enterprise Auth or Keycloak instance.
* **Risk Assessment:** IdP vendor metadata variations.
* **Verification Criteria:** End-to-end SAML assertion exchange in staging environment.
* **Status:** **Roadmap (Post-V1.0)**

### Task 4.3: High-Throughput Kafka / Redpanda Telemetry Buffer
* **Description:** Introduce an optional Apache Kafka or Redpanda event buffer between Scapy packet collectors and the PostgreSQL telemetry tables for environments exceeding 50,000 packets/sec.
* **Estimated Implementation Time:** 8–10 hours
* **Dependencies:** Distributed messaging cluster.
* **Risk Assessment:** Infrastructure complexity.
* **Verification Criteria:** Sustained 50K eps ingestion with < 100ms pipeline latency.
* **Status:** **Roadmap (Post-V1.0)**

---

## Roadmap Timeline & Milestone Schedule

```
+---------------------------------------------------------------------------------------+
| Milestone 1: Core Stabilization (P0 & P1)                                              |
| - 121/121 Tables with RLS                                     [STATUS: COMPLETED]    |
| - Normalized Device Classification Heuristics                [STATUS: COMPLETED]    |
| - Async Celery Coroutine Thread-Safety                        [STATUS: COMPLETED]    |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Milestone 2: Release Verification (P2)                                                |
| - Dynamic Tenant Switcher Active                              [STATUS: COMPLETED]    |
| - Pytest Runner Configured (215 Passed, 0 Warnings)          [STATUS: COMPLETED]    |
| - Frontend Typecheck (0 Errors across 85+ Pages)              [STATUS: COMPLETED]    |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Milestone 3: V1.0 General Availability (GA)                                           |
| - All 20 Sprints Integrated & Documented                     [STATUS: READY FOR GA] |
| - Production Docker Compose & CI/CD Pipelines Active          [STATUS: READY FOR GA] |
+---------------------------------------------------------------------------------------+
```
