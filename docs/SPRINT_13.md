# Sprint 13: Security Orchestration, Automation & Response (SOAR)

## 1. Overview
Sprint 13 introduces an enterprise-grade Security Orchestration, Automation & Response (SOAR) engine into CyberShield. The engine centralizes automated alert triage, IOC enrichment, security incident correlation, and conditional response execution with mandatory human-in-the-loop authorization gates for disruptive containment actions.

---

## 2. Key Modules & Architecture

### A. Database Layer (`supabase/migrations/20261102_sprint13_soar_engine.sql`)
1. **`soar_workflows`**: Playbook definitions, metadata, category, trigger conditions, status (`Draft`, `Published`, `Archived`), and versioning.
2. **`soar_workflow_versions`**: Immutable revision history of workflows.
3. **`soar_workflow_steps`**: Sequential step configurations with modular actions and next/failure pointers.
4. **`soar_workflow_executions`**: Execution runtime records tracking status (`Pending`, `Running`, `Waiting_Approval`, `Completed`, `Failed`, `Cancelled`), duration, idempotency keys, and error diagnostics.
5. **`soar_execution_steps`**: Per-step runtime audits containing input payloads, output payloads, and timestamps.
6. **`soar_execution_logs`**: Redacted chronological execution logs (`INFO`, `WARN`, `ACTION`, `ERROR`).
7. **`soar_action_approvals`**: Human-in-the-loop authorization requests for disruptive actions (`asset_isolation`, `account_suspension`, `firewall_rule_review`, `block_indicator`).
8. **`soar_notification_templates`**: In-App, Email, and Webhook dispatch templates.
9. **`soar_notification_deliveries`**: Delivery status tracking for alerts sent to SIEMs, Slack, and email gateways.

### B. Backend Engine & Schemas
- **`backend/app/schemas/soar.py`**: Pydantic models for triggers, 13 modular step types, executions, approvals, and analytics.
- **`backend/app/services/soar_service.py`**:
  - Sequential workflow executor.
  - Step validation (step 1 must be `trigger`, minimum 2 steps).
  - Human approval pause (`Waiting_Approval` state).
  - Decision handler: Resumes workflow upon `Approved` -> `Executed`, or cancels upon `Rejected`.
  - Analytics aggregator (execution velocity, MTTE, success rates).
- **`backend/app/api/routes/soar.py`**:
  - `GET /api/v1/soar/workflows`: Lists active playbooks.
  - `POST /api/v1/soar/workflows`: Creates new playbook definition.
  - `GET /api/v1/soar/workflows/{id}`: Retrieves workflow details and steps.
  - `PATCH /api/v1/soar/workflows/{id}`: Updates playbook metadata and steps.
  - `POST /api/v1/soar/workflows/{id}/publish`: Validates and activates playbook.
  - `POST /api/v1/soar/workflows/{id}/execute`: Triggers immediate operational execution.
  - `GET /api/v1/soar/executions`: Audit log of past and running executions.
  - `GET /api/v1/soar/executions/{id}`: Step-by-step I/O payloads and timeline.
  - `POST /api/v1/soar/executions/{id}/cancel`: Halts paused or in-progress execution.
  - `GET /api/v1/soar/approvals`: Inbox of actions requiring human authorization.
  - `POST /api/v1/soar/approvals/{id}/approve`: Authorizes containment with analyst justification.
  - `POST /api/v1/soar/approvals/{id}/reject`: Rejects action with mandatory notes.
  - `GET /api/v1/soar/analytics`: Velocity metrics, MTTE, and execution volume trends.
  - `GET /api/v1/soar/notifications`: Configured notification channel templates.
  - `POST /api/v1/soar/notifications/test`: Dispatches live test payload to webhook or email.

### C. 13 Supported Modular Playbook Steps
1. `trigger`: Ingests security alerts, vulnerabilities, IOC matches, or auth anomalies.
2. `condition`: Evaluates boolean logic on context attributes.
3. `severity_check`: Filters execution based on minimum severity threshold (e.g. High, Critical).
4. `asset_lookup`: Enriches event with host IP, hostname, OS, and owner metadata.
5. `threat_intel_lookup`: Verifies indicator reputation against threat intelligence feeds.
6. `vulnerability_lookup`: Correlates target host with known CVEs and CISA KEV status.
7. `create_incident`: Automatically raises an official tracked SOC incident.
8. `add_incident_note`: Appends investigative findings to incident audit logs.
9. `assign_analyst`: Assigns incident ticket to designated tier-1/tier-2 responder.
10. `send_notification`: Emits alert via In-App, Email, or Webhook/Slack.
11. `request_approval`: Halts execution and requires human signoff before disruptive containment.
12. `generate_report`: Produces PDF/compliance report artifact.
13. `end_workflow`: Concludes playbook execution cleanly.

### D. 5 Pre-Seeded Standard Security Playbooks
1. **Suspicious Login Response**: Enriches source IP against threat feeds, checks for brute-force patterns, and gates account suspension.
2. **Malware Alert Investigation**: Queries host inventory, isolates infected asset upon human approval, and files high-severity incident.
3. **Critical Vulnerability Remediation Escalation**: Checks CISA KEV catalog for active exploitation, notifies DevOps, and creates remediation ticket.
4. **Suspicious Network Traffic & C2 Investigation**: Gathers NetFlow telemetry, extracts IP/domain IOCs, and gates firewall ACL block.
5. **Phishing Email Indicator Triage**: Analyzes embedded URLs/attachments, updates IOC feed, and alerts SOC mailbox.

---

## 3. Frontend Implementation (SOC Dark Glassmorphism)
All routes reside in `apps/web/app/(dashboard)/soar/`:
- `/soar`: Central Operations Hub with KPI metrics, active playbooks, and live execution feed.
- `/soar/playbooks`: Catalog with status/category filters and one-click test runs.
- `/soar/playbooks/new`: Interactive visual step builder supporting all 13 modular action types.
- `/soar/approvals`: Human-in-the-loop authorization inbox with action approval modal.
- `/soar/executions`: Full execution register with status badges and cancel controls.
- `/soar/executions/[executionId]`: Step-by-step interactive timeline and redacted log viewer.
- `/soar/analytics`: Velocity charts (MTTE), daily execution volume, and playbook frequency breakdowns.
- `/soar/notifications`: Notification template settings and live webhook dispatch simulator.
- `apps/web/components/layout/Sidebar.tsx`: Updated with SOAR Hub, Playbooks, Approvals, Executions, and Analytics.

---

## 4. Verification & Quality Assurance
- **Backend Test Suite**:
  - `pytest tests/test_sprint13_soar.py`: **9/9 passed in 0.26s**.
  - Full suite (`pytest -q`): **120 passed in 2.80s** across all 13 sprints with zero regressions.
- **Frontend Type Safety**:
  - `npx tsc --noEmit`: Clean compilation with **0 errors**.
