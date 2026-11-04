# CyberShield – Sprint 8: Incident Response & Security Operations Documentation

## 1. Executive Summary

Sprint 8 delivers a comprehensive, enterprise-grade **Incident Response and Security Operations Subsystem** for CyberShield. It provides Security Operations Center (SOC) teams, incident responders, and security leads with end-to-end incident lifecycle management:
1. **Incident Case Management**: Unified incident records with sequential numbering (`CS-YYYY-XXXXXX`), severity ratings, priority levels, assigned responders, affected assets, and ISO 8601 phase timestamps.
2. **Alert-to-Incident Escalation**: Bidirectional alert linking, status promotion (`Escalated`), and full correlation preservation.
3. **Multi-Tab Investigation Workspace (`/incidents/[incidentId]`)**: A comprehensive analysis environment featuring Overview, Alerts & Events, Assets & Indicators, MITRE ATT&CK Mapping, Evidence Vault, Response Playbooks, Approval Requests, and Timeline & Analyst Notes.
4. **MITRE ATT&CK Enterprise Matrix v15.1**: Enterprise tactics and techniques catalog, manual incident-to-technique mapping with confidence ratings and analyst rationale.
5. **Evidence Management Vault**: Strict integrity verification with automatic backend SHA-256 hash generation, size enforcement (max 25MB), file sanitization, and security filtering against dangerous executables (`.exe`, `.sh`, `.bat`, etc.).
6. **Response Playbooks**: Pre-packaged standard operating procedures (Suspicious Login, Malware Alert, Phishing, Vulnerability Remediation) and custom runbooks with interactive step progress tracking.
7. **Response Approval Workflow (`/response-requests`)**: Mandatory human-in-the-loop governance for disruptive containment actions (`isolate_asset`, `disable_account`, `block_firewall_rule`, `remediate_vulnerability`, `escalate_incident`), complete with mandatory decision notes.
8. **Premium SOC Dark Glassmorphism UI**: High-contrast, accessibility-tested, dark glassmorphism interfaces across `/incidents`, `/incidents/[incidentId]`, `/playbooks`, `/response-requests`, and the main SOC dashboard.

---

## 2. Architecture & Data Flow

```
                                  +-----------------------------+
                                  |    Alert Correlation &      |
                                  |  Security Event Monitoring  |
                                  +--------------+--------------+
                                                 |
                                                 v (Escalate Alert / Manual Trigger)
+------------------------------------------------+------------------------------------------------+
|                                    INCIDENT RESPONSE ENGINE                                      |
|                                                                                                 |
|   +--------------------+     +---------------------+     +----------------------------------+   |
|   |  incidents Table   | <-> | incident_alerts     | <-> | alerts Table                     |   |
|   |  CS-2026-000001    |     +---------------------+     +----------------------------------+   |
|   +---------+----------+                                                                        |
|             |                                                                                   |
|             +--------+----------------------+----------------------+--------------------+       |
|             |        |                      |                      |                    |       |
|             v        v                      v                      v                    v       |
|   +-----------+ +------------+     +------------------+    +----------------+   +-----------+   |
|   |  Timeline | | Evidence   |     | MITRE ATT&CK     |    | Response       |   | Response  |   |
|   |  & Notes  | | Vault      |     | Mappings         |    | Playbooks      |   | Approvals |   |
|   |  (Audit)  | | (SHA-256)  |     | (Matrix v15.1)   |    | (Checklists)   |   | (HITL)    |   |
|   +-----------+ +------------+     +------------------+    +----------------+   +-----------+   |
+------------------------------------------------+------------------------------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  |     SOC Investigation       |
                                  |         Workspace           |
                                  |  /incidents/[incidentId]    |
                                  +-----------------------------+
```

---

## 3. Incident Lifecycle & State Machine

Every incident progresses through standardized lifecycle phases aligned with NIST SP 800-61 Rev. 2:

```
[ New ] ──────> [ Acknowledged ] ──────> [ Investigating ]
                       │                        │
                       ▼                        ▼
               [ Containment ] ───────> [ Eradication ]
                       │                        │
                       ▼                        ▼
                 [ Recovery ] ────────> [ Resolved ] ──────> [ Closed ]
```

### 3.1 Field Specifications
- **`incident_number`**: Formatted as `CS-YYYY-XXXXXX` (e.g. `CS-2026-000001`), sequentially generated per organization.
- **`incident_type`**: `Malware`, `Phishing`, `Unauthorized Access`, `Suspicious Network Activity`, `Vulnerability Exploitation`, `Data Exposure`, `Account Compromise`, `IoT Security Incident`, `Other`.
- **`severity`**: `Critical`, `High`, `Medium`, `Low`.
- **`priority`**: `P1` (Immediate/Emergency), `P2` (High urgency), `P3` (Standard priority), `P4` (Low priority).
- **`status`**: `New`, `Acknowledged`, `Investigating`, `Containment`, `Eradication`, `Recovery`, `Resolved`, `Closed`.
- **Timestamps**: `detected_at`, `acknowledged_at`, `investigation_started_at`, `resolved_at`, `closed_at`.
- **Audit Fields**: `created_by`, `assigned_to`, `resolution_summary`, `created_at`, `updated_at`.

---

## 4. Alert-to-Incident Escalation & Linking

1. **Escalation**: Creating an incident from an alert automatically links the alert ID, sets the alert status to `Escalated`, and records an entry in `incident_alerts`.
2. **Multi-Alert Correlation**: Responders can associate multiple existing alerts with a single incident case, aggregating telemetry and indicators.
3. **Decoupling / Unlinking**: Unlinking an alert removes the `incident_alerts` junction record and logs an audit event on the incident timeline.

---

## 5. MITRE ATT&CK Enterprise Matrix v15.1 Integration

CyberShield integrates the official MITRE ATT&CK Enterprise Matrix v15.1.
- **Service**: `backend/app/services/attack_service.py`
- **Cached Tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.
- **Techniques**: Includes standard enterprise techniques (e.g. `T1059: Command and Scripting Interpreter`, `T1078: Valid Accounts`, `T1566: Phishing`, `T1190: Exploit Public-Facing Application`, etc.).
- **Incident Mapping**: Responders map techniques with:
  - Tactic & Technique ID
  - Confidence Rating (1–100%)
  - Evidence text explaining the match rationale
  - Mapped By user attribution

---

## 6. Evidence Management Vault

The Evidence Vault securely stores forensic artifacts, logs, screenshots, and network captures:
- **Location**: `incident_evidence` table & private bucket storage.
- **Integrity Calculation**: Backend calculates a cryptographic SHA-256 hash immediately upon ingest.
- **Path Sanitization**: Filenames are sanitized, stripped of directory traversals (`../`), and assigned a unique storage key:
  `organizations/{org_id}/incidents/{incident_id}/evidence/{evidence_id}_{safe_filename}`
- **Security Validation**:
  - Max file size: **25 MB** (enforced by Pydantic & service layer).
  - Executable protection: Prohibits `.exe`, `.bat`, `.cmd`, `.sh`, `.ps1`, `.msi`, `.vbs`, `.scr`, `.jar` from being uploaded as evidence to prevent accidental remote execution in the SOC environment.

---

## 7. Incident Response Playbooks

Pre-built standard operating procedures (SOPs) are cataloged and can be bound to incidents:
1. **Suspicious Login Investigation**: Detect abnormal login spikes &rarr; Identify user & source IP &rarr; Verify with user &rarr; Force credential reset.
2. **Malware Alert Investigation**: Verify EDR detection &rarr; Isolate affected asset &rarr; Collect memory & process tree &rarr; Terminate process & delete payload.
3. **Phishing Attack Investigation**: Inspect raw email headers &rarr; Extract URLs & attachments &rarr; Search inbox for recipients &rarr; Purge messages & revoke clicked sessions.
4. **Vulnerability Remediation SOP**: Confirm asset exposure &rarr; Check CISA KEV exploit status &rarr; Coordinate patch testing &rarr; Rescan & verify closure.

### Interactive Step Progress:
Each step in an incident's attached playbook can be marked as `Pending`, `In Progress`, `Completed`, or `Skipped`, with user attribution and analyst progress notes.

---

## 8. Human-in-the-Loop Response Approvals

To ensure safety and prevent non-consensual system disruption, high-impact actions require explicit administrative authorization:
- **Action Types**:
  - `isolate_asset`: Disconnect host from internal broadcast domain.
  - `disable_account`: Revoke active session tokens and disable directory account.
  - `block_firewall_rule`: Insert temporary firewall ACL drop rule.
  - `remediate_vulnerability`: Execute emergency patch workflow.
  - `escalate_incident`: Trigger executive & legal crisis management team notification.
- **Approval Policy**:
  - Minimum justification requirement for requesters.
  - Mandatory decision justification notes (minimum 5 characters) for approval or rejection.
  - Audit trail storing `decided_by`, `decided_at`, and `decision_notes`.

---

## 9. FastAPI REST API Reference

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/incidents` | `GET` | Viewer+ | List paginated incidents with filters |
| `/incidents` | `POST` | Analyst+ | Create a new incident case |
| `/incidents/{id}` | `GET` | Viewer+ | Retrieve full incident details |
| `/incidents/{id}` | `PATCH` | Analyst+ | Update incident status, priority, severity |
| `/incidents/{id}/assign` | `POST` | Analyst+ | Assign responder to incident |
| `/incidents/{id}/alerts` | `POST` | Analyst+ | Link alert to incident |
| `/incidents/{id}/alerts/{aid}` | `DELETE` | Analyst+ | Unlink alert from incident |
| `/incidents/{id}/notes` | `GET` | Viewer+ | List notes |
| `/incidents/{id}/notes` | `POST` | Analyst+ | Add analyst note |
| `/incidents/{id}/timeline` | `GET` | Viewer+ | List chronological audit timeline events |
| `/incidents/{id}/report` | `GET` | Viewer+ | Export incident case report (JSON or CSV) |
| `/attack/tactics` | `GET` | Viewer+ | List MITRE ATT&CK tactics |
| `/attack/techniques` | `GET` | Viewer+ | List MITRE ATT&CK techniques |
| `/incidents/{id}/attack-mappings` | `GET` | Viewer+ | List mapped techniques for incident |
| `/incidents/{id}/attack-mappings` | `POST` | Analyst+ | Map technique to incident |
| `/incidents/{id}/attack-mappings/{mid}` | `DELETE` | Analyst+ | Remove technique mapping |
| `/incidents/{id}/evidence` | `GET` | Viewer+ | List evidence artifacts |
| `/incidents/{id}/evidence` | `POST` | Analyst+ | Upload evidence record with SHA-256 |
| `/incidents/{id}/evidence/{eid}` | `DELETE` | Analyst+ | Delete evidence record |
| `/playbooks` | `GET` | Viewer+ | List catalog of response playbooks |
| `/playbooks` | `POST` | Analyst+ | Create a custom playbook with steps |
| `/playbooks/{id}` | `PATCH` | Analyst+ | Update playbook or toggle enabled |
| `/incidents/{id}/playbooks` | `GET` | Viewer+ | List playbooks attached to incident |
| `/incidents/{id}/playbooks` | `POST` | Analyst+ | Attach playbook to incident |
| `/incidents/{id}/playbooks/{pid}/steps/{sid}` | `PATCH` | Analyst+ | Update step progress |
| `/response-requests` | `GET` | Viewer+ | List containment response requests |
| `/incidents/{id}/response-requests` | `POST` | Analyst+ | Submit response request |
| `/response-requests/{id}/approve` | `POST` | Admin+ | Approve response request with notes |
| `/response-requests/{id}/reject` | `POST` | Admin+ | Reject response request with notes |

---

## 10. Database Schema & Migration

Migration: `supabase/migrations/20261031_sprint8_incident_response.sql`
- **Tables**: `incidents`, `incident_alerts`, `incident_notes`, `incident_timeline`, `incident_evidence`, `incident_attack_mappings`, `playbooks`, `playbook_steps`, `incident_playbooks`, `playbook_step_progress`, `response_requests`, `response_approvals`.
- **Security**: Row-Level Security (RLS) enabled on all tables, restricted by `organization_id` foreign key check against `organization_members`.
- **Performance**: High-selectivity B-tree indexes on `(organization_id, status)`, `(organization_id, severity)`, `incident_id`, `created_at`.

---

## 11. Verification & Test Suite

All 14 automated test scenarios pass in `backend/tests/test_sprint8_incident_response.py`:
1. `test_create_incident`: Generates sequential `CS-YYYY-XXXXXX` number, validates fields.
2. `test_list_and_filter_incidents`: Tests severity, status, and search filters.
3. `test_update_incident_status_and_timestamps`: Verifies timestamp auto-transitions (`acknowledged_at`, `closed_at`).
4. `test_link_and_unlink_alert`: Validates bidirectional linking and alert status mutation.
5. `test_incident_notes_and_timeline`: Tests note creation and timeline event emission.
6. `test_mitre_attack_catalog`: Verifies tactics and techniques listing from Enterprise Matrix v15.1.
7. `test_map_and_unmap_attack_technique`: Tests incident technique mapping with confidence and rationale.
8. `test_evidence_upload_and_sha256`: Tests SHA-256 hash generation and size enforcement.
9. `test_evidence_executable_rejection`: Validates rejection of `.exe` and dangerous scripts.
10. `test_playbooks_catalog`: Verifies 4 default standard playbooks.
11. `test_attach_playbook_and_update_progress`: Tests step completion, percentage calculation, and analyst attribution.
12. `test_response_request_creation`: Tests action submission for disruptive containment operations.
13. `test_response_request_approval_and_rejection`: Tests admin review with mandatory decision notes.
14. `test_export_incident_report`: Tests JSON and CSV case report generation.

**Combined Test Results across Sprints 1–8**:
- 75 tests passing (100% pass rate).
- 0 TypeScript compiler errors (`npx tsc --noEmit`).
