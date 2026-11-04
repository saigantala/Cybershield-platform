# CyberShield – Sprint 7: Threat Intelligence & Security Monitoring Documentation

## 1. Executive Summary

Sprint 7 delivers an enterprise-grade **Threat Intelligence & Security Monitoring Subsystem** for CyberShield. It equips Security Operations Center (SOC) teams with the capabilities to:
1. Ingest, normalize, validate, and deduplicate Indicators of Compromise (IOCs) across multiple authoritative intelligence feeds (CISA KEV, abuse.ch URLhaus, abuse.ch MalwareBazaar, and AlienVault OTX).
2. Collect, sanitize, and store normalized, high-throughput security event telemetry from endpoints, firewalls, and network devices under strict multi-tenant isolation.
3. Automatically correlate incoming telemetry against active IOCs, detection rules, and known exploited vulnerabilities via a real-time **Event Correlation Engine**.
4. Manage actionable **Security Alerts** with complete triage lifecycles (New &rarr; Investigating &rarr; Escalated &rarr; Resolved / False Positive), analyst assignments, mandatory resolution justification, and incident linking.
5. Provide a responsive, command-center SOC UI built on CyberShield's **Premium SOC – Dark Glassmorphism** design system.

---

## 2. Architecture Overview

```
                                      +-------------------------------+
                                      |   External Threat Feeds       |
                                      | (CISA KEV, URLhaus, Bazaar)   |
                                      +---------------+---------------+
                                                      |
                                                      v (Celery Worker / Scheduled)
                                      +-------------------------------+
                                      | ThreatFeedManager             |
                                      | IndicatorValidator & Cache   |
                                      +---------------+---------------+
                                                      |
+--------------------------+                          v
| Security Event Sources   |               +--------------------+
| (Firewall, EDR, Syslog)  | ------------> | threat_indicators  |
+------------+-------------+               +---------+----------+
             |                                       |
             v (POST /security-events)               |
+--------------------------+                         |
| Event Ingestion &        |                         |
| Normalization Pipeline   |                         |
+------------+-------------+                         |
             |                                       |
             +-----------------------+---------------+
                                     |
                                     v
                 +---------------------------------------+
                 |       EventCorrelationEngine          |
                 | - Rule 1: Brute Force Anomaly         |
                 | - Rule 2: Threat Indicator Match      |
                 | - Rule 3: Vuln Risk (CISA KEV) Match  |
                 | - Rule 4: Asset Activity Spike        |
                 | - Rule 5: Repeated Suspicious Events  |
                 +-------------------+-------------------+
                                     |
                                     v
                         +-----------------------+
                         |     alerts Table      |
                         | (Deduplicated Alerts) |
                         +-----------+-----------+
                                     |
             +-----------------------+-----------------------+
             v                                               v
+--------------------------+                   +---------------------------+
| SOC Command Center UI    |                   | Incident Response Link    |
| - /threat-intelligence   |                   | - /incidents (escalation) |
| - /security-monitoring   |                   +---------------------------+
| - /alerts                |
| - /detection-rules       |
+--------------------------+
```

---

## 3. Threat Intelligence Module (`backend/app/threat_intelligence/`)

### 3.1 Indicator Types & Normalization
The module (`indicators.py`) validates and sanitizes all incoming indicators:
- **`ipv4`**: Strict validation using standard `ipaddress.IPv4Address`. Drops invalid bytes and formats.
- **`ipv6`**: RFC 4291/5952 validation, expanding or canonicalizing addresses.
- **`domain`**: Lowercases, strips protocol headers, paths, trailing dots, and validates FQDN structure (labels &le; 63 chars, valid ASCII/hyphens).
- **`url`**: RFC 3986 URL parsing; standardizes scheme and host to lowercase, strips tracking fragments, validates destination authority.
- **`md5`**: Exact 32 hexadecimal character verification (case-insensitive &rarr; canonical lowercase).
- **`sha1`**: Exact 40 hexadecimal character verification.
- **`sha256`**: Exact 64 hexadecimal character verification.

### 3.2 External Threat Feeds (`feed_manager.py`)
- **CISA Known Exploited Vulnerabilities Catalog (KEV)**: Actively weaponized CVEs. Integrated with Sprint 6 CVE database.
- **abuse.ch URLhaus**: Active malware payload distribution endpoints, command-and-control drop sites.
- **abuse.ch MalwareBazaar**: High-confidence malware sample hashes (SHA256, MD5) observed in targeted campaigns.
- **AlienVault OTX Community Pulse**: Open threat exchange indicators of compromise.
- **Safety Guarantee**: Unverified feeds are strictly treated as intelligence telemetry. CyberShield does not execute, download, or detonate live malware payloads.

---

## 4. Security Event Normalization & Ingestion

Every ingested event (`security_events.py`) follows the normalized schema:
- `id`: UUID Primary Key
- `organization_id`: Tenant identifier for row-level security isolation
- `source`: Reporting system (e.g. `palo-alto-fw-01`, `crowdstrike-agent`, `ssh-bastion`)
- `event_type`: Categorized event (e.g. `authentication_failure`, `threat_indicator_match`, `port_scan`)
- `severity`: Standard SOC level (`Critical`, `High`, `Medium`, `Low`, `Info`)
- `source_ip`: Originating IPv4/IPv6 address
- `destination_ip`: Target IPv4/IPv6 address
- `hostname`: Target or originating host
- `username`: Associated user account
- `asset_id`: Optional UUID foreign key linking to CyberShield Asset Inventory
- `event_description`: Human-readable summary
- `event_timestamp`: UTC timestamp with timezone offset awareness
- `metadata`: Arbitrary JSON payload for deep forensic telemetry

**Sanitization**: Passwords, API tokens, authorization headers, and raw session cookies are redacted prior to database persistence.

---

## 5. Event Correlation Engine (`correlation.py`)

The Correlation Engine evaluates events against 5 real-time detection scenarios:

| Scenario | Logic & Trigger Conditions | Default Threshold | Severity | Generated Alert Title |
|---|---|---|---|---|
| **Scenario A: Repeated Authentication Failures** | Aggregates `authentication_failure` events grouped by `source_ip` or `username` within a sliding window. | &ge; 5 events in 300s (5 min) | High | *Brute Force Authentication Anomaly Detected* |
| **Scenario B: Threat Indicator Match** | Compares `source_ip`, `destination_ip`, `hostname`, or file hashes against authoritative `threat_indicators`. | &ge; 1 match | Critical | *Threat Intelligence Match: Observed Malicious Observable* |
| **Scenario C: Vulnerability Risk Correlation** | Evaluates asset exposure against known weaponized CVEs in CISA KEV when exploit attempts or exposed ports are observed. | &ge; 1 match | High / Critical | *CISA KEV Weaponized Vulnerability Exposure* |
| **Scenario D: Asset Activity Anomaly** | Telemetry burst spike exceeding historical baseline frequency for an individual `asset_id` or `source_ip`. | &ge; 25 events in 60s | Medium | *Asset Activity Spike Anomaly Detected* |
| **Scenario E: Repeated Suspicious Events** | Aggregates repeated warning-level probes (`network_probe`, `unauthorized_access`, etc.) on target systems. | &ge; 3 events in 600s (10 min) | Medium | *Repeated Suspicious Security Events Detected* |

### Alert Deduplication
To prevent alert storms in high-throughput environments, the correlation engine checks for open alerts (`status IN ('New', 'Investigating')`) with the same title and affected asset. If found, it increments the confidence, appends new event IDs, and updates `last_detected_at` without duplicating the alert.

---

## 6. Alert Management & Triage Workflow

### 6.1 State Transitions
```
                +--------------+
                |     New      |
                +-------+------+
                        |
                        v
               +-----------------+
               |  Investigating  |
               +---+---------+---+
                   |         |
         +---------+         +---------+
         |                             |
         v                             v
+-----------------+           +-----------------+
|    Escalated    |           |    Resolved     |
| (Link Incident) |           | (Required Note) |
+-----------------+           +-----------------+
                                       |
                                       v
                              +-----------------+
                              | False Positive  |
                              | (Required Note) |
                              +-----------------+
```

- **Mandatory Justification**: Resolving an alert or marking it as a False Positive requires an explicit explanatory note from the analyst.
- **Analyst Assignment**: Alerts can be assigned to designated security analysts or response teams (`assigned_to`).
- **Incident Escalation**: Directly links an alert to a CyberShield Incident (`linked_incident_id`).
- **Audit History**: All triage actions and status transitions record an entry in `alert_history`.

---

## 7. Celery Background Tasks (`workers/tasks.py`)

1. `sync_threat_feeds`: Periodically pulls enabled threat feeds on their configured schedule.
2. `normalize_indicators`: Sanitizes and canonicalizes newly imported threat observables.
3. `expire_old_indicators`: Cleans up indicators past their TTL (`expires_at < NOW()`).
4. `process_security_event`: Validates, sanitizes, and persists an incoming event telemetry payload.
5. `correlate_security_events`: Executes correlation rules across recent time windows.
6. `evaluate_detection_rules`: Evaluates sliding window frequencies against active thresholds.
7. `generate_security_alert`: Creates a deduplicated alert and updates severity ratings.
8. `update_alert_priority`: Escalates priority for alerts with continuing telemetry activity.
9. `calculate_event_baseline`: Computes rolling event frequencies per asset to detect behavioral anomalies.
10. `cleanup_expired_events`: Purges historical raw security events according to tenant retention policies.

---

## 8. Database Migrations (`supabase/migrations/`)

Migration `20261031_sprint7_threat_intel_monitoring.sql` creates:
- `threat_indicators` (with unique index on `organization_id, indicator_type, indicator_value`)
- `threat_feeds` (feed sources, synchronization intervals, health status)
- `security_events` (normalized event collection with GIN index on `metadata`)
- `detection_rules` (configurable correlation criteria, thresholds, and time windows)
- `alerts` (deduplicated security alerts)
- `alert_notes` (analyst investigation comments timeline)
- `alert_history` (audit trail of state transitions)

**Row Level Security (RLS)** is enforced on all tables, ensuring complete tenant isolation by `organization_id`.

---

## 9. REST APIs

- `GET /api/v1/threat-intelligence/overview`: Aggregated IOC metrics and distribution.
- `GET /api/v1/threat-intelligence/indicators`: Paginated IOC list with type, severity, category, and search filters.
- `POST /api/v1/threat-intelligence/indicators`: Register a new IOC with validation.
- `GET /api/v1/threat-intelligence/indicators/{id}`: Detailed view of an IOC.
- `DELETE /api/v1/threat-intelligence/indicators/{id}`: Soft-delete/remove an indicator.
- `GET /api/v1/threat-intelligence/feeds`: List configured feed providers and sync status.
- `POST /api/v1/threat-intelligence/feeds/{id}/sync`: Trigger an immediate on-demand feed sync.
- `GET /api/v1/security-events`: Ingested event stream with severity, type, source, and search filters.
- `POST /api/v1/security-events`: Ingest a new security event and execute real-time correlation.
- `GET /api/v1/security-events/{id}`: Retrieve full event payload and metadata.
- `GET /api/v1/alerts`: List alerts with tabbed status filters (`New`, `Investigating`, `Escalated`, `Resolved`, `False Positive`).
- `GET /api/v1/alerts/{id}`: Retrieve alert details, analyst notes timeline, and audit history.
- `PATCH /api/v1/alerts/{id}`: Update alert status and assignment.
- `PATCH /api/v1/alerts/{id}/assign`: Assign an analyst to the alert.
- `POST /api/v1/alerts/{id}/notes`: Add an investigative note to the alert timeline.
- `PATCH /api/v1/alerts/{id}/link-incident`: Link the alert to an active Incident Response case.
- `GET /api/v1/detection-rules`: List all correlation rules.
- `POST /api/v1/detection-rules`: Create a custom detection rule.
- `PATCH /api/v1/detection-rules/{id}`: Tune threshold, window, or severity.
- `PATCH /api/v1/detection-rules/{id}/enable`: Activate a detection rule.
- `PATCH /api/v1/detection-rules/{id}/disable`: Pause a detection rule.

---

## 10. Frontend Implementation

- **`/threat-intelligence`**: KPI metrics overview, threat feed status cards with on-demand sync, IOC filter bar, IOC list table with copyable observables and confidence meters, IOC detail drawer, manual IOC registration modal.
- **`/security-monitoring`**: Live ingestion status, KPI stream breakdown, event search and severity filters, real-time event table, event payload inspection drawer, built-in telemetry simulation modal.
- **`/alerts`**: SOC Alert Queue, severity metrics cards, status tabs, comprehensive alert list table, triage modal with status workflow, analyst assignment, justification validation, investigation notes timeline, and incident linking.
- **`/detection-rules`**: Correlation rules catalog, active rule counters, enable/disable toggles, threshold and sliding-window editing modal, custom rule creator.
- **SOC Dashboard (`/`)**: Integrated threat telemetry ticker and active alert indicators.

---

## 11. Verification & Testing

- **Backend Test Suite**: 14 tests in `tests/test_sprint7_threat_intel.py` (61 total backend tests passing across all sprints).
- **Test Scenarios Covered**:
  1. IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256 normalization and validation.
  2. Duplicate indicator prevention and confidence aggregation.
  3. External feed synchronization and provider timeout resilience.
  4. Security event ingestion API and data sanitization.
  5. Brute force authentication failure threshold evaluation.
  6. Observable match correlation against active threat indicators.
  7. Alert lifecycle transitions, assignment, note logging, and incident linking.
  8. Detection rule enable/disable toggling.
  9. Role-based access control (Viewers blocked from mutation).
  10. Cross-tenant data isolation.
- **Frontend Verification**: TypeScript type-check (`npx tsc --noEmit`) verified with **0 errors**.
