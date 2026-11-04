# Sprint 17: Advanced Threat Hunting & Digital Forensics

## Executive Summary
CyberShield Sprint 17 implements an enterprise-grade **Advanced Threat Hunting Center** and **Digital Forensics Workspace**. It provides proactive, hypothesis-driven telemetry interrogation across multi-tenant environments, multi-type IOC correlation, immutable digital evidence vaulting, verifiable tamper-evident cryptographic hash chains (Chain of Custody), safe static artifact parsing (strictly preventing arbitrary binary or script execution), multi-source timeline reconstruction, and formal standardized 14-section evidentiary reporting.

---

## 1. Architecture Overview

```
                      +---------------------------------------+
                      |       CyberShield SOC Dashboard        |
                      |   (Next.js App Router, Tailwind CSS)   |
                      +-------------------+-------------------+
                                          |
                      +-------------------+-------------------+
                      |      FastAPI Backend Engine (v1)       |
                      |      /threat-hunting  &  /forensics    |
                      +---------+-------------------+---------+
                                |                   |
        +-----------------------+                   +-----------------------+
        |                                                                   |
+-------v-------------------------------+                   +---------------v-----------------------+
|  Threat Hunting Engine                |                   |  Digital Forensics Vault              |
|  - Structured Parameter Query Engine  |                   |  - Immutable Bitstream Repository     |
|  - AND / OR Logic Filter              |                   |  - SHA-256 Bitstream Hash Engine      |
|  - Multi-Type IOC Deep Correlation    |                   |  - Cryptographic Hash Chain Generator |
|  - Hypothesis vs Fact Separation      |                   |  - Chain of Custody Verifier          |
|  - Threat Hunting Cases (TH-YYYY-XXX) |                   |  - Safe Static AST Parser (<25MB)     |
+---------------------------------------+                   |  - Multi-Source Timeline Correlator   |
                                                            |  - 14-Section Forensic Report Engine  |
                                                            |  - Forensic Cases (FOR-YYYY-XXXXX)    |
                                                            +---------------------------------------+
```

---

## 2. Multi-Tenant Database Schema

The migration file `supabase/migrations/20261102_sprint17_threat_hunting_forensics.sql` provisions 10 tables with Row Level Security (RLS) policies:

1. `threat_hunting_cases`: Hypothesis-driven investigation tracking (`Draft`, `Active`, `Investigating`, `Suspicious Activity Found`, `No Threat Identified`, `Escalated`, `Completed`).
2. `threat_hunting_queries`: Saved structured queries and historical searches.
3. `threat_hunting_findings`: Discovered findings, MITRE ATT&CK tactic/technique mappings, and explicit separation between confirmed facts (`is_confirmed = true`) and analyst hypotheses (`is_confirmed = false`).
4. `forensic_cases`: Sequential case IDs (`FOR-YYYY-XXXXX`), objectives, and status tracking.
5. `forensic_case_assets`: Target host nodes linked to cases with adversary roles (`compromised_target`, `pivot_host`, `command_control_hop`, `unauthorized_scanner`, `witness_system`).
6. `forensic_evidence_items`: Immutable evidence artifacts with SHA-256 and MD5 bitstream hashes, storage paths, MIME types, and derivation linkages.
7. `forensic_custody_events`: Tamper-evident cryptographic hash chain records. Append-only; deletions and updates are blocked by policy.
8. `forensic_analysis_jobs`: Safe static artifact analysis jobs (`log_normalization`, `ioc_extraction`, `pcap_metadata`, `string_extraction`).
9. `forensic_case_notes`: Case notes categorized as `Confirmed_Observation`, `Analyst_Hypothesis`, `Investigative_Lead`, or `Evidence_Custody_Note`.
10. `forensic_reports`: Formal 14-section standardized forensic reports with sequential IDs (`REP-FOR-YYYY-XXXXX`).

---

## 3. Cryptographic Tamper-Evident Chain of Custody

The chain of custody employs a sequential cryptographic SHA-256 hash block chaining algorithm:

$$\text{Current Hash} = \text{SHA256}(\text{Previous Hash} : \text{Evidence ID} : \text{Actor Name} : \text{Action} : \text{Timestamp} : \text{Metadata JSON})$$

- **Genesis Block**: The initial acquisition record uses a 64-character zero string:
  `0000000000000000000000000000000000000000000000000000000000000000`
- **Subsequent Blocks**: Every action (`Collected`, `Uploaded`, `Viewed`, `Downloaded`, `Integrity_Verified`, `Transferred`, `Archived`) links cryptographically to the preceding block's hash.
- **Verification Endpoint**: `POST /api/v1/forensics/evidence/{evidence_id}/verify-chain` traverses the complete chain, re-evaluating each link. If any record or metadata is altered, the chain breaks and pinpoints the exact compromised record ID.

---

## 4. Safe Static Artifact Analysis Engine

To prevent security risks associated with malicious files:
- **Zero Binary / Script Execution**: The backend parser never invokes interpreters, shell commands, or binary loaders for uploaded files.
- **Strict Size Boundary**: Imposes a 25 MB static parsing limit to prevent resource exhaustion or denial-of-service.
- **Parser Pipelines**:
  - `log_normalization`: Extracts timestamps, IPs, event IDs (e.g. Windows Security EVTX 4624, 4625, 4769), and maps them into standardized schemas.
  - `ioc_extraction`: Safe regex scanning for IPv4, IPv6, apex domains, URLs, and hash signatures, cross-referencing against internal telemetry.
  - `pcap_metadata`: Evaluates packet headers, protocol distribution (TCP/UDP/ICMP/DNS), and conversation talkers without reassembling application payloads.
  - `string_extraction`: Safe UTF-8/ASCII printable character inspection with Shannon entropy calculation.

---

## 5. Multi-Source Timeline Reconstruction

The timeline engine correlates events chronologically across 8 distinct platform feeds:
1. **Authentication Events**: Logon failures, Kerberos TGS ticket downgrade requests (RC4 roasting).
2. **Network Monitoring**: Long-duration sessions, C2 beaconing patterns, firewall logs.
3. **Asset Discovery**: Newly detected nodes, rogue devices, port state modifications.
4. **Vulnerabilities**: Known exploited vulnerabilities (KEV) and scan detections.
5. **Threat Intelligence**: Indicators of compromise (IOCs) matched from global feeds.
6. **Security Alerts**: SOC alerts generated by detection rules.
7. **Incident Management**: Case milestones, containment actions, and status updates.
8. **Evidence Custody**: Collection, upload, and verification logs.

---

## 6. Multi-Type IOC Deep Correlation & Safety Rules

The IOC interrogation engine supports:
- `ipv4` & `ipv6`
- `domain` & `url`
- `md5`, `sha1`, `sha256`

### Crucial Safety Invariant
Unobserved or unrecognized indicators are classified strictly as `unknown_unverified` with a `0.0` confidence score and explicit warnings:
> *"Indicator not found in indexed threat intelligence feeds or internal telemetry. Status remains unknown and unverified; do not treat as benign without further behavioral triage."*

---

## 7. Frontend User Experience (Dark Glassmorphism)

Sprint 17 introduces 11 frontend dashboard routes:
- `/threat-hunting`: Threat Hunting Center overview, KPI metrics, quick launchpad.
- `/threat-hunting/cases`: Investigation directory with status tabs and case creator.
- `/threat-hunting/cases/[caseId]`: Investigation workspace, objectives, hypothesis, and finding logger.
- `/threat-hunting/search`: Structured query engine with parameter inputs, AND/OR logic, saved queries, and CSV export.
- `/threat-hunting/ioc-investigation`: Multi-type IOC console with threat status badges, confidence meters, and correlation tabs.
- `/forensics`: Digital Forensics overview, active investigations, and vault preview.
- `/forensics/cases`: Case directory with target host role tagging.
- `/forensics/cases/[caseId]`: Evidentiary workspace with static analysis runner and case notes.
- `/forensics/evidence`: Digital Evidence Vault with SHA-256 badges, upload modal, and interactive hash-chain viewer.
- `/forensics/timeline`: Chronological multi-feed timeline with filter sliders and raw telemetry inspection.
- `/forensics/reports`: Standardized 14-section formal forensic report generator and JSON/Markdown export.
