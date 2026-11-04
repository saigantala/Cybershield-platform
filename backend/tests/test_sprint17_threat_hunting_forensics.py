import base64
import hashlib
import json
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.forensics_service import compute_custody_hash, GENESIS_HASH

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ==============================================================================
# 1. CRYPTOGRAPHIC HASH CHAIN & INTEGRITY UNIT TESTS
# ==============================================================================
def test_compute_custody_hash_integrity():
    evidence_id = "test-ev-001"
    actor = "Chief Security Architect"
    action = "Collected"
    ts = "2026-11-02T10:00:00Z"
    meta = {"source": "DC-01", "disk_image": "raw"}

    h1 = compute_custody_hash(GENESIS_HASH, evidence_id, actor, action, ts, meta)
    assert len(h1) == 64
    # Deterministic output
    h2 = compute_custody_hash(GENESIS_HASH, evidence_id, actor, action, ts, meta)
    assert h1 == h2

    # Any modification breaks hash
    meta_tampered = {"source": "DC-01", "disk_image": "tampered"}
    h3 = compute_custody_hash(GENESIS_HASH, evidence_id, actor, action, ts, meta_tampered)
    assert h1 != h3


# ==============================================================================
# 2. THREAT HUNTING CENTER ENDPOINTS
# ==============================================================================
def test_threat_hunting_stats(owner_headers):
    res = client.get(f"/api/v1/threat-hunting/stats?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_cases"] >= 3
    assert data["active_investigations"] >= 1
    assert data["total_findings"] >= 2


def test_list_hunting_cases(owner_headers):
    res = client.get(f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    cases = res.json()
    assert len(cases) >= 3
    assert any(c["case_number"] == "TH-2026-00101" for c in cases)

    # Filter by status
    res_filtered = client.get(f"/api/v1/threat-hunting/cases?status=Investigating&org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res_filtered.status_code == 200
    filtered_cases = res_filtered.json()
    assert all(c["status"] == "Investigating" for c in filtered_cases)


def test_create_update_and_get_hunting_case(owner_headers):
    payload = {
        "title": "Adversary Lateral Movement over WinRM",
        "objective": "Identify abnormal TCP/5985 traffic and PowerShell process spawns.",
        "hypothesis": "Compromised administrator credentials used to pivot to internal file server.",
        "priority": "P2",
        "filter_criteria": {"port": 5985, "protocol": "TCP"},
    }
    create_res = client.post(f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}", json=payload, headers=owner_headers)
    assert create_res.status_code == 201
    created_case = create_res.json()
    case_id = created_case["id"]
    assert created_case["case_number"].startswith("TH-2026-")
    assert created_case["status"] in ("Active", "Draft")

    # Get by ID
    get_res = client.get(f"/api/v1/threat-hunting/cases/{case_id}?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert get_res.status_code == 200
    assert get_res.json()["title"] == payload["title"]

    # Update
    update_res = client.patch(
        f"/api/v1/threat-hunting/cases/{case_id}?org_id={DEFAULT_ORG_ID}",
        json={"status": "Suspicious Activity Found", "priority": "P1"},
        headers=owner_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "Suspicious Activity Found"
    assert update_res.json()["priority"] == "P1"


def test_hunting_findings_lifecycle(owner_headers):
    # Get active cases
    cases_res = client.get(f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    case_id = cases_res.json()[0]["id"]

    finding_payload = {
        "hunting_case_id": case_id,
        "title": "Unconstrained Kerberos Delegation Abuse",
        "finding_type": "credential_misuse",
        "severity": "Critical",
        "is_confirmed": True,
        "evidence_summary": "Extracted TGT for DC-01 administrator account injected into LSASS process.",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1558.001",
        "recommendations": "Disable unconstrained delegation on intermediate web tiers.",
    }
    create_f = client.post(f"/api/v1/threat-hunting/findings?org_id={DEFAULT_ORG_ID}", json=finding_payload, headers=owner_headers)
    assert create_f.status_code == 201
    finding = create_f.json()
    assert finding["title"] == finding_payload["title"]
    assert finding["is_confirmed"] is True

    # List findings
    list_f = client.get(f"/api/v1/threat-hunting/findings?case_id={case_id}&org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_f.status_code == 200
    assert any(f["id"] == finding["id"] for f in list_f.json())

    # Delete finding
    del_f = client.delete(f"/api/v1/threat-hunting/findings/{finding['id']}?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert del_f.status_code == 204


# ==============================================================================
# 3. STRUCTURED QUERY ENGINE & SAVED QUERIES
# ==============================================================================
def test_structured_query_engine_and_or_logic(owner_headers):
    # 1. Search with AND logic
    payload_and = {
        "event_category": "network",
        "port": 443,
        "operator": "AND",
        "time_range_hours": 72,
        "limit": 25,
    }
    res_and = client.post(f"/api/v1/threat-hunting/search?org_id={DEFAULT_ORG_ID}", json=payload_and, headers=owner_headers)
    assert res_and.status_code == 200
    data_and = res_and.json()
    assert "events" in data_and
    assert data_and["execution_time_ms"] >= 0

    # 2. Search with OR logic
    payload_or = {
        "source_ip": "192.168.10.45",
        "destination_ip": "198.51.100.45",
        "operator": "OR",
        "time_range_hours": 168,
        "limit": 50,
    }
    res_or = client.post(f"/api/v1/threat-hunting/search?org_id={DEFAULT_ORG_ID}", json=payload_or, headers=owner_headers)
    assert res_or.status_code == 200
    data_or = res_or.json()
    assert isinstance(data_or["events"], list)


def test_saved_queries_management(owner_headers):
    payload = {
        "name": "Beaconing Hunt to C2 Server",
        "description": "Correlates periodic outbound flows to 198.51.100.45.",
        "filter_params": {"destination_ip": "198.51.100.45", "protocol": "TCP"},
    }
    res = client.post(f"/api/v1/threat-hunting/queries?org_id={DEFAULT_ORG_ID}", json=payload, headers=owner_headers)
    assert res.status_code == 201
    q = res.json()
    assert q["name"] == payload["name"]

    # List
    list_res = client.get(f"/api/v1/threat-hunting/queries?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    assert any(sq["id"] == q["id"] for sq in list_res.json())

    # Delete
    del_res = client.delete(f"/api/v1/threat-hunting/queries/{q['id']}?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert del_res.status_code == 204


# ==============================================================================
# 4. MULTI-TYPE IOC INVESTIGATION & STATUS UNKNOWN SAFETY
# ==============================================================================
def test_ioc_investigation_known_threat(owner_headers):
    # Test indicator 198.51.100.42 (seeded in feed)
    res_feed = client.post(f"/api/v1/threat-hunting/ioc-investigation?org_id={DEFAULT_ORG_ID}", json={"ioc_value": "198.51.100.42"}, headers=owner_headers)
    assert res_feed.status_code == 200
    data_feed = res_feed.json()
    assert data_feed["ioc_type"] == "ipv4"
    assert data_feed["threat_status"] == "known_malicious"
    assert data_feed["confidence_score"] > 0.5
    assert data_feed["is_known_threat"] is True

    # Test indicator 198.51.100.45 (seeded in threat hunt findings)
    res_hunt = client.post(f"/api/v1/threat-hunting/ioc-investigation?org_id={DEFAULT_ORG_ID}", json={"ioc_value": "198.51.100.45"}, headers=owner_headers)
    assert res_hunt.status_code == 200
    data_hunt = res_hunt.json()
    assert data_hunt["ioc_type"] == "ipv4"
    assert data_hunt["threat_status"] in ("known_malicious", "suspicious")
    assert data_hunt["confidence_score"] > 0.5


def test_ioc_investigation_unknown_never_assumed_safe(owner_headers):
    # Completely arbitrary unknown domain
    payload = {"ioc_value": "random-unobserved-corp-123.net"}
    res = client.post(f"/api/v1/threat-hunting/ioc-investigation?org_id={DEFAULT_ORG_ID}", json=payload, headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["ioc_type"] == "domain"
    # STRICT REQUIREMENT: unknown indicators must be labeled 'unknown_unverified' and NEVER assumed safe!
    assert data["threat_status"] == "unknown_unverified"
    assert data["confidence_score"] == 0.0
    assert data["is_known_threat"] is False
    assert any("do not treat as benign" in note.lower() for note in data["analyst_notes"])


# ==============================================================================
# 5. FORENSICS WORKSPACE & EVIDENCE VAULT
# ==============================================================================
def test_forensics_dashboard_stats(owner_headers):
    res = client.get(f"/api/v1/forensics/stats?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_cases"] >= 2
    assert data["total_evidence_items"] >= 3
    assert data["verified_evidence_items"] >= 2


def test_forensic_case_creation_and_asset_linking(owner_headers):
    payload = {
        "title": "Ransomware Infiltration Investigation",
        "description": "Post-containment forensics on file share encryptor execution.",
        "investigation_objective": "Determine exfiltration volume and initial payload delivery vector.",
        "priority": "P1",
        "assets": [{"asset_id": "33333333-3333-3333-3333-333333333333", "role_in_case": "compromised_target"}],
    }
    res = client.post(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", json=payload, headers=owner_headers)
    assert res.status_code == 201
    case = res.json()
    assert case["case_number"].startswith("FOR-2026-")
    assert case["status"] == "Open"
    assert len(case["assets"]) == 1


def test_evidence_upload_and_chain_of_custody_verification(owner_headers):
    cases_res = client.get(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    case_id = cases_res.json()[0]["id"]

    sample_content = b"CyberShield Forensics Bitstream Artifact: Event ID 4624 user admin logon success"
    b64_content = base64.b64encode(sample_content).decode("utf-8")
    expected_sha256 = hashlib.sha256(sample_content).hexdigest()

    evidence_payload = {
        "forensic_case_id": case_id,
        "evidence_name": "Test Windows Event Log Bitstream",
        "category": "log_file",
        "original_filename": "security_test.evtx",
        "file_content_base64": b64_content,
        "description": "Captured via FTK Imager CLI",
    }
    ev_res = client.post(f"/api/v1/forensics/evidence?org_id={DEFAULT_ORG_ID}", json=evidence_payload, headers=owner_headers)
    assert ev_res.status_code == 201
    evidence = ev_res.json()
    assert evidence["sha256_hash"] == expected_sha256
    assert evidence["integrity_status"] == "Verified"

    # Verify custody chain continuity
    custody_res = client.get(f"/api/v1/forensics/evidence/{evidence['id']}/custody?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert custody_res.status_code == 200
    events = custody_res.json()
    assert len(events) >= 2  # Genesis 'Collected' + 'Uploaded'
    assert events[0]["action"] == "Collected"
    assert events[0]["previous_record_hash"] == GENESIS_HASH
    assert events[1]["action"] == "Uploaded"
    assert events[1]["previous_record_hash"] == events[0]["current_record_hash"]

    # Run cryptographic verification endpoint
    verify_res = client.post(f"/api/v1/forensics/evidence/{evidence['id']}/verify-chain?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["is_chain_valid"] is True
    assert v_data["broken_at_event_id"] is None


def test_safe_static_artifact_analysis(owner_headers):
    # Run safe static analysis on existing seeded evidence item
    ev_list = client.get(f"/api/v1/forensics/evidence?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    evidence_id = ev_list[0]["id"]
    case_id = ev_list[0]["forensic_case_id"]

    job_payload = {"analysis_type": "log_normalization"}
    job_res = client.post(
        f"/api/v1/forensics/cases/{case_id}/analysis?evidence_id={evidence_id}&org_id={DEFAULT_ORG_ID}",
        json=job_payload,
        headers=owner_headers,
    )
    assert job_res.status_code == 202
    job = job_res.json()
    assert job["status"] == "Completed"
    assert "parser_engine" in job["extracted_metadata"]
    assert len(job["matched_iocs"]) > 0
    assert len(job["suspicious_indicators"]) > 0


def test_forensic_case_notes_and_hypotheses(owner_headers):
    cases = client.get(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    case_id = cases[0]["id"]

    # Add confirmed observation note
    note_payload = {
        "note_type": "Confirmed_Observation",
        "content": "Malware persistence verified in Registry Run key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    }
    create_res = client.post(f"/api/v1/forensics/cases/{case_id}/notes?org_id={DEFAULT_ORG_ID}", json=note_payload, headers=owner_headers)
    assert create_res.status_code == 201
    note = create_res.json()
    assert note["note_type"] == "Confirmed_Observation"

    # List notes
    list_res = client.get(f"/api/v1/forensics/cases/{case_id}/notes?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    assert any(n["id"] == note["id"] for n in list_res.json())


def test_forensic_timeline_aggregation(owner_headers):
    payload = {
        "event_category": None,
        "severity": None,
        "limit": 50,
    }
    res = client.post(f"/api/v1/forensics/timeline?org_id={DEFAULT_ORG_ID}", json=payload, headers=owner_headers)
    assert res.status_code == 200
    timeline = res.json()
    assert timeline["total_count"] > 0
    assert len(timeline["events"]) > 0
    # Verify chronological sort
    timestamps = [e["timestamp"] for e in timeline["events"]]
    assert timestamps == sorted(timestamps)


def test_forensic_report_generation(owner_headers):
    cases = client.get(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    case_id = cases[0]["id"]

    report_payload = {
        "title": "Formal Forensic Analysis: Advanced Adversary Intrusion",
        "scope_and_authorization": "Authorized pursuant to Security Mandate #CYBER-2026-001.",
        "executive_summary": "Intrusion detected and contained within 4 hours. No unauthorized data exfiltration observed.",
        "analysis_methodology": "Conducted under NIST SP 800-86 standard utilizing SHA-256 chain of custody verification.",
        "confirmed_findings": [{"finding": "RC4 Kerberos Ticket Downgrade", "severity": "High"}],
        "analyst_hypotheses": [{"hypothesis": "Initial access gained via phishing", "confidence": "High"}],
        "mitre_attack_mappings": [{"tactic": "Credential Access", "technique_id": "T1558.003"}],
        "limitations": "Endpoint memory dumps were not captured prior to system reboot.",
        "recommendations": [{"action": "Enforce AES256 Kerberos encryption", "priority": "Immediate"}],
        "conclusion": "Perimeter secured, credential reset enforced across all directory users.",
        "file_format": "json",
    }
    res = client.post(f"/api/v1/forensics/cases/{case_id}/reports?org_id={DEFAULT_ORG_ID}", json=report_payload, headers=owner_headers)
    assert res.status_code == 201
    rep = res.json()
    assert rep["report_number"].startswith("REP-FOR-2026-")
    assert rep["chain_of_custody_verified"] is True
    assert len(rep["evidence_inventory_summary"]) > 0


# ==============================================================================
# 6. RBAC PERMISSIONS VERIFICATION
# ==============================================================================
def test_viewer_rbac_restrictions(viewer_headers):
    # Viewers can read threat hunting and forensics cases
    res_cases = client.get(f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}", headers=viewer_headers)
    assert res_cases.status_code == 200

    res_for = client.get(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", headers=viewer_headers)
    assert res_for.status_code == 200

    # Viewers CANNOT create hunting cases (403 Forbidden)
    res_post_th = client.post(
        f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}",
        json={"title": "Viewer Unauthorized Case", "objective": "Testing RBAC violation."},
        headers=viewer_headers,
    )
    assert res_post_th.status_code == 403

    # Viewers CANNOT create forensic cases (403 Forbidden)
    res_post_for = client.post(
        f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}",
        json={
            "title": "Viewer Unauthorized Case",
            "description": "Testing RBAC violation.",
            "investigation_objective": "Testing RBAC violation objective with sufficient length.",
        },
        headers=viewer_headers,
    )
    assert res_post_for.status_code == 403
