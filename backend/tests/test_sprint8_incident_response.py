import base64
import pytest
from uuid import uuid4

from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentEvidenceCreate,
    PlaybookCreate,
    PlaybookStepItem,
)
from app.services.attack_service import attack_service
from app.services.evidence_service import evidence_service
from app.services.supabase_service import SupabaseService


@pytest.fixture
def auth_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def view_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ------------------------------------------------------------------------------
# 1. Incident Creation & Unique Number Generation
# ------------------------------------------------------------------------------
def test_create_incident_api(client, auth_headers):
    payload = {
        "title": "Unauthorized Access Attempt via SSH",
        "description": "Repeated brute force failures followed by anomalous sudo execution on bastion.",
        "incident_type": "Unauthorized Access",
        "severity": "High",
        "priority": "P2",
        "source": "Audit Telemetry",
        "affected_assets": ["11111111-1111-1111-1111-111111111111"],
    }
    res = client.post("/api/v1/incidents", json=payload, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["incident_number"].startswith("CS-")
    assert data["title"] == payload["title"]
    assert data["severity"] == "High"
    assert data["status"] == "New"
    assert data["priority"] == "P2"


def test_incident_number_uniqueness(client, auth_headers):
    payload1 = {
        "title": "First Incident",
        "description": "First incident description for uniqueness test.",
        "incident_type": "Malware",
        "severity": "Medium",
    }
    res1 = client.post("/api/v1/incidents", json=payload1, headers=auth_headers)
    assert res1.status_code == 201
    num1 = res1.json()["incident_number"]

    payload2 = {
        "title": "Second Incident",
        "description": "Second incident description for uniqueness test.",
        "incident_type": "Phishing",
        "severity": "Low",
    }
    res2 = client.post("/api/v1/incidents", json=payload2, headers=auth_headers)
    assert res2.status_code == 201
    num2 = res2.json()["incident_number"]

    assert num1 != num2


# ------------------------------------------------------------------------------
# 2. Incident Status Transitions & Timestamps
# ------------------------------------------------------------------------------
def test_incident_status_transitions(client, auth_headers):
    # 1. Create incident
    create_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Status Transition Test Incident",
            "description": "Verifying lifecycle state machine and timestamp recording.",
            "incident_type": "Suspicious Network Activity",
            "severity": "Critical",
        },
        headers=auth_headers,
    )
    inc_id = create_res.json()["id"]

    # 2. Transition New -> Acknowledged
    res_ack = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "Acknowledged"},
        headers=auth_headers,
    )
    assert res_ack.status_code == 200
    assert res_ack.json()["status"] == "Acknowledged"
    assert res_ack.json()["acknowledged_at"] is not None

    # 3. Transition Acknowledged -> Investigating
    res_inv = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "Investigating"},
        headers=auth_headers,
    )
    assert res_inv.status_code == 200
    assert res_inv.json()["status"] == "Investigating"
    assert res_inv.json()["investigation_started_at"] is not None

    # 4. Transition Investigating -> Resolved
    res_res = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={
            "status": "Resolved",
            "resolution_summary": "Malicious traffic ACL rule deployed; endpoint validated clean.",
        },
        headers=auth_headers,
    )
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "Resolved"
    assert res_res.json()["resolved_at"] is not None
    assert "ACL rule deployed" in res_res.json()["resolution_summary"]


# ------------------------------------------------------------------------------
# 3. Analyst Assignment
# ------------------------------------------------------------------------------
def test_analyst_assignment(client, auth_headers):
    create_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Assignment Verification Incident",
            "description": "Analyst assignment testing.",
            "severity": "High",
        },
        headers=auth_headers,
    )
    inc_id = create_res.json()["id"]
    analyst_uuid = "00000000-0000-0000-0000-000000000001"

    assign_res = client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        json={"assigned_to": analyst_uuid},
        headers=auth_headers,
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["assigned_to"] == analyst_uuid


# ------------------------------------------------------------------------------
# 4. Alert Linking & Unlinking
# ------------------------------------------------------------------------------
def test_alert_linking_and_unlinking(client, auth_headers):
    # 1. Create incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Alert Linking Test Case",
            "description": "Validating multi-alert correlation and detachment.",
            "severity": "High",
        },
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]
    alert_id = "14000000-0000-0000-0000-000000000001"

    # 2. Link alert
    link_res = client.post(
        f"/api/v1/incidents/{inc_id}/alerts",
        json={"alert_id": alert_id},
        headers=auth_headers,
    )
    assert link_res.status_code == 201
    assert link_res.json()["alert_id"] == alert_id

    # 3. Verify alert appears in incident alerts
    list_alerts_res = client.get(f"/api/v1/incidents/{inc_id}/alerts", headers=auth_headers)
    assert list_alerts_res.status_code == 200
    assert any(a["alert_id"] == alert_id for a in list_alerts_res.json())

    # 4. Unlink alert
    unlink_res = client.delete(f"/api/v1/incidents/{inc_id}/alerts/{alert_id}", headers=auth_headers)
    assert unlink_res.status_code == 200

    # 5. Verify alert is unlinked
    list_after = client.get(f"/api/v1/incidents/{inc_id}/alerts", headers=auth_headers)
    assert not any(a["alert_id"] == alert_id for a in list_after.json())


# ------------------------------------------------------------------------------
# 5. Notes & Timeline
# ------------------------------------------------------------------------------
def test_incident_notes_and_timeline(client, auth_headers):
    inc_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Timeline and Notes Case",
            "description": "Logging forensic notes and auditing chronological timeline.",
            "severity": "Medium",
        },
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    # Add note
    note_res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"note": "Memory dump extraction initiated on host bastion."},
        headers=auth_headers,
    )
    assert note_res.status_code == 201
    assert "Memory dump extraction" in note_res.json()["note"]

    # List notes
    notes_list = client.get(f"/api/v1/incidents/{inc_id}/notes", headers=auth_headers)
    assert notes_list.status_code == 200
    assert len(notes_list.json()) >= 1

    # Check timeline
    timeline_res = client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=auth_headers)
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()
    assert len(timeline) >= 2  # creation + note_added
    event_types = [t["event_type"] for t in timeline]
    assert "incident_created" in event_types
    assert "note_added" in event_types


# ------------------------------------------------------------------------------
# 6. MITRE ATT&CK Integration
# ------------------------------------------------------------------------------
def test_mitre_attack_service_and_mapping(client, auth_headers):
    # 1. Query tactics
    tactics_res = client.get("/api/v1/attack/tactics", headers=auth_headers)
    assert tactics_res.status_code == 200
    tactics = tactics_res.json()
    assert len(tactics) >= 10
    assert any(t["id"] == "TA0001" and t["name"] == "Initial Access" for t in tactics)

    # 2. Query techniques
    techniques_res = client.get("/api/v1/attack/techniques?tactic_id=TA0001", headers=auth_headers)
    assert techniques_res.status_code == 200
    techniques = techniques_res.json()
    assert any(t["id"] == "T1190" for t in techniques)

    # 3. Create incident & map technique
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "ATT&CK Mapping Test", "description": "Mapping observed TTPs."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    map_res = client.post(
        f"/api/v1/incidents/{inc_id}/attack-mappings",
        json={
            "technique_id": "T1190",
            "confidence": 90,
            "evidence": "Observed HTTP exploit payloads against perimeter gateway.",
        },
        headers=auth_headers,
    )
    assert map_res.status_code == 201
    assert map_res.json()["technique_id"] == "T1190"
    assert map_res.json()["tactic_name"] == "Initial Access"

    # 4. Verify invalid technique fails
    invalid_map = client.post(
        f"/api/v1/incidents/{inc_id}/attack-mappings",
        json={"technique_id": "T99999_FAKE", "confidence": 50},
        headers=auth_headers,
    )
    assert invalid_map.status_code == 400


# ------------------------------------------------------------------------------
# 7. Evidence Vault & Integrity Validation
# ------------------------------------------------------------------------------
def test_evidence_upload_and_sha256(client, auth_headers):
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Evidence Vault Test", "description": "Testing secure artifact storage."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    test_content = b"SECURE FORENSIC LOG DUMP: IP 198.51.100.42 observed port scanning."
    b64_data = base64.b64encode(test_content).decode("utf-8")
    expected_hash = evidence_service.calculate_sha256(test_content)

    upload_res = client.post(
        f"/api/v1/incidents/{inc_id}/evidence",
        json={
            "evidence_name": "Perimeter Ingress Log Dump",
            "evidence_type": "log",
            "original_filename": "firewall_snort.log",
            "mime_type": "text/plain",
            "file_bytes_base64": b64_data,
            "description": "Firewall logs capturing malicious inbound bursts.",
        },
        headers=auth_headers,
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    assert data["sha256_hash"] == expected_hash
    assert data["file_size"] == len(test_content)
    assert "download_url" in data


def test_evidence_executable_prohibited(client, auth_headers):
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Prohibited File Test", "description": "Ensuring executable malware is blocked."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    # Attempting to upload dangerous executable extension
    bad_upload = client.post(
        f"/api/v1/incidents/{inc_id}/evidence",
        json={
            "evidence_name": "Dangerous Dropper Binary",
            "evidence_type": "other",
            "original_filename": "trojan_payload.exe",
            "mime_type": "application/octet-stream",
            "file_bytes_base64": base64.b64encode(b"MZ...").decode("utf-8"),
        },
        headers=auth_headers,
    )
    assert bad_upload.status_code == 400
    assert "Executable file extension" in bad_upload.json()["detail"]


# ------------------------------------------------------------------------------
# 8. Response Playbooks & Step Tracking
# ------------------------------------------------------------------------------
def test_playbook_catalog_and_progress(client, auth_headers):
    # 1. Verify default playbooks exist
    pbs_res = client.get("/api/v1/playbooks", headers=auth_headers)
    assert pbs_res.status_code == 200
    pbs = pbs_res.json()
    assert len(pbs) >= 4
    categories = [p["category"] for p in pbs]
    assert "authentication" in categories
    assert "malware" in categories
    assert "phishing" in categories
    assert "vulnerability" in categories

    # 2. Attach Suspicious Login playbook to an incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Playbook Step Tracking Test", "description": "Testing playbook lifecycle."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]
    auth_pb = next(p for p in pbs if p["category"] == "authentication")

    attach_res = client.post(
        f"/api/v1/incidents/{inc_id}/playbooks",
        json={"playbook_id": auth_pb["id"]},
        headers=auth_headers,
    )
    assert attach_res.status_code == 201
    assignment = attach_res.json()
    assignment_id = assignment["id"]
    assert len(assignment["step_progress"]) >= 5

    # 3. Update Step 1 to Completed
    step1 = assignment["step_progress"][0]
    update_res = client.patch(
        f"/api/v1/incidents/{inc_id}/playbooks/{assignment_id}/steps/{step1['step_id']}",
        json={
            "status": "Completed",
            "notes": "Reviewed auth logs: verified 14 brute force attempts from 198.51.100.99.",
        },
        headers=auth_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "Completed"
    assert "14 brute force attempts" in update_res.json()["notes"]


# ------------------------------------------------------------------------------
# 9. Response Request & Approval Workflow
# ------------------------------------------------------------------------------
def test_response_approval_workflow(client, auth_headers, view_headers):
    # 1. Create incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Containment Approval Test", "description": "Testing response action requests."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    # 2. Analyst submits response request
    req_res = client.post(
        f"/api/v1/incidents/{inc_id}/response-requests",
        json={
            "action_type": "isolate_asset",
            "target_resource": "PROD-EDGE-FIREWALL-01",
            "justification": "Active beaconing to known LockBit C2 infrastructure.",
        },
        headers=auth_headers,
    )
    assert req_res.status_code == 201
    req_data = req_res.json()
    assert req_data["status"] == "Pending"
    req_id = req_data["id"]

    # 3. Viewer CANNOT approve response request
    forbidden_approve = client.post(
        f"/api/v1/response-requests/{req_id}/approve",
        json={"decision_notes": "Attempting unauthorized approval"},
        headers=view_headers,
    )
    assert forbidden_approve.status_code == 403

    # 4. Administrator / Owner approves response request
    admin_approve = client.post(
        f"/api/v1/response-requests/{req_id}/approve",
        json={"decision_notes": "Authorized by Security Officer. Proceed with out-of-band VLAN quarantine."},
        headers=auth_headers,
    )
    assert admin_approve.status_code == 200
    assert admin_approve.json()["status"] == "Approved"
    assert admin_approve.json()["approval"]["decision"] == "Approved"


def test_response_request_rejection(client, auth_headers):
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Rejection Flow Test", "description": "Testing denied response requests."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    # Submit request
    req_res = client.post(
        f"/api/v1/incidents/{inc_id}/response-requests",
        json={
            "action_type": "disable_account",
            "target_resource": "executive-ceo@corp.local",
            "justification": "Suspicious login from unexpected country.",
        },
        headers=auth_headers,
    )
    req_id = req_res.json()["id"]

    # Owner rejects request with explanation note
    reject_res = client.post(
        f"/api/v1/response-requests/{req_id}/reject",
        json={"decision_notes": "CEO confirmed traveling abroad on legitimate business. Do not disable."},
        headers=auth_headers,
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["status"] == "Rejected"
    assert reject_res.json()["approval"]["decision"] == "Rejected"


# ------------------------------------------------------------------------------
# 10. Viewer Permissions & Tenant Isolation
# ------------------------------------------------------------------------------
def test_viewer_cannot_mutate_incidents(client, view_headers):
    # Viewer cannot create incidents
    blocked_create = client.post(
        "/api/v1/incidents",
        json={"title": "Viewer Incident", "description": "Should be blocked."},
        headers=view_headers,
    )
    assert blocked_create.status_code == 403

    # Viewer can read incidents
    list_res = client.get("/api/v1/incidents", headers=view_headers)
    assert list_res.status_code == 200
    assert "items" in list_res.json()


def test_incident_export(client, auth_headers):
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Export Test Case", "description": "Verifying JSON and CSV export output."},
        headers=auth_headers,
    )
    inc_id = inc_res.json()["id"]

    # JSON export
    res_json = client.get(f"/api/v1/incidents/{inc_id}/export?format=json", headers=auth_headers)
    assert res_json.status_code == 200
    assert "incident" in res_json.json()
    assert "mitre_attack_mappings" in res_json.json()

    # CSV export
    res_csv = client.get(f"/api/v1/incidents/{inc_id}/export?format=csv", headers=auth_headers)
    assert res_csv.status_code == 200
    assert "csv_data" in res_csv.json()
