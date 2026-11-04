import pytest
from starlette.testclient import TestClient

from app.main import app

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


def test_list_workflows(owner_headers):
    response = client.get(f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert response.status_code == 200
    workflows = response.json()
    assert isinstance(workflows, list)
    assert len(workflows) >= 5  # Pre-seeded 5 standard playbooks
    names = [w["name"] for w in workflows]
    assert any("Suspicious Login" in n for n in names)
    assert any("Malware Alert" in n for n in names)
    assert any("Critical Vulnerability" in n for n in names)


def test_create_workflow_validation(owner_headers):
    # 1. Invalid: Missing trigger step (step 1 is severity_check) -> raises 400
    invalid_payload = {
        "name": "Invalid Playbook No Trigger",
        "description": "Missing trigger should fail validation",
        "trigger_type": "new_critical_alert",
        "steps": [
            {
                "step_order": 1,
                "name": "Check Severity",
                "step_type": "severity_check",
                "parameters": {"minimum_severity": "Critical"},
            },
            {
                "step_order": 2,
                "name": "End Workflow",
                "step_type": "end_workflow",
                "parameters": {},
            },
        ],
    }
    res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=invalid_payload,
    )
    assert res.status_code == 400
    assert "First step of playbook must be of type 'trigger'" in res.json()["detail"]

    # 2. Valid workflow creation
    valid_payload = {
        "name": "Automated Port 22 Brute-Force Response",
        "description": "Quarantines anomalous SSH logins and logs SOC incident",
        "trigger_type": "repeated_auth_failures",
        "steps": [
            {
                "step_order": 1,
                "name": "Trigger on Auth Failure",
                "step_type": "trigger",
                "parameters": {"event_source": "auth_service", "failed_attempts_threshold": 5},
            },
            {
                "step_order": 2,
                "name": "Evaluate Severity",
                "step_type": "severity_check",
                "parameters": {"minimum_severity": "High"},
            },
            {
                "step_order": 3,
                "name": "Create SOC Incident",
                "step_type": "create_incident",
                "parameters": {
                    "title": "Automated Incident: SSH Brute Force Detected",
                    "incident_type": "Unauthorized Access",
                    "severity": "High",
                },
            },
            {
                "step_order": 4,
                "name": "Complete Workflow",
                "step_type": "end_workflow",
                "parameters": {"summary": "Incident logged and flagged for containment"},
            },
        ],
    }
    create_res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=valid_payload,
    )
    assert create_res.status_code == 201
    created_wf = create_res.json()
    assert created_wf["name"] == valid_payload["name"]
    assert created_wf["status"] == "Draft"
    assert len(created_wf["steps"]) == 4


def test_publish_workflow(owner_headers):
    # Create workflow
    valid_payload = {
        "name": "Ransomware Canary Alert Handler",
        "description": "Detects canary file modifications and raises immediate high alert",
        "trigger_type": "suspicious_network_activity",
        "steps": [
            {
                "step_order": 1,
                "name": "Catch Canary Event",
                "step_type": "trigger",
                "parameters": {},
            },
            {
                "step_order": 2,
                "name": "End Handler",
                "step_type": "end_workflow",
                "parameters": {},
            },
        ],
    }
    wf_res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=valid_payload,
    )
    assert wf_res.status_code == 201
    wf_id = wf_res.json()["id"]

    pub_res = client.post(
        f"/api/v1/soar/workflows/{wf_id}/publish?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert pub_res.status_code == 200
    published_wf = pub_res.json()
    assert published_wf["status"] == "Published"


def test_execute_workflow_immediate_success(owner_headers):
    payload = {
        "name": "Autonomous Threat Intel Enrichment",
        "description": "Look up IP indicator and notify SOC channel",
        "trigger_type": "threat_intel_ioc_match",
        "steps": [
            {
                "step_order": 1,
                "name": "IOC Match Ingest",
                "step_type": "trigger",
                "parameters": {},
            },
            {
                "step_order": 2,
                "name": "Query Threat Intel",
                "step_type": "threat_intel_lookup",
                "parameters": {"indicator": "198.51.100.23"},
            },
            {
                "step_order": 3,
                "name": "Dispatch Alert Notification",
                "step_type": "send_notification",
                "parameters": {"channel": "in_app", "recipient": "soc-team@cybershield.local"},
            },
            {
                "step_order": 4,
                "name": "Finish",
                "step_type": "end_workflow",
                "parameters": {},
            },
        ],
    }
    wf_res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert wf_res.status_code == 201
    wf_id = wf_res.json()["id"]

    # Execute workflow
    exec_req = {
        "trigger_source": "threat_feed_ingest",
        "input_context": {
            "indicator": "198.51.100.23",
            "threat_type": "Malware C2",
            "confidence_score": 94,
        },
    }
    exec_res = client.post(
        f"/api/v1/soar/workflows/{wf_id}/execute?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=exec_req,
    )
    assert exec_res.status_code == 200
    execution = exec_res.json()
    assert execution["status"] == "Completed"
    assert len(execution["steps"]) == 4
    assert len(execution["logs"]) >= 4

    # Verify execution details endpoint
    get_res = client.get(
        f"/api/v1/soar/executions/{execution['id']}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "Completed"


def test_execute_workflow_with_human_approval_lifecycle(owner_headers):
    # Workflow containing request_approval for disruptive asset isolation
    payload = {
        "name": "Zero-Day Containment with Gate",
        "description": "Requires analyst authorization before isolating critical server",
        "trigger_type": "new_critical_alert",
        "steps": [
            {
                "step_order": 1,
                "name": "Alert Ingestion",
                "step_type": "trigger",
                "parameters": {},
            },
            {
                "step_order": 2,
                "name": "Request Host Isolation Approval",
                "step_type": "request_approval",
                "parameters": {
                    "action_type": "asset_isolation",
                    "target_identifier": "srv-db-prod-01",
                    "urgency": "High",
                    "reason": "Suspected lateral movement detected from internal IP",
                },
            },
            {
                "step_order": 3,
                "name": "Log Incident After Isolation",
                "step_type": "create_incident",
                "parameters": {
                    "title": "Incident: Isolated Production Asset srv-db-prod-01",
                    "severity": "Critical",
                    "incident_type": "Malware",
                },
            },
            {
                "step_order": 4,
                "name": "Complete Containment Workflow",
                "step_type": "end_workflow",
                "parameters": {},
            },
        ],
    }
    wf_res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert wf_res.status_code == 201
    wf_id = wf_res.json()["id"]

    # Execute workflow -> pauses at request_approval
    exec_res = client.post(
        f"/api/v1/soar/workflows/{wf_id}/execute?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"trigger_source": "edr_agent", "input_context": {"host": "srv-db-prod-01"}},
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "Waiting_Approval"
    exec_id = exec_data["id"]

    # Check pending approval exists
    approvals_res = client.get(
        f"/api/v1/soar/approvals?decision=Pending&org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert approvals_res.status_code == 200
    pending_approvals = approvals_res.json()
    target_approval = next((a for a in pending_approvals if a["execution_id"] == exec_id), None)
    assert target_approval is not None
    assert target_approval["action_type"] == "asset_isolation"
    approval_id = target_approval["id"]

    # Approve the action with justification
    approve_res = client.post(
        f"/api/v1/soar/approvals/{approval_id}/approve?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"decision": "Approved", "justification_notes": "Forensic snapshot taken. Safe to isolate host."},
    )
    assert approve_res.status_code == 200
    approved_data = approve_res.json()
    assert approved_data["decision"] == "Executed"

    # Verify execution resumed to Completed
    resumed_exec_res = client.get(
        f"/api/v1/soar/executions/{exec_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert resumed_exec_res.status_code == 200
    resumed_data = resumed_exec_res.json()
    assert resumed_data["status"] == "Completed"


def test_reject_action_approval(owner_headers):
    payload = {
        "name": "Firewall Block Requester",
        "description": "Requires human review to modify ingress ACLs",
        "trigger_type": "threat_intel_ioc_match",
        "steps": [
            {
                "step_order": 1,
                "name": "Threat Trigger",
                "step_type": "trigger",
                "parameters": {},
            },
            {
                "step_order": 2,
                "name": "Gate Firewall Rule",
                "step_type": "request_approval",
                "parameters": {
                    "action_type": "firewall_rule_review",
                    "target_identifier": "edge-fw-external",
                    "reason": "Block upstream provider subnet",
                },
            },
            {
                "step_order": 3,
                "name": "Finish",
                "step_type": "end_workflow",
                "parameters": {},
            },
        ],
    }
    wf_res = client.post(
        f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert wf_res.status_code == 201
    wf_id = wf_res.json()["id"]

    exec_res = client.post(
        f"/api/v1/soar/workflows/{wf_id}/execute?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"trigger_source": "manual_test", "input_context": {}},
    )
    assert exec_res.status_code == 200
    exec_id = exec_res.json()["id"]

    # Locate pending approval
    approvals_res = client.get(
        f"/api/v1/soar/approvals?decision=Pending&org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    target_approval = next((a for a in approvals_res.json() if a["execution_id"] == exec_id), None)
    assert target_approval is not None

    # Reject approval
    reject_res = client.post(
        f"/api/v1/soar/approvals/{target_approval['id']}/reject?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"decision": "Rejected", "justification_notes": "Subnet belongs to trusted customer CDN."},
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["decision"] == "Rejected"

    # Execution status should reflect Cancelled
    cancelled_exec = client.get(
        f"/api/v1/soar/executions/{exec_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    ).json()
    assert cancelled_exec["status"] == "Cancelled"


def test_cancel_active_execution(owner_headers):
    # Execute a workflow that pauses at approval, then cancel it directly
    workflows = client.get(f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    wf_with_approval = next(
        (w for w in workflows if any(s["step_type"] == "request_approval" for s in w.get("steps", []))),
        None,
    )
    assert wf_with_approval is not None

    exec_res = client.post(
        f"/api/v1/soar/workflows/{wf_with_approval['id']}/execute?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"trigger_source": "direct_cancel_test", "input_context": {}},
    )
    assert exec_res.status_code == 200
    exec_id = exec_res.json()["id"]

    cancel_res = client.post(
        f"/api/v1/soar/executions/{exec_id}/cancel?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "Cancelled"


def test_soar_analytics_dashboard(owner_headers):
    res = client.get(f"/api/v1/soar/analytics?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    analytics = res.json()
    assert "total_playbook_executions" in analytics
    assert "successful_executions" in analytics
    assert "failed_executions" in analytics
    assert "pending_approvals" in analytics
    assert "average_execution_time_ms" in analytics
    assert "automation_success_rate" in analytics
    assert "execution_trends" in analytics
    assert len(analytics["execution_trends"]) > 0


def test_notification_channels_and_dispatch(owner_headers):
    # 1. List configured templates
    tpl_res = client.get(f"/api/v1/soar/notifications?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert tpl_res.status_code == 200
    templates = tpl_res.json()
    assert len(templates) >= 3  # in_app, email, webhook seeded
    channels = [t["channel"] for t in templates]
    assert "in_app" in channels
    assert "email" in channels
    assert "webhook" in channels

    # 2. Dispatch a test notification
    test_req = {
        "channel": "webhook",
        "recipient": "https://hooks.slack.com/services/T00/B00/X00",
        "subject": "Test SOAR Dispatch",
        "body": "{\"incident_id\": \"INC-2026-0042\", \"severity\": \"High\"}",
    }
    dispatch_res = client.post(
        f"/api/v1/soar/notifications/test?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=test_req,
    )
    assert dispatch_res.status_code == 200
    delivery = dispatch_res.json()
    assert delivery["channel"] == "webhook"
    assert delivery["recipient"] == test_req["recipient"]
    assert delivery["status"] == "Delivered"
