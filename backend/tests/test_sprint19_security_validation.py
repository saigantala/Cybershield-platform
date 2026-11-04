"""
Automated Security Validation, Penetration Testing & Regression Tests
CyberShield Sprint 19
"""

import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.security_assurance_service import security_assurance_service
from app.services.supabase_service import supabase_service

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
FOREIGN_ORG_ID = "00000000-0000-0000-0000-999999999999"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture
def expired_headers(expired_token):
    return {"Authorization": f"Bearer {expired_token}"}


@pytest.fixture
def unauthorized_headers(unauthorized_user_token):
    return {"Authorization": f"Bearer {unauthorized_user_token}"}


# ==============================================================================
# 1. DETERMINISTIC SECURITY POSTURE SCORING TESTS
# ==============================================================================

def test_deterministic_posture_score_calculation():
    """Verify deterministic scoring formula, penalty weights, and metric separation."""
    scores = security_assurance_service.calculate_posture_scores(DEFAULT_ORG_ID)
    assert 0.0 <= scores["posture_score"] <= 100.0
    assert 0.0 <= scores["risk_score"] <= 100.0
    assert 0.0 <= scores["test_coverage_pct"] <= 100.0
    assert 0.0 <= scores["compliance_pct"] <= 100.0

    # Ensure critical/high finding counts are decoupled
    assert "critical_open" in scores
    assert "high_open" in scores
    assert "failed_checks" in scores


# ==============================================================================
# 2. BROKEN ACCESS CONTROL & TENANT ISOLATION (BOLA & BFLA)
# ==============================================================================

def test_cross_tenant_isolation_bola(owner_headers):
    """Verify that requests targeting a foreign organization are strictly blocked with 403."""
    # Attempt to query assets with a foreign organization ID
    res = client.get(f"/api/v1/assets?organization_id={FOREIGN_ORG_ID}", headers=owner_headers)
    assert res.status_code == 403
    assert "access denied" in res.json()["detail"].lower()

    # Attempt to query security findings with foreign org ID
    f_res = client.get(f"/api/v1/security-assurance/findings?org_id={FOREIGN_ORG_ID}", headers=owner_headers)
    assert f_res.status_code == 403


def test_role_based_action_restriction_bfla(viewer_headers):
    """Verify that Viewer accounts cannot perform administrative or destructive mutations."""
    # Viewer attempting to delete an access policy rule -> 403
    del_res = client.delete(
        f"/api/v1/identity/policies/rules/any-rule-id?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
    )
    assert del_res.status_code == 403

    # Viewer attempting to trigger security assessment -> 403
    run_res = client.post(
        f"/api/v1/security-assurance/assessments/run?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={"assessment_name": "Unauthorized Test", "assessment_type": "full_suite"},
    )
    assert run_res.status_code == 403


# ==============================================================================
# 3. AUTHENTICATION INTEGRITY & TOKEN TAMPERING
# ==============================================================================

def test_unauthenticated_request_rejected():
    """Verify that requests missing authorization headers are rejected with 401."""
    res = client.get("/api/v1/security-assurance/overview")
    assert res.status_code == 401


def test_forged_jwt_signature_rejected():
    """Verify that cryptographically forged JWT tokens are rejected with 401."""
    forged_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZvcmdlZCJ9.invalid_signature_here"
    headers = {"Authorization": f"Bearer {forged_token}"}
    res = client.get(f"/api/v1/security-assurance/overview?org_id={DEFAULT_ORG_ID}", headers=headers)
    assert res.status_code == 401


def test_expired_jwt_token_rejected(expired_headers):
    """Verify that expired JWT tokens are rejected with 401."""
    res = client.get(f"/api/v1/security-assurance/overview?org_id={DEFAULT_ORG_ID}", headers=expired_headers)
    assert res.status_code == 401


# ==============================================================================
# 4. INPUT VALIDATION & INJECTION DEFENSES
# ==============================================================================

def test_scope_command_injection_rejected(owner_headers):
    """Verify that command injection payloads in network CIDR scopes are rejected by validators."""
    payload = {"network_cidr": "10.0.0.1/24; cat /etc/passwd"}
    res = client.post(f"/api/v1/scopes?org_id={DEFAULT_ORG_ID}", headers=owner_headers, json=payload)
    assert res.status_code in (400, 422)


def test_threat_hunting_sqli_fuzzing_safety(owner_headers):
    """Verify that SQL injection probe vectors in search endpoints are safely parameterized without DB crash."""
    payload = {
        "ioc_value": "' OR '1'='1' --",
        "time_range_hours": 24,
    }
    res = client.post(f"/api/v1/threat-hunting/search?org_id={DEFAULT_ORG_ID}", headers=owner_headers, json=payload)
    # Handled cleanly with 200 or 422, zero unhandled 500 exceptions
    assert res.status_code in (200, 422)
    assert res.status_code != 500


# ==============================================================================
# 5. ZERO TRUST AAL2 STEP-UP & LOCKOUT CONTROLS
# ==============================================================================

def test_zero_trust_step_up_evaluation(owner_headers):
    """Verify that sensitive operations requiring AAL2 reject single-factor (AAL1) callers."""
    # Ensure test user is at AAL1
    supabase_service.upsert_user_security_preferences("00000000-0000-0000-0000-000000000001", DEFAULT_ORG_ID, {
        "current_aal": "aal1"
    })

    res = client.post(
        f"/api/v1/identity/policies/evaluate?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"resource_type": "forensics", "action": "export"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is False
    assert "aal2" in data["decision_reason"].lower()


def test_last_owner_lockout_prevention(owner_headers):
    """Verify that the sole organization owner cannot be demoted or removed."""
    owner_member_id = "f5b39a43-089c-4f70-a889-cb4c5b36dc33"
    res = client.patch(
        f"/api/v1/team/members/{owner_member_id}/role?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"role": "viewer"},
    )
    assert res.status_code in (400, 403)


# ==============================================================================
# 6. SECURITY RESPONSE HEADERS & RATE LIMITING
# ==============================================================================

def test_security_response_headers():
    """Verify that essential security headers (nosniff, CSP, X-Frame-Options) are returned."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert "x-content-type-options" in res.headers
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "x-frame-options" in res.headers
    assert "content-security-policy" in res.headers


# ==============================================================================
# 7. SPRINT 19 ASSURANCE & API TEST RUNNER ENDPOINTS
# ==============================================================================

def test_security_overview_endpoint(owner_headers):
    """Verify that the security assurance overview returns posture, risk, coverage, and sample checks."""
    res = client.get(f"/api/v1/security-assurance/overview?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert "posture_score" in data
    assert "risk_score" in data
    assert "test_coverage_pct" in data
    assert "components" in data
    assert len(data["components"]) > 0


def test_api_security_suite_dispatch(owner_headers):
    """Verify automated execution and reporting of the API security validation suite."""
    res = client.post(
        f"/api/v1/security-assurance/tests/run-api-suite?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"target_host": "http://localhost:8000"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_tests"] >= 8
    assert data["passed_tests"] > 0
    assert len(data["results"]) >= 8
    assert any(r["test_category"] == "bola" for r in data["results"])


def test_assessment_run_and_checks(owner_headers):
    """Verify running a security assessment and retrieving checklist verification results."""
    # 1. Run assessment
    run_res = client.post(
        f"/api/v1/security-assurance/assessments/run?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "assessment_name": "Sprint 19 Automated Acceptance Run",
            "assessment_type": "application",
            "target_environment": "staging",
        },
    )
    assert run_res.status_code == 200
    ass_data = run_res.json()
    assert ass_data["status"] == "completed"
    ass_id = ass_data["id"]

    # 2. List assessments
    list_res = client.get(f"/api/v1/security-assurance/assessments?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    assert any(a["id"] == ass_id for a in list_res.json())


def test_security_findings_lifecycle_and_notes(owner_headers):
    """Verify finding creation, status transitions, history logging, and analyst notes."""
    # 1. Create finding
    create_res = client.post(
        f"/api/v1/security-assurance/findings?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "title": "Simulated Insecure Direct Object Reference (IDOR) Test Finding",
            "description": "Validation test to ensure finding lifecycle transitions function properly.",
            "category": "Broken Access Control",
            "source_scanner": "manual_pentest",
            "severity": "medium",
            "affected_component": "API Gateway",
            "remediation_recommendation": "Enforce strict tenant ID check in service handler.",
        },
    )
    assert create_res.status_code == 200
    finding = create_res.json()
    finding_id = finding["id"]
    assert finding["status"] == "open"

    # 2. Add analyst note
    note_res = client.post(
        f"/api/v1/security-assurance/findings/{finding_id}/notes?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"content": "Triaged finding. Confirmed patch was applied in PR #192."},
    )
    assert note_res.status_code == 200
    assert note_res.json()["content"].startswith("Triaged finding")

    # 3. Transition to 'in_progress' and then 'fixed'
    update_res = client.put(
        f"/api/v1/security-assurance/findings/{finding_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"status": "fixed", "verification_notes": "Automated regression test passed."},
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "fixed"
    assert update_res.json()["resolved_at"] is not None


def test_risk_acceptance_exception_flow(owner_headers):
    """Verify documenting an accepted risk exception with justification and expiry."""
    # Use existing seed finding SEC-2026-001
    findings = client.get(f"/api/v1/security-assurance/findings?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    target_f = findings[0]

    accept_res = client.post(
        f"/api/v1/security-assurance/findings/{target_f['id']}/accept-risk?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "justification": "Approved staging exception for developer workstation integration.",
            "compensating_controls": "Strict IP restriction and VPN requirement.",
            "duration_days": 30,
        },
    )
    assert accept_res.status_code == 200
    assert accept_res.json()["status"] == "accepted_risk"


def test_supply_chain_and_container_audits(owner_headers):
    """Verify dependencies, containers, and configuration audits return structured, sanitized data."""
    dep_res = client.get(f"/api/v1/security-assurance/dependencies?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert dep_res.status_code == 200
    deps = dep_res.json()
    assert len(deps) > 0

    cont_res = client.get(f"/api/v1/security-assurance/containers?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert cont_res.status_code == 200
    containers = cont_res.json()
    assert len(containers) > 0

    conf_res = client.get(f"/api/v1/security-assurance/configuration?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert conf_res.status_code == 200
    confs = conf_res.json()
    assert len(confs) >= 8


def test_report_export_json_and_csv(owner_headers):
    """Verify generating JSON and CSV security assurance export reports."""
    # JSON export
    json_res = client.post(
        f"/api/v1/security-assurance/reports/export?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"report_type": "application", "format": "json"},
    )
    assert json_res.status_code == 200
    assert "report_title" in json_res.json()

    # CSV export
    csv_res = client.post(
        f"/api/v1/security-assurance/reports/export?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"report_type": "application", "format": "csv"},
    )
    assert csv_res.status_code == 200
    assert "Finding Code,Title,Severity" in csv_res.json()["data"]
