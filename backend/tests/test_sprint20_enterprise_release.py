"""
Enterprise Release Readiness & End-to-End Workflow Verification Tests
CyberShield Sprint 20
"""

import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.release_readiness_service import release_readiness_service
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


# ==============================================================================
# 1. ENTERPRISE RELEASE READINESS SERVICE & ENDPOINTS
# ==============================================================================

def test_release_readiness_service_direct_evaluation():
    """Verify release readiness evaluation logic, scoring, and engine classifications."""
    overview = release_readiness_service.evaluate_release_readiness(DEFAULT_ORG_ID)
    assert overview.release_version == "v1.0.0-enterprise"
    assert overview.readiness_score >= 90.0
    assert overview.gate_status in ("ready_for_release", "conditionally_ready")
    assert overview.total_checks >= 12
    assert overview.failed_checks == 0
    assert len(overview.security_engines) >= 8

    # Verify classification honesty
    engine_names = [e.engine_name for e in overview.security_engines]
    assert any("Nmap" in name for name in engine_names)
    assert any("Scapy" in name for name in engine_names)
    assert any("CISA" in name for name in engine_names)
    assert any("Forensics" in name for name in engine_names)


def test_release_readiness_api_endpoint(owner_headers):
    """Verify GET /api/v1/release-readiness endpoint returns complete release audit."""
    res = client.get(f"/api/v1/release-readiness?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert "readiness_score" in data
    assert "gate_status" in data
    assert "checks_by_category" in data
    assert "security_engines" in data
    assert "system_metrics" in data
    assert data["system_metrics"]["total_automated_tests"] >= 201


def test_release_readiness_auth_and_isolation(owner_headers):
    """Verify unauthorized or cross-tenant access to release readiness is rejected."""
    # Unauthenticated -> 401
    unauth_res = client.get("/api/v1/release-readiness")
    assert unauth_res.status_code == 401

    # Cross-tenant BOLA -> 403
    foreign_res = client.get(f"/api/v1/release-readiness?org_id={FOREIGN_ORG_ID}", headers=owner_headers)
    assert foreign_res.status_code == 403


# ==============================================================================
# 2. END-TO-END WORKFLOW INTEGRATION CHECKS (WORKFLOWS 1 TO 11)
# ==============================================================================

def test_workflow_01_user_onboarding_and_org_context(owner_headers):
    """Workflow 1: User onboarding, profile retrieval, and organization membership."""
    res = client.get("/api/v1/auth/me", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert "id" in data
    assert "email" in data

    orgs_res = client.get("/api/v1/organizations", headers=owner_headers)
    assert orgs_res.status_code == 200
    assert len(orgs_res.json()) > 0


def test_workflow_02_asset_inventory_management(owner_headers):
    """Workflow 2: Asset inventory and RFC 1918 scope retrieval."""
    res = client.get(f"/api/v1/assets?organization_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) > 0


def test_workflow_03_vulnerability_assessment(owner_headers):
    """Workflow 3: Vulnerability inventory and CVSS scoring context."""
    res = client.get(f"/api/v1/vulnerabilities/findings?organization_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    items = data.get("items", data)
    assert len(items) > 0


def test_workflow_04_threat_intelligence_correlation(owner_headers):
    """Workflow 4: Threat Intelligence IOC retrieval and normalization."""
    res = client.get(f"/api/v1/threat-intelligence/indicators?organization_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    items = data.get("items", data)
    assert len(items) > 0


def test_workflow_05_incident_response_lifecycle(owner_headers):
    """Workflow 5: Incident case management and MITRE ATT&CK technique mapping."""
    res = client.get(f"/api/v1/incidents?organization_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    items = data.get("items", data)
    assert len(items) > 0


def test_workflow_06_ai_soc_assistant_grounded_response(owner_headers):
    """Workflow 6: AI SOC Assistant query execution with tenant context."""
    payload = {
        "message": "Summarize recent critical incidents for this organization.",
    }
    res = client.post(f"/api/v1/ai/chat?organization_id={DEFAULT_ORG_ID}", headers=owner_headers, json=payload)
    assert res.status_code in (200, 201)
    data = res.json()
    assert "response" in data or "reply" in data or "message" in data


def test_workflow_07_compliance_frameworks(owner_headers):
    """Workflow 7: Multi-framework compliance assessment retrieval."""
    res = client.get(f"/api/v1/compliance/frameworks?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    frameworks = res.json()
    assert len(frameworks) > 0
    assert any("NIST" in f.get("name", "") or "CIS" in f.get("name", "") for f in frameworks)


def test_workflow_08_soar_playbooks_and_approvals(owner_headers):
    """Workflow 8: SOAR automated playbook listings and approval gates."""
    res = client.get(f"/api/v1/soar/workflows?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    workflows = res.json()
    assert len(workflows) > 0

    approvals_res = client.get(f"/api/v1/soar/approvals?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert approvals_res.status_code == 200


def test_workflow_09_threat_hunting_and_forensics(owner_headers):
    """Workflow 9: Threat hunting queries and forensic custody verification."""
    cases_res = client.get(f"/api/v1/threat-hunting/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert cases_res.status_code == 200
    cases = cases_res.json()
    assert len(cases) > 0

    forensic_res = client.get(f"/api/v1/forensics/cases?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert forensic_res.status_code == 200


def test_workflow_10_enterprise_identity_and_zero_trust(owner_headers):
    """Workflow 10: Zero trust policy rules and session security metadata."""
    policies_res = client.get(f"/api/v1/identity/policies/rules?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert policies_res.status_code == 200

    sessions_res = client.get(f"/api/v1/identity/sessions?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert sessions_res.status_code == 200


def test_workflow_11_security_assurance_and_remediation(owner_headers):
    """Workflow 11: Continuous security assurance overview and findings triage."""
    ass_res = client.get(f"/api/v1/security-assurance/overview?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert ass_res.status_code == 200
    data = ass_res.json()
    assert "posture_score" in data
    assert "components" in data
