import io
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

APEX_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
NIST_CONTROL_ID = "81000000-0000-0000-0000-000000000001"


@pytest.fixture
def auth_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def view_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ------------------------------------------------------------------------------
# 1. Compliance Frameworks & Controls
# ------------------------------------------------------------------------------
def test_get_compliance_frameworks(client: TestClient, auth_headers):
    res = client.get(f"/api/v1/compliance/frameworks?org_id={APEX_ORG_ID}", headers=auth_headers)
    assert res.status_code == 200
    frameworks = res.json()
    assert len(frameworks) >= 4

    codes = [f["framework_code"] for f in frameworks]
    assert "NIST_CSF_2_0" in codes
    assert "CIS_CONTROLS_V8" in codes
    assert "OWASP_TOP_10_2021" in codes
    assert "ISO_27001_2022" in codes

    nist = next(f for f in frameworks if f["framework_code"] == "NIST_CSF_2_0")
    assert nist["total_controls"] >= 5
    assert "completion_percentage" in nist


def test_get_compliance_controls_filtering(client: TestClient, auth_headers):
    # Filter by framework code
    res = client.get(
        f"/api/v1/compliance/controls?framework_code=NIST_CSF_2_0&org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert res.status_code == 200
    controls = res.json()
    assert len(controls) >= 5
    assert all(c["framework_code"] == "NIST_CSF_2_0" for c in controls)

    # Filter by domain
    res_domain = client.get(
        f"/api/v1/compliance/controls?domain=Asset&org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert res_domain.status_code == 200
    assert len(res_domain.json()) >= 1


# ------------------------------------------------------------------------------
# 2. Compliance Assessments & RBAC
# ------------------------------------------------------------------------------
def test_create_and_update_assessment(client: TestClient, auth_headers, view_headers):
    # Viewer should be forbidden from creating an assessment
    payload = {
        "control_id": NIST_CONTROL_ID,
        "status": "Implemented",
        "assigned_owner": "Staff Architect",
        "notes": "Verified through automated continuous discovery telemetry",
    }
    view_res = client.post(
        f"/api/v1/compliance/assessments?org_id={APEX_ORG_ID}",
        json=payload,
        headers=view_headers,
    )
    assert view_res.status_code == 403

    # Owner/Analyst can create assessment
    create_res = client.post(
        f"/api/v1/compliance/assessments?org_id={APEX_ORG_ID}",
        json=payload,
        headers=auth_headers,
    )
    assert create_res.status_code == 201
    ass = create_res.json()
    assert ass["status"] == "Implemented"
    assert ass["assigned_owner"] == "Staff Architect"
    assessment_id = ass["id"]

    # Update assessment
    patch_payload = {
        "status": "Partially Implemented",
        "notes": "Pending audit verification for remote satellite office",
    }
    patch_res = client.patch(
        f"/api/v1/compliance/assessments/{assessment_id}?org_id={APEX_ORG_ID}",
        json=patch_payload,
        headers=auth_headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Partially Implemented"


# ------------------------------------------------------------------------------
# 3. Compliance Evidence Management & Hash Validation
# ------------------------------------------------------------------------------
def test_compliance_evidence_lifecycle(client: TestClient, auth_headers, view_headers):
    # Executable file types MUST be rejected
    malicious_file = ("exploit.exe", b"\x4d\x5a\x90\x00", "application/x-msdownload")
    bad_upload = client.post(
        f"/api/v1/compliance/evidence?org_id={APEX_ORG_ID}",
        files={"file": malicious_file},
        data={"description": "Test executable"},
        headers=auth_headers,
    )
    assert bad_upload.status_code == 400
    assert "Executable file types are strictly prohibited" in bad_upload.json()["detail"]

    # Valid PDF evidence upload
    fake_pdf = ("network_scan_audit.pdf", b"%PDF-1.4 test audit document", "application/pdf")
    upload_res = client.post(
        f"/api/v1/compliance/evidence?org_id={APEX_ORG_ID}",
        files={"file": fake_pdf},
        data={"description": "Q3 Network Scan Audit Log"},
        headers=auth_headers,
    )
    assert upload_res.status_code == 201
    evidence = upload_res.json()
    assert evidence["file_name"] == "network_scan_audit.pdf"
    assert len(evidence["sha256_hash"]) == 64  # valid SHA-256 hex string
    evidence_id = evidence["id"]

    # List evidence
    list_res = client.get(f"/api/v1/compliance/evidence?org_id={APEX_ORG_ID}", headers=auth_headers)
    assert list_res.status_code == 200
    assert any(e["id"] == evidence_id for e in list_res.json())

    # Viewer cannot delete evidence
    view_del = client.delete(
        f"/api/v1/compliance/evidence/{evidence_id}?org_id={APEX_ORG_ID}",
        headers=view_headers,
    )
    assert view_del.status_code == 403

    # Owner can delete evidence
    del_res = client.delete(
        f"/api/v1/compliance/evidence/{evidence_id}?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert del_res.status_code == 200


# ------------------------------------------------------------------------------
# 4. Security Reports Generation & Downloads (PDF & CSV)
# ------------------------------------------------------------------------------
def test_reports_preview_and_generation(client: TestClient, auth_headers):
    # 1. Preview report
    preview_req = {
        "report_type": "vulnerability_assessment",
        "format": "pdf",
        "date_range": "30d",
        "severity_filter": ["Critical", "High"],
    }
    prev_res = client.post(
        f"/api/v1/reports/preview?org_id={APEX_ORG_ID}",
        json=preview_req,
        headers=auth_headers,
    )
    assert prev_res.status_code == 200
    preview = prev_res.json()
    assert "executive_summary" in preview
    assert "key_metrics" in preview

    # 2. Generate PDF report
    gen_req = {
        "report_type": "executive_summary",
        "title": "Board of Directors Cybersecurity Brief",
        "format": "pdf",
        "date_range": "30d",
    }
    gen_res = client.post(
        f"/api/v1/reports/generate?org_id={APEX_ORG_ID}",
        json=gen_req,
        headers=auth_headers,
    )
    assert gen_res.status_code == 201
    pdf_report = gen_res.json()
    assert pdf_report["status"] == "Completed"
    assert pdf_report["format"] == "pdf"
    pdf_id = pdf_report["id"]

    # 3. Download PDF report
    pdf_download = client.get(
        f"/api/v1/reports/{pdf_id}/download?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert pdf_download.status_code == 200
    assert pdf_download.headers["content-type"] == "application/pdf"
    assert pdf_download.content.startswith(b"%PDF-1.4")
    assert pdf_download.content.endswith(b"%%EOF\n")

    # 4. Generate CSV report
    csv_gen = client.post(
        f"/api/v1/reports/generate?org_id={APEX_ORG_ID}",
        json={"report_type": "asset_inventory", "format": "csv"},
        headers=auth_headers,
    )
    assert csv_gen.status_code == 201
    csv_id = csv_gen.json()["id"]

    # 5. Download CSV report
    csv_download = client.get(
        f"/api/v1/reports/{csv_id}/download?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert csv_download.status_code == 200
    assert "text/csv" in csv_download.headers["content-type"]
    assert len(csv_download.content) > 0


# ------------------------------------------------------------------------------
# 5. Posture & Executive Dashboard Analytics
# ------------------------------------------------------------------------------
def test_posture_and_executive_dashboard(client: TestClient, auth_headers):
    # Posture analytics
    posture_res = client.get(
        f"/api/v1/analytics/posture?organization_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert posture_res.status_code == 200
    posture = posture_res.json()
    assert 0.0 <= posture["overall_score"] <= 100.0
    assert "risk_level" in posture
    assert "category_scores" in posture
    assert "score_factors" in posture
    assert len(posture["recommended_improvements"]) >= 1

    # Executive dashboard with date filtering
    for date_range in ["7d", "30d", "90d"]:
        exec_res = client.get(
            f"/api/v1/analytics/executive-summary?date_range={date_range}&organization_id={APEX_ORG_ID}",
            headers=auth_headers,
        )
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["date_range"] == date_range
        assert "security_score" in exec_data
        assert "top_5_security_risks" in exec_data
        assert len(exec_data["security_trend"]) >= 1

    # Compliance analytics summary
    comp_res = client.get(
        f"/api/v1/analytics/compliance?organization_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert comp_res.status_code == 200
    comp = comp_res.json()
    assert "overall_compliance_score" in comp
    assert comp["total_controls"] >= 10
