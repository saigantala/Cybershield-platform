import asyncio
import pytest

from app.scanners.base import RawFinding
from app.scanners.mock_scanner import MockVulnerabilityScanner
from app.scanners.normalizer import FindingNormalizer, NormalizedFinding
from app.services.cve_service import CVEService, cve_service
from app.services.kev_service import kev_service
from app.services.risk_scoring import risk_scoring_engine
from app.services.supabase_service import SupabaseService
from app.workers.tasks import (
    start_vulnerability_assessment,
    validate_assessment_scope,
)


# ------------------------------------------------------------------------------
# 1. CVE Response Parsing & Correlation
# ------------------------------------------------------------------------------
def test_cve_response_parsing():
    raw_nvd_item = {
        "id": "CVE-2024-99999",
        "descriptions": [{"lang": "en", "value": "A critical buffer overflow in demo daemon."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "references": [{"url": "https://example.com/advisory/demo"}],
        "published": "2024-01-01T00:00:00Z",
        "lastModified": "2024-01-02T00:00:00Z",
    }
    svc = CVEService()
    parsed = svc._parse_nvd_cve(raw_nvd_item)
    assert parsed["cve_id"] == "CVE-2024-99999"
    assert parsed["cvss_score"] == 9.8
    assert parsed["severity"] == "Critical"
    assert "https://example.com/advisory/demo" in parsed["reference_urls"]


# ------------------------------------------------------------------------------
# 2. CVSS Severity Mapping & Prioritization Scoring
# ------------------------------------------------------------------------------
def test_cvss_severity_mapping():
    assert FindingNormalizer.map_cvss_to_severity(10.0) == "Critical"
    assert FindingNormalizer.map_cvss_to_severity(9.1) == "Critical"
    assert FindingNormalizer.map_cvss_to_severity(8.5) == "High"
    assert FindingNormalizer.map_cvss_to_severity(7.0) == "High"
    assert FindingNormalizer.map_cvss_to_severity(5.5) == "Medium"
    assert FindingNormalizer.map_cvss_to_severity(3.2) == "Low"
    assert FindingNormalizer.map_cvss_to_severity(0.0) == "Informational"

    # Prioritization formula verification
    # CVSS 7.0 (49.0 pts) + KEV (+25.0 pts) + Critical Asset (+5.0 pts) = 79.0/100
    scores = risk_scoring_engine.calculate_scores(
        cvss_score=7.0, is_kev=True, asset_risk_level="Critical"
    )
    assert scores.official_severity == "High"
    assert scores.cvss_score == 7.0
    assert scores.prioritization_score == 79.0


# ------------------------------------------------------------------------------
# 3. CISA KEV Matching
# ------------------------------------------------------------------------------
def test_cisa_kev_matching():
    # CVE-2024-21762 is a confirmed active KEV in fallback
    assert kev_service.is_in_kev("CVE-2024-21762") is True
    meta = kev_service.get_kev_metadata("CVE-2024-21762")
    assert meta is not None
    assert meta["vendorProject"] == "Fortinet"
    assert meta["knownRansomwareCampaignUse"] == "Known"

    # Non-existent or benign CVE
    assert kev_service.is_in_kev("CVE-1999-0000") is False


# ------------------------------------------------------------------------------
# 4 & 5. Duplicate Finding Prevention & Synchronization
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_duplicate_finding_prevention_and_sync():
    db = SupabaseService()
    org_id = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
    scan_id = "77777777-7777-7777-7777-777777777777"
    asset_id = "11111111-1111-1111-1111-111111111111"

    finding1 = NormalizedFinding(
        asset_id=asset_id,
        title="Deduplication Verification Finding",
        description="Initial discovery observation",
        severity="High",
        cvss_score=8.5,
        cvss_version="3.1",
        cve_id="CVE-2024-99991",
        evidence="First scan evidence capture",
    )

    # First sync -> creates record
    res1 = await db.synchronize_vulnerability_findings(org_id, scan_id, [finding1])
    assert res1["created"] == 1
    assert res1["updated"] == 0

    # Second sync with same asset and CVE -> updates record instead of creating duplicate
    finding2 = NormalizedFinding(
        asset_id=asset_id,
        title="Deduplication Verification Finding",
        description="Subsequent observation with updated evidence",
        severity="High",
        cvss_score=8.5,
        cvss_version="3.1",
        cve_id="CVE-2024-99991",
        evidence="Second scan updated evidence capture",
    )

    res2 = await db.synchronize_vulnerability_findings(org_id, scan_id, [finding2])
    assert res2["created"] == 0
    assert res2["updated"] == 1


# ------------------------------------------------------------------------------
# 6. Missing Service Version Safe Handling
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_missing_service_version_safe_correlation():
    # If version is missing or empty, search_cves_by_product must return empty
    # to avoid claiming the asset is vulnerable based solely on an uncertain banner match
    results = await cve_service.search_cves_by_product("OpenSSH", version=None)
    assert results == []

    results_empty = await cve_service.search_cves_by_product("OpenSSH", version="   ")
    assert results_empty == []


# ------------------------------------------------------------------------------
# 7. Invalid Asset ID Validation
# ------------------------------------------------------------------------------
def test_invalid_asset_id_rejected(client, owner_token):
    non_existent_asset = "00000000-0000-0000-0000-999999999999"
    response = client.get(
        f"/api/v1/vulnerabilities/assets/{non_existent_asset}",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 8 & 9. Expired and Unapproved Scan Scope Rejections
# ------------------------------------------------------------------------------
def test_unapproved_scan_scope_rejected(client, owner_token):
    # Pending scope ID from conftest / mock_db: 55555555-5555-5555-5555-555555555555
    payload = {
        "scan_scope_id": "55555555-5555-5555-5555-555555555555",
        "scan_type": "mock",
        "operator_certified": True,
    }
    response = client.post(
        "/api/v1/vulnerabilities/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 400
    assert "unapproved" in response.json()["detail"].lower()


def test_expired_scan_scope_rejected(client, owner_token):
    # Expired scope ID from mock_db: 44444444-4444-4444-4444-444444444444
    payload = {
        "scan_scope_id": "44444444-4444-4444-4444-444444444444",
        "scan_type": "mock",
        "operator_certified": True,
    }
    response = client.post(
        "/api/v1/vulnerabilities/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 400
    assert "expired" in response.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 10. Unauthorized Organization Access Rejection
# ------------------------------------------------------------------------------
def test_unauthorized_organization_access_rejected(client, unauthorized_user_token):
    response = client.get(
        "/api/v1/vulnerabilities/overview",
        headers={"Authorization": f"Bearer {unauthorized_user_token}"},
    )
    assert response.status_code == 403


# ------------------------------------------------------------------------------
# 11. Viewer Permissions: Read-Only Enforcement
# ------------------------------------------------------------------------------
def test_viewer_cannot_launch_scan(client, viewer_token):
    payload = {
        "scan_scope_id": "33333333-3333-3333-3333-333333333333",
        "scan_type": "mock",
        "operator_certified": True,
    }
    response = client.post(
        "/api/v1/vulnerabilities/scans",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json=payload,
    )
    assert response.status_code == 403
    assert "viewer" in response.json()["detail"].lower()


def test_viewer_cannot_update_remediation(client, viewer_token):
    payload = {
        "new_status": "Resolved",
        "notes": "Attempted update by viewer",
    }
    response = client.post(
        "/api/v1/vulnerabilities/findings/88888888-8888-8888-8888-888888888888/remediation",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json=payload,
    )
    assert response.status_code == 403


# ------------------------------------------------------------------------------
# 12 & 13. Remediation Workflow & Mandatory Justification
# ------------------------------------------------------------------------------
def test_remediation_justification_required_for_accepted_risk_and_false_positive(client, owner_token):
    finding_id = "88888888-8888-8888-8888-888888888888"

    # Missing or empty justification notes must fail validation (HTTP 422)
    response = client.post(
        f"/api/v1/vulnerabilities/findings/{finding_id}/remediation",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"new_status": "Accepted Risk", "notes": ""},
    )
    assert response.status_code == 422

    response_fp = client.post(
        f"/api/v1/vulnerabilities/findings/{finding_id}/remediation",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"new_status": "False Positive", "notes": "   "},
    )
    assert response_fp.status_code == 422

    # Providing justification note succeeds
    valid_payload = {
        "new_status": "Accepted Risk",
        "notes": "Firewall is behind an isolated VPN gateway; compensating control documented in Risk Register #RR-2026-42.",
    }
    response_valid = client.post(
        f"/api/v1/vulnerabilities/findings/{finding_id}/remediation",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=valid_payload,
    )
    assert response_valid.status_code == 200
    assert response_valid.json()["status"] == "Accepted Risk"

    # Verify audit history record was persisted
    history_res = client.get(
        f"/api/v1/vulnerabilities/findings/{finding_id}/history",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert history_res.status_code == 200
    history = history_res.json()
    assert len(history) >= 1
    assert history[0]["new_status"] == "Accepted Risk"
    assert "Risk Register #RR-2026-42" in history[0]["notes"]


# ------------------------------------------------------------------------------
# 14, 15, 16. Scanner Failure, Timeout & Cancellation Handling
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scanner_timeout_handling():
    scanner = MockVulnerabilityScanner()
    with pytest.raises(asyncio.TimeoutError):
        await scanner.run_assessment(
            targets=[{"id": "11111111-1111-1111-1111-111111111111"}],
            options={"simulate_timeout": True},
        )


@pytest.mark.asyncio
async def test_scanner_failure_handling():
    scanner = MockVulnerabilityScanner()
    with pytest.raises(RuntimeError):
        await scanner.run_assessment(
            targets=[{"id": "11111111-1111-1111-1111-111111111111"}],
            options={"simulate_failure": True},
        )


def test_vulnerability_scan_cancellation(client, owner_token):
    # Launch scan on approved scope
    payload = {
        "scan_scope_id": "33333333-3333-3333-3333-333333333333",
        "scan_type": "mock",
        "operator_certified": True,
    }
    create_res = client.post(
        "/api/v1/vulnerabilities/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert create_res.status_code == 202
    scan_id = create_res.json()["id"]

    # Cancel scan
    cancel_res = client.post(
        f"/api/v1/vulnerabilities/scans/{scan_id}/cancel",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"


# ------------------------------------------------------------------------------
# 17. Overview & Findings Inventory Listing
# ------------------------------------------------------------------------------
def test_vulnerabilities_overview_and_inventory(client, owner_token):
    overview_res = client.get(
        "/api/v1/vulnerabilities/overview",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert overview_res.status_code == 200
    ov = overview_res.json()
    assert ov["total_findings"] >= 3
    assert ov["critical_count"] >= 1
    assert ov["kev_count"] >= 1
    assert "Critical" in ov["severity_distribution"]

    # Findings listing with filters
    findings_res = client.get(
        "/api/v1/vulnerabilities/findings?severity=Critical",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert findings_res.status_code == 200
    items = findings_res.json()["items"]
    for item in items:
        assert item["severity"] == "Critical"
