import pytest
from app.services.scanner_base import DiscoveredHost, DiscoveredService
from app.services.supabase_service import SupabaseService
from app.workers.tasks import validate_scan_scope, run_authorized_discovery


# ------------------------------------------------------------------------------
# 1 & 2. Scope Validation: Invalid CIDR & Public Internet Rejection
# ------------------------------------------------------------------------------
def test_create_scope_invalid_cidr(client, owner_token):
    payload = {
        "scope_name": "Invalid Subnet Test",
        "cidr_range": "not-a-cidr-network",
        "authorization_basis": "Testing validation error",
    }
    response = client.post(
        "/api/v1/scopes",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 422


def test_create_scope_public_internet_rejected(client, owner_token):
    payload = {
        "scope_name": "Public Google DNS Scope",
        "cidr_range": "8.8.8.0/24",  # Public internet address
        "authorization_basis": "Unauthorized external attempt",
    }
    response = client.post(
        "/api/v1/scopes",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 422
    err_text = str(response.json())
    assert "public internet address" in err_text.lower()


def test_create_scope_valid_private_cidr(client, owner_token):
    payload = {
        "scope_name": "Authorized Branch Office",
        "cidr_range": "10.50.0.0/24",
        "authorization_basis": "Branch office security assessment authorization signed by IT Director",
        "max_scan_rate": 800,
        "expires_in_days": 60,
    }
    response = client.post(
        "/api/v1/scopes",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["scope_name"] == payload["scope_name"]
    assert data["cidr_range"] == payload["cidr_range"]
    assert data["authorization_status"] == "Pending"


# ------------------------------------------------------------------------------
# 3. Command Injection Attempt Prevention
# ------------------------------------------------------------------------------
def test_command_injection_rejected(client, owner_token):
    payload = {
        "scope_name": "Injection Test",
        "cidr_range": "192.168.1.1; cat /etc/passwd",
        "authorization_basis": "Testing shell injection protection",
    }
    response = client.post(
        "/api/v1/scopes",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 422


# ------------------------------------------------------------------------------
# 4 & 5. Scope Approval & RBAC Permissions
# ------------------------------------------------------------------------------
def test_viewer_cannot_create_or_approve_scope(client, viewer_token):
    # Viewer cannot create scope
    create_res = client.post(
        "/api/v1/scopes",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "scope_name": "Viewer Scope",
            "cidr_range": "192.168.20.0/24",
            "authorization_basis": "Viewer unauthorized attempt",
        },
    )
    assert create_res.status_code == 403

    # Viewer cannot approve scope
    approve_res = client.post(
        "/api/v1/scopes/55555555-5555-5555-5555-555555555555/approve",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert approve_res.status_code == 403


def test_owner_can_approve_scope(client, owner_token):
    response = client.post(
        "/api/v1/scopes/55555555-5555-5555-5555-555555555555/approve",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200
    assert response.json()["authorization_status"] == "Approved"


# ------------------------------------------------------------------------------
# 6 & 7. Scan Execution Against Approved vs Unapproved / Expired Scopes
# ------------------------------------------------------------------------------
def test_scan_unapproved_pending_scope_rejected(client, owner_token):
    # Scope 55555555 is Pending (if reset or before approval)
    # Testing unapproved scope error
    payload = {
        "title": "Unapproved Scope Scan",
        "type": "network_discovery",
        "target_scope": "172.16.50.0/24",
        "scope_id": "55555555-5555-5555-5555-555555555555",
    }
    # Reset status to Pending for test
    db = SupabaseService()
    for s in db._mock_db["scan_scopes"]:
        if s["id"] == "55555555-5555-5555-5555-555555555555":
            s["authorization_status"] = "Pending"

    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 403
    assert "Pending" in response.json()["detail"]


def test_scan_expired_scope_rejected(client, owner_token):
    payload = {
        "title": "Expired Scope Scan",
        "type": "network_discovery",
        "scope_id": "44444444-4444-4444-4444-444444444444",  # Expired in 2025
    }
    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 403
    assert "expired" in response.json()["detail"].lower()


def test_scan_approved_valid_scope_accepted(client, owner_token):
    payload = {
        "title": "Approved Production Discovery",
        "type": "network_discovery",
        "profile": "fast_discovery",
        "scope_id": "33333333-3333-3333-3333-333333333333",  # Core Production Subnet (Approved)
    }
    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] in ["queued", "running", "completed"]
    assert data["target_scope"] == "192.168.10.0/24"


# ------------------------------------------------------------------------------
# 8. Real-Time Scan Events Timeline API
# ------------------------------------------------------------------------------
def test_get_scan_events_timeline(client, owner_token):
    # Launch scan
    create_res = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "title": "Timeline Test Scan",
            "type": "network_discovery",
            "scope_id": "33333333-3333-3333-3333-333333333333",
        },
    )
    scan_id = create_res.json()["id"]

    events_res = client.get(
        f"/api/v1/scans/{scan_id}/events",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert events_res.status_code == 200
    events = events_res.json()
    assert len(events) >= 1
    assert "authorized" in events[0]["event_type"] or "completed" in events[-1]["event_type"]


# ------------------------------------------------------------------------------
# 9. Celery Worker Scope Re-validation & Safe Asset Synchronization
# ------------------------------------------------------------------------------
def test_worker_pre_execution_scope_check():
    # Valid scope
    assert validate_scan_scope("33333333-3333-3333-3333-333333333333", "e4a29a43-089c-4f70-a889-cb4c5b36dc32") is True
    # Expired scope
    assert validate_scan_scope("44444444-4444-4444-4444-444444444444", "e4a29a43-089c-4f70-a889-cb4c5b36dc32") is False


def test_asset_synchronization_preserves_manual_metadata():
    import asyncio
    db = SupabaseService()
    org_id = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"

    # Pre-existing manual asset
    existing = next(a for a in db._mock_db["assets"] if a["ip_address"] == "192.168.10.1")
    manual_desc = existing["description"]
    manual_risk = existing["risk_level"]

    # Discovered host with same IP
    discovered = DiscoveredHost(
        ip_address="192.168.10.1",
        hostname="discovered-gw.internal",
        mac_address="00:1A:2B:44:88:01",
        status="up",
        os_name="Cisco IOS 15.2",
        services=[DiscoveredService(port=80, protocol="tcp", name="http", state="open")],
    )

    asyncio.run(db.synchronize_discovered_host(org_id, discovered))

    # Re-verify that existing manual notes were preserved
    updated_asset = next(a for a in db._mock_db["assets"] if a["ip_address"] == "192.168.10.1")
    assert updated_asset["description"] == manual_desc
    assert updated_asset["risk_level"] == manual_risk
    assert updated_asset["status"] == "Active"
