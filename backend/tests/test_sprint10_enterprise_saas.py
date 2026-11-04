import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from app.core.config import settings
from tests.conftest import create_test_token

APEX_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
OWNER_ID = "00000000-0000-0000-0000-000000000001"
VIEWER_ID = "00000000-0000-0000-0000-000000000002"
OWNER_MEMBER_ID = "f5b39a43-089c-4f70-a889-cb4c5b36dc33"
VIEWER_MEMBER_ID = "a1b2c3d4-089c-4f70-a889-cb4c5b36dc44"


@pytest.fixture
def auth_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def view_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture
def platform_admin_headers():
    token = create_test_token(
        user_id="99999999-9999-9999-9999-999999999999",
        email="platform.admin@cybershield.io",
    )
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------------------
# 1. Organization Management & Multi-Tenancy
# ------------------------------------------------------------------------------
def test_list_and_create_organization(client: TestClient, auth_headers):
    # List organizations user belongs to
    res = client.get("/api/v1/organizations", headers=auth_headers)
    assert res.status_code == 200
    orgs = res.json()
    assert len(orgs) >= 1
    assert any(o["id"] == APEX_ORG_ID for o in orgs)

    # Create a new organization tenant workspace
    new_org_payload = {
        "name": "Sentinel Cyber Command",
        "description": "Distributed Security Operations Node",
        "website": "https://sentinel.internal",
        "industry": "Defense & Aerospace",
        "organization_size": "250-1000 employees",
    }
    create_res = client.post("/api/v1/organizations", json=new_org_payload, headers=auth_headers)
    assert create_res.status_code == 201
    created_org = create_res.json()
    assert created_org["name"] == "Sentinel Cyber Command"
    assert created_org["member_count"] == 1
    assert created_org["status"] == "Active"

    # Switch active context to the new organization
    switch_res = client.post(
        f"/api/v1/organizations/{created_org['id']}/switch",
        headers=auth_headers,
    )
    assert switch_res.status_code == 200
    assert switch_res.json()["id"] == created_org["id"]


def test_tenant_rbac_update_organization(client: TestClient, auth_headers, view_headers):
    # Viewer should be forbidden from updating organization settings
    patch_payload = {"description": "Unauthorized malicious update"}
    res_forbidden = client.patch(
        f"/api/v1/organizations/{APEX_ORG_ID}",
        json=patch_payload,
        headers=view_headers,
    )
    assert res_forbidden.status_code == 403

    # Owner should be authorized to update
    valid_patch = {"description": "Apex CyberDefense - Hardened Tier 3 Operations"}
    res_ok = client.patch(
        f"/api/v1/organizations/{APEX_ORG_ID}",
        json=valid_patch,
        headers=auth_headers,
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["description"] == "Apex CyberDefense - Hardened Tier 3 Operations"


# ------------------------------------------------------------------------------
# 2. Team Management & Last Owner Protection
# ------------------------------------------------------------------------------
def test_team_members_and_last_owner_protection(client: TestClient, auth_headers, view_headers):
    # List members
    res = client.get(f"/api/v1/team/members?org_id={APEX_ORG_ID}", headers=auth_headers)
    assert res.status_code == 200
    members = res.json()
    assert len(members) >= 2

    # Attempt to demote sole owner to viewer - MUST BE REJECTED
    demote_res = client.patch(
        f"/api/v1/team/members/{OWNER_MEMBER_ID}/role?org_id={APEX_ORG_ID}",
        json={"role": "viewer"},
        headers=auth_headers,
    )
    assert demote_res.status_code == 400
    assert "Cannot demote the last organization owner" in demote_res.json()["detail"]

    # Attempt to remove sole owner - MUST BE REJECTED
    remove_res = client.delete(
        f"/api/v1/team/members/{OWNER_MEMBER_ID}?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert remove_res.status_code == 400
    assert "Cannot remove the last organization owner" in remove_res.json()["detail"]

    # Update viewer member role to analyst
    upgrade_res = client.patch(
        f"/api/v1/team/members/{VIEWER_MEMBER_ID}/role?org_id={APEX_ORG_ID}",
        json={"role": "analyst"},
        headers=auth_headers,
    )
    assert upgrade_res.status_code == 200
    assert upgrade_res.json()["role"] == "analyst"

    # Reset back to viewer so other test suites maintain viewer role isolation
    reset_res = client.patch(
        f"/api/v1/team/members/{VIEWER_MEMBER_ID}/role?org_id={APEX_ORG_ID}",
        json={"role": "viewer"},
        headers=auth_headers,
    )
    assert reset_res.status_code == 200


# ------------------------------------------------------------------------------
# 3. Team Invitations Lifecycle & Quotas
# ------------------------------------------------------------------------------
def test_team_invitations_lifecycle(client: TestClient, auth_headers):
    unique_email = f"analyst.{uuid4().hex[:6]}@apexcyberdefense.io"

    # 1. Create invitation
    invite_res = client.post(
        f"/api/v1/team/invitations?org_id={APEX_ORG_ID}",
        json={"email": unique_email, "role": "analyst"},
        headers=auth_headers,
    )
    assert invite_res.status_code == 201
    inv = invite_res.json()
    assert inv["email"] == unique_email
    assert inv["status"] == "Pending"
    inv_id = inv["id"]

    # 2. Duplicate invitation should be rejected
    dup_res = client.post(
        f"/api/v1/team/invitations?org_id={APEX_ORG_ID}",
        json={"email": unique_email, "role": "analyst"},
        headers=auth_headers,
    )
    assert dup_res.status_code == 400
    assert "active invitation already exists" in dup_res.json()["detail"]

    # 3. Resend invitation (refreshes expiry)
    resend_res = client.post(
        f"/api/v1/team/invitations/{inv_id}/resend?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert resend_res.status_code == 200
    assert resend_res.json()["status"] == "Pending"

    # 4. Cancel invitation
    cancel_res = client.delete(
        f"/api/v1/team/invitations/{inv_id}?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert cancel_res.status_code == 200


# ------------------------------------------------------------------------------
# 4. Subscription Plans, Quotas & Metered Usage
# ------------------------------------------------------------------------------
def test_subscription_plans_and_usage(client: TestClient, auth_headers):
    # List available plans
    plans_res = client.get("/api/v1/subscriptions/plans")
    assert plans_res.status_code == 200
    plans = plans_res.json()
    assert len(plans) >= 3
    plan_codes = [p["plan_code"] for p in plans]
    assert "FREE" in plan_codes
    assert "PROFESSIONAL" in plan_codes
    assert "ENTERPRISE" in plan_codes

    # Get active organization subscription
    sub_res = client.get(
        f"/api/v1/subscriptions/current?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert sub_res.status_code == 200
    sub = sub_res.json()
    assert sub["status"] == "Active"

    # Get usage metrics against plan quotas
    usage_res = client.get(
        f"/api/v1/subscriptions/usage?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert usage_res.status_code == 200
    usage = usage_res.json()
    assert "assets_used" in usage
    assert "assets_limit" in usage
    assert "members_used" in usage
    assert "monthly_scans_used" in usage
    assert "ai_requests_used" in usage

    # Checkout plan upgrade
    checkout_res = client.post(
        f"/api/v1/subscriptions/checkout?org_id={APEX_ORG_ID}",
        json={"plan_code": "ENTERPRISE", "billing_interval": "monthly"},
        headers=auth_headers,
    )
    assert checkout_res.status_code == 200
    checkout_data = checkout_res.json()
    assert checkout_data["subscription"]["plan_code"] == "ENTERPRISE"
    assert "checkout_url" in checkout_data

    # Cancel auto-renewal
    cancel_res = client.post(
        f"/api/v1/subscriptions/cancel?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["cancel_at_period_end"] is True


def test_billing_webhook_processing(client: TestClient):
    # Webhook with valid mock signature
    payload = {
        "event": "subscription.activated",
        "organization_id": APEX_ORG_ID,
        "plan_code": "PROFESSIONAL",
    }
    headers = {"X-Webhook-Signature": "mock_valid_sig"}
    res = client.post("/api/v1/subscriptions/webhook", json=payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "processed"

    # Webhook with invalid signature
    bad_headers = {"X-Webhook-Signature": "invalid_sig_xyz"}
    bad_res = client.post("/api/v1/subscriptions/webhook", json=payload, headers=bad_headers)
    assert bad_res.status_code == 401


# ------------------------------------------------------------------------------
# 5. API Key Management
# ------------------------------------------------------------------------------
def test_api_key_lifecycle(client: TestClient, auth_headers, view_headers):
    # Viewer forbidden from managing API keys
    key_payload = {"key_name": "SOC Test Key", "scopes": ["read:assets"]}
    res_forbidden = client.post(
        f"/api/v1/api-keys?org_id={APEX_ORG_ID}",
        json=key_payload,
        headers=view_headers,
    )
    assert res_forbidden.status_code == 403

    # Owner creates API Key
    create_res = client.post(
        f"/api/v1/api-keys?org_id={APEX_ORG_ID}",
        json=key_payload,
        headers=auth_headers,
    )
    assert create_res.status_code == 201
    key_data = create_res.json()
    assert "raw_api_key" in key_data
    assert key_data["raw_api_key"].startswith("cs_live_")
    key_id = key_data["id"]

    # List API Keys - raw_api_key and hash MUST NOT be exposed
    list_res = client.get(f"/api/v1/api-keys?org_id={APEX_ORG_ID}", headers=auth_headers)
    assert list_res.status_code == 200
    keys = list_res.json()
    match = next(k for k in keys if k["id"] == key_id)
    assert "raw_api_key" not in match
    assert "key_hash" not in match
    assert match["key_prefix"].startswith("cs_live_")

    # Rotate API Key
    rotate_res = client.post(
        f"/api/v1/api-keys/{key_id}/rotate?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert rotate_res.status_code == 200
    rotated_key = rotate_res.json()
    assert "raw_api_key" in rotated_key
    assert rotated_key["id"] != key_id

    # Revoke original key
    revoke_res = client.delete(
        f"/api/v1/api-keys/{key_id}?org_id={APEX_ORG_ID}",
        headers=auth_headers,
    )
    assert revoke_res.status_code == 200


# ------------------------------------------------------------------------------
# 6. Platform Admin Operations & Organization Suspension
# ------------------------------------------------------------------------------
def test_platform_admin_separation_and_suspension(
    client: TestClient, view_headers, platform_admin_headers
):
    # Regular tenant viewer CANNOT access platform admin control center
    res_forbidden = client.get("/api/v1/platform-admin/overview", headers=view_headers)
    assert res_forbidden.status_code == 403
    assert "Platform Administrator access required" in res_forbidden.json()["detail"]

    # Platform Administrator can access overview
    overview_res = client.get("/api/v1/platform-admin/overview", headers=platform_admin_headers)
    assert overview_res.status_code == 200
    overview = overview_res.json()
    assert overview["total_organizations"] >= 1
    assert overview["db_connectivity"] == "Connected"
    assert overview["background_worker_health"] == "Operational"

    # Platform Admin lists all cross-tenant organizations
    orgs_res = client.get("/api/v1/platform-admin/organizations", headers=platform_admin_headers)
    assert orgs_res.status_code == 200
    assert len(orgs_res.json()) >= 1

    # Platform Admin lists platform users
    users_res = client.get("/api/v1/platform-admin/users", headers=platform_admin_headers)
    assert users_res.status_code == 200
    assert len(users_res.json()) >= 1

    # Suspend organization
    suspend_res = client.post(
        f"/api/v1/platform-admin/organizations/{APEX_ORG_ID}/suspend",
        json={"reason": "Security audit non-compliance hold"},
        headers=platform_admin_headers,
    )
    assert suspend_res.status_code == 200
    suspended_org = suspend_res.json()
    assert suspended_org["status"] == "Suspended"
    assert suspended_org["suspension_reason"] == "Security audit non-compliance hold"

    # Reactivate organization
    reactivate_res = client.post(
        f"/api/v1/platform-admin/organizations/{APEX_ORG_ID}/reactivate",
        headers=platform_admin_headers,
    )
    assert reactivate_res.status_code == 200
    assert reactivate_res.json()["status"] == "Active"
    assert reactivate_res.json()["suspension_reason"] is None
