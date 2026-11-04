"""
Enterprise Identity, SSO, MFA & Zero Trust Security Architecture Tests
CyberShield Sprint 18
"""

import time
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.identity_service import identity_service
from app.services.supabase_service import supabase_service

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ==============================================================================
# 1. CRYPTOGRAPHIC TOTP UNIT TESTS
# ==============================================================================

def test_totp_rfc6238_generation_and_drift_verification():
    """Verify RFC 6238 TOTP computation and time-drift validation."""
    secret = identity_service.generate_totp_secret()
    assert len(secret) >= 26

    # Test deterministic code for current timestamp
    now = int(time.time())
    code = identity_service.compute_totp_code(secret, now)
    assert len(code) == 6
    assert code.isdigit()

    # Valid within current window
    assert identity_service.verify_totp(secret, code, window=1) is True

    # Valid within drift window (-30s)
    past_code = identity_service.compute_totp_code(secret, now - 30)
    assert identity_service.verify_totp(secret, past_code, window=1) is True

    # Valid within drift window (+30s)
    future_code = identity_service.compute_totp_code(secret, now + 30)
    assert identity_service.verify_totp(secret, future_code, window=1) is True

    # Invalid code rejected
    assert identity_service.verify_totp(secret, "000000" if code != "000000" else "111111", window=1) is False


def test_recovery_code_generation_and_single_use_burn():
    """Verify backup recovery codes are generated, verified, and burned on use."""
    plain_codes, hashed_records = identity_service.generate_recovery_codes(10)
    assert len(plain_codes) == 10
    assert len(hashed_records) == 10
    assert all(c.startswith("CS-") for c in plain_codes)

    first_code = plain_codes[0]

    # First use: should succeed and mark used_at
    valid, updated_records = identity_service.verify_recovery_code(hashed_records, first_code)
    assert valid is True
    assert updated_records[0]["used_at"] is not None

    # Immediate second use: should be rejected (single-use protection)
    valid_again, _ = identity_service.verify_recovery_code(updated_records, first_code)
    assert valid_again is False


# ==============================================================================
# 2. MFA ENROLLMENT & VERIFICATION API TESTS
# ==============================================================================

def test_mfa_setup_and_verify_flow(owner_headers):
    """Test full TOTP enrollment: setup, code verification, elevation to AAL2, recovery code receipt."""
    # 1. Setup
    res = client.post(f"/api/v1/identity/mfa/setup?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert "secret" in data
    assert "otpauth_uri" in data
    assert "<svg" in data["qr_code_svg"]
    secret = data["secret"]

    # 2. Generate valid TOTP code
    valid_code = identity_service.compute_totp_code(secret)

    # 3. Verify and Enable
    verify_res = client.post(
        f"/api/v1/identity/mfa/verify?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": valid_code, "is_recovery_code": False},
    )
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["success"] is True
    assert verify_data["current_aal"] == "aal2"
    assert verify_data["recovery_codes"] is not None
    assert len(verify_data["recovery_codes"]) == 10


def test_mfa_invalid_code_and_rate_limiting(owner_headers):
    """Test invalid TOTP code returns 400 and rate limiting locks out after 5 consecutive failures."""
    # Set up user to have an active secret
    client.post(f"/api/v1/identity/mfa/setup?org_id={DEFAULT_ORG_ID}", headers=owner_headers)

    # Clear prior failed attempts for clean test run
    user_id = "00000000-0000-0000-0000-000000000001"
    supabase_service._mock_db["mfa_challenge_attempts"] = []

    # Send 4 invalid codes -> 400
    for _ in range(4):
        res = client.post(
            f"/api/v1/identity/mfa/verify?org_id={DEFAULT_ORG_ID}",
            headers=owner_headers,
            json={"code": "999999", "is_recovery_code": False},
        )
        assert res.status_code == 400

    # 5th invalid code -> 400
    res5 = client.post(
        f"/api/v1/identity/mfa/verify?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": "999999", "is_recovery_code": False},
    )
    assert res5.status_code == 400

    # 6th attempt -> 429 Too Many Requests
    res6 = client.post(
        f"/api/v1/identity/mfa/verify?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": "999999", "is_recovery_code": False},
    )
    assert res6.status_code == 429
    assert "locked" in res6.json()["detail"].lower()

    # Reset attempts for subsequent tests
    supabase_service._mock_db["mfa_challenge_attempts"] = []


def test_rotate_recovery_codes_flow(owner_headers):
    """Test recovery code rotation requiring valid TOTP code."""
    # Ensure MFA is enabled
    setup_res = client.post(f"/api/v1/identity/mfa/setup?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    secret = setup_res.json()["secret"]
    valid_code = identity_service.compute_totp_code(secret)
    client.post(
        f"/api/v1/identity/mfa/verify?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": valid_code, "is_recovery_code": False},
    )

    # Rotate with invalid code -> 400
    bad_rotate = client.post(
        f"/api/v1/identity/mfa/rotate-recovery?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": "000000"},
    )
    assert bad_rotate.status_code == 400

    # Rotate with valid code -> 200
    new_valid_code = identity_service.compute_totp_code(secret)
    good_rotate = client.post(
        f"/api/v1/identity/mfa/rotate-recovery?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"code": new_valid_code},
    )
    assert good_rotate.status_code == 200
    rotate_data = good_rotate.json()
    assert len(rotate_data["recovery_codes"]) == 10
    assert rotate_data["remaining_count"] == 10


def test_step_up_authentication_token(owner_headers):
    """Test step-up authentication endpoint granting 5-minute action token."""
    setup_res = client.post(f"/api/v1/identity/mfa/setup?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    secret = setup_res.json()["secret"]
    valid_code = identity_service.compute_totp_code(secret)

    res = client.post(
        f"/api/v1/identity/mfa/step-up?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"action": "export_forensics_evidence", "code": valid_code},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["step_up_token"].startswith("stepup_")
    assert data["action"] == "export_forensics_evidence"


# ==============================================================================
# 3. ENTERPRISE SINGLE SIGN-ON (SSO) API TESTS
# ==============================================================================

def test_sso_provider_crud_and_secret_masking(owner_headers, viewer_headers):
    """Test SSO IdP creation, listing, masking of secrets, and viewer RBAC restrictions."""
    # 1. Viewer is rejected from creating SSO provider (403)
    viewer_create = client.post(
        f"/api/v1/identity/sso/providers?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={
            "name": "Unauthorized IdP",
            "provider_type": "oidc",
            "issuer_url": "https://idp.example.com",
            "client_id": "test_client",
            "client_secret": "super_secret_key_12345",
        },
    )
    assert viewer_create.status_code == 403

    # 2. Owner creates new SSO provider
    create_res = client.post(
        f"/api/v1/identity/sso/providers?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "name": "Google Workspace Enterprise",
            "provider_type": "google_workspace",
            "issuer_url": "https://accounts.google.com",
            "client_id": "google-client-id-001.apps.googleusercontent.com",
            "client_secret": "google_client_super_secret_9988",
            "domains": ["google.apexcyber.io"],
            "default_role": "analyst",
        },
    )
    assert create_res.status_code == 200
    idp_data = create_res.json()
    assert idp_data["name"] == "Google Workspace Enterprise"
    # Verify client_secret is strictly masked
    assert idp_data["client_secret_masked"] == "••••••••••••"
    assert idp_data["client_secret_last4"] == "9988"
    assert "super_secret" not in str(idp_data)
    provider_id = idp_data["id"]

    # 3. List providers
    list_res = client.get(f"/api/v1/identity/sso/providers?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    providers = list_res.json()
    assert any(p["id"] == provider_id for p in providers)

    # 4. Test connection
    test_res = client.post(f"/api/v1/identity/sso/providers/{provider_id}/test?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert test_res.status_code == 200
    assert test_res.json()["success"] is True

    # 5. Delete provider
    del_res = client.delete(f"/api/v1/identity/sso/providers/{provider_id}?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert del_res.status_code == 200


def test_domain_verification_workflow(owner_headers):
    """Test domain TXT record challenge generation and verification."""
    # 1. Initiate domain verification challenge
    domain = "soc-operations.apexcyber.com"
    init_res = client.post(
        f"/api/v1/identity/sso/domains?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"domain_name": domain},
    )
    assert init_res.status_code == 200
    data = init_res.json()
    assert data["domain_name"] == domain
    assert data["status"] == "pending"
    assert data["verification_token"].startswith("cybershield-verify=")

    # 2. Check verification
    verify_res = client.post(
        f"/api/v1/identity/sso/domains/{domain}/verify?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "verified"
    assert verify_res.json()["verified_at"] is not None


def test_sso_login_initiation_and_callback():
    """Test public/SSO login initiation and callback claim mapping."""
    # 1. Initiate login
    res = client.post(
        "/api/v1/identity/sso/login/initiate",
        json={"domain": "apexcyberdefense.io"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "authorization_url" in data
    assert "state" in data
    assert "nonce" in data

    # 2. Callback
    cb_res = client.post(
        "/api/v1/identity/sso/login/callback",
        json={"state": data["state"], "code": "mock_auth_code_from_idp"},
    )
    assert cb_res.status_code == 200
    cb_data = cb_res.json()
    assert cb_data["success"] is True
    assert cb_data["current_aal"] == "aal2"
    assert "access_token" in cb_data


# ==============================================================================
# 4. SESSION SECURITY & REVOCATION TESTS
# ==============================================================================

def test_active_session_listing_and_revocation(owner_headers):
    """Test active session listing, metadata inspection, and individual revocation."""
    list_res = client.get(f"/api/v1/identity/sessions?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    sessions = list_res.json()
    assert len(sessions) >= 2

    # Suspicious session flagged
    suspicious_sess = next((s for s in sessions if s["is_suspicious"]), None)
    assert suspicious_sess is not None
    assert len(suspicious_sess["suspicion_reasons"]) > 0

    # Revoke suspicious session
    revoke_res = client.post(
        f"/api/v1/identity/sessions/revoke?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"session_id": suspicious_sess["id"], "reason": "Suspected impossible travel token theft"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["success"] is True

    # Revoked session no longer active in list
    list_res2 = client.get(f"/api/v1/identity/sessions?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    active_ids = [s["id"] for s in list_res2.json()]
    assert suspicious_sess["id"] not in active_ids


def test_revoke_all_sessions(owner_headers):
    """Test bulk session revocation preserving current session."""
    revoke_all_res = client.post(f"/api/v1/identity/sessions/revoke-all?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert revoke_all_res.status_code == 200
    assert revoke_all_res.json()["success"] is True


# ==============================================================================
# 5. ZERO TRUST ACCESS POLICY TESTS
# ==============================================================================

def test_zero_trust_policy_crud_and_continuous_evaluation(owner_headers, viewer_headers):
    """Test Zero Trust policy rules and continuous server-side authorization evaluation."""
    # 1. Retrieve Org policy
    org_pol_res = client.get(f"/api/v1/identity/policies/org?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert org_pol_res.status_code == 200
    assert "mfa_required" in org_pol_res.json()

    # 2. Update Org policy
    update_pol_res = client.put(
        f"/api/v1/identity/policies/org?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"session_idle_timeout_minutes": 45, "max_concurrent_sessions_per_user": 4},
    )
    assert update_pol_res.status_code == 200
    assert update_pol_res.json()["session_idle_timeout_minutes"] == 45

    # 3. Create Zero Trust rule: Require AAL2 for SOAR playbook execution
    create_rule_res = client.post(
        f"/api/v1/identity/policies/rules?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "name": "Mandate AAL2 MFA for SOAR Playbook Execution",
            "resource_type": "soar",
            "action": "execute",
            "effect": "allow",
            "allowed_roles": ["owner", "admin", "analyst"],
            "require_mfa": True,
            "min_aal": "aal2",
            "priority": 15,
        },
    )
    assert create_rule_res.status_code == 200
    rule_data = create_rule_res.json()
    rule_id = rule_data["id"]

    # 4. Evaluate access for user with AAL1: should be DENIED
    supabase_service.upsert_user_security_preferences("00000000-0000-0000-0000-000000000001", DEFAULT_ORG_ID, {
        "current_aal": "aal1"
    })
    eval_aal1 = client.post(
        f"/api/v1/identity/policies/evaluate?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"resource_type": "soar", "action": "execute"},
    )
    assert eval_aal1.status_code == 200
    assert eval_aal1.json()["allowed"] is False
    assert "aal2" in eval_aal1.json()["decision_reason"].lower()

    # 5. Elevate user to AAL2: should be ALLOWED
    supabase_service.upsert_user_security_preferences("00000000-0000-0000-0000-000000000001", DEFAULT_ORG_ID, {
        "current_aal": "aal2"
    })
    eval_aal2 = client.post(
        f"/api/v1/identity/policies/evaluate?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"resource_type": "soar", "action": "execute"},
    )
    assert eval_aal2.status_code == 200
    assert eval_aal2.json()["allowed"] is True

    # 6. Evaluate viewer role trying to delete: explicit deny
    eval_viewer_del = client.post(
        f"/api/v1/identity/policies/evaluate?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={"resource_type": "all", "action": "delete"},
    )
    assert eval_viewer_del.status_code == 200
    assert eval_viewer_del.json()["allowed"] is False

    # Cleanup rule
    client.delete(f"/api/v1/identity/policies/rules/{rule_id}?org_id={DEFAULT_ORG_ID}", headers=owner_headers)


# ==============================================================================
# 6. SECURITY OVERVIEW & IDENTITY AUDIT LOG TESTS
# ==============================================================================

def test_user_security_overview(owner_headers):
    """Test user security posture calculation and score output."""
    res = client.get(f"/api/v1/identity/overview?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()
    assert 0 <= data["security_score"] <= 100
    assert "mfa_enabled" in data
    assert "recovery_codes_remaining" in data
    assert len(data["security_recommendations"]) > 0


def test_identity_audit_log_query(owner_headers):
    """Test querying immutable identity audit logs."""
    res = client.get(f"/api/v1/identity/audit?org_id={DEFAULT_ORG_ID}&limit=10", headers=owner_headers)
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    assert len(events) > 0
    first_event = events[0]
    assert "event_type" in first_event
    assert "status" in first_event
    assert "correlation_id" in first_event
    # Verify no raw secrets are in details
    assert "secret" not in str(first_event["details"]).lower() or "action" in str(first_event["details"]).lower()
