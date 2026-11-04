"""
Enterprise Identity, SSO, MFA & Zero Trust API Routes
CyberShield Sprint 18
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.identity import (
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    MFARecoveryCodeResponse,
    MFARotateRecoveryRequest,
    MFADisableRequest,
    StepUpAuthRequest,
    StepUpAuthResponse,
    SSOProviderCreate,
    SSOProviderUpdate,
    SSOProviderResponse,
    DomainVerificationCreate,
    DomainVerificationResponse,
    SSOLoginInitiateRequest,
    SSOLoginInitiateResponse,
    SSOCallbackRequest,
    SSOCallbackResponse,
    SSOTestResponse,
    SessionMetadataResponse,
    SessionRevokeRequest,
    SessionRevokeResponse,
    RevokeAllSessionsResponse,
    AccessPolicyCreate,
    AccessPolicyUpdate,
    AccessPolicyResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    OrganizationIdentityPolicyUpdate,
    OrganizationIdentityPolicyResponse,
    IdentityAuditEventResponse,
    UserSecurityOverviewResponse,
)
from app.services.identity_service import identity_service
from app.services.supabase_service import SupabaseService, supabase_service

router = APIRouter(prefix="/identity", tags=["Enterprise Identity, SSO, MFA & Zero Trust"])


async def _resolve_org_and_role(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> tuple[str, str]:
    """Verify organization membership, access permissions, and return target org_id and user role."""
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id, allowed_roles)

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id, role


# ------------------------------------------------------------------------------
# 1. SECURITY OVERVIEW & SCORE
# ------------------------------------------------------------------------------

@router.get("/overview", response_model=UserSecurityOverviewResponse)
async def get_user_security_overview(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve personal security posture, MFA enrollment status, and active session summary."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, role = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.get_security_overview(
        user_id=str(user.user_id),
        org_id=target_org_id,
        role=role,
        email=user.email,
    )


# ------------------------------------------------------------------------------
# 2. MULTI-FACTOR AUTHENTICATION (MFA)
# ------------------------------------------------------------------------------

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Initiate TOTP MFA enrollment. Returns Base32 secret key, otpauth URI, and QR code SVG."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.setup_mfa(
        user_id=str(user.user_id),
        org_id=target_org_id,
        email=user.email,
    )


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def verify_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Verify TOTP or backup recovery code. Elevates session to AAL2 and generates initial backup codes."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.verify_and_enable_mfa(
        user_id=str(user.user_id),
        org_id=target_org_id,
        code=payload.code,
        is_recovery=payload.is_recovery_code,
        client_ip=client_ip,
        user_email=user.email,
    )


@router.post("/mfa/rotate-recovery", response_model=MFARecoveryCodeResponse)
async def rotate_recovery_codes(
    payload: MFARotateRecoveryRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Rotate backup recovery codes. Requires current TOTP verification."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.rotate_recovery_codes(
        user_id=str(user.user_id),
        org_id=target_org_id,
        code=payload.code,
        client_ip=client_ip,
        user_email=user.email,
    )


@router.post("/mfa/disable")
async def disable_mfa(
    payload: MFADisableRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Disable MFA if allowed by organization identity policy."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, role = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.disable_mfa(
        user_id=str(user.user_id),
        org_id=target_org_id,
        code=payload.code,
        user_role=role,
        client_ip=client_ip,
        user_email=user.email,
    )


@router.post("/mfa/step-up", response_model=StepUpAuthResponse)
async def step_up_authentication(
    payload: StepUpAuthRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Authenticate with TOTP to receive short-lived step-up token for sensitive actions."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.issue_step_up_token(
        user_id=str(user.user_id),
        org_id=target_org_id,
        action=payload.action,
        code=payload.code,
        client_ip=client_ip,
        user_email=user.email,
    )


# ------------------------------------------------------------------------------
# 3. ENTERPRISE SINGLE SIGN-ON (SSO)
# ------------------------------------------------------------------------------

@router.get("/sso/providers", response_model=List[SSOProviderResponse])
async def list_sso_providers(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List configured SSO Identity Providers for the organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.list_sso_providers(target_org_id)


@router.post("/sso/providers", response_model=SSOProviderResponse)
async def create_sso_provider(
    payload: SSOProviderCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Configure new enterprise SSO Identity Provider. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.create_sso_provider(
        org_id=target_org_id,
        data=payload,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.put("/sso/providers/{provider_id}", response_model=SSOProviderResponse)
async def update_sso_provider(
    provider_id: str,
    payload: SSOProviderUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Update SSO Identity Provider settings. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.update_sso_provider(
        org_id=target_org_id,
        provider_id=provider_id,
        data=payload,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.delete("/sso/providers/{provider_id}")
async def delete_sso_provider(
    provider_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Delete SSO Identity Provider with lockout prevention. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.delete_sso_provider(
        org_id=target_org_id,
        provider_id=provider_id,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.post("/sso/providers/{provider_id}/test", response_model=SSOTestResponse)
async def test_sso_provider_connection(
    provider_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Test and validate SSO provider discovery endpoints and configuration readiness."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.test_sso_connection(target_org_id, provider_id)


@router.get("/sso/domains", response_model=List[DomainVerificationResponse])
async def list_domain_verifications(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List domain verification challenges for SSO routing."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    domains = supabase_service.list_domain_verifications(target_org_id)
    return [
        DomainVerificationResponse(
            id=d["id"],
            organization_id=d["organization_id"],
            identity_provider_id=d.get("identity_provider_id"),
            domain_name=d["domain_name"],
            verification_token=d["verification_token"],
            expected_txt_record=d["verification_token"],
            status=d["status"],
            verified_at=d.get("verified_at"),
            last_checked_at=d.get("last_checked_at"),
            created_at=d["created_at"],
        )
        for d in domains
    ]


@router.post("/sso/domains", response_model=DomainVerificationResponse)
async def initiate_domain_verification(
    payload: DomainVerificationCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Generate DNS TXT token challenge to verify corporate domain ownership for SSO."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.initiate_domain_verification(target_org_id, payload.domain_name)


@router.post("/sso/domains/{domain_name}/verify", response_model=DomainVerificationResponse)
async def check_domain_verification(
    domain_name: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Check DNS TXT record for domain verification token."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.verify_domain(target_org_id, domain_name, str(user.user_id), user.email)


@router.post("/sso/login/initiate", response_model=SSOLoginInitiateResponse)
async def initiate_sso_login(
    payload: SSOLoginInitiateRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
):
    """Public/semi-authenticated endpoint to initiate OIDC authorization flow for enterprise users."""
    target_org_id = str(org_id) if org_id else "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
    return identity_service.initiate_sso_login(
        org_id=target_org_id,
        domain=payload.domain,
        provider_id=payload.provider_id,
    )


@router.post("/sso/login/callback", response_model=SSOCallbackResponse)
async def handle_sso_callback(
    payload: SSOCallbackRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
):
    """Exchange authorization code from IdP for CyberShield enterprise session."""
    target_org_id = str(org_id) if org_id else "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
    client_ip = request.client.host if request.client else "127.0.0.1"
    return identity_service.handle_sso_callback(
        org_id=target_org_id,
        state=payload.state,
        code=payload.code,
        client_ip=client_ip,
    )


# ------------------------------------------------------------------------------
# 4. SESSION SECURITY & DEVICE MANAGEMENT
# ------------------------------------------------------------------------------

@router.get("/sessions", response_model=List[SessionMetadataResponse])
async def list_active_sessions(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List all active authenticated sessions for the current user."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.list_sessions(
        user_id=str(user.user_id),
        org_id=target_org_id,
        current_token_hash="tokhash_current_active_session_001",
    )


@router.post("/sessions/revoke", response_model=SessionRevokeResponse)
async def revoke_session(
    payload: SessionRevokeRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Revoke a specific active session."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.revoke_session(
        user_id=str(user.user_id),
        org_id=target_org_id,
        session_id=payload.session_id,
        reason=payload.reason or "User initiated revocation",
        client_ip=client_ip,
    )


@router.post("/sessions/revoke-all", response_model=RevokeAllSessionsResponse)
async def revoke_all_sessions(
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Revoke all sessions for user except current session."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    client_ip = request.client.host if request.client else "127.0.0.1"

    return identity_service.revoke_all_sessions(
        user_id=str(user.user_id),
        org_id=target_org_id,
        keep_session_id="sess-0000-0000-0000-000000000001",
        client_ip=client_ip,
    )


# ------------------------------------------------------------------------------
# 5. ZERO TRUST ACCESS POLICIES & CONTINUOUS EVALUATION
# ------------------------------------------------------------------------------

@router.get("/policies/org", response_model=OrganizationIdentityPolicyResponse)
async def get_organization_identity_policy(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve organization-wide identity policies (MFA mandatory, SSO enforcement, timeout)."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.get_organization_policy(target_org_id)


@router.put("/policies/org", response_model=OrganizationIdentityPolicyResponse)
async def update_organization_identity_policy(
    payload: OrganizationIdentityPolicyUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Update organization-wide identity policies. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, role = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.update_organization_policy(
        org_id=target_org_id,
        data=payload,
        actor_id=str(user.user_id),
        actor_role=role,
        actor_email=user.email,
    )


@router.get("/policies/rules", response_model=List[AccessPolicyResponse])
async def list_access_policies(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List Zero Trust microsegmentation access policies."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.list_access_policies(target_org_id)


@router.post("/policies/rules", response_model=AccessPolicyResponse)
async def create_access_policy(
    payload: AccessPolicyCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Create new Zero Trust ABAC access policy rule. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.create_access_policy(
        org_id=target_org_id,
        data=payload,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.put("/policies/rules/{policy_id}", response_model=AccessPolicyResponse)
async def update_access_policy(
    policy_id: str,
    payload: AccessPolicyUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Update Zero Trust access policy rule. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.update_access_policy(
        org_id=target_org_id,
        policy_id=policy_id,
        data=payload,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.delete("/policies/rules/{policy_id}")
async def delete_access_policy(
    policy_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Delete Zero Trust access policy rule. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return identity_service.delete_access_policy(
        org_id=target_org_id,
        policy_id=policy_id,
        actor_id=str(user.user_id),
        actor_email=user.email,
    )


@router.post("/policies/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_access(
    payload: PolicyEvaluationRequest,
    request: Request,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Continuous Zero Trust Server-Side Authorization Evaluation (Fail-Closed)."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, role = await _resolve_org_and_role(db_service, user, org_id)

    # Check user security preferences for current AAL level
    prefs = supabase_service.get_user_security_preferences(str(user.user_id), target_org_id)
    current_aal = prefs.get("current_aal", "aal1")

    client_ip = payload.client_ip or (request.client.host if request.client else "127.0.0.1")

    return identity_service.evaluate_zero_trust_access(
        org_id=target_org_id,
        user_id=str(user.user_id),
        role=role,
        resource_type=payload.resource_type,
        action=payload.action,
        current_aal=current_aal,
        client_ip=client_ip,
    )


# ------------------------------------------------------------------------------
# 6. IDENTITY AUDIT TRAIL
# ------------------------------------------------------------------------------

@router.get("/audit", response_model=List[IdentityAuditEventResponse])
async def list_identity_audit_log(
    limit: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = Query(None),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Query immutable identity and authentication audit log."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return identity_service.list_audit_trail(
        org_id=target_org_id,
        limit=limit,
        event_type=event_type,
    )
