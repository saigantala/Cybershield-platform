"""
Identity, SSO, MFA & Zero Trust Schemas
CyberShield Sprint 18
"""

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

AALLevel = Literal["aal1", "aal2"]
MFAFactorType = Literal["totp", "recovery_code", "webauthn"]
SSOProviderType = Literal["oidc", "saml2", "azure_ad", "okta", "google_workspace"]
DeviceType = Literal["desktop", "mobile", "tablet", "api_client", "unknown"]
RoleType = Literal["owner", "admin", "analyst", "viewer"]
ResourceType = Literal[
    "all", "assets", "vulnerabilities", "incidents", "soar",
    "threat_hunting", "forensics", "api_keys", "settings", "sso", "billing"
]
ActionType = Literal["all", "read", "write", "execute", "export", "delete", "admin"]
PolicyEffect = Literal["allow", "deny"]
DomainVerificationStatus = Literal["pending", "verified", "failed"]

# ------------------------------------------------------------------------------
# 1. MULTI-FACTOR AUTHENTICATION (MFA)
# ------------------------------------------------------------------------------

class MFASetupResponse(BaseModel):
    secret: str = Field(..., description="Base32 TOTP secret key for manual entry")
    otpauth_uri: str = Field(..., description="Standard otpauth:// URI for authenticator apps")
    qr_code_svg: str = Field(..., description="SVG format rendering of the QR code")
    issuer: str = "CyberShield SOC"
    account_name: str
    message: str = "Scan this QR code with an authenticator app (Google Authenticator, 1Password, etc.)"

class MFAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=10, description="6-digit TOTP code or backup code")
    is_recovery_code: bool = Field(default=False, description="Flag indicating if the code is a backup recovery code")

class MFAVerifyResponse(BaseModel):
    success: bool
    current_aal: AALLevel
    message: str
    recovery_codes: Optional[List[str]] = Field(default=None, description="Generated single-use backup recovery codes (provided on initial setup)")
    token: Optional[str] = None

class MFARecoveryCodeResponse(BaseModel):
    recovery_codes: List[str]
    generated_at: str
    remaining_count: int
    note: str = "Store these recovery codes in a secure vault. Each code can only be used once."

class MFARotateRecoveryRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=10, description="Current TOTP 6-digit verification code to confirm rotation")

class StepUpAuthRequest(BaseModel):
    action: str = Field(..., description="The sensitive action being authorized (e.g. export_evidence, change_ownership, rotate_api_key)")
    code: str = Field(..., min_length=6, max_length=10, description="6-digit TOTP verification code")

class StepUpAuthResponse(BaseModel):
    success: bool
    step_up_token: str
    action: str
    expires_at: str
    message: str

class MFADisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=10, description="6-digit TOTP verification code to confirm disabling MFA")

# ------------------------------------------------------------------------------
# 2. ENTERPRISE SINGLE SIGN-ON (SSO / OIDC / SAML)
# ------------------------------------------------------------------------------

class SSOProviderCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider_type: SSOProviderType
    issuer_url: str = Field(..., min_length=8)
    client_id: str = Field(..., min_length=2)
    client_secret: Optional[str] = Field(None, min_length=8)
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    saml_metadata_url: Optional[str] = None
    saml_entity_id: Optional[str] = None
    saml_acs_url: Optional[str] = None
    saml_certificate: Optional[str] = None
    domains: List[str] = Field(default_factory=list)
    enforce_sso: bool = False
    sync_profile_attributes: bool = True
    default_role: RoleType = "analyst"

class SSOProviderUpdate(BaseModel):
    name: Optional[str] = None
    provider_type: Optional[SSOProviderType] = None
    issuer_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    saml_metadata_url: Optional[str] = None
    saml_entity_id: Optional[str] = None
    saml_acs_url: Optional[str] = None
    saml_certificate: Optional[str] = None
    domains: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    enforce_sso: Optional[bool] = None
    sync_profile_attributes: Optional[bool] = None
    default_role: Optional[RoleType] = None

class SSOProviderResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    provider_type: SSOProviderType
    issuer_url: str
    client_id: str
    client_secret_masked: str = "••••••••••••"
    client_secret_last4: Optional[str] = None
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    saml_metadata_url: Optional[str] = None
    saml_entity_id: Optional[str] = None
    saml_acs_url: Optional[str] = None
    domains: List[str]
    is_enabled: bool
    enforce_sso: bool
    sync_profile_attributes: bool
    default_role: RoleType
    created_at: str
    updated_at: str

class DomainVerificationCreate(BaseModel):
    domain_name: str = Field(..., min_length=3, description="FQDN e.g. company.com")

class DomainVerificationResponse(BaseModel):
    id: str
    organization_id: str
    identity_provider_id: Optional[str] = None
    domain_name: str
    verification_token: str
    expected_txt_record: str
    status: DomainVerificationStatus
    verified_at: Optional[str] = None
    last_checked_at: Optional[str] = None
    created_at: str

class SSOLoginInitiateRequest(BaseModel):
    domain: Optional[str] = None
    provider_id: Optional[str] = None
    redirect_uri: Optional[str] = None

class SSOLoginInitiateResponse(BaseModel):
    authorization_url: str
    state: str
    nonce: str
    provider_id: str

class SSOCallbackRequest(BaseModel):
    state: str
    code: str
    error: Optional[str] = None

class SSOCallbackResponse(BaseModel):
    success: bool
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    current_aal: AALLevel
    user: Dict[str, Any]

class SSOTestResponse(BaseModel):
    success: bool
    provider_name: str
    discovery_status: str
    message: str
    details: Dict[str, Any]

# ------------------------------------------------------------------------------
# 3. SESSION MANAGEMENT
# ------------------------------------------------------------------------------

class SessionMetadataResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str
    device_type: DeviceType
    browser: Optional[str]
    os: Optional[str]
    ip_address: str
    approx_location: Optional[str]
    is_suspicious: bool = False
    suspicion_reasons: List[str] = Field(default_factory=list)
    aal_level: AALLevel
    created_at: str
    last_active_at: str
    expires_at: str
    is_current: bool = False

class SessionRevokeRequest(BaseModel):
    session_id: str
    reason: Optional[str] = "User requested revocation"

class SessionRevokeResponse(BaseModel):
    success: bool
    revoked_session_id: str
    message: str

class RevokeAllSessionsResponse(BaseModel):
    success: bool
    revoked_count: int
    message: str

# ------------------------------------------------------------------------------
# 4. ZERO TRUST ACCESS POLICIES (ABAC)
# ------------------------------------------------------------------------------

class AccessPolicyCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: Optional[str] = None
    resource_type: ResourceType = "all"
    action: ActionType = "all"
    effect: PolicyEffect = "allow"
    allowed_roles: List[RoleType] = Field(default_factory=lambda: ["owner", "admin", "analyst", "viewer"])
    require_mfa: bool = False
    min_aal: AALLevel = "aal1"
    ip_whitelist: List[str] = Field(default_factory=list)
    is_enabled: bool = True
    priority: int = 100

class AccessPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    resource_type: Optional[ResourceType] = None
    action: Optional[ActionType] = None
    effect: Optional[PolicyEffect] = None
    allowed_roles: Optional[List[RoleType]] = None
    require_mfa: Optional[bool] = None
    min_aal: Optional[AALLevel] = None
    ip_whitelist: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    priority: Optional[int] = None

class AccessPolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: Optional[str]
    resource_type: ResourceType
    action: ActionType
    effect: PolicyEffect
    allowed_roles: List[RoleType]
    require_mfa: bool
    min_aal: AALLevel
    ip_whitelist: List[str]
    is_enabled: bool
    priority: int
    created_at: str
    updated_at: str

class PolicyEvaluationRequest(BaseModel):
    resource_type: ResourceType
    action: ActionType
    client_ip: Optional[str] = None

class PolicyEvaluationResponse(BaseModel):
    allowed: bool
    decision_reason: str
    required_aal: AALLevel
    current_aal: AALLevel
    matching_policies: List[str]

# ------------------------------------------------------------------------------
# 5. ORGANIZATION IDENTITY POLICIES
# ------------------------------------------------------------------------------

class OrganizationIdentityPolicyUpdate(BaseModel):
    mfa_required: Optional[bool] = None
    mfa_enforced_roles: Optional[List[str]] = None
    sso_required: Optional[bool] = None
    sso_bypass_allowed_for_breakglass: Optional[bool] = None
    breakglass_email: Optional[str] = None
    session_idle_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)
    session_absolute_timeout_hours: Optional[int] = Field(None, ge=1, le=168)
    max_concurrent_sessions_per_user: Optional[int] = Field(None, ge=1, le=20)
    allowed_ip_cidrs: Optional[List[str]] = None
    allowed_email_domains: Optional[List[str]] = None
    require_step_up_for_sensitive_actions: Optional[bool] = None

class OrganizationIdentityPolicyResponse(BaseModel):
    id: str
    organization_id: str
    mfa_required: bool
    mfa_enforced_roles: List[str]
    sso_required: bool
    sso_bypass_allowed_for_breakglass: bool
    breakglass_email: Optional[str]
    session_idle_timeout_minutes: int
    session_absolute_timeout_hours: int
    max_concurrent_sessions_per_user: int
    allowed_ip_cidrs: List[str]
    allowed_email_domains: List[str]
    require_step_up_for_sensitive_actions: bool
    created_at: str
    updated_at: str

# ------------------------------------------------------------------------------
# 6. IDENTITY AUDIT & OVERVIEW
# ------------------------------------------------------------------------------

class IdentityAuditEventResponse(BaseModel):
    id: str
    organization_id: str
    user_id: Optional[str]
    user_email: Optional[str]
    event_type: str
    status: str
    ip_address: str
    user_agent: Optional[str]
    correlation_id: str
    details: Dict[str, Any]
    created_at: str

class UserSecurityOverviewResponse(BaseModel):
    user_id: str
    email: str
    role: str
    mfa_enabled: bool
    current_aal: AALLevel
    mfa_enforced_by_org: bool
    recovery_codes_remaining: int
    active_sessions_count: int
    sso_enforced_by_org: bool
    security_score: int
    security_recommendations: List[str]
