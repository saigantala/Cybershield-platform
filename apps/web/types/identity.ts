/**
 * Enterprise Identity, SSO, MFA & Zero Trust Types
 * CyberShield Sprint 18
 */

export type AALLevel = 'aal1' | 'aal2';

export type SSOProviderType = 'oidc' | 'saml2' | 'azure_ad' | 'okta' | 'google_workspace';

export type DeviceType = 'desktop' | 'mobile' | 'tablet' | 'api_client' | 'unknown';

export type RoleType = 'owner' | 'admin' | 'analyst' | 'viewer';

export type ResourceType =
  | 'all'
  | 'assets'
  | 'vulnerabilities'
  | 'incidents'
  | 'soar'
  | 'threat_hunting'
  | 'forensics'
  | 'api_keys'
  | 'settings'
  | 'sso'
  | 'billing';

export type ActionType = 'all' | 'read' | 'write' | 'execute' | 'export' | 'delete' | 'admin';

export type PolicyEffect = 'allow' | 'deny';

export type DomainVerificationStatus = 'pending' | 'verified' | 'failed';

export interface MFASetupResponse {
  secret: string;
  otpauth_uri: string;
  qr_code_svg: string;
  issuer: string;
  account_name: string;
  message: string;
}

export interface MFAVerifyRequest {
  code: string;
  is_recovery_code?: boolean;
}

export interface MFAVerifyResponse {
  success: boolean;
  current_aal: AALLevel;
  message: string;
  recovery_codes?: string[];
  token?: string;
}

export interface MFARecoveryCodeResponse {
  recovery_codes: string[];
  generated_at: string;
  remaining_count: number;
  note: string;
}

export interface StepUpAuthResponse {
  success: boolean;
  step_up_token: string;
  action: string;
  expires_at: string;
  message: string;
}

export interface SSOProvider {
  id: string;
  organization_id: string;
  name: string;
  provider_type: SSOProviderType;
  issuer_url: string;
  client_id: string;
  client_secret_masked: string;
  client_secret_last4?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  saml_metadata_url?: string;
  saml_entity_id?: string;
  saml_acs_url?: string;
  domains: string[];
  is_enabled: boolean;
  enforce_sso: boolean;
  sync_profile_attributes: boolean;
  default_role: RoleType;
  created_at: string;
  updated_at: string;
}

export interface SSOProviderCreate {
  name: string;
  provider_type: SSOProviderType;
  issuer_url: string;
  client_id: string;
  client_secret?: string;
  domains?: string[];
  enforce_sso?: boolean;
  sync_profile_attributes?: boolean;
  default_role?: RoleType;
}

export interface DomainVerification {
  id: string;
  organization_id: string;
  identity_provider_id?: string;
  domain_name: string;
  verification_token: string;
  expected_txt_record: string;
  status: DomainVerificationStatus;
  verified_at?: string;
  last_checked_at?: string;
  created_at: string;
}

export interface SessionMetadata {
  id: string;
  user_id: string;
  organization_id: string;
  device_type: DeviceType;
  browser?: string;
  os?: string;
  ip_address: string;
  approx_location?: string;
  is_suspicious: boolean;
  suspicion_reasons: string[];
  aal_level: AALLevel;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface AccessPolicy {
  id: string;
  organization_id: string;
  name: string;
  description?: string;
  resource_type: ResourceType;
  action: ActionType;
  effect: PolicyEffect;
  allowed_roles: RoleType[];
  require_mfa: boolean;
  min_aal: AALLevel;
  ip_whitelist: string[];
  is_enabled: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface AccessPolicyCreate {
  name: string;
  description?: string;
  resource_type: ResourceType;
  action: ActionType;
  effect: PolicyEffect;
  allowed_roles?: RoleType[];
  require_mfa?: boolean;
  min_aal?: AALLevel;
  ip_whitelist?: string[];
  is_enabled?: boolean;
  priority?: number;
}

export interface PolicyEvaluationRequest {
  resource_type: ResourceType;
  action: ActionType;
  client_ip?: string;
}

export interface PolicyEvaluationResponse {
  allowed: boolean;
  decision_reason: string;
  required_aal: AALLevel;
  current_aal: AALLevel;
  matching_policies: string[];
}

export interface OrganizationIdentityPolicy {
  id: string;
  organization_id: string;
  mfa_required: boolean;
  mfa_enforced_roles: string[];
  sso_required: boolean;
  sso_bypass_allowed_for_breakglass: boolean;
  breakglass_email?: string;
  session_idle_timeout_minutes: number;
  session_absolute_timeout_hours: number;
  max_concurrent_sessions_per_user: number;
  allowed_ip_cidrs: string[];
  allowed_email_domains: string[];
  require_step_up_for_sensitive_actions: boolean;
  created_at: string;
  updated_at: string;
}

export interface IdentityAuditEvent {
  id: string;
  organization_id: string;
  user_id?: string;
  user_email?: string;
  event_type: string;
  status: 'success' | 'failure' | 'warning' | 'denied';
  ip_address: string;
  user_agent?: string;
  correlation_id: string;
  details: Record<string, any>;
  created_at: string;
}

export interface UserSecurityOverview {
  user_id: string;
  email: string;
  role: string;
  mfa_enabled: boolean;
  current_aal: AALLevel;
  mfa_enforced_by_org: boolean;
  recovery_codes_remaining: number;
  active_sessions_count: number;
  sso_enforced_by_org: boolean;
  security_score: number;
  security_recommendations: string[];
}
