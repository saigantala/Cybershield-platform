-- ==============================================================================
-- CyberShield Sprint 18: Enterprise Identity, SSO, MFA & Zero Trust Architecture
-- Migration: 20261102_sprint18_enterprise_identity_sso_mfa.sql
-- ==============================================================================

-- 1. Identity Providers (OIDC / SAML 2.0 / Entra / Okta / Google Workspace)
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('oidc', 'saml2', 'azure_ad', 'okta', 'google_workspace')),
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT,
    client_secret_last4 TEXT,
    authorization_url TEXT,
    token_url TEXT,
    userinfo_url TEXT,
    saml_metadata_url TEXT,
    saml_entity_id TEXT,
    saml_acs_url TEXT,
    saml_certificate TEXT,
    domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    enforce_sso BOOLEAN NOT NULL DEFAULT false,
    sync_profile_attributes BOOLEAN NOT NULL DEFAULT true,
    default_role TEXT NOT NULL DEFAULT 'analyst' CHECK (default_role IN ('viewer', 'analyst', 'admin')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_idp_org ON identity_providers(organization_id);
CREATE INDEX IF NOT EXISTS idx_idp_type ON identity_providers(provider_type);

-- 2. Domain Verifications for SSO
CREATE TABLE IF NOT EXISTS identity_domain_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    identity_provider_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
    domain_name TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed')),
    verified_at TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    dns_records_found JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_org_unique ON identity_domain_verifications(organization_id, domain_name);

-- 3. Organization Identity & Zero Trust Policies
CREATE TABLE IF NOT EXISTS organization_identity_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    mfa_required BOOLEAN NOT NULL DEFAULT false,
    mfa_enforced_roles JSONB NOT NULL DEFAULT '["owner", "admin"]'::jsonb,
    sso_required BOOLEAN NOT NULL DEFAULT false,
    sso_bypass_allowed_for_breakglass BOOLEAN NOT NULL DEFAULT true,
    breakglass_email TEXT,
    session_idle_timeout_minutes INTEGER NOT NULL DEFAULT 60,
    session_absolute_timeout_hours INTEGER NOT NULL DEFAULT 24,
    max_concurrent_sessions_per_user INTEGER NOT NULL DEFAULT 5,
    allowed_ip_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_email_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    require_step_up_for_sensitive_actions BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_org_identity_policies_org ON organization_identity_policies(organization_id);

-- 4. User Security Preferences & MFA Credentials
CREATE TABLE IF NOT EXISTS user_security_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    totp_secret_encrypted TEXT,
    totp_enrolled_at TIMESTAMPTZ,
    hashed_recovery_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
    recovery_codes_generated_at TIMESTAMPTZ,
    current_aal TEXT NOT NULL DEFAULT 'aal1' CHECK (current_aal IN ('aal1', 'aal2')),
    webauthn_credentials JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_user_security_prefs_user ON user_security_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_user_security_prefs_org ON user_security_preferences(organization_id);

-- 5. Session Security Metadata & Revocation Tracking
CREATE TABLE IF NOT EXISTS session_security_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL UNIQUE,
    device_type TEXT NOT NULL DEFAULT 'desktop' CHECK (device_type IN ('desktop', 'mobile', 'tablet', 'api_client', 'unknown')),
    browser TEXT,
    os TEXT,
    ip_address TEXT NOT NULL,
    approx_location TEXT,
    is_suspicious BOOLEAN NOT NULL DEFAULT false,
    suspicion_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    aal_level TEXT NOT NULL DEFAULT 'aal1' CHECK (aal_level IN ('aal1', 'aal2')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_session_metadata_user ON session_security_metadata(user_id);
CREATE INDEX IF NOT EXISTS idx_session_metadata_org ON session_security_metadata(organization_id);
CREATE INDEX IF NOT EXISTS idx_session_metadata_token ON session_security_metadata(session_token_hash);

-- 6. Zero Trust Access Policies (ABAC / Micro-segmentation)
CREATE TABLE IF NOT EXISTS access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('all', 'assets', 'vulnerabilities', 'incidents', 'soar', 'threat_hunting', 'forensics', 'api_keys', 'settings', 'sso', 'billing')),
    action TEXT NOT NULL CHECK (action IN ('all', 'read', 'write', 'execute', 'export', 'delete', 'admin')),
    effect TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
    allowed_roles JSONB NOT NULL DEFAULT '["owner", "admin", "analyst", "viewer"]'::jsonb,
    require_mfa BOOLEAN NOT NULL DEFAULT false,
    min_aal TEXT NOT NULL DEFAULT 'aal1' CHECK (min_aal IN ('aal1', 'aal2')),
    ip_whitelist JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_policies_org ON access_policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_resource ON access_policies(resource_type, action);

-- 7. Access Policy Assignments
CREATE TABLE IF NOT EXISTS access_policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('organization', 'role', 'user')),
    target_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON access_policy_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_target ON access_policy_assignments(target_type, target_value);

-- 8. Immutable Identity Audit Events
CREATE TABLE IF NOT EXISTS identity_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID,
    user_email TEXT,
    event_type TEXT NOT NULL CHECK (event_type IN (
       'login_success', 'login_failure', 'logout',
       'mfa_enrollment_started', 'mfa_enrolled', 'mfa_disabled',
       'mfa_challenge_success', 'mfa_challenge_failure', 'mfa_recovery_code_used', 'mfa_recovery_codes_rotated',
       'step_up_success', 'step_up_failure',
       'sso_login_success', 'sso_login_failure', 'sso_provider_configured', 'sso_provider_updated', 'sso_domain_verified',
       'session_created', 'session_revoked', 'all_sessions_revoked', 'suspicious_session_flagged',
       'access_policy_created', 'access_policy_updated', 'access_policy_deleted',
       'identity_policy_updated', 'zero_trust_access_denied', 'breakglass_login_used'
    )),
    status TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failure', 'warning', 'denied')),
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    session_id UUID,
    correlation_id TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_identity_audit_org ON identity_audit_events(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_audit_user ON identity_audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_identity_audit_event ON identity_audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_identity_audit_corr ON identity_audit_events(correlation_id);

-- 9. MFA Factors Registry
CREATE TABLE IF NOT EXISTS mfa_factors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    factor_type TEXT NOT NULL DEFAULT 'totp' CHECK (factor_type IN ('totp', 'recovery_code', 'webauthn')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('unverified', 'active', 'revoked')),
    friendly_name TEXT DEFAULT 'Authenticator App',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mfa_factors_user ON mfa_factors(user_id);

-- 10. MFA Challenge Attempts (for rate limiting and lockouts)
CREATE TABLE IF NOT EXISTS mfa_challenge_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    attempt_type TEXT NOT NULL CHECK (attempt_type IN ('totp', 'recovery_code', 'step_up')),
    is_successful BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user_time ON mfa_challenge_attempts(user_id, attempted_at DESC);

-- Enable Row Level Security (RLS) on all 10 tables
ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_domain_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_identity_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_security_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_security_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_policy_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_challenge_attempts ENABLE ROW LEVEL SECURITY;

-- Add RLS Tenant Isolation Policies
DO $$
BEGIN
    -- identity_providers
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'identity_providers' AND policyname = 'tenant_isolation_idp') THEN
        CREATE POLICY tenant_isolation_idp ON identity_providers
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- identity_domain_verifications
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'identity_domain_verifications' AND policyname = 'tenant_isolation_domain_verifications') THEN
        CREATE POLICY tenant_isolation_domain_verifications ON identity_domain_verifications
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- organization_identity_policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'organization_identity_policies' AND policyname = 'tenant_isolation_identity_policies') THEN
        CREATE POLICY tenant_isolation_identity_policies ON organization_identity_policies
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- user_security_preferences
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_security_preferences' AND policyname = 'tenant_isolation_security_preferences') THEN
        CREATE POLICY tenant_isolation_security_preferences ON user_security_preferences
            FOR ALL USING (user_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
            ));
    END IF;

    -- session_security_metadata
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'session_security_metadata' AND policyname = 'tenant_isolation_sessions') THEN
        CREATE POLICY tenant_isolation_sessions ON session_security_metadata
            FOR ALL USING (user_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
            ));
    END IF;

    -- access_policies
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'access_policies' AND policyname = 'tenant_isolation_access_policies') THEN
        CREATE POLICY tenant_isolation_access_policies ON access_policies
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- access_policy_assignments
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'access_policy_assignments' AND policyname = 'tenant_isolation_policy_assignments') THEN
        CREATE POLICY tenant_isolation_policy_assignments ON access_policy_assignments
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- identity_audit_events
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'identity_audit_events' AND policyname = 'tenant_isolation_identity_audit') THEN
        CREATE POLICY tenant_isolation_identity_audit ON identity_audit_events
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    -- mfa_factors
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'mfa_factors' AND policyname = 'tenant_isolation_mfa_factors') THEN
        CREATE POLICY tenant_isolation_mfa_factors ON mfa_factors
            FOR ALL USING (user_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
            ));
    END IF;

    -- mfa_challenge_attempts
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'mfa_challenge_attempts' AND policyname = 'tenant_isolation_mfa_attempts') THEN
        CREATE POLICY tenant_isolation_mfa_attempts ON mfa_challenge_attempts
            FOR ALL USING (user_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
            ));
    END IF;
END $$;
