-- ==============================================================================
-- CyberShield Sprint 2 Database Migration
-- Supabase Authentication, Organizations, 9 Core Application Tables & Strict RLS
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------------------------------------
-- 1. PROFILES (Extends auth.users)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 2. ORGANIZATIONS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 3. ORGANIZATION MEMBERS (RBAC: owner, admin, analyst, viewer)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

-- ------------------------------------------------------------------------------
-- 4. SCAN SCOPES (Approved Target Boundaries)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('cidr', 'ip_range', 'single_ip', 'hostname')),
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval', 'approved', 'rejected', 'revoked')),
    approved_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 5. ASSETS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    ip_address INET NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    category TEXT NOT NULL DEFAULT 'Unknown device' CHECK (
        category IN ('Laptop', 'Desktop', 'Server', 'Router', 'Switch', 'Mobile', 'IoT device', 'Printer', 'Camera', 'Unknown device')
    ),
    classification_confidence INTEGER NOT NULL DEFAULT 50 CHECK (classification_confidence BETWEEN 0 AND 100),
    classification_evidence TEXT,
    os TEXT,
    status TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online', 'offline', 'unresponsive')),
    risk_level TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'safe')),
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    segment TEXT,
    tags TEXT[] DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 6. SCANS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('network_discovery', 'vulnerability_assessment', 'web_baseline')),
    profile TEXT NOT NULL CHECK (profile IN ('fast_discovery', 'comprehensive_audit', 'web_baseline_safe', 'full_compliance')),
    target_scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    hosts_discovered INTEGER NOT NULL DEFAULT 0,
    findings_count JSONB NOT NULL DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0}'::jsonb,
    initiated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    logs TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 7. FINDINGS (Vulnerabilities)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score NUMERIC(3, 1) NOT NULL DEFAULT 0.0 CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    asset_id UUID NOT NULL REFERENCES public.assets(id) ON DELETE CASCADE,
    port INTEGER,
    service TEXT,
    remediation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    cisa_kev BOOLEAN NOT NULL DEFAULT false,
    exploit_available BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'mitigated', 'false_positive', 'accepted_risk')),
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 8. INCIDENTS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    assigned_to UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    assigned_to_name TEXT,
    affected_assets TEXT[] DEFAULT '{}',
    evidence_notes TEXT,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 9. AUDIT LOGS (Immutable Append-Only Ledger)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details TEXT NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- INDEXES
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_members_org_user ON public.organization_members(organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_assets_org_ip ON public.assets(organization_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_findings_org_severity ON public.findings(organization_id, severity);
CREATE INDEX IF NOT EXISTS idx_scans_org_status ON public.scans(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON public.incidents(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time ON public.audit_logs(organization_id, timestamp DESC);

-- ------------------------------------------------------------------------------
-- AUTOMATIC PROFILE & DEFAULT ORGANIZATION CREATION TRIGGER
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    new_org_id UUID;
    org_name_val TEXT;
BEGIN
    -- 1. Create Profile
    INSERT INTO public.profiles (id, email, full_name, avatar_url)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
        NEW.raw_user_meta_data->>'avatar_url'
    );

    -- 2. Determine initial organization name
    org_name_val := COALESCE(NEW.raw_user_meta_data->>'organization_name', split_part(NEW.email, '@', 1) || ' SecOps');

    -- 3. Create initial tenant organization
    INSERT INTO public.organizations (name, slug, created_by)
    VALUES (
        org_name_val,
        lower(regexp_replace(org_name_val, '[^a-zA-Z0-9]+', '-', 'g')) || '-' || substring(NEW.id::text, 1, 6),
        NEW.id
    )
    RETURNING id INTO new_org_id;

    -- 4. Assign user as Owner of their new organization
    INSERT INTO public.organization_members (organization_id, user_id, role)
    VALUES (new_org_id, NEW.id, 'owner');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ------------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS) ACTIVATION
-- ------------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- SECURITY HELPER FUNCTIONS
-- ------------------------------------------------------------------------------
-- Returns the organization IDs the current user belongs to
CREATE OR REPLACE FUNCTION public.get_user_organizations()
RETURNS SETOF UUID AS $$
    SELECT organization_id 
    FROM public.organization_members 
    WHERE user_id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- Returns the role of the current user in a specific organization
CREATE OR REPLACE FUNCTION public.get_user_org_role(org_id UUID)
RETURNS TEXT AS $$
    SELECT role 
    FROM public.organization_members 
    WHERE organization_id = org_id AND user_id = auth.uid()
    LIMIT 1;
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- ------------------------------------------------------------------------------
-- RLS POLICIES
-- ------------------------------------------------------------------------------

-- Profiles: users can read any profile in their organization, update only their own
CREATE POLICY "Users can read profiles in same organization" ON public.profiles
    FOR SELECT USING (
        id = auth.uid() OR
        id IN (
            SELECT user_id FROM public.organization_members 
            WHERE organization_id IN (SELECT public.get_user_organizations())
        )
    );

CREATE POLICY "Users can update their own profile" ON public.profiles
    FOR UPDATE USING (id = auth.uid());

-- Organizations: members can read, only owners/admins can update
CREATE POLICY "Members can view their organizations" ON public.organizations
    FOR SELECT USING (id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Owners and admins can update their organization" ON public.organizations
    FOR UPDATE USING (public.get_user_org_role(id) IN ('owner', 'admin'));

-- Organization Members: members can view team, only owners/admins can invite/modify
CREATE POLICY "Members can view teammates" ON public.organization_members
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Owners and admins can manage memberships" ON public.organization_members
    FOR ALL USING (public.get_user_org_role(organization_id) IN ('owner', 'admin'));

-- Scan Scopes: members can read, only owners/admins can create/approve
CREATE POLICY "Members can view approved scopes" ON public.scan_scopes
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Owners and admins can manage scopes" ON public.scan_scopes
    FOR ALL USING (public.get_user_org_role(organization_id) IN ('owner', 'admin'));

-- Assets: members can read, non-viewers can insert/update
CREATE POLICY "Members can view organization assets" ON public.assets
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Operators can update assets" ON public.assets
    FOR ALL USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- Scans: members can read, non-viewers can initiate/cancel
CREATE POLICY "Members can view scans" ON public.scans
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Analysts and Admins can launch scans" ON public.scans
    FOR INSERT WITH CHECK (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

CREATE POLICY "Analysts and Admins can cancel scans" ON public.scans
    FOR UPDATE USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- Findings: members can read, non-viewers can triage
CREATE POLICY "Members can view findings" ON public.findings
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Analysts and Admins can triage findings" ON public.findings
    FOR UPDATE USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- Incidents: members can read, non-viewers can declare/update
CREATE POLICY "Members can view incidents" ON public.incidents
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Analysts and Admins can manage incidents" ON public.incidents
    FOR ALL USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- Audit Logs: members can read, users CANNOT update or delete (append-only)
CREATE POLICY "Members can view audit logs" ON public.audit_logs
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Append-only insert for audit logs" ON public.audit_logs
    FOR INSERT WITH CHECK (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "No modification of audit logs permitted" ON public.audit_logs
    FOR UPDATE USING (false);

CREATE POLICY "No deletion of audit logs permitted" ON public.audit_logs
    FOR DELETE USING (false);
