-- CyberShield Multi-Organization PostgreSQL Database Schema
-- Strict Multi-Tenant Isolation with Row Level Security (RLS)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. ORGANIZATIONS
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'standard' CHECK (plan IN ('standard', 'professional', 'enterprise')),
    verified_domain TEXT,
    logo_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. PROFILES (Extends Supabase auth.users)
CREATE TABLE profiles (
    id UUID PRIMARY KEY, -- Maps to auth.users.id
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. ORGANIZATION MEMBERS (RBAC: owner, admin, analyst, viewer)
CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

-- 4. SCAN SCOPES (Target containment: CIDR, hostname, single_ip)
CREATE TABLE scan_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('cidr', 'ip_range', 'single_ip', 'hostname')),
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval', 'approved', 'rejected', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. SCAN SCOPE APPROVALS
CREATE TABLE scan_scope_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id UUID NOT NULL REFERENCES scan_scopes(id) ON DELETE CASCADE,
    approved_by UUID NOT NULL REFERENCES profiles(id),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected', 'revoked')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. ASSETS
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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

-- 7. ASSET INTERFACES
CREATE TABLE asset_interfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    interface_name TEXT NOT NULL,
    mac_address TEXT,
    ip_address INET,
    is_primary BOOLEAN NOT NULL DEFAULT true
);

-- 8. SERVICES (Open ports & banners discovered)
CREATE TABLE services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp')),
    name TEXT NOT NULL,
    version TEXT,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'filtered', 'closed')),
    banner TEXT,
    is_baseline_approved BOOLEAN NOT NULL DEFAULT false,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

-- 9. SCANS
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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
    initiated_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 10. SCAN JOBS (Celery worker execution mapping)
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    celery_task_id TEXT UNIQUE NOT NULL,
    worker_node TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. SCAN EVENTS (Live execution telemetry logs)
CREATE TABLE scan_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    event_level TEXT NOT NULL DEFAULT 'info' CHECK (event_level IN ('info', 'warn', 'error', 'critical')),
    message TEXT NOT NULL,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. FINDINGS (Vulnerabilities)
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score NUMERIC(3, 1) NOT NULL DEFAULT 0.0 CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
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

-- 13. EVIDENCE (Attached scan artifacts)
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    raw_content TEXT,
    storage_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. REMEDIATION HISTORY
CREATE TABLE remediation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    changed_by UUID NOT NULL REFERENCES profiles(id),
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 15. INCIDENTS
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    assigned_to UUID REFERENCES profiles(id),
    affected_assets TEXT[] DEFAULT '{}',
    evidence_notes TEXT,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 16. INCIDENT COMMENTS
CREATE TABLE incident_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES profiles(id),
    comment TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 17. NOTIFICATIONS
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('critical', 'warning', 'info', 'success')),
    read BOOLEAN NOT NULL DEFAULT false,
    link TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 18. NOTIFICATION PREFERENCES
CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    email_alerts BOOLEAN NOT NULL DEFAULT true,
    push_alerts BOOLEAN NOT NULL DEFAULT true,
    critical_only BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

-- 19. REPORTS
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('executive_summary', 'technical_vulnerability', 'compliance_assessment', 'network_inventory')),
    scope TEXT NOT NULL,
    generated_by UUID REFERENCES profiles(id),
    asset_count INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    storage_path TEXT,
    file_size TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 20. AUDIT LOGS (Immutable append-only)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id),
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    details TEXT NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- INDEXES FOR HIGH-THROUGHPUT SOC QUERIES
CREATE INDEX idx_assets_org_ip ON assets(organization_id, ip_address);
CREATE INDEX idx_assets_risk ON assets(organization_id, risk_level);
CREATE INDEX idx_findings_org_severity ON findings(organization_id, severity);
CREATE INDEX idx_findings_cve ON findings(cve_id);
CREATE INDEX idx_findings_cisa_kev ON findings(organization_id, cisa_kev) WHERE cisa_kev = true;
CREATE INDEX idx_scans_org_status ON scans(organization_id, status);
CREATE INDEX idx_audit_logs_org_time ON audit_logs(organization_id, timestamp DESC);

-- ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_scope_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_interfaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Helper function: Get organization IDs the authenticated user belongs to
CREATE OR REPLACE FUNCTION get_user_organizations()
RETURNS SETOF UUID AS $$
    SELECT organization_id FROM organization_members WHERE user_id = auth.uid();
$$ LANGUAGE sql SECURITY DEFINER STABLE;

-- Generic Organization RLS Policy Template applied to tenant tables
CREATE POLICY "Users can access their organization's assets" ON assets
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can access their organization's scopes" ON scan_scopes
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can access their organization's scans" ON scans
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can access their organization's findings" ON findings
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can access their organization's incidents" ON incidents
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Users can view audit logs in their organization" ON audit_logs
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Normal users cannot modify audit logs" ON audit_logs
    FOR UPDATE USING (false);

CREATE POLICY "Normal users cannot delete audit logs" ON audit_logs
    FOR DELETE USING (false);
