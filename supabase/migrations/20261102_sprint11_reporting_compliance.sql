-- ==============================================================================
-- CyberShield – Sprint 11: Advanced Reporting, Compliance & Posture Management
-- Migration: 20261102_sprint11_reporting_compliance.sql
-- ==============================================================================

-- 1. Compliance Frameworks Table
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'Cybersecurity',
    total_controls INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Compliance Controls Table
CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    domain TEXT,
    remediation_guidance TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_framework_control UNIQUE (framework_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_controls_code ON compliance_controls(control_id);

-- 3. Compliance Assessments Table (Tenant-scoped)
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_id UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('Not Assessed', 'Partially Implemented', 'Implemented', 'Not Applicable')) DEFAULT 'Not Assessed',
    assigned_owner TEXT,
    review_date DATE,
    notes TEXT,
    remediation_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_org_control_assessment UNIQUE (organization_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_assessments_org ON compliance_assessments(organization_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_status ON compliance_assessments(status);

-- 4. Compliance Evidence Table
CREATE TABLE IF NOT EXISTS compliance_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_id UUID REFERENCES compliance_controls(id) ON DELETE SET NULL,
    assessment_id UUID REFERENCES compliance_assessments(id) ON DELETE SET NULL,
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    description TEXT,
    uploaded_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    uploaded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_org ON compliance_evidence(organization_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_hash ON compliance_evidence(sha256_hash);

-- 5. Security Reports Table
CREATE TABLE IF NOT EXISTS security_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN (
        'vulnerability_assessment',
        'asset_inventory',
        'incident_summary',
        'threat_intelligence',
        'compliance_assessment',
        'security_posture',
        'executive_summary'
    )),
    format TEXT CHECK (format IN ('pdf', 'csv', 'json')) DEFAULT 'pdf',
    status TEXT CHECK (status IN ('Pending', 'Processing', 'Completed', 'Failed')) DEFAULT 'Completed',
    parameters JSONB DEFAULT '{}'::jsonb,
    summary_metrics JSONB DEFAULT '{}'::jsonb,
    file_size_bytes BIGINT DEFAULT 0,
    download_url TEXT,
    generated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_reports_org ON security_reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_security_reports_type ON security_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_security_reports_created ON security_reports(created_at DESC);

-- 6. Report Schedules Table
CREATE TABLE IF NOT EXISTS report_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL,
    frequency TEXT CHECK (frequency IN ('daily', 'weekly', 'monthly')) NOT NULL,
    recipients JSONB DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_schedules_org ON report_schedules(organization_id);

-- 7. Posture Score History Table
CREATE TABLE IF NOT EXISTS posture_score_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    posture_score NUMERIC(5, 2) NOT NULL,
    risk_level TEXT NOT NULL,
    breakdown JSONB NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posture_score_history_org ON posture_score_history(organization_id, recorded_at DESC);

-- ==============================================================================
-- Row Level Security (RLS) Policies
-- ==============================================================================

-- Frameworks & Controls: Publicly readable by all authenticated users
ALTER TABLE compliance_frameworks ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated read compliance_frameworks"
    ON compliance_frameworks FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow authenticated read compliance_controls"
    ON compliance_controls FOR SELECT
    TO authenticated
    USING (true);

-- Compliance Assessments RLS
ALTER TABLE compliance_assessments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view organization compliance assessments"
    ON compliance_assessments FOR SELECT
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Analysts and Admins can mutate compliance assessments"
    ON compliance_assessments FOR ALL
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')
        )
    );

-- Compliance Evidence RLS
ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view organization compliance evidence"
    ON compliance_evidence FOR SELECT
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Analysts and Admins can insert compliance evidence"
    ON compliance_evidence FOR INSERT
    TO authenticated
    WITH CHECK (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')
        )
    );

CREATE POLICY "Admins and Owners can delete compliance evidence"
    ON compliance_evidence FOR DELETE
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- Security Reports RLS
ALTER TABLE security_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view organization reports"
    ON security_reports FOR SELECT
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Users can insert organization reports"
    ON security_reports FOR INSERT
    TO authenticated
    WITH CHECK (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

-- Posture Score History RLS
ALTER TABLE posture_score_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view organization posture history"
    ON posture_score_history FOR SELECT
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

-- Report Schedules RLS
ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view organization report schedules"
    ON report_schedules FOR SELECT
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Admins and Owners can manage organization report schedules"
    ON report_schedules FOR ALL
    TO authenticated
    USING (
        organization_id IN (
            SELECT organization_id FROM organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

