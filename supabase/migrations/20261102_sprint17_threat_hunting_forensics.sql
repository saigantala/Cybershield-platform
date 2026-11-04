-- ==============================================================================
-- CyberShield - Sprint 17 Migration: Advanced Threat Hunting & Digital Forensics
-- Multi-tenant Row-Level Security, Threat Hunting Cases, Structured Query Engine,
-- Forensic Cases, Digital Evidence Vault, Tamper-Evident Chain of Custody,
-- Static Artifact Analysis, and Forensic Reporting
-- ==============================================================================

-- 1. THREAT HUNTING CASES
CREATE TABLE IF NOT EXISTS threat_hunting_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    case_number TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    hypothesis TEXT,
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Active', 'Investigating', 'Suspicious Activity Found', 'No Threat Identified', 'Escalated', 'Completed')),
    priority TEXT NOT NULL DEFAULT 'P3' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    assigned_to UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    selected_asset_ids JSONB DEFAULT '[]'::jsonb,
    filter_criteria JSONB DEFAULT '{}'::jsonb,
    summary_findings TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_th_case_number UNIQUE (organization_id, case_number)
);

CREATE INDEX IF NOT EXISTS idx_th_cases_org ON threat_hunting_cases(organization_id);
CREATE INDEX IF NOT EXISTS idx_th_cases_status ON threat_hunting_cases(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_th_cases_created ON threat_hunting_cases(organization_id, created_at DESC);

-- 2. THREAT HUNTING SAVED QUERIES & HISTORY
CREATE TABLE IF NOT EXISTS threat_hunting_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hunting_case_id UUID REFERENCES threat_hunting_cases(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    description TEXT,
    filter_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    match_count INT NOT NULL DEFAULT 0,
    is_saved BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_th_queries_org ON threat_hunting_queries(organization_id);

-- 3. THREAT HUNTING FINDINGS
CREATE TABLE IF NOT EXISTS threat_hunting_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hunting_case_id UUID NOT NULL REFERENCES threat_hunting_cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    finding_type TEXT NOT NULL CHECK (finding_type IN ('anomalous_traffic', 'ioc_match', 'behavioral_anomaly', 'credential_misuse', 'unauthorized_service')),
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    is_confirmed BOOLEAN NOT NULL DEFAULT false, -- Distinguishes facts from hypotheses
    affected_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    evidence_summary TEXT NOT NULL,
    mitre_tactic_name TEXT,
    mitre_technique_id TEXT,
    recommendations TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_th_findings_case ON threat_hunting_findings(hunting_case_id);

-- 4. DIGITAL FORENSICS CASES
CREATE TABLE IF NOT EXISTS forensic_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    case_number TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    investigation_objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Evidence Collection', 'Analysis', 'Review', 'Completed', 'Archived')),
    priority TEXT NOT NULL DEFAULT 'P2' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    assigned_investigator_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    related_incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    related_hunting_case_id UUID REFERENCES threat_hunting_cases(id) ON DELETE SET NULL,
    conclusion_summary TEXT,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_for_case_number UNIQUE (organization_id, case_number)
);

CREATE INDEX IF NOT EXISTS idx_for_cases_org ON forensic_cases(organization_id);
CREATE INDEX IF NOT EXISTS idx_for_cases_status ON forensic_cases(organization_id, status);

-- 5. FORENSIC CASE TARGET ASSETS
CREATE TABLE IF NOT EXISTS forensic_case_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    forensic_case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    role_in_case TEXT NOT NULL DEFAULT 'compromised_target' CHECK (role_in_case IN ('compromised_target', 'pivot_host', 'command_control_hop', 'unauthorized_scanner', 'witness_system')),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_for_case_asset UNIQUE (forensic_case_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_for_case_assets_case ON forensic_case_assets(forensic_case_id);

-- 6. FORENSIC EVIDENCE ITEMS
CREATE TABLE IF NOT EXISTS forensic_evidence_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    forensic_case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    evidence_name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('log_file', 'network_metadata_pcap', 'memory_dump_metadata', 'disk_artifact', 'screenshot', 'config_export', 'pdf_report', 'csv_export', 'other')),
    original_filename TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    sha256_hash TEXT NOT NULL,
    md5_hash TEXT,
    uploaded_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    description TEXT,
    is_derived BOOLEAN NOT NULL DEFAULT false,
    parent_evidence_id UUID REFERENCES forensic_evidence_items(id) ON DELETE SET NULL,
    transformation_notes TEXT,
    integrity_status TEXT NOT NULL DEFAULT 'Verified' CHECK (integrity_status IN ('Verified', 'Tampered', 'Unverified')),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_for_evidence_case ON forensic_evidence_items(forensic_case_id);
CREATE INDEX IF NOT EXISTS idx_for_evidence_hash ON forensic_evidence_items(organization_id, sha256_hash);

-- 7. TAMPER-EVIDENT CHAIN OF CUSTODY LOGS (Cryptographic Hash Chain)
CREATE TABLE IF NOT EXISTS forensic_custody_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES forensic_evidence_items(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('Collected', 'Uploaded', 'Viewed', 'Downloaded', 'Integrity_Verified', 'Transferred', 'Archived')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    previous_record_hash TEXT NOT NULL,
    current_record_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_for_custody_evidence ON forensic_custody_events(evidence_id, timestamp ASC);

-- 8. SAFE STATIC ARTIFACT ANALYSIS JOBS
CREATE TABLE IF NOT EXISTS forensic_analysis_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    forensic_case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES forensic_evidence_items(id) ON DELETE CASCADE,
    analysis_type TEXT NOT NULL CHECK (analysis_type IN ('log_normalization', 'ioc_extraction', 'pcap_metadata', 'string_extraction')),
    status TEXT NOT NULL DEFAULT 'Queued' CHECK (status IN ('Queued', 'Processing', 'Completed', 'Failed')),
    extracted_metadata JSONB DEFAULT '{}'::jsonb,
    matched_iocs JSONB DEFAULT '[]'::jsonb,
    suspicious_indicators JSONB DEFAULT '[]'::jsonb,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INT
);

CREATE INDEX IF NOT EXISTS idx_for_analysis_case ON forensic_analysis_jobs(forensic_case_id);

-- 9. FORENSIC CASE NOTES & HYPOTHESES
CREATE TABLE IF NOT EXISTS forensic_case_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    forensic_case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    author_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    note_type TEXT NOT NULL DEFAULT 'Confirmed_Observation' CHECK (note_type IN ('Analyst_Hypothesis', 'Confirmed_Observation', 'Investigative_Lead', 'Evidence_Custody_Note')),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_for_notes_case ON forensic_case_notes(forensic_case_id, created_at ASC);

-- 10. FORENSIC REPORTS
CREATE TABLE IF NOT EXISTS forensic_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    forensic_case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    report_number TEXT NOT NULL,
    title TEXT NOT NULL,
    author_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    scope_and_authorization TEXT NOT NULL,
    executive_summary TEXT NOT NULL,
    evidence_inventory_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
    chain_of_custody_verified BOOLEAN NOT NULL DEFAULT true,
    analysis_methodology TEXT NOT NULL,
    confirmed_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    analyst_hypotheses JSONB NOT NULL DEFAULT '[]'::jsonb,
    mitre_attack_mappings JSONB NOT NULL DEFAULT '[]'::jsonb,
    limitations TEXT,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    conclusion TEXT NOT NULL,
    file_format TEXT NOT NULL DEFAULT 'json' CHECK (file_format IN ('json', 'markdown', 'pdf')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_for_report_number UNIQUE (organization_id, report_number)
);

CREATE INDEX IF NOT EXISTS idx_for_reports_case ON forensic_reports(forensic_case_id);

-- -----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS) POLICIES
-- -----------------------------------------------------------------------------
ALTER TABLE threat_hunting_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_hunting_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_hunting_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_case_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_evidence_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_custody_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_case_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_reports ENABLE ROW LEVEL SECURITY;

-- Threat Hunting RLS
CREATE POLICY "Org members can view hunting cases" ON threat_hunting_cases
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Admins and analysts can manage hunting cases" ON threat_hunting_cases
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view hunting queries" ON threat_hunting_queries
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view hunting findings" ON threat_hunting_findings
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

-- Forensics RLS
CREATE POLICY "Org members can view forensic cases" ON forensic_cases
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Admins and investigators can manage forensic cases" ON forensic_cases
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view forensic case assets" ON forensic_case_assets
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view forensic evidence" ON forensic_evidence_items
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Investigators can manage forensic evidence" ON forensic_evidence_items
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

-- Chain of Custody: Append & Read Only, strictly no UPDATE or DELETE
CREATE POLICY "Org members can view custody events" ON forensic_custody_events
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Investigators can append custody events" ON forensic_custody_events
    FOR INSERT WITH CHECK (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view analysis jobs" ON forensic_analysis_jobs
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view case notes" ON forensic_case_notes
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view forensic reports" ON forensic_reports
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));
