-- ==============================================================================
-- CyberShield Sprint 19: Advanced Security Validation, Penetration Testing & Continuous Assurance
-- Migration: 20261104_sprint19_security_validation_assurance.sql
-- ==============================================================================

-- 1. Security Assessments Run Records
CREATE TABLE IF NOT EXISTS security_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_name TEXT NOT NULL,
    assessment_type TEXT NOT NULL CHECK (assessment_type IN ('full_suite', 'application', 'api', 'dependencies', 'containers', 'configuration', 'owasp_top10')),
    target_environment TEXT NOT NULL DEFAULT 'staging' CHECK (target_environment IN ('development', 'staging', 'preproduction', 'production_isolated')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    posture_score NUMERIC(5,2) DEFAULT 100.00,
    risk_score NUMERIC(5,2) DEFAULT 0.00,
    test_coverage_pct NUMERIC(5,2) DEFAULT 0.00,
    compliance_pct NUMERIC(5,2) DEFAULT 0.00,
    total_checks INTEGER NOT NULL DEFAULT 0,
    passed_checks INTEGER NOT NULL DEFAULT 0,
    failed_checks INTEGER NOT NULL DEFAULT 0,
    warning_checks INTEGER NOT NULL DEFAULT 0,
    critical_findings_count INTEGER NOT NULL DEFAULT 0,
    high_findings_count INTEGER NOT NULL DEFAULT 0,
    medium_findings_count INTEGER NOT NULL DEFAULT 0,
    low_findings_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    initiated_by UUID,
    initiated_by_email TEXT,
    execution_logs JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_assessments_org ON security_assessments(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_assessments_type ON security_assessments(assessment_type);

-- 2. Individual Assessment Checks (OWASP, API, Config, Containers)
CREATE TABLE IF NOT EXISTS security_assessment_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES security_assessments(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    framework_ref TEXT,
    status TEXT NOT NULL DEFAULT 'pass' CHECK (status IN ('pass', 'fail', 'warn', 'info', 'skipped')),
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation TEXT,
    execution_time_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_checks_assessment ON security_assessment_checks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_sec_checks_category ON security_assessment_checks(category);

-- 3. Security Test Runs (API Test Runner Batches)
CREATE TABLE IF NOT EXISTS security_test_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    suite_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    total_tests INTEGER NOT NULL DEFAULT 0,
    passed_tests INTEGER NOT NULL DEFAULT 0,
    failed_tests INTEGER NOT NULL DEFAULT 0,
    execution_duration_sec NUMERIC(6,2) DEFAULT 0.0,
    target_host TEXT NOT NULL,
    executed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_test_runs_org ON security_test_runs(organization_id, created_at DESC);

-- 4. Individual Security Test Results
CREATE TABLE IF NOT EXISTS security_test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_run_id UUID NOT NULL REFERENCES security_test_runs(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    test_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    test_category TEXT NOT NULL,
    expected_status INTEGER NOT NULL,
    actual_status INTEGER NOT NULL,
    passed BOOLEAN NOT NULL,
    request_payload JSONB DEFAULT '{}'::jsonb,
    response_summary TEXT,
    failure_reason TEXT,
    execution_time_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_test_results_run ON security_test_results(test_run_id);
CREATE INDEX IF NOT EXISTS idx_sec_test_results_passed ON security_test_results(passed);

-- 5. Unified Security Findings Lifecycle
CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_code TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    source_scanner TEXT NOT NULL CHECK (source_scanner IN ('api_security_engine', 'owasp_zap', 'semgrep', 'pip_audit', 'npm_audit', 'trivy', 'gitleaks', 'config_audit', 'manual_pentest')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    affected_component TEXT NOT NULL,
    affected_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    cve_reference TEXT,
    cwe_id TEXT,
    cvss_score NUMERIC(3,1),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation_recommendation TEXT NOT NULL,
    remediation_pr_url TEXT,
    assigned_to_user_id UUID,
    assigned_to_name TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'in_progress', 'fixed', 'accepted_risk', 'false_positive', 'verified')),
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    verification_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_findings_org_status ON security_findings(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_sec_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sec_findings_source ON security_findings(source_scanner);

-- 6. Security Finding Analyst Notes
CREATE TABLE IF NOT EXISTS security_finding_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    author_id UUID NOT NULL,
    author_name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_finding_notes_finding ON security_finding_notes(finding_id);

-- 7. Security Finding History Audit Trail
CREATE TABLE IF NOT EXISTS security_finding_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_name TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    change_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_finding_history_finding ON security_finding_history(finding_id);

-- 8. Security Scanner Configurations
CREATE TABLE IF NOT EXISTS security_scan_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scanner_type TEXT NOT NULL CHECK (scanner_type IN ('api_security_engine', 'owasp_zap', 'semgrep', 'pip_audit', 'npm_audit', 'trivy', 'config_audit')),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    approved_targets JSONB NOT NULL DEFAULT '["http://localhost:8000", "http://localhost:3000"]'::jsonb,
    scan_mode TEXT NOT NULL DEFAULT 'passive' CHECK (scan_mode IN ('passive', 'baseline', 'authenticated_safe', 'active_approved')),
    max_requests_per_second INTEGER NOT NULL DEFAULT 10,
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    auth_token_secret_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_scan_configs_org ON security_scan_configurations(organization_id);

-- 9. Security Scan Schedules
CREATE TABLE IF NOT EXISTS security_scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    configuration_id UUID NOT NULL REFERENCES security_scan_configurations(id) ON DELETE CASCADE,
    schedule_name TEXT NOT NULL,
    cron_expression TEXT NOT NULL DEFAULT '0 2 * * *',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_scan_schedules_org ON security_scan_schedules(organization_id);

-- 10. Security Regression Test Runs (CI/CD Gates)
CREATE TABLE IF NOT EXISTS security_regression_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    pipeline_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'main',
    total_tests INTEGER NOT NULL,
    passed_tests INTEGER NOT NULL,
    failed_tests INTEGER NOT NULL,
    duration_sec NUMERIC(6,2) NOT NULL,
    gate_passed BOOLEAN NOT NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_regression_org ON security_regression_results(organization_id, created_at DESC);

-- 11. Documented Security Exceptions
CREATE TABLE IF NOT EXISTS security_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES security_findings(id) ON DELETE CASCADE,
    exception_code TEXT NOT NULL,
    title TEXT NOT NULL,
    justification TEXT NOT NULL,
    compensating_controls TEXT NOT NULL,
    approved_by_user_id UUID NOT NULL,
    approved_by_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_exceptions_org ON security_exceptions(organization_id);

-- 12. Architecture Component Security Inventory
CREATE TABLE IF NOT EXISTS security_component_inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    component_name TEXT NOT NULL,
    component_type TEXT NOT NULL CHECK (component_type IN ('application_backend', 'application_frontend', 'database', 'identity_auth', 'queue_broker', 'container_runtime', 'storage')),
    version TEXT,
    health_score NUMERIC(5,2) NOT NULL DEFAULT 100.00,
    last_scanned_at TIMESTAMPTZ,
    open_vulnerabilities_count INTEGER NOT NULL DEFAULT 0,
    misconfigurations_count INTEGER NOT NULL DEFAULT 0,
    security_gate_status TEXT NOT NULL DEFAULT 'compliant' CHECK (security_gate_status IN ('compliant', 'warning', 'non_compliant')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sec_inventory_org ON security_component_inventory(organization_id);

-- Enable RLS on all 12 tables
ALTER TABLE security_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_assessment_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_test_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_finding_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_scan_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_regression_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_component_inventory ENABLE ROW LEVEL SECURITY;

-- Add RLS Tenant Isolation Policies
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_assessments' AND policyname = 'tenant_isolation_sec_assessments') THEN
        CREATE POLICY tenant_isolation_sec_assessments ON security_assessments
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_assessment_checks' AND policyname = 'tenant_isolation_sec_checks') THEN
        CREATE POLICY tenant_isolation_sec_checks ON security_assessment_checks
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_test_runs' AND policyname = 'tenant_isolation_sec_test_runs') THEN
        CREATE POLICY tenant_isolation_sec_test_runs ON security_test_runs
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_test_results' AND policyname = 'tenant_isolation_sec_test_results') THEN
        CREATE POLICY tenant_isolation_sec_test_results ON security_test_results
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_findings' AND policyname = 'tenant_isolation_sec_findings') THEN
        CREATE POLICY tenant_isolation_sec_findings ON security_findings
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_finding_notes' AND policyname = 'tenant_isolation_sec_finding_notes') THEN
        CREATE POLICY tenant_isolation_sec_finding_notes ON security_finding_notes
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_finding_history' AND policyname = 'tenant_isolation_sec_finding_history') THEN
        CREATE POLICY tenant_isolation_sec_finding_history ON security_finding_history
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_scan_configurations' AND policyname = 'tenant_isolation_sec_scan_configs') THEN
        CREATE POLICY tenant_isolation_sec_scan_configs ON security_scan_configurations
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_scan_schedules' AND policyname = 'tenant_isolation_sec_scan_schedules') THEN
        CREATE POLICY tenant_isolation_sec_scan_schedules ON security_scan_schedules
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_regression_results' AND policyname = 'tenant_isolation_sec_regression_results') THEN
        CREATE POLICY tenant_isolation_sec_regression_results ON security_regression_results
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_exceptions' AND policyname = 'tenant_isolation_sec_exceptions') THEN
        CREATE POLICY tenant_isolation_sec_exceptions ON security_exceptions
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'security_component_inventory' AND policyname = 'tenant_isolation_sec_inventory') THEN
        CREATE POLICY tenant_isolation_sec_inventory ON security_component_inventory
            FOR ALL USING (organization_id = auth.uid() OR organization_id IN (
                SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
            ));
    END IF;
END $$;
