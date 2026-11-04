-- ==============================================================================
-- CyberShield - Sprint 8 Migration: Incident Response & Security Operations
-- Multi-tenant Row-Level Security, Incident Management, MITRE ATT&CK,
-- Evidence Vault, Playbooks, and Response Approval Workflows
-- ==============================================================================

-- 1. EXTEND INCIDENTS TABLE
-- If incidents table exists from initial schema, alter to add all Sprint 8 fields
DO $$
BEGIN
    -- Add incident_number if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'incident_number') THEN
        ALTER TABLE incidents ADD COLUMN incident_number TEXT;
    END IF;

    -- Add incident_type if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'incident_type') THEN
        ALTER TABLE incidents ADD COLUMN incident_type TEXT NOT NULL DEFAULT 'Other';
    END IF;

    -- Add priority if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'priority') THEN
        ALTER TABLE incidents ADD COLUMN priority TEXT NOT NULL DEFAULT 'P3';
    END IF;

    -- Add source if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'source') THEN
        ALTER TABLE incidents ADD COLUMN source TEXT NOT NULL DEFAULT 'Manual Ingestion';
    END IF;

    -- Add created_by if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'created_by') THEN
        ALTER TABLE incidents ADD COLUMN created_by UUID REFERENCES profiles(id);
    END IF;

    -- Add detected_at if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'detected_at') THEN
        ALTER TABLE incidents ADD COLUMN detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    END IF;

    -- Add acknowledged_at if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'acknowledged_at') THEN
        ALTER TABLE incidents ADD COLUMN acknowledged_at TIMESTAMPTZ;
    END IF;

    -- Add investigation_started_at if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'investigation_started_at') THEN
        ALTER TABLE incidents ADD COLUMN investigation_started_at TIMESTAMPTZ;
    END IF;

    -- Add resolved_at if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'resolved_at') THEN
        ALTER TABLE incidents ADD COLUMN resolved_at TIMESTAMPTZ;
    END IF;

    -- Add closed_at if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'closed_at') THEN
        ALTER TABLE incidents ADD COLUMN closed_at TIMESTAMPTZ;
    END IF;

    -- Add resolution_summary if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'incidents' AND column_name = 'resolution_summary') THEN
        ALTER TABLE incidents ADD COLUMN resolution_summary TEXT;
    END IF;
END $$;

-- Populate incident_number for any existing rows and enforce uniqueness per organization
UPDATE incidents 
SET incident_number = 'CS-' || TO_CHAR(created_at, 'YYYY') || '-' || LPAD(SUBSTRING(id::text, 1, 6), 6, '0')
WHERE incident_number IS NULL;

ALTER TABLE incidents ALTER COLUMN incident_number SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_org_number ON incidents(organization_id, incident_number);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(organization_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(organization_id, created_at DESC);

-- 2. INCIDENT ALERTS LINKING TABLE
CREATE TABLE IF NOT EXISTS incident_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    linked_by UUID REFERENCES profiles(id),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_incident_alert UNIQUE (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident ON incident_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts(alert_id);

-- 3. INCIDENT NOTES TABLE
CREATE TABLE IF NOT EXISTS incident_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id UUID REFERENCES profiles(id),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id, created_at DESC);

-- 4. INCIDENT TIMELINE TABLE
CREATE TABLE IF NOT EXISTS incident_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    actor_id UUID REFERENCES profiles(id),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident ON incident_timeline(incident_id, created_at ASC);

-- 5. INCIDENT EVIDENCE VAULT
CREATE TABLE IF NOT EXISTS incident_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    evidence_name TEXT NOT NULL,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('log', 'document', 'screenshot', 'network_capture', 'forensic_artifact', 'other')),
    storage_path TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    sha256_hash TEXT NOT NULL,
    uploaded_by UUID REFERENCES profiles(id),
    description TEXT,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident ON incident_evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_hash ON incident_evidence(organization_id, sha256_hash);

-- 6. INCIDENT MITRE ATT&CK MAPPINGS
CREATE TABLE IF NOT EXISTS incident_attack_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    tactic_id TEXT NOT NULL,
    tactic_name TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    confidence INT NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 1 AND 100),
    evidence TEXT,
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_incident_technique UNIQUE (incident_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_mappings_incident ON incident_attack_mappings(incident_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique ON incident_attack_mappings(technique_id);

-- 7. RESPONSE PLAYBOOKS
CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    playbook_name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('authentication', 'malware', 'phishing', 'vulnerability', 'ransomware', 'network', 'custom')),
    description TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbooks_org ON playbooks(organization_id);

-- 8. PLAYBOOK STEPS
CREATE TABLE IF NOT EXISTS playbook_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    step_title TEXT NOT NULL,
    step_description TEXT NOT NULL,
    is_required BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_playbook_step_order UNIQUE (playbook_id, step_number)
);

CREATE INDEX IF NOT EXISTS idx_playbook_steps_playbook ON playbook_steps(playbook_id, step_number ASC);

-- 9. INCIDENT PLAYBOOK ATTACHMENTS
CREATE TABLE IF NOT EXISTS incident_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    assigned_to UUID REFERENCES profiles(id),
    status TEXT NOT NULL DEFAULT 'In Progress' CHECK (status IN ('In Progress', 'Completed', 'Abandoned')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_incident_playbook UNIQUE (incident_id, playbook_id)
);

-- 10. PLAYBOOK STEP PROGRESS
CREATE TABLE IF NOT EXISTS playbook_step_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_playbook_id UUID NOT NULL REFERENCES incident_playbooks(id) ON DELETE CASCADE,
    step_id UUID NOT NULL REFERENCES playbook_steps(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed', 'Skipped')),
    notes TEXT,
    completed_by UUID REFERENCES profiles(id),
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_step_progress UNIQUE (incident_playbook_id, step_id)
);

-- 11. RESPONSE REQUESTS
CREATE TABLE IF NOT EXISTS response_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (action_type IN ('isolate_asset', 'disable_account', 'block_firewall_rule', 'remediate_vulnerability', 'escalate_incident')),
    target_resource TEXT NOT NULL,
    justification TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    requested_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_requests_incident ON response_requests(incident_id);
CREATE INDEX IF NOT EXISTS idx_response_requests_status ON response_requests(organization_id, status);

-- 12. RESPONSE APPROVALS
CREATE TABLE IF NOT EXISTS response_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES response_requests(id) ON DELETE CASCADE,
    decided_by UUID REFERENCES profiles(id),
    decision TEXT NOT NULL CHECK (decision IN ('Approved', 'Rejected')),
    decision_notes TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_request_approval UNIQUE (request_id)
);

-- ==============================================================================
-- ROW LEVEL SECURITY POLICIES
-- ==============================================================================
ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_attack_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_step_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_approvals ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Org members can view incident alerts" ON incident_alerts
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Analysts and admins can manage incident alerts" ON incident_alerts
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view incident notes" ON incident_notes
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Analysts can manage incident notes" ON incident_notes
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view incident timeline" ON incident_timeline
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "System and analysts can append timeline" ON incident_timeline
    FOR INSERT WITH CHECK (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view evidence" ON incident_evidence
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Analysts can upload evidence" ON incident_evidence
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view attack mappings" ON incident_attack_mappings
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Analysts can manage attack mappings" ON incident_attack_mappings
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view playbooks" ON playbooks
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Admins and analysts can manage playbooks" ON playbooks
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view playbook steps" ON playbook_steps
    FOR SELECT USING (playbook_id IN (SELECT id FROM playbooks WHERE organization_id IN (SELECT get_user_organizations())));
CREATE POLICY "Admins can manage playbook steps" ON playbook_steps
    FOR ALL USING (playbook_id IN (SELECT id FROM playbooks WHERE organization_id IN (SELECT get_user_organizations())));

CREATE POLICY "Org members can view incident playbooks" ON incident_playbooks
    FOR ALL USING (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view step progress" ON playbook_step_progress
    FOR ALL USING (incident_playbook_id IN (SELECT id FROM incident_playbooks WHERE organization_id IN (SELECT get_user_organizations())));

CREATE POLICY "Org members can view response requests" ON response_requests
    FOR SELECT USING (organization_id IN (SELECT get_user_organizations()));
CREATE POLICY "Analysts can submit response requests" ON response_requests
    FOR INSERT WITH CHECK (organization_id IN (SELECT get_user_organizations()));

CREATE POLICY "Org members can view response approvals" ON response_approvals
    FOR SELECT USING (request_id IN (SELECT id FROM response_requests WHERE organization_id IN (SELECT get_user_organizations())));
CREATE POLICY "Admins can decide response approvals" ON response_approvals
    FOR INSERT WITH CHECK (request_id IN (SELECT id FROM response_requests WHERE organization_id IN (SELECT get_user_organizations())));
