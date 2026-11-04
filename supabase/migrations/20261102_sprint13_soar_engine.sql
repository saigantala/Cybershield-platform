-- ============================================================================
-- CYBERSHIELD SPRINT 13: SECURITY ORCHESTRATION, AUTOMATION & RESPONSE (SOAR)
-- ============================================================================

-- 1. SOAR WORKFLOWS (Automated Playbook Definitions)
CREATE TABLE IF NOT EXISTS public.soar_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL DEFAULT 'incident_response' CHECK (category IN ('incident_response', 'vulnerability_management', 'threat_hunting', 'network_security', 'identity_access', 'custom')),
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('new_critical_alert', 'new_high_vulnerability', 'suspicious_network_activity', 'threat_intel_ioc_match', 'repeated_auth_failures', 'unauthorized_asset_detected', 'manual_investigation')),
    trigger_conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft', 'Published', 'Archived')),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    version INT NOT NULL DEFAULT 1,
    created_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. SOAR WORKFLOW VERSIONS (Immutable historical versions)
CREATE TABLE IF NOT EXISTS public.soar_workflow_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES public.soar_workflows(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    version INT NOT NULL,
    definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_workflow_version UNIQUE (workflow_id, version)
);

-- 3. SOAR WORKFLOW STEPS (Configurable modular step blocks)
CREATE TABLE IF NOT EXISTS public.soar_workflow_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES public.soar_workflows(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    step_type TEXT NOT NULL CHECK (step_type IN ('trigger', 'condition', 'severity_check', 'asset_lookup', 'threat_intel_lookup', 'vulnerability_lookup', 'create_incident', 'add_incident_note', 'assign_analyst', 'send_notification', 'request_approval', 'generate_report', 'end_workflow')),
    name TEXT NOT NULL,
    parameters JSONB DEFAULT '{}'::jsonb,
    next_step_id UUID,
    on_failure_step_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. SOAR WORKFLOW EXECUTIONS (Runtime state of orchestrated playbooks)
CREATE TABLE IF NOT EXISTS public.soar_workflow_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES public.soar_workflows(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    trigger_source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Running', 'Waiting_Approval', 'Completed', 'Failed', 'Cancelled')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INT,
    current_step_id UUID,
    context_data JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    retry_count INT NOT NULL DEFAULT 0,
    idempotency_key TEXT,
    triggered_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. SOAR EXECUTION STEPS (Audit of each executed step with I/O payloads)
CREATE TABLE IF NOT EXISTS public.soar_execution_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES public.soar_workflow_executions(id) ON DELETE CASCADE,
    step_id UUID,
    step_name TEXT NOT NULL,
    step_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Running', 'Completed', 'Failed', 'Skipped', 'Waiting_Approval')),
    input_payload JSONB DEFAULT '{}'::jsonb,
    output_payload JSONB DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

-- 6. SOAR EXECUTION LOGS (Redacted, structured execution log events)
CREATE TABLE IF NOT EXISTS public.soar_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES public.soar_workflow_executions(id) ON DELETE CASCADE,
    step_id UUID,
    log_level TEXT NOT NULL DEFAULT 'INFO' CHECK (log_level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR')),
    message TEXT NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. SOAR ACTION APPROVALS (Human-in-the-loop response governance)
CREATE TABLE IF NOT EXISTS public.soar_action_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    execution_id UUID NOT NULL REFERENCES public.soar_workflow_executions(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (action_type IN ('account_suspension', 'asset_isolation', 'firewall_rule_review', 'vulnerability_remediation', 'incident_escalation', 'block_indicator')),
    target_resource TEXT NOT NULL,
    justification TEXT NOT NULL,
    requested_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    approver_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    decision TEXT NOT NULL DEFAULT 'Pending' CHECK (decision IN ('Pending', 'Approved', 'Rejected', 'Expired', 'Cancelled', 'Executed', 'Execution_Failed')),
    decision_notes TEXT,
    decided_at TIMESTAMPTZ,
    execution_result JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. SOAR NOTIFICATION TEMPLATES (In-app, Email, Webhook templates)
CREATE TABLE IF NOT EXISTS public.soar_notification_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    template_name TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email', 'webhook')),
    subject TEXT,
    body_template TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. SOAR NOTIFICATION DELIVERIES (Audit log of dispatched messages)
CREATE TABLE IF NOT EXISTS public.soar_notification_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    execution_id UUID REFERENCES public.soar_workflow_executions(id) ON DELETE SET NULL,
    template_id UUID REFERENCES public.soar_notification_templates(id) ON DELETE SET NULL,
    channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email', 'webhook')),
    recipient TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Delivered' CHECK (status IN ('Pending', 'Delivered', 'Failed', 'Retrying')),
    payload JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    delivered_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR HIGH-THROUGHPUT SOAR ENGINE
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_soar_workflows_org ON public.soar_workflows(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_soar_workflows_trigger ON public.soar_workflows(trigger_type, is_enabled);
CREATE INDEX IF NOT EXISTS idx_soar_steps_wf ON public.soar_workflow_steps(workflow_id, step_order);
CREATE INDEX IF NOT EXISTS idx_soar_exec_org_status ON public.soar_workflow_executions(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_soar_exec_started ON public.soar_workflow_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_exec_steps_exec ON public.soar_execution_steps(execution_id);
CREATE INDEX IF NOT EXISTS idx_soar_exec_logs_exec ON public.soar_execution_logs(execution_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_soar_approvals_org_status ON public.soar_action_approvals(organization_id, decision);
CREATE INDEX IF NOT EXISTS idx_soar_approvals_exec ON public.soar_action_approvals(execution_id);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.soar_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_workflow_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_workflow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_workflow_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_execution_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_execution_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_action_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_notification_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_notification_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view workflows in their organization"
    ON public.soar_workflows FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Analysts and Admins can manage workflows"
    ON public.soar_workflows FOR ALL
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')));

CREATE POLICY "Users can view executions in their organization"
    ON public.soar_workflow_executions FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Users can view approvals in their organization"
    ON public.soar_action_approvals FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Analysts and Admins can decide approvals"
    ON public.soar_action_approvals FOR UPDATE
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')));

CREATE POLICY "Users can view notification deliveries in their organization"
    ON public.soar_notification_deliveries FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));
