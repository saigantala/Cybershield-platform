-- ==============================================================================
-- SPRINT 15: ENTERPRISE INTEGRATIONS & EXTERNAL SECURITY ECOSYSTEM
-- ==============================================================================

-- 1. INTEGRATIONS CATALOG & CONFIGURATION
CREATE TABLE IF NOT EXISTS public.integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    slug VARCHAR(64) NOT NULL, -- splunk, sentinel, elastic, wazuh, slack, teams, email, cisa_kev, urlhaus, aws_security, azure_sentinel, gcp_scc
    category VARCHAR(64) NOT NULL, -- siem, communication, threat_intelligence, cloud_security, webhooks, auth_sso, monitoring
    provider VARCHAR(64) NOT NULL,
    description TEXT,
    connection_status VARCHAR(32) NOT NULL DEFAULT 'Disconnected', -- Connected, Disconnected, Pending_Configuration, Error, Disabled
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    health_status VARCHAR(32) NOT NULL DEFAULT 'Healthy', -- Healthy, Degraded, Critical, Unknown
    config JSONB NOT NULL DEFAULT '{}'::jsonb, -- Endpoint URL, channel, index name, timeout, etc. (no raw secret keys)
    last_synced_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 2. INTEGRATION CREDENTIALS (Secure Server-Side References)
CREATE TABLE IF NOT EXISTS public.integration_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES public.integrations(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    key_name VARCHAR(64) NOT NULL, -- api_token, webhook_url, client_secret, private_key
    encrypted_secret TEXT NOT NULL, -- Server-side encrypted or hashed reference
    secret_masked VARCHAR(64) NOT NULL, -- e.g. "sk_live_...9x4b"
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 3. INTEGRATION SYNCHRONIZATION HISTORY
CREATE TABLE IF NOT EXISTS public.integration_sync_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES public.integrations(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    sync_type VARCHAR(64) NOT NULL DEFAULT 'scheduled', -- scheduled, manual, real_time
    status VARCHAR(32) NOT NULL DEFAULT 'Success', -- Success, Failed, Partial
    items_synced INT NOT NULL DEFAULT 0,
    duration_ms INT NOT NULL DEFAULT 0,
    error_message TEXT,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 4. INTEGRATION EVENT DELIVERY LOGS
CREATE TABLE IF NOT EXISTS public.integration_delivery_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES public.integrations(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL, -- alert_export, incident_sync, notification_dispatch
    status VARCHAR(32) NOT NULL DEFAULT 'Delivered', -- Delivered, Failed, Retrying
    http_status_code INT,
    attempt_count INT NOT NULL DEFAULT 1,
    payload_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_summary TEXT,
    duration_ms INT NOT NULL DEFAULT 0,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 5. WEBHOOK ENDPOINTS (Secure Outgoing Webhooks)
CREATE TABLE IF NOT EXISTS public.webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    secret_token VARCHAR(128) NOT NULL, -- HMAC-SHA256 signing secret
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    events TEXT[] NOT NULL DEFAULT ARRAY['alert.created', 'incident.created'],
    retry_limit INT NOT NULL DEFAULT 3,
    timeout_seconds INT NOT NULL DEFAULT 10,
    failure_count INT NOT NULL DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 6. WEBHOOK DELIVERY ATTEMPTS & REPLAY LOGS
CREATE TABLE IF NOT EXISTS public.webhook_delivery_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES public.webhook_endpoints(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'Delivered', -- Delivered, Failed, Pending_Retry
    http_status_code INT,
    attempt_number INT NOT NULL DEFAULT 1,
    response_body TEXT,
    error_message TEXT,
    duration_ms INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_integrations_org ON public.integrations(organization_id);
CREATE INDEX IF NOT EXISTS idx_integrations_category ON public.integrations(category);
CREATE INDEX IF NOT EXISTS idx_integration_logs_org ON public.integration_delivery_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_org ON public.webhook_endpoints(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhook_attempts_endpoint ON public.webhook_delivery_attempts(webhook_id);

-- ROW LEVEL SECURITY (RLS)
ALTER TABLE public.integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integration_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integration_sync_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.integration_delivery_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_delivery_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "integrations_org_access" ON public.integrations
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "integration_credentials_org_access" ON public.integration_credentials
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "integration_sync_org_access" ON public.integration_sync_history
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "integration_logs_org_access" ON public.integration_delivery_logs
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "webhook_endpoints_org_access" ON public.webhook_endpoints
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "webhook_attempts_org_access" ON public.webhook_delivery_attempts
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));
