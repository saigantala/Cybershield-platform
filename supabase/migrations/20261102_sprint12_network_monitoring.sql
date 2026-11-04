-- ============================================================================
-- CYBERSHIELD SPRINT 12: ADVANCED NETWORK MONITORING & REAL-TIME SOC MIGRATION
-- ============================================================================

-- 1. MONITORING AGENTS (Authorized endpoint & sensor agents)
CREATE TABLE IF NOT EXISTS public.monitoring_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES public.assets(id) ON DELETE SET NULL,
    agent_name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    os_type TEXT NOT NULL,
    agent_version TEXT NOT NULL DEFAULT '1.0.0',
    api_key_hash TEXT NOT NULL,
    api_key_prefix TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Offline', 'Suspended', 'Revoked')),
    last_heartbeat_at TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    config JSONB DEFAULT '{"reporting_interval_seconds": 30, "capture_telemetry": true, "capture_system_metrics": true}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_org_hostname UNIQUE (organization_id, hostname)
);

-- 2. MONITORING SESSIONS (Active reporting sessions per agent)
CREATE TABLE IF NOT EXISTS public.monitoring_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.monitoring_agents(id) ON DELETE CASCADE,
    session_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_end TIMESTAMPTZ,
    ip_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Terminated', 'Expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. NETWORK TELEMETRY (Aggregated packet metadata from authorized interfaces)
CREATE TABLE IF NOT EXISTS public.network_telemetry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES public.monitoring_agents(id) ON DELETE SET NULL,
    interface TEXT NOT NULL DEFAULT 'eth0',
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'TLS', 'OTHER')),
    source_port INTEGER,
    destination_port INTEGER,
    packet_count INTEGER NOT NULL DEFAULT 1,
    byte_count BIGINT NOT NULL DEFAULT 64,
    direction TEXT NOT NULL DEFAULT 'Inbound' CHECK (direction IN ('Inbound', 'Outbound', 'Internal')),
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. DEVICE HEALTH METRICS (Host telemetry: CPU, RAM, Disk, Interface status)
CREATE TABLE IF NOT EXISTS public.device_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES public.monitoring_agents(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES public.assets(id) ON DELETE CASCADE,
    cpu_utilization_pct NUMERIC(5,2) CHECK (cpu_utilization_pct BETWEEN 0 AND 100),
    memory_utilization_pct NUMERIC(5,2) CHECK (memory_utilization_pct BETWEEN 0 AND 100),
    disk_utilization_pct NUMERIC(5,2) CHECK (disk_utilization_pct BETWEEN 0 AND 100),
    network_interface_status TEXT NOT NULL DEFAULT 'Up',
    health_state TEXT NOT NULL DEFAULT 'Healthy' CHECK (health_state IN ('Healthy', 'Warning', 'Critical', 'Offline', 'Unknown')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. MONITORING RULES (Threshold & heuristic rules for anomaly evaluation)
CREATE TABLE IF NOT EXISTS public.monitoring_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK (rule_type IN ('traffic_spike', 'unexpected_port', 'connection_failure_burst', 'volume_anomaly', 'new_device', 'suspicious_outbound', 'ioc_traffic_match')),
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'Medium' CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    threshold NUMERIC(10,2) NOT NULL DEFAULT 100,
    time_window_seconds INTEGER NOT NULL DEFAULT 300,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    parameters JSONB DEFAULT '{}'::jsonb,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. NETWORK ANOMALIES (Detected deviations, unexpected flows & spikes)
CREATE TABLE IF NOT EXISTS public.network_anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES public.assets(id) ON DELETE SET NULL,
    source_asset TEXT,
    event_category TEXT NOT NULL CHECK (event_category IN ('traffic_spike', 'unexpected_port', 'connection_failure', 'unusual_volume', 'new_device', 'suspicious_outbound', 'ioc_match')),
    severity TEXT NOT NULL DEFAULT 'Medium' CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    rule_name TEXT NOT NULL,
    rule_id UUID REFERENCES public.monitoring_rules(id) ON DELETE SET NULL,
    evidence JSONB DEFAULT '{}'::jsonb,
    confidence INTEGER NOT NULL DEFAULT 85 CHECK (confidence BETWEEN 0 AND 100),
    recommended_investigation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Investigating', 'Resolved', 'Dismissed')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. MONITORING RULE HISTORY (Audit trail of triggered rules)
CREATE TABLE IF NOT EXISTS public.monitoring_rule_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES public.monitoring_rules(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    anomaly_id UUID REFERENCES public.network_anomalies(id) ON DELETE SET NULL,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metrics_snapshot JSONB DEFAULT '{}'::jsonb
);

-- 8. MONITORING EVENTS (Stream of real-time SOC monitoring events)
CREATE TABLE IF NOT EXISTS public.monitoring_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES public.monitoring_agents(id) ON DELETE SET NULL,
    asset_id UUID REFERENCES public.assets(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Informational' CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    title TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    event_fingerprint TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR HIGH-THROUGHPUT REAL-TIME QUERIES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_telemetry_org_captured ON public.network_telemetry(organization_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_ips ON public.network_telemetry(source_ip, destination_ip);
CREATE INDEX IF NOT EXISTS idx_device_health_org_recorded ON public.device_health_metrics(organization_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_health_asset ON public.device_health_metrics(asset_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_org_detected ON public.network_anomalies(organization_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitoring_events_org_ts ON public.monitoring_events(organization_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_monitoring_events_fp ON public.monitoring_events(event_fingerprint);
CREATE INDEX IF NOT EXISTS idx_agents_org_status ON public.monitoring_agents(organization_id, status);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================
ALTER TABLE public.monitoring_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitoring_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_health_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitoring_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitoring_rule_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitoring_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view monitoring agents in their organization"
    ON public.monitoring_agents FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Analysts and Admins can register agents"
    ON public.monitoring_agents FOR INSERT
    WITH CHECK (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')));

CREATE POLICY "Analysts and Admins can update agents"
    ON public.monitoring_agents FOR UPDATE
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')));

CREATE POLICY "Users can view telemetry in their organization"
    ON public.network_telemetry FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Service roles and agents can insert telemetry"
    ON public.network_telemetry FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Users can view device health in their organization"
    ON public.device_health_metrics FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Service roles and agents can insert health metrics"
    ON public.device_health_metrics FOR INSERT
    WITH CHECK (true);

CREATE POLICY "Users can view monitoring rules in their organization"
    ON public.monitoring_rules FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Analysts and Admins can manage monitoring rules"
    ON public.monitoring_rules FOR ALL
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')));

CREATE POLICY "Users can view network anomalies in their organization"
    ON public.network_anomalies FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));

CREATE POLICY "Users can view monitoring events in their organization"
    ON public.monitoring_events FOR SELECT
    USING (organization_id IN (SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()));
