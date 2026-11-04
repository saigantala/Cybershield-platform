-- ==============================================================================
-- SPRINT 14: ADVANCED AI THREAT DETECTION & PREDICTIVE SECURITY INTELLIGENCE
-- ==============================================================================

-- 1. AI DETECTION MODELS REGISTRY
CREATE TABLE IF NOT EXISTS public.ai_detection_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    model_name VARCHAR(128) NOT NULL,
    model_type VARCHAR(64) NOT NULL, -- isolation_forest, statistical_baseline, ueba_ensemble, rule_engine
    description TEXT,
    active_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- active, deprecated, training, evaluating
    is_production_ready BOOLEAN NOT NULL DEFAULT FALSE, -- Clearly separates demo/pre-trained from evaluated models
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 2. AI MODEL VERSIONS & EVALUATION METRICS
CREATE TABLE IF NOT EXISTS public.ai_model_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id UUID NOT NULL REFERENCES public.ai_detection_models(id) ON DELETE CASCADE,
    version VARCHAR(32) NOT NULL,
    dataset_reference VARCHAR(256),
    training_samples_count INT NOT NULL DEFAULT 0,
    hyperparameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    evaluation_metrics JSONB NOT NULL DEFAULT '{}'::jsonb, -- precision, recall, f1, false_positive_rate, detection_rate
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    trained_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    deployed_at TIMESTAMPTZ
);

-- 3. AI DETECTION RULES (Rule-based & statistical fallback)
CREATE TABLE IF NOT EXISTS public.ai_detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    rule_name VARCHAR(128) NOT NULL,
    rule_type VARCHAR(64) NOT NULL, -- statistical_threshold, behavioral_deviation, ioc_matching, event_correlation
    description TEXT,
    severity VARCHAR(32) NOT NULL DEFAULT 'High', -- Critical, High, Medium, Low
    data_sources TEXT[] NOT NULL DEFAULT ARRAY['network_monitoring', 'auth_events'],
    threshold_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    evaluation_interval_seconds INT NOT NULL DEFAULT 300,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    matched_events_count INT NOT NULL DEFAULT 0,
    false_positive_count INT NOT NULL DEFAULT 0,
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 4. USER & ASSET BEHAVIOR BASELINES (UEBA)
CREATE TABLE IF NOT EXISTS public.ai_behavior_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES public.assets(id) ON DELETE CASCADE,
    metric_name VARCHAR(64) NOT NULL, -- daily_connections, egress_volume_bytes, unique_dst_ports, failed_logins
    baseline_mean DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    baseline_std DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    p95_value DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    sample_window_days INT NOT NULL DEFAULT 14,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 5. AI DETECTION RESULTS
CREATE TABLE IF NOT EXISTS public.ai_detection_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    source_asset_id UUID REFERENCES public.assets(id) ON DELETE SET NULL,
    source_asset_name VARCHAR(128),
    detection_category VARCHAR(64) NOT NULL, -- network_anomaly, suspicious_outbound, unusual_port, repeated_auth_failures, ueba_deviation, ioc_match, vulnerability_exposure
    severity VARCHAR(32) NOT NULL DEFAULT 'High',
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.85, -- 0.0 to 1.0
    anomaly_score DOUBLE PRECISION NOT NULL DEFAULT 0.75, -- Normalized deviation score
    detection_method VARCHAR(64) NOT NULL, -- ml_isolation_forest, statistical_baseline, deterministic_rule, ueba_behavioral
    supporting_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    recommended_investigation TEXT,
    model_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    status VARCHAR(32) NOT NULL DEFAULT 'new', -- new, investigating, confirmed_suspicious, false_positive, resolved
    detected_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 6. AI DETECTION INVESTIGATION WORKSPACE
CREATE TABLE IF NOT EXISTS public.ai_detection_investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    detection_id UUID NOT NULL REFERENCES public.ai_detection_results(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'New', -- New, Reviewing, Confirmed Suspicious, False Positive, Escalated, Resolved
    assigned_analyst UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    analyst_notes TEXT,
    findings_summary TEXT,
    timeline_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    confirmed_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 7. ANALYST FEEDBACK FOR FALSE-POSITIVE TUNING
CREATE TABLE IF NOT EXISTS public.ai_detection_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    detection_id UUID NOT NULL REFERENCES public.ai_detection_results(id) ON DELETE CASCADE,
    analyst_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    verdict VARCHAR(32) NOT NULL, -- true_positive, false_positive, benign_anomaly
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 8. PREDICTIVE ASSET RISK PREDICTIONS
CREATE TABLE IF NOT EXISTS public.ai_risk_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES public.assets(id) ON DELETE CASCADE,
    risk_score INT NOT NULL DEFAULT 50, -- 0-100 deterministic risk score
    risk_level VARCHAR(32) NOT NULL DEFAULT 'Medium', -- Critical, High, Medium, Low
    risk_trend VARCHAR(32) NOT NULL DEFAULT 'stable', -- increasing, stable, decreasing
    contributing_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.88,
    data_coverage_score DOUBLE PRECISION NOT NULL DEFAULT 0.85,
    recommended_remediation_priority VARCHAR(32) NOT NULL DEFAULT 'P2',
    predicted_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_ai_detection_models_org ON public.ai_detection_models(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_detection_rules_org ON public.ai_detection_rules(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_detection_results_org ON public.ai_detection_results(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_detection_results_asset ON public.ai_detection_results(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_ai_detection_investigations_org ON public.ai_detection_investigations(organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_risk_predictions_asset ON public.ai_risk_predictions(asset_id);

-- ROW LEVEL SECURITY (RLS)
ALTER TABLE public.ai_detection_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_model_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_behavior_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_detection_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_detection_investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_detection_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_risk_predictions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "ai_models_org_access" ON public.ai_detection_models
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_rules_org_access" ON public.ai_detection_rules
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_baselines_org_access" ON public.ai_behavior_baselines
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_results_org_access" ON public.ai_detection_results
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_investigations_org_access" ON public.ai_detection_investigations
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_feedback_org_access" ON public.ai_detection_feedback
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));

CREATE POLICY "ai_risk_predictions_org_access" ON public.ai_risk_predictions
    FOR ALL USING (organization_id IN (
        SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
    ));
