-- ==============================================================================
-- CyberShield – Sprint 9: AI-Powered SOC Assistant & Security Analytics Migration
-- ==============================================================================

-- 1. AI Conversations Table
CREATE TABLE IF NOT EXISTS public.ai_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT 'Security Consultation',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 2. AI Messages Table
CREATE TABLE IF NOT EXISTS public.ai_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES public.ai_conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    source_references JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 3. AI Security Recommendations Table
CREATE TABLE IF NOT EXISTS public.ai_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    recommendation_type TEXT NOT NULL CHECK (recommendation_type IN ('vulnerability', 'alert', 'incident', 'asset_hardening', 'suspicious_login', 'general')),
    related_entity_type TEXT NOT NULL,
    related_entity_id TEXT NOT NULL,
    recommendation JSONB NOT NULL,
    model_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending Review' CHECK (status IN ('Pending Review', 'Approved', 'Rejected', 'Implemented')),
    reviewed_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMPTZ,
    review_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 4. AI Usage & Audit Logs Table
CREATE TABLE IF NOT EXISTS public.ai_usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT 'chat',
    input_tokens INT NOT NULL DEFAULT 0,
    output_tokens INT NOT NULL DEFAULT 0,
    total_tokens INT NOT NULL DEFAULT 0,
    estimated_cost NUMERIC(10, 6) DEFAULT 0.000000,
    request_status TEXT NOT NULL DEFAULT 'success',
    latency_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.ai_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_usage_logs ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- RLS Policies
-- ------------------------------------------------------------------------------

-- ai_conversations
CREATE POLICY "Users can view conversations within their organization"
    ON public.ai_conversations FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Users can create conversations in their organization"
    ON public.ai_conversations FOR INSERT
    WITH CHECK (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Users can delete their own conversations"
    ON public.ai_conversations FOR DELETE
    USING (
        user_id = auth.uid() OR
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- ai_messages
CREATE POLICY "Users can view messages of their organization conversations"
    ON public.ai_messages FOR SELECT
    USING (
        conversation_id IN (
            SELECT id FROM public.ai_conversations
            WHERE organization_id IN (
                SELECT organization_id FROM public.organization_members
                WHERE user_id = auth.uid()
            )
        )
    );

CREATE POLICY "Users can insert messages into their organization conversations"
    ON public.ai_messages FOR INSERT
    WITH CHECK (
        conversation_id IN (
            SELECT id FROM public.ai_conversations
            WHERE organization_id IN (
                SELECT organization_id FROM public.organization_members
                WHERE user_id = auth.uid()
            )
        )
    );

-- ai_recommendations
CREATE POLICY "Users can view AI recommendations in their organization"
    ON public.ai_recommendations FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Analysts and Admins can create and review recommendations"
    ON public.ai_recommendations FOR ALL
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin', 'analyst')
        )
    );

-- ai_usage_logs
CREATE POLICY "Admins and Owners can view AI usage logs"
    ON public.ai_usage_logs FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

CREATE POLICY "System can record AI usage logs"
    ON public.ai_usage_logs FOR INSERT
    WITH CHECK (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid()
        )
    );

-- ------------------------------------------------------------------------------
-- Indexes for High Performance Retrieval
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ai_conversations_org_user ON public.ai_conversations (organization_id, user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_messages_conversation ON public.ai_messages (conversation_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_entity ON public.ai_recommendations (organization_id, related_entity_type, related_entity_id);
CREATE INDEX IF NOT EXISTS idx_ai_usage_logs_org_date ON public.ai_usage_logs (organization_id, created_at DESC);
