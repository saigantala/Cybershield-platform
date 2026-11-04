-- ==============================================================================
-- CyberShield – Sprint 10: Enterprise SaaS, Multi-Tenancy & Subscriptions Migration
-- ==============================================================================

-- 1. Extend Organizations Table
ALTER TABLE public.organizations 
    ADD COLUMN IF NOT EXISTS slug TEXT,
    ADD COLUMN IF NOT EXISTS website TEXT,
    ADD COLUMN IF NOT EXISTS industry TEXT,
    ADD COLUMN IF NOT EXISTS organization_size TEXT,
    ADD COLUMN IF NOT EXISTS country TEXT DEFAULT 'US',
    ADD COLUMN IF NOT EXISTS time_zone TEXT DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Suspended')),
    ADD COLUMN IF NOT EXISTS suspension_reason TEXT;

-- 2. Extend Profiles Table for Platform Admin distinction
ALTER TABLE public.profiles
    ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- 3. Subscription Plans Table
CREATE TABLE IF NOT EXISTS public.subscription_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_name TEXT NOT NULL,
    plan_code TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
    currency TEXT NOT NULL DEFAULT 'USD',
    billing_interval TEXT NOT NULL DEFAULT 'monthly' CHECK (billing_interval IN ('monthly', 'yearly')),
    max_members INT NOT NULL DEFAULT 3,
    max_assets INT NOT NULL DEFAULT 25,
    monthly_scan_limit INT NOT NULL DEFAULT 10,
    ai_usage_limit INT NOT NULL DEFAULT 50,
    feature_flags JSONB NOT NULL DEFAULT '{"threat_intel": false, "incident_response": false, "custom_playbooks": false}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 4. Organization Subscriptions Table
CREATE TABLE IF NOT EXISTS public.organization_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES public.subscription_plans(id),
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Trial', 'Active', 'Past Due', 'Cancelled', 'Expired', 'Suspended')),
    billing_provider TEXT NOT NULL DEFAULT 'mock',
    provider_customer_id TEXT,
    provider_subscription_id TEXT,
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    current_period_end TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now() + interval '30 days'),
    trial_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT uq_org_subscription UNIQUE (organization_id)
);

-- 5. Subscription Usage Metering Table
CREATE TABLE IF NOT EXISTS public.subscription_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    usage_type TEXT NOT NULL CHECK (usage_type IN ('assets', 'members', 'monthly_scans', 'ai_requests', 'report_exports')),
    usage_count INT NOT NULL DEFAULT 0,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT uq_org_usage_period UNIQUE (organization_id, usage_type, period_start)
);

-- 6. Organization Invitations Table
CREATE TABLE IF NOT EXISTS public.organization_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    invitation_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Accepted', 'Expired', 'Cancelled')),
    invited_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now() + interval '7 days'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 7. Organization API Keys Table
CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    key_name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{read:assets, read:scans}',
    created_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- 8. Platform Admin Audit Logs Table
CREATE TABLE IF NOT EXISTS public.platform_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    target_entity_type TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Enable RLS
ALTER TABLE public.subscription_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscription_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_audit_logs ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- RLS Policies
-- ------------------------------------------------------------------------------

-- subscription_plans: publicly readable
CREATE POLICY "Subscription plans are visible to all users"
    ON public.subscription_plans FOR SELECT
    USING (is_active = TRUE);

-- organization_subscriptions: visible to organization members, manageable by owner
CREATE POLICY "Members can view their organization subscription"
    ON public.organization_subscriptions FOR SELECT
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid()
        )
    );

-- organization_invitations
CREATE POLICY "Admins and Owners can view and manage team invitations"
    ON public.organization_invitations FOR ALL
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- api_keys: visible and manageable by Admins and Owners
CREATE POLICY "Admins and Owners can manage API keys"
    ON public.api_keys FOR ALL
    USING (
        organization_id IN (
            SELECT organization_id FROM public.organization_members
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );

-- platform_audit_logs: restricted strictly to platform admins
CREATE POLICY "Only platform admins can view platform audit logs"
    ON public.platform_audit_logs FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM public.profiles
            WHERE id = auth.uid() AND is_platform_admin = TRUE
        )
    );
