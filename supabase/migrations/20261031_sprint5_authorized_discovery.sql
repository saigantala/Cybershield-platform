-- ==============================================================================
-- CyberShield Sprint 5 Database Migration
-- Authorized Network Discovery, Scope Management, Services & Interface Telemetry
-- ==============================================================================

-- 1. Enhance Scan Scopes Table
DO $$
BEGIN
    -- scope_name
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='scope_name') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN scope_name TEXT;
    END IF;

    -- cidr_range
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='cidr_range') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN cidr_range TEXT;
    END IF;

    -- authorization_status (Pending, Approved, Rejected, Expired)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='authorization_status') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN authorization_status TEXT DEFAULT 'Pending';
    END IF;

    -- authorization_basis
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='authorization_basis') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN authorization_basis TEXT;
    END IF;

    -- expires_at
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='expires_at') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN expires_at TIMESTAMPTZ;
    END IF;

    -- max_scan_rate
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scan_scopes' AND column_name='max_scan_rate') THEN
        ALTER TABLE public.scan_scopes ADD COLUMN max_scan_rate INTEGER DEFAULT 1000;
    END IF;
END $$;

-- Populate cidr_range and scope_name from target if empty
UPDATE public.scan_scopes 
SET 
    cidr_range = COALESCE(cidr_range, target),
    scope_name = COALESCE(scope_name, 'Scope ' || target),
    authorization_status = CASE 
        WHEN status = 'approved' THEN 'Approved'
        WHEN status = 'rejected' THEN 'Rejected'
        WHEN status = 'revoked' THEN 'Expired'
        ELSE 'Pending'
    END,
    expires_at = COALESCE(expires_at, NOW() + INTERVAL '90 days')
WHERE cidr_range IS NULL;

-- 2. Enhance Scans Table with scope_id and error_message
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scans' AND column_name='scope_id') THEN
        ALTER TABLE public.scans ADD COLUMN scope_id UUID REFERENCES public.scan_scopes(id) ON DELETE SET NULL;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scans' AND column_name='error_message') THEN
        ALTER TABLE public.scans ADD COLUMN error_message TEXT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='scans' AND column_name='task_id') THEN
        ALTER TABLE public.scans ADD COLUMN task_id TEXT;
    END IF;
END $$;

-- 3. Enhance Assets Table with discovery tracking & evidence
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='discovery_method') THEN
        ALTER TABLE public.assets ADD COLUMN discovery_method TEXT DEFAULT 'manual';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='confidence') THEN
        ALTER TABLE public.assets ADD COLUMN confidence INTEGER DEFAULT 50;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='evidence') THEN
        ALTER TABLE public.assets ADD COLUMN evidence TEXT[] DEFAULT '{}';
    END IF;
END $$;

-- 4. Create Scan Events Table (Live Telemetry & Timeline)
CREATE TABLE IF NOT EXISTS public.scan_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Create Asset Interfaces Table
CREATE TABLE IF NOT EXISTS public.asset_interfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES public.assets(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    mac_address TEXT,
    interface_name TEXT DEFAULT 'eth0',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Create Services Table (Discovered TCP/UDP Ports)
CREATE TABLE IF NOT EXISTS public.services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES public.assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp')),
    service_name TEXT NOT NULL DEFAULT 'unknown',
    service_version TEXT,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'filtered', 'closed')),
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

-- 7. Indexes for Query Performance
CREATE INDEX IF NOT EXISTS idx_scan_scopes_org_status ON public.scan_scopes(organization_id, authorization_status);
CREATE INDEX IF NOT EXISTS idx_scan_scopes_expires ON public.scan_scopes(expires_at);
CREATE INDEX IF NOT EXISTS idx_scans_scope_id ON public.scans(scope_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON public.scan_events(scan_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_services_asset_id ON public.services(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_interfaces_asset_id ON public.asset_interfaces(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_org_ip ON public.assets(organization_id, ip_address);

-- 8. Row Level Security (RLS) Policies

-- Scan Scopes: Members can view, Analysts/Admins/Owners can insert, Only Owners/Admins can approve
ALTER TABLE public.scan_scopes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Members can view approved scopes" ON public.scan_scopes;
DROP POLICY IF EXISTS "Owners and admins can manage scopes" ON public.scan_scopes;
DROP POLICY IF EXISTS "Members can view scopes" ON public.scan_scopes;
DROP POLICY IF EXISTS "Authorized members can create scopes" ON public.scan_scopes;
DROP POLICY IF EXISTS "Owners and admins can approve scopes" ON public.scan_scopes;

CREATE POLICY "Members can view scopes" ON public.scan_scopes
    FOR SELECT USING (organization_id IN (SELECT public.get_user_organizations()));

CREATE POLICY "Authorized members can create scopes" ON public.scan_scopes
    FOR INSERT WITH CHECK (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

CREATE POLICY "Owners and admins can approve scopes" ON public.scan_scopes
    FOR UPDATE USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin')
    );

-- Scan Events: Members can view events of their organization's scans
ALTER TABLE public.scan_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Members can view scan events" ON public.scan_events;
CREATE POLICY "Members can view scan events" ON public.scan_events
    FOR SELECT USING (
        scan_id IN (
            SELECT id FROM public.scans 
            WHERE organization_id IN (SELECT public.get_user_organizations())
        )
    );

DROP POLICY IF EXISTS "Workers can append scan events" ON public.scan_events;
CREATE POLICY "Workers can append scan events" ON public.scan_events
    FOR INSERT WITH CHECK (
        scan_id IN (
            SELECT id FROM public.scans 
            WHERE organization_id IN (SELECT public.get_user_organizations())
        )
    );

-- Services: Members can view services on organization assets
ALTER TABLE public.services ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Members can view discovered services" ON public.services;
CREATE POLICY "Members can view discovered services" ON public.services
    FOR SELECT USING (
        asset_id IN (
            SELECT id FROM public.assets 
            WHERE organization_id IN (SELECT public.get_user_organizations())
        )
    );

DROP POLICY IF EXISTS "Operators and workers can upsert services" ON public.services;
CREATE POLICY "Operators and workers can upsert services" ON public.services
    FOR ALL USING (
        asset_id IN (
            SELECT id FROM public.assets 
            WHERE organization_id IN (SELECT public.get_user_organizations()) AND
            public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
        )
    );

-- Asset Interfaces: Members can view interfaces
ALTER TABLE public.asset_interfaces ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Members can view asset interfaces" ON public.asset_interfaces;
CREATE POLICY "Members can view asset interfaces" ON public.asset_interfaces
    FOR SELECT USING (
        asset_id IN (
            SELECT id FROM public.assets 
            WHERE organization_id IN (SELECT public.get_user_organizations())
        )
    );

DROP POLICY IF EXISTS "Operators and workers can manage interfaces" ON public.asset_interfaces;
CREATE POLICY "Operators and workers can manage interfaces" ON public.asset_interfaces
    FOR ALL USING (
        asset_id IN (
            SELECT id FROM public.assets 
            WHERE organization_id IN (SELECT public.get_user_organizations()) AND
            public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
        )
    );
