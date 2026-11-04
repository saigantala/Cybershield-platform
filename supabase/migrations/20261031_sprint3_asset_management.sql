-- ==============================================================================
-- CyberShield Sprint 3 Database Migration
-- Asset Management System Schema Enhancement & RLS Policies
-- ==============================================================================

-- 1. Ensure Table Structure & Missing Columns
CREATE TABLE IF NOT EXISTS public.assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    ip_address INET NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    device_type TEXT NOT NULL DEFAULT 'Other',
    operating_system TEXT,
    manufacturer TEXT,
    risk_level TEXT NOT NULL DEFAULT 'Unassessed',
    status TEXT NOT NULL DEFAULT 'Active',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add any missing fields to existing assets table if it was created in Sprint 2
DO $$
BEGIN
    -- device_type
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='device_type') THEN
        ALTER TABLE public.assets ADD COLUMN device_type TEXT DEFAULT 'Other';
    END IF;

    -- operating_system
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='operating_system') THEN
        ALTER TABLE public.assets ADD COLUMN operating_system TEXT;
    END IF;

    -- manufacturer
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='manufacturer') THEN
        ALTER TABLE public.assets ADD COLUMN manufacturer TEXT;
    END IF;

    -- description
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='description') THEN
        ALTER TABLE public.assets ADD COLUMN description TEXT;
    END IF;

    -- created_at
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='created_at') THEN
        ALTER TABLE public.assets ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
    END IF;

    -- updated_at
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='updated_at') THEN
        ALTER TABLE public.assets ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();
    END IF;
END $$;

-- 2. Backfill Data From Sprint 2 Columns (if present)
DO $$
BEGIN
    -- Backfill device_type from category
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='category') THEN
        UPDATE public.assets 
        SET device_type = CASE 
            WHEN category = 'IoT device' THEN 'IoT'
            WHEN category IN ('Laptop', 'Desktop', 'Server', 'Router', 'Mobile') THEN category
            ELSE 'Other'
        END
        WHERE device_type IS NULL OR device_type = 'Other';
    END IF;

    -- Backfill operating_system from os
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='assets' AND column_name='os') THEN
        UPDATE public.assets 
        SET operating_system = os 
        WHERE operating_system IS NULL AND os IS NOT NULL;
    END IF;

    -- Normalize status values
    UPDATE public.assets
    SET status = CASE
        WHEN lower(status) = 'online' THEN 'Active'
        WHEN lower(status) = 'offline' THEN 'Inactive'
        WHEN lower(status) = 'unresponsive' THEN 'Unknown'
        WHEN status IN ('Active', 'Inactive', 'Unknown') THEN status
        ELSE 'Active'
    END;

    -- Normalize risk_level values
    UPDATE public.assets
    SET risk_level = CASE
        WHEN lower(risk_level) = 'critical' THEN 'Critical'
        WHEN lower(risk_level) = 'high' THEN 'High'
        WHEN lower(risk_level) = 'medium' THEN 'Medium'
        WHEN lower(risk_level) = 'low' THEN 'Low'
        WHEN lower(risk_level) = 'safe' THEN 'Low'
        WHEN lower(risk_level) = 'unassessed' THEN 'Unassessed'
        WHEN risk_level IN ('Critical', 'High', 'Medium', 'Low', 'Unassessed') THEN risk_level
        ELSE 'Unassessed'
    END;
END $$;

-- 3. Constraints for Sprint 3 Standardized Values
ALTER TABLE public.assets DROP CONSTRAINT IF EXISTS assets_device_type_check;
ALTER TABLE public.assets ADD CONSTRAINT assets_device_type_check CHECK (
    device_type IN ('Laptop', 'Desktop', 'Server', 'Router', 'Mobile', 'IoT', 'Other')
);

ALTER TABLE public.assets DROP CONSTRAINT IF EXISTS assets_risk_level_check;
ALTER TABLE public.assets ADD CONSTRAINT assets_risk_level_check CHECK (
    risk_level IN ('Critical', 'High', 'Medium', 'Low', 'Unassessed', 'critical', 'high', 'medium', 'low', 'safe')
);

ALTER TABLE public.assets DROP CONSTRAINT IF EXISTS assets_status_check;
ALTER TABLE public.assets ADD CONSTRAINT assets_status_check CHECK (
    status IN ('Active', 'Inactive', 'Unknown', 'online', 'offline', 'unresponsive')
);

-- Set defaults
ALTER TABLE public.assets ALTER COLUMN device_type SET DEFAULT 'Other';
ALTER TABLE public.assets ALTER COLUMN risk_level SET DEFAULT 'Unassessed';
ALTER TABLE public.assets ALTER COLUMN status SET DEFAULT 'Active';
ALTER TABLE public.assets ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE public.assets ALTER COLUMN updated_at SET DEFAULT NOW();

-- 4. Fast Query Indexes
CREATE INDEX IF NOT EXISTS idx_assets_org_id ON public.assets(organization_id);
CREATE INDEX IF NOT EXISTS idx_assets_device_type ON public.assets(organization_id, device_type);
CREATE INDEX IF NOT EXISTS idx_assets_risk_level ON public.assets(organization_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_assets_status ON public.assets(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON public.assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON public.assets(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_name_search ON public.assets(organization_id, name);

-- 5. Auto-Update Timestamp Trigger
CREATE OR REPLACE FUNCTION public.set_assets_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_assets_updated_at ON public.assets;
CREATE TRIGGER trigger_assets_updated_at
    BEFORE UPDATE ON public.assets
    FOR EACH ROW
    EXECUTE FUNCTION public.set_assets_updated_at();

-- 6. Row Level Security (RLS) Granular Policies
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

-- Drop legacy broad policy if exists
DROP POLICY IF EXISTS "Members can view organization assets" ON public.assets;
DROP POLICY IF EXISTS "Operators can update assets" ON public.assets;
DROP POLICY IF EXISTS "Members can view assets" ON public.assets;
DROP POLICY IF EXISTS "Authorized members can create assets" ON public.assets;
DROP POLICY IF EXISTS "Authorized members can update assets" ON public.assets;
DROP POLICY IF EXISTS "Owners and admins can delete assets" ON public.assets;

-- SELECT: All organization members (owner, admin, analyst, viewer) can view assets
CREATE POLICY "Members can view assets" ON public.assets
    FOR SELECT USING (
        organization_id IN (SELECT public.get_user_organizations())
    );

-- INSERT: Only owners, admins, and analysts can register new assets (Viewers cannot)
CREATE POLICY "Authorized members can create assets" ON public.assets
    FOR INSERT WITH CHECK (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- UPDATE: Only owners, admins, and analysts can modify asset records
CREATE POLICY "Authorized members can update assets" ON public.assets
    FOR UPDATE USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );

-- DELETE: Only owners, admins, and analysts can decommission/delete assets (Viewers cannot)
CREATE POLICY "Authorized members can delete assets" ON public.assets
    FOR DELETE USING (
        organization_id IN (SELECT public.get_user_organizations()) AND
        public.get_user_org_role(organization_id) IN ('owner', 'admin', 'analyst')
    );
