export type OrganizationRole = 'owner' | 'admin' | 'analyst' | 'viewer';

export interface Organization {
  id: string;
  name: string;
  slug?: string;
  description?: string;
  website?: string;
  industry?: string;
  organization_size?: string;
  country?: string;
  time_zone?: string;
  status: 'Active' | 'Suspended';
  suspension_reason?: string;
  created_at: string;
  member_count: number;
  current_plan?: string;
  user_role?: OrganizationRole;
}

export interface OrganizationMember {
  id: string;
  user_id: string;
  organization_id: string;
  email: string;
  role: OrganizationRole;
  full_name?: string;
  joined_at: string;
  last_active?: string;
}

export interface OrganizationInvitation {
  id: string;
  organization_id: string;
  email: string;
  role: OrganizationRole;
  status: 'Pending' | 'Accepted' | 'Expired' | 'Cancelled';
  invited_by?: string;
  expires_at: string;
  created_at: string;
}

export interface SubscriptionPlan {
  id: string;
  plan_name: string;
  plan_code: 'FREE' | 'PROFESSIONAL' | 'ENTERPRISE';
  description: string;
  price: number;
  currency: string;
  billing_interval: 'monthly' | 'yearly';
  max_members: number;
  max_assets: number;
  monthly_scan_limit: number;
  ai_usage_limit: number;
  feature_flags: Record<string, boolean>;
  is_active: boolean;
}

export interface OrganizationSubscription {
  id: string;
  organization_id: string;
  plan_id: string;
  plan_name: string;
  plan_code: string;
  status: 'Trial' | 'Active' | 'Past Due' | 'Cancelled' | 'Expired' | 'Suspended';
  billing_provider: string;
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  price: number;
}

export interface SubscriptionUsage {
  organization_id: string;
  plan_code: string;
  assets_used: number;
  assets_limit: number;
  members_used: number;
  members_limit: number;
  monthly_scans_used: number;
  monthly_scans_limit: number;
  ai_requests_used: number;
  ai_requests_limit: number;
  period_start: string;
  period_end: string;
}

export interface APIKey {
  id: string;
  organization_id: string;
  key_name: string;
  key_prefix: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  is_revoked: boolean;
}

export interface APIKeyCreated extends APIKey {
  raw_api_key: string;
}

export interface PlatformOverview {
  total_users: number;
  total_organizations: number;
  active_subscriptions: number;
  trial_organizations: number;
  suspended_organizations: number;
  total_assets_monitored: number;
  background_worker_health: string;
  api_gateway_health: string;
  db_connectivity: string;
}
