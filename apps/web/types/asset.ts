export type DeviceType =
  | 'Laptop'
  | 'Desktop'
  | 'Server'
  | 'Router'
  | 'Mobile'
  | 'IoT'
  | 'Other';

export type RiskLevel =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Unassessed';

export type AssetStatus = 'Active' | 'Inactive' | 'Unknown';

export interface AssetRecord {
  id: string;
  organization_id: string;
  name: string;
  ip_address: string;
  mac_address?: string | null;
  device_type: DeviceType;
  operating_system?: string | null;
  hostname?: string | null;
  manufacturer?: string | null;
  risk_level: RiskLevel;
  status: AssetStatus;
  description?: string | null;
  discovery_method?: "manual" | "discovered" | string;
  confidence?: number;
  evidence?: string[];
  services?: Array<{
    id?: string;
    port: number;
    protocol: string;
    service_name?: string;
    banner?: string;
    version?: string;
  }>;
  created_at: string;
  updated_at: string;
}

export interface CreateAssetInput {
  name: string;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  device_type: DeviceType;
  operating_system?: string;
  manufacturer?: string;
  risk_level: RiskLevel;
  status: AssetStatus;
  description?: string;
}

export interface UpdateAssetInput extends Partial<CreateAssetInput> {
  id: string;
}

export interface AssetSummaryStats {
  total: number;
  active: number;
  critical: number;
  unassessed: number;
}

export interface AssetFilterParams {
  search?: string;
  device_type?: string;
  risk_level?: string;
  status?: string;
  sort_by?: 'name' | 'ip_address' | 'created_at' | 'updated_at' | 'risk_level' | 'status';
  sort_order?: 'asc' | 'desc';
  page?: number;
  page_size?: number;
}

export interface PaginatedAssetsResponse {
  assets: AssetRecord[];
  totalCount: number;
  page: number;
  pageSize: number;
  totalPages: number;
}
