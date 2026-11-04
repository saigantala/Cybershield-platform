import { createClient } from "@/lib/supabase/client";
import {
  AssetRecord,
  CreateAssetInput,
  UpdateAssetInput,
  AssetFilterParams,
  PaginatedAssetsResponse,
  AssetSummaryStats,
} from "@/types/asset";
import { mockAssets } from "@/lib/mockData";
import { validateAssetInput } from "./validation";

// Convert mock data to AssetRecord format for graceful fallback & demo states
export const fallbackAssets: AssetRecord[] = mockAssets.map((m, index) => {
  let mappedType: AssetRecord["device_type"] = "Other";
  if (m.category === "Laptop") mappedType = "Laptop";
  else if (m.category === "Desktop") mappedType = "Desktop";
  else if (m.category === "Server") mappedType = "Server";
  else if (m.category === "Router" || m.category === "Switch") mappedType = "Router";
  else if (m.category === "Mobile") mappedType = "Mobile";
  else if (m.category === "IoT device") mappedType = "IoT";

  let mappedRisk: AssetRecord["risk_level"] = "Unassessed";
  if (m.riskLevel === "critical") mappedRisk = "Critical";
  else if (m.riskLevel === "high") mappedRisk = "High";
  else if (m.riskLevel === "medium") mappedRisk = "Medium";
  else if (m.riskLevel === "low" || m.riskLevel === "safe") mappedRisk = "Low";

  let mappedStatus: AssetRecord["status"] = "Active";
  if (m.status === "offline") mappedStatus = "Inactive";
  else if (m.status === "unresponsive") mappedStatus = "Unknown";

  return {
    id: m.id,
    organization_id: m.organizationId,
    name: m.name,
    ip_address: m.ipAddress,
    mac_address: m.macAddress || null,
    device_type: mappedType,
    operating_system: m.os || "Enterprise Linux",
    hostname: m.hostname || null,
    manufacturer: index % 2 === 0 ? "Dell Technologies" : "Cisco Systems",
    risk_level: mappedRisk,
    status: mappedStatus,
    description: m.classificationEvidence || "Discovered during baseline network sweep.",
    created_at: m.firstSeen,
    updated_at: m.lastSeen,
  };
});

/**
 * Resolves current user's active organization and role from Supabase
 */
export async function getCurrentUserOrgAndRole(): Promise<{
  orgId: string | null;
  role: string | null;
  userId: string | null;
  userEmail: string | null;
}> {
  const supabase = createClient();
  const { data: { user }, error: userError } = await supabase.auth.getUser();

  if (userError || !user) {
    return { orgId: null, role: null, userId: null, userEmail: null };
  }

  // Look up membership in organization_members
  const { data: memberData } = await supabase
    .from("organization_members")
    .select("organization_id, role")
    .eq("user_id", user.id)
    .order("joined_at", { ascending: true })
    .limit(1)
    .single();

  if (memberData) {
    return {
      orgId: memberData.organization_id,
      role: memberData.role,
      userId: user.id,
      userEmail: user.email || null,
    };
  }

  // Fallback: check if user owns an organization directly
  const { data: orgData } = await supabase
    .from("organizations")
    .select("id")
    .eq("created_by", user.id)
    .limit(1)
    .single();

  return {
    orgId: orgData?.id || null,
    role: orgData ? "owner" : "analyst",
    userId: user.id,
    userEmail: user.email || null,
  };
}

/**
 * Fetch paginated assets with server-side filters & sorting
 */
export async function getAssets(params: AssetFilterParams = {}): Promise<PaginatedAssetsResponse> {
  const supabase = createClient();
  const { orgId } = await getCurrentUserOrgAndRole();

  const page = Math.max(1, params.page || 1);
  const pageSize = Math.max(1, Math.min(100, params.page_size || 10));
  const from = (page - 1) * pageSize;
  const to = from + pageSize - 1;

  if (orgId) {
    try {
      let query = supabase
        .from("assets")
        .select("*", { count: "exact" })
        .eq("organization_id", orgId);

      // Search filter across name, hostname, mac_address, ip_address
      if (params.search && params.search.trim()) {
        const term = `%${params.search.trim()}%`;
        query = query.or(`name.ilike.${term},hostname.ilike.${term},mac_address.ilike.${term}`);
      }

      // Device Type filter
      if (params.device_type && params.device_type !== "all") {
        query = query.eq("device_type", params.device_type);
      }

      // Risk Level filter
      if (params.risk_level && params.risk_level !== "all") {
        query = query.eq("risk_level", params.risk_level);
      }

      // Status filter
      if (params.status && params.status !== "all") {
        query = query.eq("status", params.status);
      }

      // Sorting
      const sortColumn = params.sort_by || "updated_at";
      const isAsc = params.sort_order === "asc";
      query = query.order(sortColumn, { ascending: isAsc });

      // Pagination
      query = query.range(from, to);

      const { data, count, error } = await query;

      if (!error && data) {
        const totalCount = count ?? data.length;
        return {
          assets: data as AssetRecord[],
          totalCount,
          page,
          pageSize,
          totalPages: Math.ceil(totalCount / pageSize) || 1,
        };
      }
    } catch (e) {
      console.warn("Supabase query error, using local fallback state", e);
    }
  }

  // In-memory fallback if no database records or demo mode
  let filtered = [...fallbackAssets];

  if (params.search && params.search.trim()) {
    const s = params.search.toLowerCase().trim();
    filtered = filtered.filter(
      (a) =>
        a.name.toLowerCase().includes(s) ||
        a.ip_address.toLowerCase().includes(s) ||
        (a.hostname && a.hostname.toLowerCase().includes(s)) ||
        (a.mac_address && a.mac_address.toLowerCase().includes(s))
    );
  }

  if (params.device_type && params.device_type !== "all") {
    filtered = filtered.filter((a) => a.device_type === params.device_type);
  }

  if (params.risk_level && params.risk_level !== "all") {
    filtered = filtered.filter((a) => a.risk_level === params.risk_level);
  }

  if (params.status && params.status !== "all") {
    filtered = filtered.filter((a) => a.status === params.status);
  }

  // Sorting
  const sortKey = (params.sort_by || "updated_at") as keyof AssetRecord;
  const isAsc = params.sort_order === "asc";
  filtered.sort((a, b) => {
    const valA = (a[sortKey] ?? "") as string;
    const valB = (b[sortKey] ?? "") as string;
    if (valA < valB) return isAsc ? -1 : 1;
    if (valA > valB) return isAsc ? 1 : -1;
    return 0;
  });

  const totalCount = filtered.length;
  const paginated = filtered.slice(from, from + pageSize);

  return {
    assets: paginated,
    totalCount,
    page,
    pageSize,
    totalPages: Math.ceil(totalCount / pageSize) || 1,
  };
}

/**
 * Fetch summary stats for assets (Total, Active, Critical, Unassessed)
 */
export async function getAssetSummaryStats(): Promise<AssetSummaryStats> {
  const supabase = createClient();
  const { orgId } = await getCurrentUserOrgAndRole();

  if (orgId) {
    try {
      const { data: allAssets, error } = await supabase
        .from("assets")
        .select("status, risk_level")
        .eq("organization_id", orgId);

      if (!error && allAssets) {
        return {
          total: allAssets.length,
          active: allAssets.filter((a) => a.status === "Active" || a.status === "online").length,
          critical: allAssets.filter(
            (a) => a.risk_level === "Critical" || a.risk_level === "critical"
          ).length,
          unassessed: allAssets.filter(
            (a) => a.risk_level === "Unassessed" || !a.risk_level
          ).length,
        };
      }
    } catch (e) {
      console.warn("Unable to fetch asset summary from Supabase", e);
    }
  }

  // Real-world default: 0 assets when none exist or unauthenticated
  return {
    total: 0,
    active: 0,
    critical: 0,
    unassessed: 0,
  };
}

/**
 * Fetch a single asset by UUID or fallback ID
 */
export async function getAssetById(id: string): Promise<AssetRecord | null> {
  const supabase = createClient();
  const { orgId } = await getCurrentUserOrgAndRole();

  if (orgId) {
    try {
      const { data, error } = await supabase
        .from("assets")
        .select("*")
        .eq("id", id)
        .eq("organization_id", orgId)
        .single();

      if (!error && data) {
        return data as AssetRecord;
      }
    } catch (e) {
      // Fall through to fallback
    }
  }

  const found = fallbackAssets.find((a) => a.id === id);
  return found || null;
}

/**
 * Create a new asset in Supabase with validation and RBAC checks
 */
export async function createAsset(
  input: CreateAssetInput
): Promise<{ success: boolean; data?: AssetRecord; error?: string }> {
  const validation = validateAssetInput(input);
  if (!validation.isValid) {
    const errorMsg = Object.values(validation.errors).join("; ");
    return { success: false, error: errorMsg };
  }

  const supabase = createClient();
  const { orgId, role, userId, userEmail } = await getCurrentUserOrgAndRole();

  if (!orgId || !userId) {
    return {
      success: false,
      error: "Authentication required. Please log in to an authorized organization.",
    };
  }

  if (role === "viewer") {
    return {
      success: false,
      error: "Access Denied: Viewers have read-only permissions and cannot register assets.",
    };
  }

  try {
    const newAssetPayload = {
      organization_id: orgId,
      name: input.name.trim(),
      ip_address: input.ip_address.trim(),
      mac_address: input.mac_address?.trim() || null,
      hostname: input.hostname?.trim() || null,
      device_type: input.device_type,
      operating_system: input.operating_system?.trim() || null,
      manufacturer: input.manufacturer?.trim() || null,
      risk_level: input.risk_level,
      status: input.status,
      description: input.description?.trim() || null,
    };

    const { data, error } = await supabase
      .from("assets")
      .insert(newAssetPayload)
      .select()
      .single();

    if (error) {
      return { success: false, error: error.message };
    }

    // Write audit log
    await supabase.from("audit_logs").insert({
      organization_id: orgId,
      actor_id: userId,
      actor_email: userEmail,
      action: "ASSET_REGISTERED",
      target_type: "asset",
      target_id: data.id,
      details: {
        name: data.name,
        ip: data.ip_address,
        device_type: data.device_type,
      },
    });

    return { success: true, data: data as AssetRecord };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to create asset" };
  }
}

/**
 * Update an existing asset with validation and RBAC checks
 */
export async function updateAsset(
  input: UpdateAssetInput
): Promise<{ success: boolean; data?: AssetRecord; error?: string }> {
  const validation = validateAssetInput(input);
  if (!validation.isValid) {
    const errorMsg = Object.values(validation.errors).join("; ");
    return { success: false, error: errorMsg };
  }

  const supabase = createClient();
  const { orgId, role, userId, userEmail } = await getCurrentUserOrgAndRole();

  if (!orgId || !userId) {
    return {
      success: false,
      error: "Authentication required. Please log in to modify assets.",
    };
  }

  if (role === "viewer") {
    return {
      success: false,
      error: "Access Denied: Viewers have read-only permissions and cannot edit assets.",
    };
  }

  try {
    const updatePayload = {
      name: input.name?.trim(),
      ip_address: input.ip_address?.trim(),
      mac_address: input.mac_address?.trim() || null,
      hostname: input.hostname?.trim() || null,
      device_type: input.device_type,
      operating_system: input.operating_system?.trim() || null,
      manufacturer: input.manufacturer?.trim() || null,
      risk_level: input.risk_level,
      status: input.status,
      description: input.description?.trim() || null,
      updated_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from("assets")
      .update(updatePayload)
      .eq("id", input.id)
      .eq("organization_id", orgId)
      .select()
      .single();

    if (error) {
      return { success: false, error: error.message };
    }

    // Write audit log
    await supabase.from("audit_logs").insert({
      organization_id: orgId,
      actor_id: userId,
      actor_email: userEmail,
      action: "ASSET_MODIFIED",
      target_type: "asset",
      target_id: input.id,
      details: {
        name: updatePayload.name,
        ip: updatePayload.ip_address,
      },
    });

    return { success: true, data: data as AssetRecord };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to update asset" };
  }
}

/**
 * Delete an asset with permission check and audit logging
 */
export async function deleteAsset(
  id: string
): Promise<{ success: boolean; error?: string }> {
  const supabase = createClient();
  const { orgId, role, userId, userEmail } = await getCurrentUserOrgAndRole();

  if (!orgId || !userId) {
    return {
      success: false,
      error: "Authentication required. Please log in to decommission assets.",
    };
  }

  if (role === "viewer") {
    return {
      success: false,
      error: "Access Denied: Viewers have read-only permissions and cannot delete assets.",
    };
  }

  try {
    // Fetch asset details prior to deletion for audit trail
    const { data: assetToDelete } = await supabase
      .from("assets")
      .select("name, ip_address")
      .eq("id", id)
      .eq("organization_id", orgId)
      .single();

    const { error } = await supabase
      .from("assets")
      .delete()
      .eq("id", id)
      .eq("organization_id", orgId);

    if (error) {
      return { success: false, error: error.message };
    }

    // Write audit log
    await supabase.from("audit_logs").insert({
      organization_id: orgId,
      actor_id: userId,
      actor_email: userEmail,
      action: "ASSET_DECOMMISSIONED",
      target_type: "asset",
      target_id: id,
      details: {
        name: assetToDelete?.name || "Unknown Asset",
        ip: assetToDelete?.ip_address || "N/A",
      },
    });

    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message || "Failed to delete asset" };
  }
}
