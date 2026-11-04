"use client";

import { useState, useEffect, useCallback } from "react";
import { Plus, Server, CheckCircle2, AlertCircle } from "lucide-react";
import {
  AssetRecord,
  CreateAssetInput,
  AssetSummaryStats,
} from "@/types/asset";
import {
  getAssets,
  getAssetSummaryStats,
  createAsset,
  updateAsset,
  deleteAsset,
  getCurrentUserOrgAndRole,
} from "@/lib/assets/asset-service";
import { AssetSummaryCards } from "@/components/assets/AssetSummaryCards";
import { AssetFilters } from "@/components/assets/AssetFilters";
import { AssetTable } from "@/components/assets/AssetTable";
import { AssetFormModal } from "@/components/assets/AssetFormModal";
import { AssetDetailsModal } from "@/components/assets/AssetDetailsModal";
import { DeleteAssetDialog } from "@/components/assets/DeleteAssetDialog";

export default function AssetManagementPage() {
  // Asset records & state
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [stats, setStats] = useState<AssetSummaryStats>({
    total: 0,
    active: 0,
    critical: 0,
    unassessed: 0,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [userRole, setUserRole] = useState<string | null>(null);

  // Search & Filters
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedDeviceType, setSelectedDeviceType] = useState<string>("all");
  const [selectedRisk, setSelectedRisk] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");

  // Sorting
  const [sortField, setSortField] = useState<string>("updated_at");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("desc");

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Modals & Panels
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<AssetRecord | null>(null);
  const [inspectingAsset, setInspectingAsset] = useState<AssetRecord | null>(null);
  const [deletingAsset, setDeletingAsset] = useState<AssetRecord | null>(null);

  // Notifications
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const showNotification = (type: "success" | "error", message: string) => {
    setFeedback({ type, message });
    setTimeout(() => {
      setFeedback(null);
    }, 4500);
  };

  // Fetch data
  const fetchData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [assetsRes, statsRes, userAuth] = await Promise.all([
        getAssets({
          search: searchTerm,
          device_type: selectedDeviceType,
          risk_level: selectedRisk,
          status: selectedStatus,
          sort_by: sortField as any,
          sort_order: sortDirection,
          page: currentPage,
          page_size: pageSize,
        }),
        getAssetSummaryStats(),
        getCurrentUserOrgAndRole(),
      ]);

      setAssets(assetsRes.assets);
      setTotalCount(assetsRes.totalCount);
      setStats(statsRes);
      setUserRole(userAuth.role);
    } catch (e: any) {
      showNotification("error", e.message || "Failed to load asset inventory");
    } finally {
      setIsLoading(false);
    }
  }, [
    searchTerm,
    selectedDeviceType,
    selectedRisk,
    selectedStatus,
    sortField,
    sortDirection,
    currentPage,
    pageSize,
  ]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Handle Sort
  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("desc");
    }
    setCurrentPage(1);
  };

  // Reset Filters
  const handleResetFilters = () => {
    setSearchTerm("");
    setSelectedDeviceType("all");
    setSelectedRisk("all");
    setSelectedStatus("all");
    setCurrentPage(1);
  };

  // Form Submissions (Create / Update)
  const handleFormSubmit = async (
    input: CreateAssetInput,
    assetId?: string
  ): Promise<{ success: boolean; error?: string }> => {
    if (assetId) {
      // Update
      const res = await updateAsset({ ...input, id: assetId });
      if (res.success) {
        showNotification("success", `Asset "${input.name}" successfully updated.`);
        setEditingAsset(null);
        fetchData();
        return { success: true };
      }
      return { success: false, error: res.error };
    } else {
      // Create
      const res = await createAsset(input);
      if (res.success) {
        showNotification("success", `Asset "${input.name}" registered successfully.`);
        setIsAddOpen(false);
        fetchData();
        return { success: true };
      }
      return { success: false, error: res.error };
    }
  };

  // Delete Action
  const handleDeleteConfirm = async (
    assetId: string
  ): Promise<{ success: boolean; error?: string }> => {
    const res = await deleteAsset(assetId);
    if (res.success) {
      showNotification("success", "Asset decommissioned and removed from inventory.");
      setDeletingAsset(null);
      fetchData();
      return { success: true };
    }
    return { success: false, error: res.error };
  };

  const isViewer = userRole === "viewer";

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Server className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Asset Management
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Monitor and manage your organization&apos;s infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {!isViewer && (
            <button
              onClick={() => setIsAddOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white shadow-lg shadow-blue-500/20 hover:from-blue-500 hover:to-cyan-500 active:scale-95 transition-all"
            >
              <Plus className="h-4 w-4" />
              <span>Add Asset</span>
            </button>
          )}
        </div>
      </div>

      {/* Dynamic Feedback Alert */}
      {feedback && (
        <div
          className={`p-3.5 rounded-xl border flex items-center justify-between gap-3 text-xs animate-in fade-in slide-in-from-top-2 duration-200 ${
            feedback.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-rose-500/10 border-rose-500/30 text-rose-300"
          }`}
        >
          <div className="flex items-center gap-2.5">
            {feedback.type === "success" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            ) : (
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            )}
            <span className="font-semibold">{feedback.message}</span>
          </div>
          <button
            onClick={() => setFeedback(null)}
            className="text-slate-400 hover:text-white text-xs"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Summary Cards */}
      <AssetSummaryCards stats={stats} isLoading={isLoading} />

      {/* Search and Filters Bar */}
      <AssetFilters
        searchTerm={searchTerm}
        onSearchChange={(val) => {
          setSearchTerm(val);
          setCurrentPage(1);
        }}
        selectedDeviceType={selectedDeviceType}
        onDeviceTypeChange={(val) => {
          setSelectedDeviceType(val);
          setCurrentPage(1);
        }}
        selectedRisk={selectedRisk}
        onRiskChange={(val) => {
          setSelectedRisk(val);
          setCurrentPage(1);
        }}
        selectedStatus={selectedStatus}
        onStatusChange={(val) => {
          setSelectedStatus(val);
          setCurrentPage(1);
        }}
        onReset={handleResetFilters}
        totalFiltered={totalCount}
      />

      {/* Assets Table */}
      <AssetTable
        assets={assets}
        totalCount={totalCount}
        currentPage={currentPage}
        pageSize={pageSize}
        onPageChange={setCurrentPage}
        sortField={sortField}
        sortDirection={sortDirection}
        onSort={handleSort}
        onInspect={(asset) => setInspectingAsset(asset)}
        onEdit={(asset) => setEditingAsset(asset)}
        onDelete={(asset) => setDeletingAsset(asset)}
        userRole={userRole}
        isLoading={isLoading}
      />

      {/* Add / Edit Asset Modal */}
      <AssetFormModal
        isOpen={isAddOpen || Boolean(editingAsset)}
        onClose={() => {
          setIsAddOpen(false);
          setEditingAsset(null);
        }}
        onSubmit={handleFormSubmit}
        initialData={editingAsset}
      />

      {/* Asset Inspection Modal */}
      <AssetDetailsModal
        isOpen={Boolean(inspectingAsset)}
        asset={inspectingAsset}
        onClose={() => setInspectingAsset(null)}
        onEdit={(asset) => setEditingAsset(asset)}
        userRole={userRole}
      />

      {/* Decommission Asset Dialog */}
      <DeleteAssetDialog
        isOpen={Boolean(deletingAsset)}
        asset={deletingAsset}
        onClose={() => setDeletingAsset(null)}
        onConfirm={handleDeleteConfirm}
      />
    </div>
  );
}
