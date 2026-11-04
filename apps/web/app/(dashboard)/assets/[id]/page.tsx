"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Server,
  Laptop,
  Monitor,
  Smartphone,
  Cpu,
  Layers,
  HardDrive,
  Calendar,
  Clock,
  Shield,
  Activity,
  Copy,
  Check,
  Edit2,
  Trash2,
  AlertTriangle,
} from "lucide-react";
import { AssetRecord, DeviceType } from "@/types/asset";
import {
  getAssetById,
  deleteAsset,
  updateAsset,
  getCurrentUserOrgAndRole,
} from "@/lib/assets/asset-service";
import { formatDateTime } from "@/lib/utils";
import { AssetFormModal } from "@/components/assets/AssetFormModal";
import { DeleteAssetDialog } from "@/components/assets/DeleteAssetDialog";

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params?.id as string;

  const [asset, setAsset] = useState<AssetRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [userRole, setUserRole] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Edit / Delete dialogs
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);

  useEffect(() => {
    async function loadData() {
      setIsLoading(true);
      const { role } = await getCurrentUserOrgAndRole();
      setUserRole(role);

      if (assetId) {
        const found = await getAssetById(assetId);
        setAsset(found);
      }
      setIsLoading(false);
    }
    loadData();
  }, [assetId]);

  const copyId = () => {
    if (asset?.id) {
      navigator.clipboard.writeText(asset.id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getDeviceIcon = (deviceType: DeviceType) => {
    switch (deviceType) {
      case "Laptop":
        return Laptop;
      case "Desktop":
        return Monitor;
      case "Server":
        return Server;
      case "Router":
        return Layers;
      case "Mobile":
        return Smartphone;
      case "IoT":
        return Cpu;
      default:
        return HardDrive;
    }
  };

  const handleUpdate = async (input: any) => {
    if (!asset) return { success: false, error: "Asset not loaded" };
    const res = await updateAsset({ ...input, id: asset.id });
    if (res.success && res.data) {
      setAsset(res.data);
    }
    return res;
  };

  const handleDelete = async (id: string) => {
    const res = await deleteAsset(id);
    if (res.success) {
      router.push("/assets");
    }
    return res;
  };

  if (isLoading) {
    return (
      <div className="py-24 flex flex-col items-center justify-center gap-3">
        <div className="h-8 w-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-slate-400 font-mono">Loading asset record...</p>
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="py-16 text-center space-y-4">
        <div className="p-3 w-12 h-12 mx-auto rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center">
          <AlertTriangle className="h-6 w-6" />
        </div>
        <h2 className="text-lg font-bold text-white">Asset Not Found</h2>
        <p className="text-xs text-slate-400 max-w-sm mx-auto">
          The requested infrastructure asset could not be located in your organization&apos;s inventory.
        </p>
        <Link
          href="/assets"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-xs font-semibold text-white hover:bg-blue-500"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Return to Assets</span>
        </Link>
      </div>
    );
  }

  const DeviceIcon = getDeviceIcon(asset.device_type);

  return (
    <div className="space-y-6">
      {/* Back button and actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            href="/assets"
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white hover:border-cyan-400 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                {asset.name}
              </h1>
              <span
                className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                  asset.status === "Active"
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    : "bg-slate-500/10 text-slate-400 border-slate-700"
                }`}
              >
                {asset.status}
              </span>
            </div>
            <p className="text-xs font-mono text-cyan-400 mt-0.5">
              IP: {asset.ip_address} {asset.hostname ? `• Host: ${asset.hostname}` : ""}
            </p>
          </div>
        </div>

        {userRole !== "viewer" && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsEditOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#111C2D] border border-blue-500/30 text-xs font-semibold text-slate-200 hover:text-white hover:border-blue-400 transition-colors"
            >
              <Edit2 className="h-3.5 w-3.5 text-amber-400" />
              <span>Edit Asset</span>
            </button>

            <button
              onClick={() => setIsDeleteOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-rose-600/10 border border-rose-500/30 text-xs font-semibold text-rose-300 hover:bg-rose-600 hover:text-white transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Decommission</span>
            </button>
          </div>
        )}
      </div>

      {/* UUID Card */}
      <div className="soc-glass rounded-xl p-3 border border-blue-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2 font-mono">
          <span className="text-slate-400">Inventory ID:</span>
          <span className="text-slate-200">{asset.id}</span>
        </div>
        <button
          onClick={copyId}
          className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              <span>Copy UUID</span>
            </>
          )}
        </button>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Specifications */}
        <div className="lg:col-span-2 space-y-6">
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <DeviceIcon className="h-4 w-4 text-cyan-400" />
              Hardware & Network Telemetry
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">Device Type</span>
                <span className="font-semibold text-white text-sm">{asset.device_type}</span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">Operating System</span>
                <span className="font-semibold text-white text-sm">
                  {asset.operating_system || "Not Specified"}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">Manufacturer</span>
                <span className="font-semibold text-white text-sm">
                  {asset.manufacturer || "Generic / Unbranded"}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">MAC Address</span>
                <span className="font-mono text-cyan-300 text-sm">
                  {asset.mac_address || "None recorded"}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">Hostname (FQDN)</span>
                <span className="font-mono text-slate-200 text-sm">
                  {asset.hostname || "No PTR record"}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <span className="text-slate-400 block mb-1">Risk Profile</span>
                <span
                  className={`inline-block px-2.5 py-0.5 rounded text-xs uppercase font-bold border ${
                    asset.risk_level === "Critical"
                      ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
                      : asset.risk_level === "High"
                      ? "bg-amber-500/10 text-amber-300 border-amber-500/30"
                      : asset.risk_level === "Medium"
                      ? "bg-sky-500/10 text-sky-300 border-sky-500/30"
                      : "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                  }`}
                >
                  {asset.risk_level}
                </span>
              </div>
            </div>

            {asset.description && (
              <div className="pt-2 border-t border-slate-800">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                  Operational Description
                </span>
                <p className="text-xs text-slate-300 leading-relaxed bg-[#0B1220] p-3 rounded-lg border border-slate-800">
                  {asset.description}
                </p>
              </div>
            )}
          </div>

          {/* Activity Section */}
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Asset Audit & Lifecycle Activity
            </h2>

            <div className="space-y-4 text-xs">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <div className="h-2 w-2 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                <div className="space-y-0.5">
                  <p className="text-white font-semibold">Registered in Organization Inventory</p>
                  <p className="text-slate-400 text-[11px] font-mono">
                    {formatDateTime(asset.created_at)}
                  </p>
                  <p className="text-slate-400 text-[11px]">
                    Endpoint discovered and associated with organization security boundary.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                <div className="h-2 w-2 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                <div className="space-y-0.5">
                  <p className="text-white font-semibold">Posture Evaluation</p>
                  <p className="text-slate-400 text-[11px] font-mono">
                    {formatDateTime(asset.created_at)}
                  </p>
                  <p className="text-slate-400 text-[11px]">
                    Assigned baseline risk level: <strong className="text-white">{asset.risk_level}</strong>
                  </p>
                </div>
              </div>

              {asset.updated_at && asset.updated_at !== asset.created_at && (
                <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1220] border border-slate-800">
                  <div className="h-2 w-2 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                  <div className="space-y-0.5">
                    <p className="text-white font-semibold">Configuration Synchronized</p>
                    <p className="text-slate-400 text-[11px] font-mono">
                      {formatDateTime(asset.updated_at)}
                    </p>
                    <p className="text-slate-400 text-[11px]">
                      Asset properties updated in centralized database.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Metadata & Security Posture */}
        <div className="space-y-6">
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Security Posture State
            </h2>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[11px] block">Availability Status</span>
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2.5 w-2.5 rounded-full ${
                      asset.status === "Active" ? "bg-emerald-400 animate-pulse" : "bg-slate-500"
                    }`}
                  />
                  <span className="font-bold text-white">{asset.status}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[11px] block">Assessed Risk Tier</span>
                <span className="font-bold text-white">{asset.risk_level} Risk</span>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[11px] block">First Ingested</span>
                <div className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                  <Calendar className="h-3.5 w-3.5 text-cyan-400" />
                  <span>{formatDateTime(asset.created_at)}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1">
                <span className="text-slate-400 text-[11px] block">Last Synchronized</span>
                <div className="flex items-center gap-2 text-slate-300 font-mono text-[11px]">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  <span>{formatDateTime(asset.updated_at)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Edit Form Modal */}
      <AssetFormModal
        isOpen={isEditOpen}
        onClose={() => setIsEditOpen(false)}
        onSubmit={handleUpdate}
        initialData={asset}
      />

      {/* Delete Dialog */}
      <DeleteAssetDialog
        isOpen={isDeleteOpen}
        asset={asset}
        onClose={() => setIsDeleteOpen(false)}
        onConfirm={handleDelete}
      />
    </div>
  );
}
