"use client";

import Link from "next/link";
import {
  X,
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
  ExternalLink,
  Copy,
  Check,
  Radar,
  Radio,
  Network,
} from "lucide-react";
import { useState } from "react";
import { AssetRecord, DeviceType } from "@/types/asset";
import { formatDateTime } from "@/lib/utils";

interface AssetDetailsModalProps {
  isOpen: boolean;
  asset: AssetRecord | null;
  onClose: () => void;
  onEdit?: (asset: AssetRecord) => void;
  userRole?: string | null;
}

export function AssetDetailsModal({
  isOpen,
  asset,
  onClose,
  onEdit,
  userRole,
}: AssetDetailsModalProps) {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !asset) return null;

  const copyId = () => {
    navigator.clipboard.writeText(asset.id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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

  const DeviceIcon = getDeviceIcon(asset.device_type);

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111C2D] border border-blue-500/30 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 shadow-2xl space-y-6 animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-cyan-400">
              <DeviceIcon className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-white">{asset.name}</h3>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                    asset.status === "Active"
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                      : "bg-slate-500/10 text-slate-400 border-slate-700"
                  }`}
                >
                  {asset.status}
                </span>
              </div>
              <p className="text-xs font-mono text-cyan-400 mt-0.5">
                {asset.ip_address} {asset.hostname ? `• ${asset.hostname}` : ""}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href={`/assets/${asset.id}`}
              className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
              title="Open Dedicated Full Page"
            >
              <ExternalLink className="h-4 w-4" />
            </Link>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* UUID banner */}
        <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#0B1220] border border-blue-500/20 text-xs">
          <span className="text-slate-400 font-mono text-[11px] truncate max-w-[380px]">
            UUID: <span className="text-slate-200">{asset.id}</span>
          </span>
          <button
            onClick={copyId}
            className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                <span>Copy UUID</span>
              </>
            )}
          </button>
        </div>

        {/* Specs Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">Device Type</span>
            <span className="font-semibold text-white">{asset.device_type}</span>
          </div>

          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">Operating System</span>
            <span className="font-semibold text-white">
              {asset.operating_system || "Not Specified"}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">Manufacturer</span>
            <span className="font-semibold text-white">
              {asset.manufacturer || "Generic / Virtual"}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">MAC Address</span>
            <span className="font-mono text-slate-200">
              {asset.mac_address || "None recorded"}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">Risk Posture</span>
            <span
              className={`inline-block px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
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

          <div className="p-3 rounded-lg bg-[#162338]/60 border border-slate-800">
            <span className="text-slate-400 block mb-1">Status</span>
            <span className="font-semibold text-white">{asset.status}</span>
          </div>
        </div>

        {/* Description / Notes */}
        {asset.description && (
          <div className="p-3.5 rounded-lg bg-[#0B1220] border border-blue-500/20 text-xs">
            <span className="font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
              Asset Notes & Context
            </span>
            <p className="text-slate-300 leading-relaxed">{asset.description}</p>
          </div>
        )}

        {/* Timestamps */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0B1220]/60 border border-slate-800 text-slate-400">
            <Calendar className="h-4 w-4 text-cyan-400 shrink-0" />
            <div>
              <span className="text-[10px] block uppercase">Registered</span>
              <span className="font-mono text-white text-[11px]">
                {formatDateTime(asset.created_at)}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0B1220]/60 border border-slate-800 text-slate-400">
            <Clock className="h-4 w-4 text-cyan-400 shrink-0" />
            <div>
              <span className="text-[10px] block uppercase">Last Updated</span>
              <span className="font-mono text-white text-[11px]">
                {formatDateTime(asset.updated_at)}
              </span>
            </div>
          </div>
        </div>

        {/* Discovery Intelligence & Surface Telemetry (Sprint 5) */}
        <div className="p-4 rounded-xl bg-[#0B1220] border border-blue-500/20 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-cyan-400" />
              <span className="font-bold text-white text-xs uppercase tracking-wider">
                Discovery Telemetry & Classification
              </span>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                asset.discovery_method === "discovered"
                  ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                  : "bg-slate-700/30 text-slate-400 border-slate-700"
              }`}
            >
              {asset.discovery_method === "discovered" ? "Automatic Discovery" : "Manual Enrollment"}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-slate-400 text-[10px] uppercase font-bold block mb-1">
                Classification Confidence
              </span>
              <div className="flex items-center gap-2">
                <div className="flex-1 bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full"
                    style={{ width: `${asset.confidence ?? (asset.discovery_method === "discovered" ? 85 : 100)}%` }}
                  />
                </div>
                <span className="font-mono text-cyan-300 font-bold text-[11px]">
                  {asset.confidence ?? (asset.discovery_method === "discovered" ? 85 : 100)}%
                </span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 text-[10px] uppercase font-bold block mb-1">
                Discovery Engine
              </span>
              <span className="font-semibold text-slate-200">
                {asset.discovery_method === "discovered"
                  ? "Nmap RFC-1918 Safe Discovery"
                  : "Administrative Operator"}
              </span>
            </div>
          </div>

          {/* Evidence Signals */}
          {asset.evidence && asset.evidence.length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">
                Evidence Signals Evaluated:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {asset.evidence.map((sig, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-blue-950/40 border border-blue-500/20 text-slate-300 text-[10px] font-mono"
                  >
                    {sig}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Open Services */}
          {asset.services && asset.services.length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">
                Exposed Services ({asset.services.length}):
              </span>
              <div className="grid grid-cols-2 gap-2">
                {asset.services.map((srv, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center justify-between"
                  >
                    <span className="text-cyan-400 font-bold">
                      {srv.port}/{srv.protocol}
                    </span>
                    <span className="text-slate-200 truncate">{srv.service_name || "open"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Asset Activity Section (No fake scan results, authentic audit timeline) */}
        <div className="space-y-3 pt-2">
          <span className="font-bold text-white text-xs uppercase tracking-wider block flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            Asset Lifecycle & Audit Timeline
          </span>

          <div className="soc-glass p-3.5 rounded-lg border border-slate-800 text-xs space-y-3">
            <div className="flex items-start gap-3">
              <div className="h-2 w-2 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
              <div>
                <p className="text-slate-200 font-semibold">Asset Registered in Inventory</p>
                <p className="text-[11px] text-slate-400 font-mono">
                  {formatDateTime(asset.created_at)} • Ingested via CyberShield Asset Manager
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="h-2 w-2 rounded-full bg-blue-400 mt-1.5 shrink-0" />
              <div>
                <p className="text-slate-200 font-semibold">Posture Evaluation</p>
                <p className="text-[11px] text-slate-400 font-mono">
                  Assigned risk profile: <strong className="text-white">{asset.risk_level}</strong>
                </p>
              </div>
            </div>

            {asset.updated_at && asset.updated_at !== asset.created_at && (
              <div className="flex items-start gap-3">
                <div className="h-2 w-2 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                <div>
                  <p className="text-slate-200 font-semibold">Configuration Synchronized</p>
                  <p className="text-[11px] text-slate-400 font-mono">
                    {formatDateTime(asset.updated_at)} • Record updated by operator
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
          <Link
            href={`/assets/${asset.id}`}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 hover:underline"
          >
            <span>Full-Screen Asset View</span>
            <ExternalLink className="h-3 w-3" />
          </Link>

          <div className="flex items-center gap-3">
            {userRole !== "viewer" && onEdit && (
              <button
                onClick={() => {
                  onClose();
                  onEdit(asset);
                }}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs text-white font-semibold transition-colors"
              >
                Edit Asset
              </button>
            )}

            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 text-xs text-slate-300 hover:text-white transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
