"use client";

import { useState } from "react";
import { AlertTriangle, Trash2, X } from "lucide-react";
import { AssetRecord } from "@/types/asset";

interface DeleteAssetDialogProps {
  isOpen: boolean;
  asset: AssetRecord | null;
  onClose: () => void;
  onConfirm: (assetId: string) => Promise<{ success: boolean; error?: string }>;
}

export function DeleteAssetDialog({
  isOpen,
  asset,
  onClose,
  onConfirm,
}: DeleteAssetDialogProps) {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !asset) return null;

  const handleDelete = async () => {
    setIsDeleting(true);
    setError(null);
    try {
      const result = await onConfirm(asset.id);
      if (!result.success) {
        setError(result.error || "Failed to decommission asset.");
      } else {
        onClose();
      }
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111C2D] border border-rose-500/30 rounded-xl w-full max-w-md p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Decommission Asset</h3>
              <p className="text-xs text-slate-400">Confirm permanent removal from inventory</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
            {error}
          </div>
        )}

        <div className="bg-[#0B1220] p-3.5 rounded-lg border border-slate-800 text-xs space-y-2">
          <div className="flex justify-between">
            <span className="text-slate-400">Device Name:</span>
            <span className="font-bold text-white">{asset.name}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">IP Address:</span>
            <span className="font-mono text-cyan-400 font-bold">{asset.ip_address}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Device Type:</span>
            <span className="text-slate-200">{asset.device_type}</span>
          </div>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Are you sure you want to delete this asset from your organization&apos;s inventory?
          Associated historical telemetry may be impacted. This action cannot be undone.
        </p>

        <div className="pt-2 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={isDeleting}
            className="px-4 py-2 rounded-lg bg-slate-800 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleDelete}
            disabled={isDeleting}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs text-white font-semibold shadow-lg shadow-rose-600/20 active:scale-95 transition-all disabled:opacity-50"
          >
            {isDeleting ? (
              <>
                <div className="h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Decommissioning...</span>
              </>
            ) : (
              <>
                <Trash2 className="h-3.5 w-3.5" />
                <span>Decommission Asset</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
