"use client";

import { useState, useEffect } from "react";
import { X, Save, AlertCircle, Laptop, Server, HardDrive, Shield } from "lucide-react";
import {
  AssetRecord,
  CreateAssetInput,
  DeviceType,
  RiskLevel,
  AssetStatus,
} from "@/types/asset";
import { validateAssetInput } from "@/lib/assets/validation";

interface AssetFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (input: CreateAssetInput, assetId?: string) => Promise<{ success: boolean; error?: string }>;
  initialData?: AssetRecord | null;
}

export function AssetFormModal({
  isOpen,
  onClose,
  onSubmit,
  initialData,
}: AssetFormModalProps) {
  const isEdit = Boolean(initialData);

  const [formData, setFormData] = useState<CreateAssetInput>({
    name: "",
    ip_address: "",
    mac_address: "",
    hostname: "",
    device_type: "Server",
    operating_system: "",
    manufacturer: "",
    risk_level: "Unassessed",
    status: "Active",
    description: "",
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (initialData) {
      setFormData({
        name: initialData.name || "",
        ip_address: initialData.ip_address || "",
        mac_address: initialData.mac_address || "",
        hostname: initialData.hostname || "",
        device_type: initialData.device_type || "Server",
        operating_system: initialData.operating_system || "",
        manufacturer: initialData.manufacturer || "",
        risk_level: initialData.risk_level || "Unassessed",
        status: initialData.status || "Active",
        description: initialData.description || "",
      });
    } else {
      setFormData({
        name: "",
        ip_address: "",
        mac_address: "",
        hostname: "",
        device_type: "Server",
        operating_system: "",
        manufacturer: "",
        risk_level: "Unassessed",
        status: "Active",
        description: "",
      });
    }
    setErrors({});
    setSubmitError(null);
  }, [initialData, isOpen]);

  if (!isOpen) return null;

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[name];
        return next;
      });
    }
    setSubmitError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);

    const validation = validateAssetInput(formData);
    if (!validation.isValid) {
      setErrors(validation.errors);
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await onSubmit(formData, initialData?.id);
      if (!result.success) {
        setSubmitError(result.error || "Failed to process asset record.");
      } else {
        onClose();
      }
    } catch (err: any) {
      setSubmitError(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#111C2D] border border-blue-500/30 rounded-xl w-full max-w-2xl max-h-[92vh] overflow-y-auto p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-cyan-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">
                {isEdit ? "Edit Asset Configuration" : "Register New Infrastructure Asset"}
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {isEdit
                  ? "Update endpoint telemetry, classification, and security posture state"
                  : "Add an authorized network device to continuous posture inventory"}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {submitError && (
          <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-start gap-2.5 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Operation Rejected</p>
              <p className="text-rose-400/90 mt-0.5">{submitError}</p>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {/* Row 1: Name and Hostname */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Device Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="e.g. PROD-API-GATEWAY-01"
                className={`w-full bg-[#0B1220] border ${
                  errors.name ? "border-rose-500" : "border-slate-800"
                } rounded-lg px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400`}
              />
              {errors.name && (
                <p className="text-rose-400 text-[11px] mt-1">{errors.name}</p>
              )}
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Hostname (FQDN)
              </label>
              <input
                type="text"
                name="hostname"
                value={formData.hostname || ""}
                onChange={handleChange}
                placeholder="e.g. api.internal.corp"
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          {/* Row 2: IP Address & MAC Address */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                IP Address (IPv4) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                name="ip_address"
                value={formData.ip_address}
                onChange={handleChange}
                placeholder="e.g. 192.168.10.25"
                className={`w-full bg-[#0B1220] font-mono border ${
                  errors.ip_address ? "border-rose-500" : "border-slate-800"
                } rounded-lg px-3 py-2 text-cyan-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400`}
              />
              {errors.ip_address && (
                <p className="text-rose-400 text-[11px] mt-1">{errors.ip_address}</p>
              )}
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                MAC Address
              </label>
              <input
                type="text"
                name="mac_address"
                value={formData.mac_address || ""}
                onChange={handleChange}
                placeholder="e.g. 52:54:00:8F:90:A1"
                className={`w-full bg-[#0B1220] font-mono border ${
                  errors.mac_address ? "border-rose-500" : "border-slate-800"
                } rounded-lg px-3 py-2 text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400`}
              />
              {errors.mac_address && (
                <p className="text-rose-400 text-[11px] mt-1">{errors.mac_address}</p>
              )}
            </div>
          </div>

          {/* Row 3: Device Type & Operating System */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Device Type <span className="text-rose-400">*</span>
              </label>
              <select
                name="device_type"
                value={formData.device_type}
                onChange={handleChange}
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="Server">Server</option>
                <option value="Laptop">Laptop</option>
                <option value="Desktop">Desktop</option>
                <option value="Router">Router / Switch</option>
                <option value="Mobile">Mobile Device</option>
                <option value="IoT">IoT Controller</option>
                <option value="Other">Other Equipment</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Operating System
              </label>
              <input
                type="text"
                name="operating_system"
                value={formData.operating_system || ""}
                onChange={handleChange}
                placeholder="e.g. Ubuntu 22.04 LTS / Windows Server 2022"
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          {/* Row 4: Manufacturer, Risk Level & Status */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Manufacturer
              </label>
              <input
                type="text"
                name="manufacturer"
                value={formData.manufacturer || ""}
                onChange={handleChange}
                placeholder="e.g. Dell / Cisco / Apple"
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Initial Risk Level <span className="text-rose-400">*</span>
              </label>
              <select
                name="risk_level"
                value={formData.risk_level}
                onChange={handleChange}
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Unassessed">Unassessed</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Status <span className="text-rose-400">*</span>
              </label>
              <select
                name="status"
                value={formData.status}
                onChange={handleChange}
                className="w-full bg-[#0B1220] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                <option value="Unknown">Unknown</option>
              </select>
            </div>
          </div>

          {/* Row 5: Description */}
          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Asset Description & Security Notes
            </label>
            <textarea
              name="description"
              rows={3}
              value={formData.description || ""}
              onChange={handleChange}
              placeholder="Operational context, network segment location, deployment notes..."
              className="w-full bg-[#0B1220] border border-slate-800 rounded-lg p-3 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400 resize-none"
            />
          </div>

          {/* Form Actions */}
          <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-semibold shadow-lg shadow-blue-500/20 hover:from-blue-500 hover:to-cyan-500 active:scale-95 transition-all disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <div className="h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Save className="h-4 w-4" />
                  <span>{isEdit ? "Update Asset" : "Save Asset"}</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
