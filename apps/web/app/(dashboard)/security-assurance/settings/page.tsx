"use client";

import { useEffect, useState } from "react";
import {
  Settings,
  Shield,
  Save,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Radio,
  Sliders,
  RefreshCw,
  Lock,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityScannerConfig } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function SecurityAssuranceSettingsPage() {
  const [configs, setConfigs] = useState<SecurityScannerConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const loadConfigs = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.listScannerConfigs();
      if (res.data) setConfigs(res.data);
    } catch (err) {
      console.error("Failed to load scanner configs", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadConfigs();
  }, []);

  const handleToggle = async (config: SecurityScannerConfig) => {
    setSavingId(config.id);
    setStatusMsg(null);
    try {
      const res = await apiSecurityAssurance.updateScannerConfig(config.id, {
        is_enabled: !config.is_enabled,
      });
      if (res.data) {
        setConfigs((prev) => prev.map((c) => (c.id === config.id ? res.data! : c)));
        setStatusMsg(`Updated ${config.scanner_name} status.`);
      }
    } catch (err) {
      console.error("Failed to update scanner config", err);
    } finally {
      setSavingId(null);
    }
  };

  const handleFrequencyChange = async (config: SecurityScannerConfig, newFreq: string) => {
    setSavingId(config.id);
    setStatusMsg(null);
    try {
      const res = await apiSecurityAssurance.updateScannerConfig(config.id, {
        scan_frequency: newFreq,
      });
      if (res.data) {
        setConfigs((prev) => prev.map((c) => (c.id === config.id ? res.data! : c)));
        setStatusMsg(`Updated schedule for ${config.scanner_name}.`);
      }
    } catch (err) {
      console.error("Failed to update scanner schedule", err);
    } finally {
      setSavingId(null);
    }
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Settings className="w-7 h-7 text-slate-400" />
              Scanner Orchestration & Scope Governance
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Configure automated assessment schedules, approved target scopes, and risk exception boundaries.
            </p>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {statusMsg && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center justify-between">
            <span>{statusMsg}</span>
            <button onClick={() => setStatusMsg(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
        )}

        {/* Scanner Configurations */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white">Active Scanners & Automated Engines</h2>
              <p className="text-xs text-slate-400 mt-0.5">Automated continuous assurance engine triggers.</p>
            </div>
          </div>

          <div className="divide-y divide-slate-800/60">
            {configs.map((scanner) => (
              <div key={scanner.id} className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">{scanner.scanner_name}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-400">
                      {scanner.scanner_type}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center gap-2">
                    <span>Approved Scope:</span>
                    <span className="font-mono text-slate-300">
                      {scanner.target_scope?.join(", ") || "localhost"}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    <select
                      value={scanner.scan_frequency}
                      onChange={(e) => handleFrequencyChange(scanner, e.target.value)}
                      disabled={savingId === scanner.id}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-slate-600"
                    >
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="on_commit">On-Commit (CI)</option>
                    </select>
                  </div>

                  <button
                    onClick={() => handleToggle(scanner)}
                    disabled={savingId === scanner.id}
                    className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                      scanner.is_enabled
                        ? "bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30"
                        : "bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700"
                    }`}
                  >
                    {scanner.is_enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Target Scope Governance & Boundary Policies */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              Approved Target Scope Boundary
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              CyberShield continuous validation engines are restricted strictly to authorized internal hosts and staging environments:
            </p>
            <ul className="text-xs text-slate-400 font-mono space-y-1 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
              <li>• http://localhost:8000 (FastAPI Core Gateway)</li>
              <li>• http://localhost:3000 (Next.js Frontend Application)</li>
              <li>• redis://localhost:6379 (Redis Broker)</li>
              <li>• PostgreSQL Supabase Staging Tenant</li>
            </ul>
            <p className="text-[11px] text-amber-400/90 italic">
              Notice: Scanning external or unapproved public CIDR ranges is strictly blocked by input validation policies.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Risk Acceptance Governance Policy
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Exceptions allow teams to accept residual risk for documented business requirements:
            </p>
            <ul className="text-xs text-slate-400 space-y-1.5">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Requires documented business justification (minimum 10 characters).</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Compensating security controls must be specified.</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Maximum exception lifespan: 90 days with automatic expiration.</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Audit logged with tamper-resistant actor attribution.</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
