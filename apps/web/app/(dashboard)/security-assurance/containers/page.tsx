"use client";

import { useEffect, useState } from "react";
import {
  Container,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Cpu,
  Lock,
  Layers,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { ContainerScanResult } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function ContainersPage() {
  const [containers, setContainers] = useState<ContainerScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  const loadContainers = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.getContainers();
      if (res.data) setContainers(res.data);
    } catch (err) {
      console.error("Failed to load container scan results", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadContainers();
  }, []);

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Container className="w-7 h-7 text-cyan-400" />
              Container Runtime & Docker Image Security
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Automated image vulnerability scanning and CIS Docker Benchmark compliance verification.
            </p>
          </div>
          <button
            onClick={loadContainers}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Re-scan Images
          </button>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {/* Container Image Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {containers.map((c) => (
            <div
              key={c.image_name}
              className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 space-y-4"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">{c.image_name}</h3>
                  <span className="text-xs text-slate-400">Tag: {c.tag} • {c.base_os}</span>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                    c.status === "pass"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                  }`}
                >
                  {c.status}
                </span>
              </div>

              {/* Security Controls Badges */}
              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800">
                  <span className="text-slate-400">Execution Privilege</span>
                  <span className={`font-semibold flex items-center gap-1 ${
                    c.runs_as_root ? "text-rose-400" : "text-emerald-400"
                  }`}>
                    {c.runs_as_root ? (
                      <>
                        <XCircle className="w-3.5 h-3.5" /> Root User
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" /> Non-Root
                      </>
                    )}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800">
                  <span className="text-slate-400">Total Vulnerabilities</span>
                  <span className="font-bold text-slate-200">{c.vulnerabilities_total}</span>
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="grid grid-cols-4 gap-1.5 text-center text-[10px]">
                <div className="p-1.5 rounded bg-rose-500/10 border border-rose-500/20">
                  <span className="text-rose-400 block font-bold">{c.critical_count}</span>
                  <span className="text-slate-500">Critical</span>
                </div>
                <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/20">
                  <span className="text-amber-400 block font-bold">{c.high_count}</span>
                  <span className="text-slate-500">High</span>
                </div>
                <div className="p-1.5 rounded bg-slate-800/60 border border-slate-800">
                  <span className="text-slate-300 block font-bold">{c.medium_count}</span>
                  <span className="text-slate-500">Medium</span>
                </div>
                <div className="p-1.5 rounded bg-slate-800/60 border border-slate-800">
                  <span className="text-slate-400 block font-bold">{c.low_count}</span>
                  <span className="text-slate-500">Low</span>
                </div>
              </div>

              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
                Last scanned: {new Date(c.scanned_at).toLocaleString()}
              </div>
            </div>
          ))}
        </div>

        {/* CIS Benchmark Guidelines */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
            <Lock className="w-4 h-4 text-emerald-400" />
            CIS Docker Benchmark Hardening Checklist
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Rule 4.1: Non-Root User Execution</span>
                <p className="text-slate-400 text-[11px] mt-0.5">Containers specify USER appuser to prevent root privilege escalation.</p>
              </div>
            </div>
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Rule 4.2: Minimal Distroless / Slim Base Images</span>
                <p className="text-slate-400 text-[11px] mt-0.5">Images use Alpine and Debian-slim to eliminate extraneous build tools and compilers.</p>
              </div>
            </div>
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Rule 5.1: No Privileged Container Flags</span>
                <p className="text-slate-400 text-[11px] mt-0.5">Compose definitions explicitly drop Linux capabilities and prohibit `--privileged` mode.</p>
              </div>
            </div>
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Rule 5.10: Memory and CPU Quotas</span>
                <p className="text-slate-400 text-[11px] mt-0.5">Resource constraints prevent DoS by runaway processes or memory leaks.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
