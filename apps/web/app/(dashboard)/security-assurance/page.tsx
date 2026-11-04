"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  Activity,
  Layers,
  ArrowRight,
  Info,
  RefreshCw,
  Clock,
  Server,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityAssuranceOverview } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function SecurityAssuranceOverviewPage() {
  const [data, setData] = useState<SecurityAssuranceOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningSuite, setRunningSuite] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadOverview = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.getOverview();
      if (res.data) setData(res.data);
    } catch (err) {
      console.error("Failed to load security assurance overview", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, []);

  const handleRunFullPentest = async () => {
    setRunningSuite(true);
    setActionMessage(null);
    try {
      const res = await apiSecurityAssurance.runAssessment({
        assessment_name: "On-Demand Full Continuous Assurance Run",
        assessment_type: "full_suite",
        target_environment: "production",
      });
      if (res.data) {
        setActionMessage(`Pentest suite completed! Posture score: ${res.data.posture_score}/100.`);
        await loadOverview();
      }
    } catch (err: any) {
      setActionMessage(`Error running assessment: ${err.message || "Failed"}`);
    } finally {
      setRunningSuite(false);
    }
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-emerald-400" />
              Continuous Security Assurance & Validation
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Automated penetration testing, OWASP verification, and deterministic posture tracking across all system layers.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={loadOverview}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-emerald-400" : ""}`} />
              Refresh
            </button>
            <button
              onClick={handleRunFullPentest}
              disabled={runningSuite}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-950/40 transition-all disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {runningSuite ? "Executing Pentest Suite..." : "Run Full Assurance Suite"}
            </button>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {actionMessage && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center justify-between">
            <span>{actionMessage}</span>
            <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
        )}

        {/* 4 Score Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Posture Score */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Security Posture</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-3xl font-extrabold ${
                (data?.posture_score ?? 100) >= 80
                  ? "text-emerald-400"
                  : (data?.posture_score ?? 100) >= 60
                  ? "text-amber-400"
                  : "text-rose-400"
              }`}>
                {data ? `${data.posture_score}` : "—"}
              </span>
              <span className="text-xs text-slate-400">/ 100</span>
            </div>
            <div className="mt-3 text-[11px] text-slate-400 flex items-center gap-1.5">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Formula-based, deterministic penalty score
            </div>
          </div>

          {/* Risk Score */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Aggregate Risk</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-3xl font-extrabold ${
                (data?.risk_score ?? 0) <= 25
                  ? "text-emerald-400"
                  : (data?.risk_score ?? 0) <= 50
                  ? "text-amber-400"
                  : "text-rose-400"
              }`}>
                {data ? `${data.risk_score}` : "—"}
              </span>
              <span className="text-xs text-slate-400">/ 100</span>
            </div>
            <div className="mt-3 text-[11px] text-slate-400">
              {data?.critical_findings ?? 0} Critical, {data?.high_findings ?? 0} High open findings
            </div>
          </div>

          {/* Test Coverage */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Test Coverage</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-cyan-400">
                {data ? `${data.test_coverage_pct}%` : "—"}
              </span>
            </div>
            <div className="mt-3 text-[11px] text-slate-400">
              17-Component architecture validation checks
            </div>
          </div>

          {/* Compliance */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">OWASP / ASVS Pass</span>
              <CheckCircle2 className="w-4 h-4 text-violet-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-violet-400">
                {data ? `${data.compliance_pct}%` : "—"}
              </span>
            </div>
            <div className="mt-3 text-[11px] text-slate-400">
              Verified against OWASP Top 10 & ASVS 4.0
            </div>
          </div>
        </div>

        {/* Scoring Formula & Triage Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 lg:col-span-2">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <Info className="w-4 h-4 text-cyan-400" />
              Deterministic Scoring Model & Penalty Breakdown
            </h2>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 mb-4">
              {data?.scoring_breakdown?.formula || "100 - (Crit*15 + High*8 + Med*3 + Low*1 + FailedChecks*4)"}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">Base Score</span>
                <span className="font-bold text-slate-200">100.0</span>
              </div>
              <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">Critical Deductions</span>
                <span className="font-bold text-rose-400">-{data?.scoring_breakdown?.critical_deductions ?? 0}</span>
              </div>
              <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">High Deductions</span>
                <span className="font-bold text-amber-400">-{data?.scoring_breakdown?.high_deductions ?? 0}</span>
              </div>
              <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-800">
                <span className="text-slate-400 block mb-1">Failed Check Penalty</span>
                <span className="font-bold text-orange-400">-{data?.scoring_breakdown?.failed_tests_deductions ?? 0}</span>
              </div>
            </div>
          </div>

          {/* Findings Lifecycle Status */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
            <h2 className="text-sm font-semibold text-white flex items-center justify-between mb-4">
              <span>Findings Lifecycle</span>
              <Link href="/security-assurance/findings" className="text-xs text-emerald-400 hover:underline flex items-center gap-1">
                View All <ArrowRight className="w-3 h-3" />
              </Link>
            </h2>
            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between items-center p-2 rounded bg-slate-800/30 border border-slate-800">
                <span className="text-slate-300">Open / Triaging</span>
                <span className="px-2 py-0.5 rounded font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  {data?.open_findings ?? 0}
                </span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-slate-800/30 border border-slate-800">
                <span className="text-slate-300">Fixed & Patched</span>
                <span className="px-2 py-0.5 rounded font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {data?.fixed_findings ?? 0}
                </span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-slate-800/30 border border-slate-800">
                <span className="text-slate-300">Accepted Risk (Documented)</span>
                <span className="px-2 py-0.5 rounded font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  {data?.accepted_risk_findings ?? 0}
                </span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-slate-800/30 border border-slate-800">
                <span className="text-slate-300">Verified by Automation</span>
                <span className="px-2 py-0.5 rounded font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {data?.verified_findings ?? 0}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* 17-Component Attack Surface Inventory */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                Component Inventory & Attack Surface Ratings
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Continuous security evaluation across all deployed platform tiers.
              </p>
            </div>
            <Link
              href="/security-assurance/application"
              className="text-xs text-emerald-400 hover:underline flex items-center gap-1"
            >
              Run Checklist <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {data?.components?.map((c) => (
              <div
                key={c.id}
                className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-slate-400" />
                    <span className="text-xs font-semibold text-slate-200">{c.component_name}</span>
                  </div>
                  <span
                    className={`px-1.5 py-0.5 text-[10px] uppercase font-bold rounded ${
                      c.status === "secure"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : c.status === "needs_review"
                        ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                        : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                    }`}
                  >
                    {c.status}
                  </span>
                </div>
                <div className="mt-2 text-[11px] text-slate-400 space-y-1">
                  <div>Stack: <span className="text-slate-300 font-mono">{c.technology_stack}</span></div>
                  <div className="flex justify-between">
                    <span>Attack Surface: <span className="font-semibold text-slate-300 uppercase">{c.attack_surface_rating}</span></span>
                    <span>Open Findings: <span className="font-semibold text-amber-400">{c.open_findings_count}</span></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Failed / Warning Checks Sample */}
        {data?.failed_checks_sample && data.failed_checks_sample.length > 0 && (
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <XCircle className="w-4 h-4 text-rose-400" />
              Failed or Warning Checks Requiring Remediation
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                    <th className="pb-2">Code</th>
                    <th className="pb-2">Name</th>
                    <th className="pb-2">Component</th>
                    <th className="pb-2">Severity</th>
                    <th className="pb-2">Status</th>
                    <th className="pb-2">Remediation Guidance</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {data.failed_checks_sample.map((check) => (
                    <tr key={check.id} className="hover:bg-slate-800/20">
                      <td className="py-2.5 font-mono text-slate-400">{check.check_code}</td>
                      <td className="py-2.5 font-medium text-slate-200">{check.name}</td>
                      <td className="py-2.5 text-slate-400">{check.target_component}</td>
                      <td className="py-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                          check.severity === "critical"
                            ? "bg-rose-500/10 text-rose-400"
                            : check.severity === "high"
                            ? "bg-amber-500/10 text-amber-400"
                            : "bg-slate-800 text-slate-300"
                        }`}>
                          {check.severity}
                        </span>
                      </td>
                      <td className="py-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                          check.status === "fail"
                            ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                            : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        }`}>
                          {check.status}
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-300">{check.remediation || "Review security configuration"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
