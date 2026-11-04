"use client";

import { useEffect, useState } from "react";
import {
  History,
  Download,
  FileText,
  CheckCircle2,
  XCircle,
  Calendar,
  Clock,
  RefreshCw,
  TrendingUp,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityAssessment, SecurityTestRun } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function HistoryPage() {
  const [assessments, setAssessments] = useState<SecurityAssessment[]>([]);
  const [testRuns, setTestRuns] = useState<SecurityTestRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const [assRes, runsRes] = await Promise.all([
        apiSecurityAssurance.listAssessments(),
        apiSecurityAssurance.listTestRuns(),
      ]);
      if (assRes.data) setAssessments(assRes.data);
      if (runsRes.data) setTestRuns(runsRes.data);
    } catch (err) {
      console.error("Failed to load historical data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleExportReport = async (format: "json" | "csv") => {
    setExporting(format);
    setExportSuccess(null);
    try {
      const res = await apiSecurityAssurance.exportReport({
        report_type: "application",
        format,
      });
      if (res.data) {
        // Trigger browser download
        const blob = new Blob(
          [format === "json" ? JSON.stringify(res.data.data, null, 2) : res.data.data],
          { type: format === "json" ? "application/json" : "text/csv" }
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cybershield-security-assessment-${new Date().toISOString().slice(0, 10)}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setExportSuccess(`Successfully exported ${format.toUpperCase()} report!`);
      }
    } catch (err: any) {
      console.error("Failed to export report", err);
    } finally {
      setExporting(null);
    }
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <History className="w-7 h-7 text-violet-400" />
              Security Posture History & Audit Reports
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Historical posture scores, regression test logs, and formal compliance report export.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExportReport("json")}
              disabled={!!exporting}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
            <button
              onClick={() => handleExportReport("csv")}
              disabled={!!exporting}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white"
            >
              <FileText className="w-3.5 h-3.5" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {exportSuccess && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center justify-between">
            <span>{exportSuccess}</span>
            <button onClick={() => setExportSuccess(null)} className="text-slate-400 hover:text-white">✕</button>
          </div>
        )}

        {/* Historical Assessment Runs */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
            Formal Assessment Runs Log
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/40">
                  <th className="py-2.5 px-3">Assessment Name</th>
                  <th className="py-2.5 px-3">Scope / Type</th>
                  <th className="py-2.5 px-3">Environment</th>
                  <th className="py-2.5 px-3">Posture Score</th>
                  <th className="py-2.5 px-3">Check Breakdown</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Completed At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assessments.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/20">
                    <td className="py-3 px-3 font-semibold text-white">{a.assessment_name}</td>
                    <td className="py-3 px-3 font-mono uppercase text-slate-300">{a.assessment_type}</td>
                    <td className="py-3 px-3 text-slate-400">{a.target_environment}</td>
                    <td className="py-3 px-3">
                      <span className="font-bold text-emerald-400 text-sm">{a.posture_score}</span>
                      <span className="text-slate-500 text-[10px]"> / 100</span>
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      <span className="text-emerald-400 font-semibold">{a.passed_checks}</span> passed,{" "}
                      <span className="text-rose-400 font-semibold">{a.failed_checks}</span> failed
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {a.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {a.completed_at ? new Date(a.completed_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Automated API & Regression Runs */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <Clock className="w-4 h-4 text-cyan-400" />
            Automated API & CI Regression Suite Runs
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/40">
                  <th className="py-2.5 px-3">Suite Name</th>
                  <th className="py-2.5 px-3">Trigger Source</th>
                  <th className="py-2.5 px-3">Probes</th>
                  <th className="py-2.5 px-3">Passed</th>
                  <th className="py-2.5 px-3">Failed</th>
                  <th className="py-2.5 px-3">Duration</th>
                  <th className="py-2.5 px-3">Executed At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {testRuns.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/20">
                    <td className="py-3 px-3 font-semibold text-white">{r.suite_name}</td>
                    <td className="py-3 px-3 font-mono text-cyan-400">{r.trigger_source}</td>
                    <td className="py-3 px-3 text-slate-200">{r.total_tests}</td>
                    <td className="py-3 px-3 text-emerald-400 font-semibold">{r.passed_tests}</td>
                    <td className="py-3 px-3 text-rose-400 font-semibold">{r.failed_tests}</td>
                    <td className="py-3 px-3 font-mono text-slate-400">{r.duration_ms} ms</td>
                    <td className="py-3 px-3 text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
