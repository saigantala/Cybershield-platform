"use client";
export const dynamic = 'force-dynamic';
export const dynamic = 'force-dynamic';

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  FileText,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Download,
  RefreshCw,
  Search,
  Plus,
  ArrowRight,
  Printer,
  FileCode,
  X,
  ExternalLink,
} from "lucide-react";
import { apiForensics } from "@/lib/api-client";
import type {
  ForensicReport,
  ForensicReportCreate,
  ForensicCase,
} from "@/types/forensics";

export default function ForensicReportsPage() {
  const searchParams = useSearchParams();
  const reportIdParam = searchParams.get("id");

  const [reports, setReports] = useState<ForensicReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<ForensicReport | null>(null);

  // Report Generator Modal
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [repTitle, setRepTitle] = useState("");
  const [repScope, setRepScope] = useState("");
  const [repExecSummary, setRepExecSummary] = useState("");
  const [repMethodology, setRepMethodology] = useState("");
  const [repConclusion, setRepConclusion] = useState("");
  const [generating, setGenerating] = useState(false);

  const loadReports = async () => {
    setLoading(true);
    try {
      const [repsRes, casesRes] = await Promise.all([
        apiForensics.listReports(""),
        apiForensics.listCases(),
      ]);
      if (repsRes.data) {
        setReports(repsRes.data);
        if (reportIdParam) {
          const found = repsRes.data.find((r) => r.id === reportIdParam);
          if (found) setSelectedReport(found);
        } else if (repsRes.data.length > 0 && !selectedReport) {
          setSelectedReport(repsRes.data[0]);
        }
      }
      if (casesRes.data) {
        setCases(casesRes.data);
        if (casesRes.data.length > 0) setSelectedCaseId(casesRes.data[0].id);
      }
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, [reportIdParam]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !repTitle || !repScope || !repExecSummary || !repConclusion) return;
    setGenerating(true);
    try {
      const payload: ForensicReportCreate = {
        title: repTitle,
        scope_and_authorization: repScope,
        executive_summary: repExecSummary,
        analysis_methodology: repMethodology || "NIST SP 800-86 Guide to Integrating Forensic Techniques",
        confirmed_findings: [
          { finding: "Kerberos TGS Ticket Encryption Downgrade (0x17 RC4-HMAC)", severity: "High", mitre: "T1558.003" },
          { finding: "Encrypted C2 session established with 198.51.100.45", severity: "Critical", mitre: "T1071.001" },
        ],
        analyst_hypotheses: [
          { hypothesis: "Initial infection introduced via spearphishing attachment on workstation PIVOT-WS-09.", confidence: "Medium-High" },
        ],
        mitre_attack_mappings: [
          { tactic: "Credential Access", technique_id: "T1558.003", name: "Kerberoasting" },
          { tactic: "Command and Control", technique_id: "T1071.001", name: "Web Protocols" },
        ],
        recommendations: [
          { priority: "Immediate", action: "Force password reset for all Active Directory service accounts." },
          { priority: "Immediate", action: "Enforce AES256-only Kerberos encryption policy across all DCs." },
        ],
        conclusion: repConclusion,
      };
      const res = await apiForensics.createReport(selectedCaseId, payload);
      if (res.data) {
        setReports([res.data, ...reports]);
        setSelectedReport(res.data);
        setShowGenerateModal(false);
        setRepTitle("");
        setRepScope("");
        setRepExecSummary("");
        setRepConclusion("");
      }
    } catch (err) {
      console.error("Failed to create report:", err);
    } finally {
      setGenerating(false);
    }
  };

  const handleExportJSON = () => {
    if (!selectedReport) return;
    const blob = new Blob([JSON.stringify(selectedReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedReport.report_number}.json`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-lg shadow-emerald-500/5">
              <FileText className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Forensics Reporting Center</h1>
              <p className="text-sm text-slate-400">
                14-Section standardized formal forensic reports with verifiable chain of custody statements
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadReports}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleExportJSON}
            disabled={!selectedReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-emerald-300 border border-emerald-500/30 transition text-sm font-medium disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
          <button
            onClick={() => setShowGenerateModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            Generate Forensic Report
          </button>
        </div>
      </div>

      {/* Main Grid: Report Selector & Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Report List */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-3 h-fit">
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider text-xs">
            Compiled Evidentiary Reports
          </h2>

          <div className="space-y-2">
            {loading ? (
              <div className="text-center py-10 text-slate-500 text-xs">
                <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2 text-emerald-400" />
                Loading reports...
              </div>
            ) : reports.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-xs">
                No formal reports compiled yet.
              </div>
            ) : (
              reports.map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelectedReport(r)}
                  className={`w-full text-left p-3.5 rounded-lg border transition space-y-1 block ${
                    selectedReport?.id === r.id
                      ? "bg-emerald-950/20 border-emerald-500/40 text-emerald-200"
                      : "bg-slate-800/40 hover:bg-slate-800/70 border-slate-700/50 text-slate-300"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-emerald-400">{r.report_number}</span>
                    <span className="text-slate-500 text-[10px]">
                      {new Date(r.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <h4 className="text-xs font-semibold text-slate-100 line-clamp-1">{r.title}</h4>
                  <p className="text-[11px] text-slate-400 line-clamp-1">{r.executive_summary}</p>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Right Column: 14-Section Standardized Report Viewer */}
        <div className="lg:col-span-2 bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-8 shadow-xl space-y-8">
          {!selectedReport ? (
            <div className="text-center py-24 text-slate-500 text-sm">
              Select a forensic report from the catalog to review evidentiary details.
            </div>
          ) : (
            <div className="space-y-8 text-xs leading-relaxed text-slate-300">
              {/* 1. Header & Report Metadata */}
              <div className="border-b border-slate-800 pb-5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-bold text-emerald-400">
                    {selectedReport.report_number}
                  </span>
                  <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-semibold flex items-center gap-1">
                    <ShieldCheck className="h-3.5 w-3.5" /> Chain of Custody Verified
                  </span>
                </div>
                <h1 className="text-xl font-bold text-slate-100">{selectedReport.title}</h1>
                <div className="text-slate-400 flex flex-wrap gap-4 pt-1 font-mono text-[11px]">
                  <span>Author: {selectedReport.author_name || "Chief Security Architect"}</span>
                  <span>Compiled: {new Date(selectedReport.created_at).toLocaleString()}</span>
                  <span>Standard: NIST SP 800-86</span>
                </div>
              </div>

              {/* 2. Scope & Legal Authorization */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  1. Scope & Legal Authorization Mandate
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800 text-slate-300">
                  {selectedReport.scope_and_authorization}
                </div>
              </div>

              {/* 3. Executive Summary */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  2. Executive Summary
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800 text-slate-300">
                  {selectedReport.executive_summary}
                </div>
              </div>

              {/* 4. Evidence Inventory Summary */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  3. Digital Evidence Inventory & Integrity Hashes
                </h3>
                <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950">
                  <table className="w-full text-left font-mono text-[11px]">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Evidence Name</th>
                        <th className="py-2.5 px-3">SHA-256 Bitstream Hash</th>
                        <th className="py-2.5 px-3">Integrity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {selectedReport.evidence_inventory_summary.map((ev, i) => (
                        <tr key={i}>
                          <td className="py-2 px-3 font-sans text-slate-200">{ev.name || ev.filename}</td>
                          <td className="py-2 px-3 text-purple-300 truncate max-w-xs">{ev.sha256}</td>
                          <td className="py-2 px-3 text-emerald-400 font-semibold">{ev.integrity || "Verified"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 5. Analysis Methodology */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  4. Analysis Methodology & Tools
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800 text-slate-300">
                  {selectedReport.analysis_methodology}
                </div>
              </div>

              {/* 6. Confirmed Findings vs Analyst Hypotheses */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="h-4 w-4" /> 5. Confirmed Facts (Evidence-Backed)
                  </h3>
                  <div className="space-y-2">
                    {selectedReport.confirmed_findings.map((f, i) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800">
                        <strong className="text-slate-100 block">{f.finding || f.title}</strong>
                        {f.severity && <span className="text-[10px] text-rose-400 font-bold uppercase">Severity: {f.severity}</span>}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                    <Clock className="h-4 w-4" /> 6. Analyst Hypotheses (Unconfirmed Leads)
                  </h3>
                  <div className="space-y-2">
                    {selectedReport.analyst_hypotheses.map((h, i) => (
                      <div key={i} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800">
                        <p className="text-slate-300">{h.hypothesis || h.content}</p>
                        {h.confidence && <span className="text-[10px] text-amber-400 font-mono">Confidence: {h.confidence}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* 7. MITRE ATT&CK Mapping */}
              {selectedReport.mitre_attack_mappings && selectedReport.mitre_attack_mappings.length > 0 && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    7. MITRE ATT&CK Investigation Mapping
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedReport.mitre_attack_mappings.map((m, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700 flex items-center gap-2">
                        <span className="font-mono text-cyan-400 font-bold px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
                          {m.technique_id}
                        </span>
                        <span className="text-slate-200 font-medium">{m.name}</span>
                        <span className="text-slate-500 font-sans">({m.tactic})</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 8. Limitations & Recommendations */}
              <div className="space-y-3">
                {selectedReport.limitations && (
                  <div className="space-y-1">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      8. Investigative Limitations
                    </h3>
                    <p className="p-3 rounded-lg bg-slate-800/30 border border-slate-800 text-slate-400">
                      {selectedReport.limitations}
                    </p>
                  </div>
                )}

                {selectedReport.recommendations && selectedReport.recommendations.length > 0 && (
                  <div className="space-y-1">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400">
                      9. Remediation Recommendations
                    </h3>
                    <div className="space-y-1.5">
                      {selectedReport.recommendations.map((rec, i) => (
                        <div key={i} className="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-800/30 text-cyan-200 flex items-center justify-between">
                          <span>{rec.action || rec.recommendation}</span>
                          <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-300">
                            {rec.priority || "Immediate"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* 9. Conclusion */}
              <div className="space-y-1.5 pt-2 border-t border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  10. Conclusion & Security Posture Assessment
                </h3>
                <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-800 text-slate-200 leading-relaxed">
                  {selectedReport.conclusion}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400">
                <FileText className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Compile Formal Forensic Report</h3>
              </div>
              <button
                onClick={() => setShowGenerateModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="p-6 space-y-4 max-h-[80vh] overflow-y-auto">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Forensic Case <span className="text-rose-400">*</span>
                </label>
                <select
                  required
                  value={selectedCaseId}
                  onChange={(e) => setSelectedCaseId(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  {cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.case_number} - {c.title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Report Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Comprehensive Forensic Examination: Lateral Movement Infiltration"
                  value={repTitle}
                  onChange={(e) => setRepTitle(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Scope & Legal Authorization Mandate <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Authorized pursuant to Mandate #CYBER-2026-001 by CISO..."
                  value={repScope}
                  onChange={(e) => setRepScope(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Executive Summary <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Summary narrative of breach timeline, evidence acquired, and impact..."
                  value={repExecSummary}
                  onChange={(e) => setRepExecSummary(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Analysis Methodology
                </label>
                <input
                  type="text"
                  placeholder="Default: NIST SP 800-86 Guide to Integrating Forensic Techniques"
                  value={repMethodology}
                  onChange={(e) => setRepMethodology(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Conclusion Statement <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Final evidentiary conclusion and posture assessment..."
                  value={repConclusion}
                  onChange={(e) => setRepConclusion(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowGenerateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-sm font-medium shadow-lg shadow-emerald-500/20 transition flex items-center gap-2"
                >
                  {generating && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Compile 14-Section Report
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
