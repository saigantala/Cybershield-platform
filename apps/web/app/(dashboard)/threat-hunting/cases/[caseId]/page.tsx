"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Crosshair,
  ArrowLeft,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  Flame,
  FileCheck,
  Tag,
  Sliders,
  Send,
  X,
  ExternalLink,
} from "lucide-react";
import { apiThreatHunting } from "@/lib/api-client";
import type {
  ThreatHuntingCase,
  ThreatHuntingFinding,
  ThreatHuntingFindingCreate,
  ThreatHuntingCaseStatus,
  ThreatHuntingFindingType,
  SeverityLevel,
} from "@/types/threat-hunting";

export default function ThreatHuntingCaseDetailPage({
  params,
}: {
  params: { caseId: string };
}) {
  const caseId = params.caseId;
  const [caseObj, setCaseObj] = useState<ThreatHuntingCase | null>(null);
  const [findings, setFindings] = useState<ThreatHuntingFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"findings" | "queries" | "summary">("findings");

  // Create Finding Modal
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [fTitle, setFTitle] = useState("");
  const [fType, setFType] = useState<ThreatHuntingFindingType>("ioc_match");
  const [fSeverity, setFSeverity] = useState<SeverityLevel>("High");
  const [fConfirmed, setFConfirmed] = useState(false);
  const [fSummary, setFSummary] = useState("");
  const [fTactic, setFTactic] = useState("");
  const [fTechnique, setFTechnique] = useState("");
  const [fRecommendations, setFRecommendations] = useState("");
  const [savingFinding, setSavingFinding] = useState(false);

  // Status updating
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const loadCaseDetails = async () => {
    setLoading(true);
    try {
      const [caseRes, findingsRes] = await Promise.all([
        apiThreatHunting.getCase(caseId),
        apiThreatHunting.listFindings({ caseId }),
      ]);
      if (caseRes.data) setCaseObj(caseRes.data);
      if (findingsRes.data) setFindings(findingsRes.data);
    } catch (err) {
      console.error("Failed to load case workspace:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCaseDetails();
  }, [caseId]);

  const handleUpdateStatus = async (newStatus: ThreatHuntingCaseStatus) => {
    if (!caseObj) return;
    setUpdatingStatus(true);
    try {
      const res = await apiThreatHunting.updateCase(caseId, { status: newStatus });
      if (res.data) setCaseObj(res.data);
    } catch (err) {
      console.error("Failed to update status:", err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleCreateFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fTitle || !fSummary) return;
    setSavingFinding(true);
    try {
      const payload: ThreatHuntingFindingCreate = {
        hunting_case_id: caseId,
        title: fTitle,
        finding_type: fType,
        severity: fSeverity,
        is_confirmed: fConfirmed,
        evidence_summary: fSummary,
        mitre_tactic_name: fTactic || undefined,
        mitre_technique_id: fTechnique || undefined,
        recommendations: fRecommendations || undefined,
      };
      const res = await apiThreatHunting.createFinding(payload);
      if (res.data) {
        setFindings([res.data, ...findings]);
        setShowFindingModal(false);
        setFTitle("");
        setFSummary("");
        setFRecommendations("");
        setFConfirmed(false);
        // Reload case status if changed
        loadCaseDetails();
      }
    } catch (err) {
      console.error("Failed to save finding:", err);
    } finally {
      setSavingFinding(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "high":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "medium":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      default:
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/40";
    }
  };

  if (loading) {
    return (
      <div className="text-center py-24 text-slate-400">
        <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-3 text-cyan-400" />
        Loading Threat Hunting Workspace...
      </div>
    );
  }

  if (!caseObj) {
    return (
      <div className="text-center py-24 text-slate-400">
        <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto mb-3" />
        <h2 className="text-xl font-bold text-slate-200">Investigation Case Not Found</h2>
        <Link href="/threat-hunting/cases" className="mt-4 inline-block text-cyan-400 hover:underline">
          Return to cases
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Status Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <Link
            href="/threat-hunting/cases"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
          >
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-cyan-400">{caseObj.case_number}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                {caseObj.priority}
              </span>
            </div>
            <h1 className="text-xl font-bold text-slate-100 mt-0.5">{caseObj.title}</h1>
          </div>
        </div>

        {/* Status Controller */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Status:</span>
            <select
              value={caseObj.status}
              disabled={updatingStatus}
              onChange={(e) => handleUpdateStatus(e.target.value as ThreatHuntingCaseStatus)}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-medium"
            >
              <option value="Draft">Draft</option>
              <option value="Active">Active</option>
              <option value="Investigating">Investigating</option>
              <option value="Suspicious Activity Found">Suspicious Activity Found</option>
              <option value="No Threat Identified">No Threat Identified</option>
              <option value="Escalated">Escalated</option>
              <option value="Completed">Completed</option>
            </select>
          </div>

          <Link
            href={`/threat-hunting/search?caseId=${caseId}`}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition"
          >
            <Search className="h-3.5 w-3.5" />
            Query Telemetry
          </Link>
        </div>
      </div>

      {/* Case Details Card */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-4">
        <div>
          <h4 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-1">
            Investigation Objective
          </h4>
          <p className="text-sm text-slate-200">{caseObj.objective}</p>
        </div>

        {caseObj.hypothesis && (
          <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <span className="text-xs uppercase font-bold text-amber-400 block mb-1">
              Adversary Hypothesis
            </span>
            <p className="text-xs text-amber-200/90 leading-relaxed">{caseObj.hypothesis}</p>
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-3 border-t border-slate-800/80 text-xs text-slate-400">
          <div>
            <span className="text-slate-500 block">Initiated</span>
            <span className="text-slate-300 font-medium">{new Date(caseObj.created_at).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Findings Logged</span>
            <span className="text-slate-300 font-medium font-mono">{findings.length} findings</span>
          </div>
          <div>
            <span className="text-slate-500 block">Target Scope</span>
            <span className="text-slate-300 font-medium font-mono">
              {caseObj.selected_asset_ids?.length || "Enterprise Tenant"}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block">Last Active</span>
            <span className="text-slate-300 font-medium">{new Date(caseObj.updated_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("findings")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "findings"
                ? "text-cyan-400 border-b-2 border-cyan-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Documented Findings ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab("queries")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "queries"
                ? "text-cyan-400 border-b-2 border-cyan-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Hunting Queries
          </button>
        </div>

        <button
          onClick={() => setShowFindingModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-xs font-medium hover:from-cyan-500 hover:to-blue-500 transition shadow"
        >
          <Plus className="h-3.5 w-3.5" />
          Add Finding
        </button>
      </div>

      {/* Tab 1: Findings List */}
      {activeTab === "findings" && (
        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
              <Crosshair className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No findings documented for this case yet</p>
              <p className="text-xs text-slate-500 mt-1">
                Run telemetry interrogations in the query engine or record an observed anomaly
              </p>
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.id}
                className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold tracking-wider ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {f.finding_type.replace("_", " ")}
                      </span>
                      {f.is_confirmed ? (
                        <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium flex items-center gap-1">
                          <CheckCircle2 className="h-3.5 w-3.5" /> Confirmed Adversary Fact
                        </span>
                      ) : (
                        <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">
                          Analyst Hypothesis
                        </span>
                      )}
                    </div>
                    <h3 className="text-base font-semibold text-slate-100">{f.title}</h3>
                  </div>

                  <span className="text-xs text-slate-500 font-mono">
                    {new Date(f.created_at).toLocaleDateString()}
                  </span>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800 text-xs text-slate-300 leading-relaxed">
                  <span className="text-slate-500 block mb-1 font-semibold uppercase text-[10px]">Evidence Summary</span>
                  {f.evidence_summary}
                </div>

                {f.mitre_technique_id && (
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-500 font-medium">MITRE ATT&CK:</span>
                    <span className="font-mono text-cyan-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-semibold">
                      {f.mitre_technique_id}
                    </span>
                    <span className="text-slate-400">{f.mitre_tactic_name}</span>
                  </div>
                )}

                {f.recommendations && (
                  <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-800/30 text-xs text-cyan-300/90">
                    <strong className="text-cyan-400 block mb-0.5">Recommendations:</strong>
                    {f.recommendations}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Queries */}
      {activeTab === "queries" && (
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-8 shadow-xl text-center">
          <Search className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
          <h3 className="text-base font-semibold text-slate-200">Structured Telemetry Interrogation</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 mb-4">
            Search multi-source network flows, auth logs, and security events linked to this hunting investigation.
          </p>
          <Link
            href={`/threat-hunting/search?caseId=${caseId}`}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/20 transition"
          >
            <Search className="h-4 w-4" />
            Launch Query Engine
          </Link>
        </div>
      )}

      {/* Add Finding Modal */}
      {showFindingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-cyan-400">
                <Crosshair className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Document Investigation Finding</h3>
              </div>
              <button
                onClick={() => setShowFindingModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateFinding} className="p-6 space-y-4 max-h-[80vh] overflow-y-auto">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Finding Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Unconstrained Kerberos Delegation Abuse"
                  value={fTitle}
                  onChange={(e) => setFTitle(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Finding Category</label>
                  <select
                    value={fType}
                    onChange={(e) => setFType(e.target.value as ThreatHuntingFindingType)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="ioc_match">IOC Match</option>
                    <option value="anomalous_traffic">Anomalous Traffic</option>
                    <option value="behavioral_anomaly">Behavioral Anomaly</option>
                    <option value="credential_misuse">Credential Misuse</option>
                    <option value="unauthorized_service">Unauthorized Service</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Severity</label>
                  <select
                    value={fSeverity}
                    onChange={(e) => setFSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                  </select>
                </div>
              </div>

              <div className="p-3 bg-slate-800/60 rounded-lg border border-slate-700/60 flex items-center gap-3">
                <input
                  type="checkbox"
                  id="confirm-finding"
                  checked={fConfirmed}
                  onChange={(e) => setFConfirmed(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 h-4 w-4 bg-slate-800"
                />
                <label htmlFor="confirm-finding" className="text-xs text-slate-200 cursor-pointer">
                  <strong className="block text-emerald-400">Confirmed Fact (Not Hypothesis)</strong>
                  Check if verified by forensic evidence or validated telemetry match.
                </label>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Evidence Summary <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Detail forensic artifacts, observed IP timestamps, packets, or process execution..."
                  value={fSummary}
                  onChange={(e) => setFSummary(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">MITRE Tactic Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Credential Access"
                    value={fTactic}
                    onChange={(e) => setFTactic(e.target.value)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">MITRE Technique ID</label>
                  <input
                    type="text"
                    placeholder="e.g. T1558.003"
                    value={fTechnique}
                    onChange={(e) => setFTechnique(e.target.value)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Recommendations</label>
                <textarea
                  rows={2}
                  placeholder="Remediation steps, containment guidance, or credential reset instructions..."
                  value={fRecommendations}
                  onChange={(e) => setFRecommendations(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowFindingModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingFinding}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-medium shadow-lg shadow-cyan-500/20 transition flex items-center gap-2"
                >
                  {savingFinding && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Save Finding
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
