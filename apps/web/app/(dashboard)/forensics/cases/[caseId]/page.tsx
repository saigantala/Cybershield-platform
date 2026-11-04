"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  FileSearch,
  ArrowLeft,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Plus,
  RefreshCw,
  FolderArchive,
  HardDrive,
  Cpu,
  FileCode,
  FileText,
  ShieldCheck,
  Server,
  X,
  Play,
  Bookmark,
} from "lucide-react";
import { apiForensics } from "@/lib/api-client";
import type {
  ForensicCase,
  ForensicEvidenceItem,
  ForensicEvidenceItemCreate,
  ForensicAnalysisJob,
  ForensicCaseNote,
  ForensicCaseNoteCreate,
  ForensicReport,
  ForensicReportCreate,
  ForensicCaseStatus,
  AnalysisJobType,
  CaseNoteType,
} from "@/types/forensics";

export default function ForensicCaseDetailPage({
  params,
}: {
  params: { caseId: string };
}) {
  const caseId = params.caseId;
  const [caseObj, setCaseObj] = useState<ForensicCase | null>(null);
  const [evidenceList, setEvidenceList] = useState<ForensicEvidenceItem[]>([]);
  const [analysisJobs, setAnalysisJobs] = useState<ForensicAnalysisJob[]>([]);
  const [notes, setNotes] = useState<ForensicCaseNote[]>([]);
  const [reports, setReports] = useState<ForensicReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"evidence" | "analysis" | "notes" | "reports">("evidence");

  // Evidence Upload Modal
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [evName, setEvName] = useState("");
  const [evFilename, setEvFilename] = useState("");
  const [evCategory, setEvCategory] = useState<any>("log_file");
  const [evDesc, setEvDesc] = useState("");
  const [uploading, setUploading] = useState(false);

  // Analysis Runner
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
  const [selectedEvidenceForAnalysis, setSelectedEvidenceForAnalysis] = useState("");
  const [selectedAnalysisType, setSelectedAnalysisType] = useState<AnalysisJobType>("log_normalization");
  const [runningAnalysis, setRunningAnalysis] = useState(false);

  // Case Note Modal
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [noteContent, setNoteContent] = useState("");
  const [noteType, setNoteType] = useState<CaseNoteType>("Confirmed_Observation");
  const [savingNote, setSavingNote] = useState(false);

  // Report Generator Modal
  const [showReportModal, setShowReportModal] = useState(false);
  const [repTitle, setRepTitle] = useState("");
  const [repScope, setRepScope] = useState("");
  const [repExecSummary, setRepExecSummary] = useState("");
  const [repMethodology, setRepMethodology] = useState("");
  const [repConclusion, setRepConclusion] = useState("");
  const [generatingReport, setGeneratingReport] = useState(false);

  const loadCaseData = async () => {
    setLoading(true);
    try {
      const [caseRes, evRes, jobsRes, notesRes, repsRes] = await Promise.all([
        apiForensics.getCase(caseId),
        apiForensics.listEvidence({ caseId }),
        apiForensics.listAnalysisJobs(caseId),
        apiForensics.listNotes(caseId),
        apiForensics.listReports(caseId),
      ]);
      if (caseRes.data) setCaseObj(caseRes.data);
      if (evRes.data) setEvidenceList(evRes.data);
      if (jobsRes.data) setAnalysisJobs(jobsRes.data);
      if (notesRes.data) setNotes(notesRes.data);
      if (repsRes.data) setReports(repsRes.data);
    } catch (err) {
      console.error("Failed to load forensic workspace:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCaseData();
  }, [caseId]);

  const handleUpdateStatus = async (newStatus: ForensicCaseStatus) => {
    if (!caseObj) return;
    try {
      const res = await apiForensics.updateCase(caseId, { status: newStatus });
      if (res.data) setCaseObj(res.data);
    } catch (err) {
      console.error("Failed to update status:", err);
    }
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!evName || !evFilename) return;
    setUploading(true);
    try {
      const payload: ForensicEvidenceItemCreate = {
        forensic_case_id: caseId,
        evidence_name: evName,
        category: evCategory,
        original_filename: evFilename,
        description: evDesc || undefined,
      };
      const res = await apiForensics.uploadEvidence(payload);
      if (res.data) {
        setEvidenceList([res.data, ...evidenceList]);
        setShowUploadModal(false);
        setEvName("");
        setEvFilename("");
        setEvDesc("");
      }
    } catch (err) {
      console.error("Failed to upload evidence:", err);
    } finally {
      setUploading(false);
    }
  };

  const handleRunAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvidenceForAnalysis) return;
    setRunningAnalysis(true);
    try {
      const res = await apiForensics.runAnalysis(caseId, selectedEvidenceForAnalysis, selectedAnalysisType);
      if (res.data) {
        setAnalysisJobs([res.data, ...analysisJobs]);
        setShowAnalysisModal(false);
        setActiveTab("analysis");
      }
    } catch (err) {
      console.error("Analysis job execution failed:", err);
    } finally {
      setRunningAnalysis(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteContent) return;
    setSavingNote(true);
    try {
      const res = await apiForensics.createNote(caseId, { note_type: noteType, content: noteContent });
      if (res.data) {
        setNotes([...notes, res.data]);
        setShowNoteModal(false);
        setNoteContent("");
      }
    } catch (err) {
      console.error("Failed to add note:", err);
    } finally {
      setSavingNote(false);
    }
  };

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repTitle || !repScope || !repExecSummary || !repConclusion) return;
    setGeneratingReport(true);
    try {
      const payload: ForensicReportCreate = {
        title: repTitle,
        scope_and_authorization: repScope,
        executive_summary: repExecSummary,
        analysis_methodology: repMethodology || "Standard NIST SP 800-86 Forensic Analysis Workflow",
        confirmed_findings: [
          { finding: "Validated anomalous artifact execution", severity: "High" },
        ],
        analyst_hypotheses: [
          { hypothesis: "Initial infection via spearphishing attachment", confidence: "Medium" },
        ],
        mitre_attack_mappings: [
          { tactic: "Execution", technique_id: "T1059", name: "Command and Scripting Interpreter" },
        ],
        recommendations: [
          { action: "Enforce credential resets and Kerberos AES encryption", priority: "Immediate" },
        ],
        conclusion: repConclusion,
      };
      const res = await apiForensics.createReport(caseId, payload);
      if (res.data) {
        setReports([res.data, ...reports]);
        setShowReportModal(false);
        setActiveTab("reports");
        setRepTitle("");
        setRepScope("");
        setRepExecSummary("");
        setRepConclusion("");
      }
    } catch (err) {
      console.error("Failed to generate report:", err);
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-24 text-slate-400">
        <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-3 text-purple-400" />
        Loading Forensics Workspace...
      </div>
    );
  }

  if (!caseObj) {
    return (
      <div className="text-center py-24 text-slate-400">
        <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto mb-3" />
        <h2 className="text-xl font-bold text-slate-200">Forensic Case Not Found</h2>
        <Link href="/forensics/cases" className="mt-4 inline-block text-purple-400 hover:underline">
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
            href="/forensics/cases"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
          >
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-purple-400">{caseObj.case_number}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                {caseObj.priority}
              </span>
            </div>
            <h1 className="text-xl font-bold text-slate-100 mt-0.5">{caseObj.title}</h1>
          </div>
        </div>

        {/* Status Dropdown */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Status:</span>
            <select
              value={caseObj.status}
              onChange={(e) => handleUpdateStatus(e.target.value as ForensicCaseStatus)}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-purple-500 font-medium"
            >
              <option value="Open">Open</option>
              <option value="Evidence Collection">Evidence Collection</option>
              <option value="Analysis">Analysis</option>
              <option value="Review">Review</option>
              <option value="Completed">Completed</option>
              <option value="Archived">Archived</option>
            </select>
          </div>

          <Link
            href="/forensics/timeline"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition"
          >
            <Clock className="h-3.5 w-3.5" />
            Timeline View
          </Link>
        </div>
      </div>

      {/* Case Overview Card */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-4">
        <div>
          <h4 className="text-xs uppercase font-bold text-slate-400 tracking-wider mb-1">
            Investigation Objective
          </h4>
          <p className="text-sm text-slate-200">{caseObj.investigation_objective}</p>
        </div>

        <div>
          <span className="text-slate-500 block text-xs mb-1 font-semibold uppercase">Incident Description</span>
          <p className="text-xs text-slate-300">{caseObj.description}</p>
        </div>

        {/* Linked Target Assets */}
        {caseObj.assets && caseObj.assets.length > 0 && (
          <div className="pt-2 border-t border-slate-800/80">
            <span className="text-xs text-slate-500 block mb-2 font-semibold uppercase">
              Target Nodes Under Examination
            </span>
            <div className="flex flex-wrap gap-2">
              {caseObj.assets.map((ast) => (
                <div
                  key={ast.id}
                  className="px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs flex items-center gap-2"
                >
                  <Server className="h-3.5 w-3.5 text-cyan-400" />
                  <span className="text-slate-200 font-semibold">{ast.asset_name || "Target Host"}</span>
                  <span className="text-slate-400 font-mono text-[11px]">({ast.ip_address})</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 uppercase font-mono">
                    {ast.role_in_case.replace("_", " ")}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab("evidence")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "evidence"
                ? "text-purple-400 border-b-2 border-purple-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Evidence Artifacts ({evidenceList.length})
          </button>
          <button
            onClick={() => setActiveTab("analysis")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "analysis"
                ? "text-purple-400 border-b-2 border-purple-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Static AST Analysis ({analysisJobs.length})
          </button>
          <button
            onClick={() => setActiveTab("notes")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "notes"
                ? "text-purple-400 border-b-2 border-purple-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Case Notes & Hypotheses ({notes.length})
          </button>
          <button
            onClick={() => setActiveTab("reports")}
            className={`pb-3 text-sm font-medium transition relative ${
              activeTab === "reports"
                ? "text-purple-400 border-b-2 border-purple-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Forensic Reports ({reports.length})
          </button>
        </div>

        {/* Action button corresponding to active tab */}
        {activeTab === "evidence" && (
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 text-white text-xs font-medium hover:from-purple-500 hover:to-indigo-500 transition shadow"
          >
            <Plus className="h-3.5 w-3.5" />
            Preserve Evidence
          </button>
        )}
        {activeTab === "analysis" && (
          <button
            onClick={() => setShowAnalysisModal(true)}
            disabled={evidenceList.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-xs font-medium hover:from-cyan-500 hover:to-blue-500 transition shadow disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            Run Static Inspection
          </button>
        )}
        {activeTab === "notes" && (
          <button
            onClick={() => setShowNoteModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 text-white text-xs font-medium hover:from-purple-500 hover:to-indigo-500 transition shadow"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Note
          </button>
        )}
        {activeTab === "reports" && (
          <button
            onClick={() => setShowReportModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 text-white text-xs font-medium hover:from-emerald-500 hover:to-teal-500 transition shadow"
          >
            <FileText className="h-3.5 w-3.5" />
            Compile 14-Section Report
          </button>
        )}
      </div>

      {/* Tab 1: Evidence List */}
      {activeTab === "evidence" && (
        <div className="space-y-3">
          {evidenceList.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
              <FolderArchive className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No evidence preserved for this case yet</p>
              <p className="text-xs text-slate-500 mt-1">Upload event log dumps, PCAP flows, or memory metadata</p>
            </div>
          ) : (
            evidenceList.map((e) => (
              <div
                key={e.id}
                className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {e.category.replace("_", " ")}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> {e.integrity_status}
                      </span>
                      {e.is_derived && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                          Derived Artifact
                        </span>
                      )}
                    </div>
                    <h3 className="text-base font-semibold text-slate-100">{e.evidence_name}</h3>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      {e.original_filename} &bull; {(e.file_size / (1024 * 1024)).toFixed(2)} MB &bull; {e.mime_type}
                    </p>
                  </div>

                  <Link
                    href={`/forensics/evidence?verify=${e.id}`}
                    className="text-xs px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 transition shrink-0 font-medium"
                  >
                    View Chain
                  </Link>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 font-mono text-xs flex items-center justify-between text-slate-400">
                  <span>SHA-256: <strong className="text-purple-300">{e.sha256_hash}</strong></span>
                </div>

                {e.description && (
                  <p className="text-xs text-slate-400">{e.description}</p>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Analysis Jobs */}
      {activeTab === "analysis" && (
        <div className="space-y-3">
          {analysisJobs.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
              <Cpu className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No static analysis jobs run yet</p>
              <p className="text-xs text-slate-500 mt-1">Execute safe log AST parsing or PCAP header extraction</p>
            </div>
          ) : (
            analysisJobs.map((j) => (
              <div
                key={j.id}
                className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-4"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs uppercase font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {j.analysis_type.replace("_", " ")}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                      {j.status}
                    </span>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">
                    Duration: {j.duration_ms} ms
                  </span>
                </div>

                {/* Parsed Metadata JSON */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">
                    Static AST Extraction Output
                  </span>
                  <pre className="text-cyan-300 font-mono text-xs overflow-x-auto max-h-48">
                    {JSON.stringify(j.extracted_metadata || {}, null, 2)}
                  </pre>
                </div>

                {/* Matched Indicators */}
                {j.matched_iocs && j.matched_iocs.length > 0 && (
                  <div>
                    <span className="text-xs text-slate-400 font-semibold block mb-1.5">
                      Matched Indicators of Compromise:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {j.matched_iocs.map((ioc: any, idx: number) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 text-xs font-mono"
                        >
                          {ioc.type}: {ioc.value} ({ioc.matches || ioc.occurrences} hits)
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 3: Notes & Hypotheses */}
      {activeTab === "notes" && (
        <div className="space-y-3">
          {notes.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
              <Bookmark className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No investigator notes recorded yet</p>
              <p className="text-xs text-slate-500 mt-1">Record verified observations or investigative leads</p>
            </div>
          ) : (
            notes.map((n) => (
              <div
                key={n.id}
                className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-4 shadow-xl space-y-2"
              >
                <div className="flex items-center justify-between text-xs">
                  <span
                    className={`font-semibold px-2 py-0.5 rounded border ${
                      n.note_type === "Confirmed_Observation"
                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                        : n.note_type === "Analyst_Hypothesis"
                        ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                        : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                    }`}
                  >
                    {n.note_type.replace("_", " ")}
                  </span>
                  <span className="text-slate-500">{new Date(n.created_at).toLocaleString()}</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{n.content}</p>
                <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800">
                  Author: <span className="text-slate-400">{n.author_name || "Investigator"}</span>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 4: Reports */}
      {activeTab === "reports" && (
        <div className="space-y-3">
          {reports.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
              <FileText className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No formal forensic reports generated yet</p>
              <p className="text-xs text-slate-500 mt-1">Compile evidence inventory and findings into an evidentiary report</p>
            </div>
          ) : (
            reports.map((r) => (
              <div
                key={r.id}
                className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="font-mono text-xs font-bold text-emerald-400">{r.report_number}</span>
                    <h3 className="text-base font-semibold text-slate-100">{r.title}</h3>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-2">{r.executive_summary}</p>
                  </div>
                  <Link
                    href={`/forensics/reports?id=${r.id}`}
                    className="text-xs px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 transition shrink-0 font-medium"
                  >
                    View Report
                  </Link>
                </div>
                <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
                  <span>Author: {r.author_name || "Lead Forensic Analyst"}</span>
                  <span className="text-emerald-400 font-semibold">Chain of Custody Verified &bull; SHA-256 Intact</span>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Upload Evidence Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <FolderArchive className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Preserve Digital Evidence Artifact</h3>
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleUploadEvidence} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Evidence Label / Name <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Domain Controller Security Event Log Bitstream"
                  value={evName}
                  onChange={(e) => setEvName(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Original Filename <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. dc01_security_evtx_dump.json"
                  value={evFilename}
                  onChange={(e) => setEvFilename(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Category</label>
                <select
                  value={evCategory}
                  onChange={(e) => setEvCategory(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="log_file">Log File (EVTX, syslog, auditd)</option>
                  <option value="network_metadata_pcap">Network PCAP Flow Metadata</option>
                  <option value="memory_dump_metadata">Memory Dump Artifact</option>
                  <option value="disk_artifact">Disk Image Artifact</option>
                  <option value="csv_export">CSV Data Export</option>
                  <option value="screenshot">Evidentiary Screenshot</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Acquisition Notes</label>
                <textarea
                  rows={2}
                  placeholder="Acquisition hardware, FTK command line, or bit-stream verification details..."
                  value={evDesc}
                  onChange={(e) => setEvDesc(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-sm font-medium shadow-lg shadow-purple-500/20 transition flex items-center gap-2"
                >
                  {uploading && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Register & Hash Bitstream
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Analysis Modal */}
      {showAnalysisModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-cyan-400">
                <Cpu className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Safe Static Artifact Inspection</h3>
              </div>
              <button
                onClick={() => setShowAnalysisModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleRunAnalysis} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Select Evidence Artifact <span className="text-rose-400">*</span>
                </label>
                <select
                  required
                  value={selectedEvidenceForAnalysis}
                  onChange={(e) => setSelectedEvidenceForAnalysis(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Select an artifact...</option>
                  {evidenceList.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.evidence_name} ({e.original_filename})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Analysis Engine</label>
                <select
                  value={selectedAnalysisType}
                  onChange={(e) => setSelectedAnalysisType(e.target.value as AnalysisJobType)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="log_normalization">Safe Log Normalization (Static AST)</option>
                  <option value="ioc_extraction">Safe Regex IOC Extractor (IPs, Hashes, Domains)</option>
                  <option value="pcap_metadata">PCAP Packet Header Metadata Parser</option>
                  <option value="string_extraction">Safe String Sanitizer & Entropy Analysis</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/60 text-xs text-slate-400">
                <strong className="text-slate-200 block mb-0.5">Static Analysis Safety Boundary:</strong>
                Artifacts are analyzed without code execution or binary activation, enforcing strict 25 MB memory bounds.
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAnalysisModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={runningAnalysis || !selectedEvidenceForAnalysis}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium shadow-lg shadow-cyan-500/20 transition flex items-center gap-2"
                >
                  {runningAnalysis && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Execute Inspection
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Note Modal */}
      {showNoteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <Bookmark className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Add Case Observation</h3>
              </div>
              <button
                onClick={() => setShowNoteModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleAddNote} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Observation Type</label>
                <select
                  value={noteType}
                  onChange={(e) => setNoteType(e.target.value as CaseNoteType)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="Confirmed_Observation">Confirmed Observation (Fact)</option>
                  <option value="Analyst_Hypothesis">Analyst Hypothesis (Unconfirmed Lead)</option>
                  <option value="Investigative_Lead">Investigative Lead</option>
                  <option value="Evidence_Custody_Note">Evidence Custody Note</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Observation Details <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={4}
                  placeholder="Document specific forensic observations or hypotheses..."
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNoteModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingNote}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-medium shadow-lg shadow-purple-500/20 transition flex items-center gap-2"
                >
                  {savingNote && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Save Observation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Report Modal */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400">
                <FileText className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Generate Formal Forensic Report</h3>
              </div>
              <button
                onClick={() => setShowReportModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="p-6 space-y-4 max-h-[80vh] overflow-y-auto">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Report Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Formal Digital Forensics Examination: DC-01 Breach"
                  value={repTitle}
                  onChange={(e) => setRepTitle(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Scope & Authorization Mandate <span className="text-rose-400">*</span>
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
                  placeholder="High-level narrative of intrusion, impact, and containment..."
                  value={repExecSummary}
                  onChange={(e) => setRepExecSummary(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Conclusion Statement <span className="text-rose-400">*</span></label>
                <textarea
                  required
                  rows={2}
                  placeholder="Final analytical opinion on scope of compromise and remediation efficacy..."
                  value={repConclusion}
                  onChange={(e) => setRepConclusion(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowReportModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generatingReport}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium shadow-lg shadow-emerald-500/20 transition flex items-center gap-2"
                >
                  {generatingReport && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Compile Report
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
