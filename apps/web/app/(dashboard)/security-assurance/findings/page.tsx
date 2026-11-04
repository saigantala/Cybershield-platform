"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  MessageSquare,
  FileText,
  ChevronRight,
  ExternalLink,
  Plus,
  Send,
  Lock,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityFinding, SecurityFindingNote } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function FindingsTrackerPage() {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  // Notes state
  const [noteContent, setNoteContent] = useState("");
  const [submittingNote, setSubmittingNote] = useState(false);

  // Risk acceptance modal state
  const [showRiskModal, setShowRiskModal] = useState(false);
  const [riskJustification, setRiskJustification] = useState("");
  const [compensatingControls, setCompensatingControls] = useState("");
  const [riskDurationDays, setRiskDurationDays] = useState(30);
  const [submittingRisk, setSubmittingRisk] = useState(false);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.listFindings();
      if (res.data) {
        setFindings(res.data);
        if (res.data.length > 0 && !selectedFinding) {
          setSelectedFinding(res.data[0]);
        }
      }
    } catch (err) {
      console.error("Failed to load findings", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  const handleStatusTransition = async (newStatus: string) => {
    if (!selectedFinding) return;
    try {
      const res = await apiSecurityAssurance.updateFinding(selectedFinding.id, {
        status: newStatus,
        verification_notes: `Status transitioned to ${newStatus} via Findings Center.`,
      });
      if (res.data) {
        setSelectedFinding(res.data);
        await loadFindings();
      }
    } catch (err) {
      console.error("Failed to update status", err);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding || !noteContent.trim()) return;
    setSubmittingNote(true);
    try {
      const res = await apiSecurityAssurance.addFindingNote(selectedFinding.id, noteContent.trim());
      if (res.data) {
        const updatedNotes = [...(selectedFinding.notes || []), res.data];
        setSelectedFinding({
          ...selectedFinding,
          notes: updatedNotes,
          notes_count: updatedNotes.length,
        });
        setNoteContent("");
        await loadFindings();
      }
    } catch (err) {
      console.error("Failed to add note", err);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleAcceptRisk = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding || !riskJustification.trim()) return;
    setSubmittingRisk(true);
    try {
      const res = await apiSecurityAssurance.acceptRisk(selectedFinding.id, {
        justification: riskJustification,
        compensating_controls: compensatingControls,
        duration_days: riskDurationDays,
      });
      if (res.data) {
        setSelectedFinding(res.data);
        setShowRiskModal(false);
        setRiskJustification("");
        setCompensatingControls("");
        await loadFindings();
      }
    } catch (err) {
      console.error("Failed to accept risk", err);
    } finally {
      setSubmittingRisk(false);
    }
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.finding_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_component.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === "all" || f.status === statusFilter;
    const matchesSev = severityFilter === "all" || f.severity === severityFilter;
    return matchesSearch && matchesStatus && matchesSev;
  });

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <AlertTriangle className="w-7 h-7 text-rose-400" />
              Unified Vulnerability & Findings Center
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              End-to-end vulnerability lifecycle tracking, analyst collaboration notes, and formal risk acceptance workflows.
            </p>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {/* Search & Filters */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings, CVEs, components..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-rose-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-rose-500"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="in_progress">In Progress</option>
              <option value="fixed">Fixed</option>
              <option value="accepted_risk">Accepted Risk</option>
              <option value="verified">Verified</option>
            </select>
          </div>
        </div>

        {/* Master-Detail Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Findings List (7 cols) */}
          <div className="lg:col-span-7 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Security Findings ({filteredFindings.length})
              </span>
              <span className="text-[11px] text-slate-500">Select to triage & remediate</span>
            </div>

            <div className="divide-y divide-slate-800/60 max-h-[640px] overflow-y-auto">
              {filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className={`p-4 flex items-start justify-between cursor-pointer transition-colors ${
                    selectedFinding?.id === finding.id
                      ? "bg-slate-800/60 border-l-2 border-rose-400"
                      : "hover:bg-slate-800/20"
                  }`}
                >
                  <div className="space-y-1 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-rose-400">
                        {finding.finding_code}
                      </span>
                      <span className="text-xs font-medium text-white">{finding.title}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-2">
                      <span>{finding.category}</span>
                      <span>•</span>
                      <span className="text-slate-300">{finding.affected_component}</span>
                      {finding.notes_count > 0 && (
                        <>
                          <span>•</span>
                          <span className="flex items-center gap-1 text-slate-400">
                            <MessageSquare className="w-3 h-3" /> {finding.notes_count}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-1.5 shrink-0">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        finding.severity === "critical"
                          ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          : finding.severity === "high"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          : "bg-slate-800 text-slate-300 border border-slate-700"
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[9px] uppercase font-medium ${
                        finding.status === "fixed"
                          ? "text-emerald-400"
                          : finding.status === "accepted_risk"
                          ? "text-amber-400"
                          : "text-slate-400"
                      }`}
                    >
                      {finding.status.replace("_", " ")}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Finding Details & Actions (5 cols) */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5 space-y-4">
            {selectedFinding ? (
              <>
                <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-rose-400 font-bold">
                      {selectedFinding.finding_code}
                    </span>
                    <h3 className="text-sm font-semibold text-white mt-0.5">
                      {selectedFinding.title}
                    </h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-200">
                    {selectedFinding.status.replace("_", " ")}
                  </span>
                </div>

                <div className="text-xs text-slate-300 space-y-3">
                  <div>
                    <span className="text-slate-400 block mb-1">Vulnerability Description</span>
                    <p className="leading-relaxed bg-slate-950/40 p-2.5 rounded border border-slate-800">
                      {selectedFinding.description}
                    </p>
                  </div>

                  {selectedFinding.remediation_recommendation && (
                    <div>
                      <span className="text-emerald-400 font-semibold block mb-1">
                        Remediation Recommendation
                      </span>
                      <p className="p-2.5 bg-emerald-950/20 border border-emerald-500/30 rounded text-emerald-200 leading-relaxed">
                        {selectedFinding.remediation_recommendation}
                      </p>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                      <span className="text-slate-500 block">Affected Component</span>
                      <span className="font-semibold text-slate-200">{selectedFinding.affected_component}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                      <span className="text-slate-500 block">Scanner Source</span>
                      <span className="font-semibold text-slate-200">{selectedFinding.source_scanner}</span>
                    </div>
                  </div>

                  {/* Lifecycle Transitions */}
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-[11px] font-semibold text-slate-400 block mb-2">
                      Triage Actions
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {selectedFinding.status !== "in_progress" && selectedFinding.status !== "fixed" && (
                        <button
                          onClick={() => handleStatusTransition("in_progress")}
                          className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                        >
                          Start Remediation
                        </button>
                      )}
                      {selectedFinding.status !== "fixed" && (
                        <button
                          onClick={() => handleStatusTransition("fixed")}
                          className="px-2.5 py-1 text-xs rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40"
                        >
                          Mark as Fixed
                        </button>
                      )}
                      {selectedFinding.status !== "accepted_risk" && (
                        <button
                          onClick={() => setShowRiskModal(true)}
                          className="px-2.5 py-1 text-xs rounded bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40"
                        >
                          Accept Risk
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Analyst Notes Thread */}
                  <div className="pt-3 border-t border-slate-800">
                    <span className="text-[11px] font-semibold text-slate-400 block mb-2">
                      Analyst Collaboration Notes ({selectedFinding.notes?.length || 0})
                    </span>

                    <div className="space-y-2 max-h-36 overflow-y-auto mb-3">
                      {selectedFinding.notes && selectedFinding.notes.length > 0 ? (
                        selectedFinding.notes.map((note) => (
                          <div key={note.id} className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[11px]">
                            <div className="flex justify-between text-slate-400 text-[10px] mb-1">
                              <span className="font-semibold text-slate-300">{note.author_email}</span>
                              <span>{new Date(note.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                            </div>
                            <p className="text-slate-200">{note.content}</p>
                          </div>
                        ))
                      ) : (
                        <p className="text-[11px] text-slate-500 italic">No notes recorded yet.</p>
                      )}
                    </div>

                    <form onSubmit={handleAddNote} className="flex gap-2">
                      <input
                        type="text"
                        placeholder="Add analyst note..."
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        className="flex-1 bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
                      />
                      <button
                        type="submit"
                        disabled={submittingNote || !noteContent.trim()}
                        className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs disabled:opacity-50"
                      >
                        <Send className="w-3.5 h-3.5" />
                      </button>
                    </form>
                  </div>
                </div>
              </>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs">
                Select a finding to triage.
              </div>
            )}
          </div>
        </div>

        {/* Risk Acceptance Modal */}
        {showRiskModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 w-full max-w-md space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-amber-400" />
                  Accept Risk Exception
                </h3>
                <button onClick={() => setShowRiskModal(false)} className="text-slate-400 hover:text-white">✕</button>
              </div>

              <form onSubmit={handleAcceptRisk} className="space-y-3 text-xs">
                <div>
                  <label className="text-slate-300 block mb-1 font-semibold">Business Justification *</label>
                  <textarea
                    rows={3}
                    required
                    placeholder="Document formal justification (e.g. legacy dependency pending Q2 refactor)..."
                    value={riskJustification}
                    onChange={(e) => setRiskJustification(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  />
                </div>

                <div>
                  <label className="text-slate-300 block mb-1 font-semibold">Compensating Controls</label>
                  <input
                    type="text"
                    placeholder="e.g. Enforced IP whitelist & WAF strict rule..."
                    value={compensatingControls}
                    onChange={(e) => setCompensatingControls(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  />
                </div>

                <div>
                  <label className="text-slate-300 block mb-1 font-semibold">Exception Duration</label>
                  <select
                    value={riskDurationDays}
                    onChange={(e) => setRiskDurationDays(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-300 focus:outline-none focus:border-amber-500"
                  >
                    <option value={15}>15 Days</option>
                    <option value={30}>30 Days</option>
                    <option value={60}>60 Days</option>
                    <option value={90}>90 Days</option>
                  </select>
                </div>

                <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => setShowRiskModal(false)}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submittingRisk || !riskJustification.trim()}
                    className="px-4 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs disabled:opacity-50"
                  >
                    {submittingRisk ? "Authorizing Exception..." : "Authorize Exception"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
