"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  SearchCheck,
  CheckCircle2,
  AlertTriangle,
  Clock,
  RefreshCw,
  Search,
  Filter,
  UserCheck,
  ShieldAlert,
  ArrowLeft,
  ExternalLink,
  MessageSquare,
  ThumbsDown,
  ThumbsUp,
  BrainCircuit,
} from "lucide-react";
import { apiAIDetection } from "@/lib/api-client";
import type {
  AIDetectionInvestigation,
  InvestigationStatus,
} from "@/types/ai-detection";

export default function AIDetectionInvestigationsPage() {
  const [investigations, setInvestigations] = useState<AIDetectionInvestigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("All");
  const [selectedInv, setSelectedInv] = useState<AIDetectionInvestigation | null>(null);

  // Status & Note Update Form
  const [newStatus, setNewStatus] = useState<InvestigationStatus>("Reviewing");
  const [analystNote, setAnalystNote] = useState("");
  const [updating, setUpdating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  // False Positive Feedback Form
  const [feedbackVerdict, setFeedbackVerdict] = useState<"true_positive" | "false_positive">("true_positive");
  const [feedbackNotes, setFeedbackNotes] = useState("");
  const [submittingFeedback, setSubmittingFeedback] = useState(false);

  const loadInvestigations = async () => {
    setLoading(true);
    try {
      const res = await apiAIDetection.listInvestigations(
        statusFilter !== "All" ? statusFilter : undefined
      );
      if (res.data) {
        setInvestigations(res.data);
        if (res.data.length > 0 && !selectedInv) {
          setSelectedInv(res.data[0]);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigations();
  }, [statusFilter]);

  const handleUpdateStatus = async () => {
    if (!selectedInv) return;
    setUpdating(true);
    try {
      const res = await apiAIDetection.updateInvestigation(selectedInv.id, {
        status: newStatus,
        analyst_notes: analystNote || undefined,
      });
      if (res.data) {
        setNotice(`Case updated to status: "${newStatus}".`);
        setSelectedInv(res.data);
        setAnalystNote("");
        loadInvestigations();
      } else {
        alert(res.error || "Update failed");
      }
    } catch (e: any) {
      alert(e.message);
    } finally {
      setUpdating(false);
    }
  };

  const handleSubmitFeedback = async () => {
    if (!selectedInv || !selectedInv.detection_id) return;
    setSubmittingFeedback(true);
    try {
      const res = await apiAIDetection.submitFeedback({
        detection_id: selectedInv.detection_id,
        verdict: feedbackVerdict,
        notes: feedbackNotes || undefined,
      });
      if (res.data) {
        setNotice(`Analyst feedback recorded (${feedbackVerdict}). Model tuning profile updated.`);
        setFeedbackNotes("");
        loadInvestigations();
      } else {
        alert(res.error || "Feedback failed");
      }
    } catch (e: any) {
      alert(e.message);
    } finally {
      setSubmittingFeedback(false);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/ai-detection"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to AI Threat Hub
          </Link>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <SearchCheck className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                AI Detection Investigation Workspace
              </h1>
              <p className="text-sm text-slate-400">
                Triage anomalous telemetry detections, confirm suspicious activity, and submit model calibration feedback
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadInvestigations}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {notice && (
        <div className="flex items-center justify-between rounded-xl border border-cyan-500/40 bg-cyan-950/40 p-4 text-sm text-cyan-300">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-cyan-400" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-2">
        {["All", "New", "Reviewing", "Confirmed Suspicious", "False Positive", "Resolved"].map((tab) => (
          <button
            key={tab}
            onClick={() => setStatusFilter(tab)}
            className={`rounded-lg px-4 py-2 text-xs font-semibold transition-colors ${
              statusFilter === tab
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Workspace Master-Detail Split */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Investigation Cases List */}
        <div className="lg:col-span-5 space-y-3">
          {investigations.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center text-xs text-slate-500">
              No investigation cases found for status: {statusFilter}
            </div>
          ) : (
            investigations.map((inv) => {
              const isSelected = selectedInv?.id === inv.id;
              return (
                <div
                  key={inv.id}
                  onClick={() => setSelectedInv(inv)}
                  className={`cursor-pointer rounded-xl border p-4 transition-all ${
                    isSelected
                      ? "border-cyan-500 bg-slate-900 shadow-lg shadow-cyan-950/30"
                      : "border-slate-800 bg-slate-900/60 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        inv.status === "Confirmed Suspicious"
                          ? "bg-red-500/20 text-red-300 border border-red-500/30"
                          : inv.status === "Reviewing"
                          ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                          : inv.status === "False Positive"
                          ? "bg-slate-700 text-slate-400"
                          : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                      }`}
                    >
                      {inv.status}
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {new Date(inv.created_at).toLocaleTimeString()}
                    </span>
                  </div>

                  <h4 className="mt-2 text-sm font-bold text-white">
                    {inv.detection?.detection_category.replace("_", " ") || "Security Anomaly"}
                  </h4>
                  <p className="mt-1 text-xs text-slate-400 line-clamp-1">
                    Asset: {inv.detection?.source_asset_name || "Enterprise Node"}
                  </p>

                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
                    <span>Score: <strong className="text-amber-300 font-mono">{inv.detection?.anomaly_score || 0.85}</strong></span>
                    <span>Confidence: <strong className="text-emerald-300 font-mono">{Math.round((inv.detection?.confidence_score || 0.9) * 100)}%</strong></span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Case Deep-Dive & Action Drawer */}
        <div className="lg:col-span-7">
          {selectedInv ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md space-y-6">
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-cyan-400">
                    Case ID: {selectedInv.id.slice(0, 8)}...
                  </span>
                  <Link
                    href={`/ai-threat-investigation?detection_id=${selectedInv.detection_id}`}
                    className="flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
                  >
                    <BrainCircuit className="h-3.5 w-3.5" />
                    Query AI Assistant
                  </Link>
                </div>

                <h2 className="mt-2 text-xl font-bold text-white">
                  {selectedInv.detection?.detection_category.replace("_", " ").toUpperCase()}
                </h2>
                <p className="mt-1 text-xs text-slate-300">
                  Target Asset: <strong className="text-white">{selectedInv.detection?.source_asset_name || "192.168.10.15"}</strong>
                </p>
              </div>

              {/* Anomaly & Evidence Metrics */}
              <div className="grid grid-cols-3 gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-center">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase">Severity</div>
                  <div className="mt-0.5 text-sm font-bold text-amber-300">
                    {selectedInv.detection?.severity || "High"}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase">Anomaly Score</div>
                  <div className="mt-0.5 text-sm font-bold text-cyan-300 font-mono">
                    {selectedInv.detection?.anomaly_score || 0.88}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase">Detection Method</div>
                  <div className="mt-0.5 text-xs font-bold text-slate-300 font-mono">
                    {selectedInv.detection?.detection_method || "ml_isolation_forest"}
                  </div>
                </div>
              </div>

              {/* Supporting Evidence Breakdown */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Telemetry Evidence & Features Analyzed
                </h4>
                <pre className="max-h-48 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                  {JSON.stringify(selectedInv.detection?.supporting_evidence || {}, null, 2)}
                </pre>
              </div>

              {/* Timeline of Investigation Events */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Investigation Audit Timeline
                </h4>
                <div className="space-y-2">
                  {selectedInv.timeline_events.map((evt, idx) => (
                    <div key={idx} className="flex items-start gap-2 rounded bg-slate-950/40 p-2.5 text-xs">
                      <Clock className="h-3.5 w-3.5 text-slate-500 mt-0.5 shrink-0" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-white">{evt.action}</span>
                          <span className="text-[10px] text-slate-500 font-mono">[{evt.actor}]</span>
                        </div>
                        {evt.notes && <p className="text-[11px] text-slate-400 mt-0.5">{evt.notes}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action: Transition Status & Add Note */}
              <div className="border-t border-slate-800 pt-4 space-y-3">
                <h4 className="text-xs font-semibold text-white">Analyst Disposition & Triage</h4>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label className="text-[11px] text-slate-400">Update Status</label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as InvestigationStatus)}
                      className="mt-1 w-full rounded border border-slate-800 bg-slate-950 p-2 text-xs text-white"
                    >
                      <option value="Reviewing">Reviewing (Triage Active)</option>
                      <option value="Confirmed Suspicious">Confirmed Suspicious</option>
                      <option value="False Positive">False Positive</option>
                      <option value="Escalated">Escalated to Incident</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[11px] text-slate-400">Add Analyst Note</label>
                    <input
                      type="text"
                      value={analystNote}
                      onChange={(e) => setAnalystNote(e.target.value)}
                      placeholder="e.g. Host verified clean, periodic cron job..."
                      className="mt-1 w-full rounded border border-slate-800 bg-slate-950 p-2 text-xs text-white"
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleUpdateStatus}
                    disabled={updating}
                    className="rounded bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                  >
                    {updating ? "Updating..." : "Save Case Disposition"}
                  </button>
                </div>
              </div>

              {/* Action: False Positive / Model Calibration Feedback */}
              <div className="border-t border-slate-800 pt-4 space-y-3">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Model Calibration Feedback
                </h4>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setFeedbackVerdict("true_positive")}
                    className={`flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-semibold ${
                      feedbackVerdict === "true_positive"
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    <ThumbsUp className="h-3.5 w-3.5" />
                    True Positive (Accurate)
                  </button>
                  <button
                    onClick={() => setFeedbackVerdict("false_positive")}
                    className={`flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-semibold ${
                      feedbackVerdict === "false_positive"
                        ? "bg-red-500/20 text-red-300 border border-red-500/40"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    <ThumbsDown className="h-3.5 w-3.5" />
                    False Positive (Noise)
                  </button>
                </div>

                <button
                  onClick={handleSubmitFeedback}
                  disabled={submittingFeedback}
                  className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-50"
                >
                  {submittingFeedback ? "Submitting..." : "Submit Model Feedback"}
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center text-sm text-slate-500">
              Select an investigation case on the left to review telemetry evidence and update triage status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
