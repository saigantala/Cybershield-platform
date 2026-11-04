"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ShieldAlert,
  Server,
  Lock,
  RefreshCw,
  Search,
  Filter,
  UserCheck,
  ExternalLink,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { SOARApproval } from "@/types/soar";

export default function SOARApprovalsPage() {
  const [approvals, setApprovals] = useState<SOARApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState<string>("Pending");
  const [selectedApproval, setSelectedApproval] = useState<SOARApproval | null>(null);
  const [actionType, setActionType] = useState<"approve" | "reject">("approve");
  const [justificationNotes, setJustificationNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const loadApprovals = async () => {
    setLoading(true);
    try {
      const res = await apiSOAR.listApprovals(
        decisionFilter !== "All" ? decisionFilter : undefined
      );
      if (res.data) setApprovals(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
  }, [decisionFilter]);

  const handleOpenDecisionModal = (approval: SOARApproval, type: "approve" | "reject") => {
    setSelectedApproval(approval);
    setActionType(type);
    setJustificationNotes(
      type === "approve"
        ? "Action authorized after reviewing forensic event and network scope."
        : "Rejected: Verified target is normal business infrastructure."
    );
  };

  const handleSubmitDecision = async () => {
    if (!selectedApproval) return;
    if (!justificationNotes.trim()) {
      alert("Please provide justification notes for the audit trail.");
      return;
    }

    setSubmitting(true);
    try {
      let res;
      if (actionType === "approve") {
        res = await apiSOAR.approveAction(selectedApproval.id, {
          decision: "Approved",
          justification_notes: justificationNotes,
        });
      } else {
        res = await apiSOAR.rejectAction(selectedApproval.id, {
          decision: "Rejected",
          justification_notes: justificationNotes,
        });
      }

      if (res.data) {
        setNotice(
          `Action "${selectedApproval.action_type}" on ${selectedApproval.target_resource} was ${actionType === "approve" ? "APPROVED & EXECUTED" : "REJECTED"}.`
        );
        setSelectedApproval(null);
        loadApprovals();
      } else {
        alert(res.error || "Decision processing failed");
      }
    } catch (e: any) {
      alert(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-950/40 text-amber-400">
              <ClipboardCheck className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Action Approvals & Authorization Gates
              </h1>
              <p className="text-sm text-slate-400">
                Human-in-the-loop review for disruptive containment (host isolation, account suspension, firewall ACLs)
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadApprovals}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {notice && (
        <div className="flex items-center justify-between rounded-xl border border-emerald-500/40 bg-emerald-950/40 p-4 text-sm text-emerald-300">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Safety Policy Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-cyan-400" />
          <div className="text-xs text-slate-300">
            <strong className="text-white font-semibold">Zero-Disruption Safety Protocol:</strong>{" "}
            Playbooks pause automatically at containment gates. Destructive or isolating actions require explicit
            analyst validation to prevent unauthorized network outages or false-positive asset locks.
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-2">
        {["Pending", "Executed", "Rejected", "All"].map((tab) => (
          <button
            key={tab}
            onClick={() => setDecisionFilter(tab)}
            className={`rounded-lg px-4 py-2 text-xs font-semibold transition-colors ${
              decisionFilter === tab
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            }`}
          >
            {tab === "Pending" ? "Pending Authorization" : tab}
          </button>
        ))}
      </div>

      {/* Approvals List */}
      <div className="space-y-4">
        {approvals.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 py-12 text-center text-sm text-slate-500">
            No approval requests found for filter: <strong className="text-slate-300">{decisionFilter}</strong>
          </div>
        ) : (
          approvals.map((app) => (
            <div
              key={app.id}
              className={`rounded-xl border p-6 backdrop-blur-md transition-all ${
                app.decision === "Pending"
                  ? "border-amber-500/40 bg-amber-950/10"
                  : app.decision === "Executed" || app.decision === "Approved"
                  ? "border-emerald-500/30 bg-slate-900/60"
                  : "border-slate-800 bg-slate-900/40"
              }`}
            >
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-amber-500/20 px-2 py-0.5 text-xs font-bold text-amber-300 border border-amber-500/30 uppercase tracking-wide">
                      {app.action_type.replace("_", " ")}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        app.decision === "Pending"
                          ? "bg-amber-500/20 text-amber-300"
                          : app.decision === "Executed" || app.decision === "Approved"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : "bg-red-500/20 text-red-300"
                      }`}
                    >
                      {app.decision}
                    </span>
                    <span className="text-xs text-slate-500">
                      ID: <code className="text-slate-400">{app.id.slice(0, 8)}</code>
                    </span>
                  </div>

                  <h3 className="mt-2 text-base font-bold text-white">
                    Target Resource: <span className="font-mono text-cyan-300">{app.target_resource}</span>
                  </h3>
                  <p className="mt-1 text-xs text-slate-300">
                    Playbook: <strong className="text-white">{app.workflow_name}</strong>
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    Justification: <span className="text-slate-200">{app.justification}</span>
                  </p>

                  <div className="mt-3 flex flex-wrap items-center gap-4 text-[11px] text-slate-500">
                    <span>Created: {new Date(app.created_at).toLocaleString()}</span>
                    {app.expires_at && (
                      <span className="flex items-center gap-1 text-amber-400">
                        <Clock className="h-3 w-3" />
                        Expires: {new Date(app.expires_at).toLocaleString()}
                      </span>
                    )}
                    {app.decision_notes && (
                      <span className="text-slate-300">
                        Analyst Note: <em>"{app.decision_notes}"</em>
                      </span>
                    )}
                  </div>
                </div>

                {/* Action buttons if Pending */}
                {app.decision === "Pending" && (
                  <div className="flex items-center gap-3 shrink-0">
                    <button
                      onClick={() => handleOpenDecisionModal(app, "reject")}
                      className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-950/40 px-4 py-2 text-xs font-semibold text-red-300 transition-colors hover:bg-red-900/60"
                    >
                      <XCircle className="h-4 w-4" />
                      Reject
                    </button>
                    <button
                      onClick={() => handleOpenDecisionModal(app, "approve")}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-emerald-950/50 transition-colors hover:bg-emerald-500"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      Authorize & Execute
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Decision Authorization Modal */}
      {selectedApproval && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white">
                  {actionType === "approve" ? "Authorize Containment Action" : "Reject Action Request"}
                </h3>
                <p className="text-xs text-slate-400">
                  Target: {selectedApproval.target_resource} ({selectedApproval.action_type})
                </p>
              </div>
              <button
                onClick={() => setSelectedApproval(null)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            <div className="mt-4 space-y-4">
              <div
                className={`rounded-lg border p-3 text-xs ${
                  actionType === "approve"
                    ? "border-emerald-500/30 bg-emerald-950/20 text-emerald-200"
                    : "border-red-500/30 bg-red-950/20 text-red-200"
                }`}
              >
                {actionType === "approve"
                  ? "Approving will resume the workflow execution immediately and execute the disruptive containment action."
                  : "Rejecting will abort the containment step and mark the workflow execution as Cancelled."}
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300">
                  Mandatory Analyst Audit Justification
                </label>
                <textarea
                  rows={3}
                  value={justificationNotes}
                  onChange={(e) => setJustificationNotes(e.target.value)}
                  placeholder="State the technical reason, ticket ID, or investigation finding..."
                  className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                onClick={() => setSelectedApproval(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitDecision}
                disabled={submitting}
                className={`flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50 ${
                  actionType === "approve"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                }`}
              >
                {submitting ? "Processing..." : actionType === "approve" ? "Sign & Execute" : "Confirm Rejection"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
