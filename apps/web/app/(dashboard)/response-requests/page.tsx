"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Search,
  RefreshCw,
  AlertTriangle,
  Lock,
  WifiOff,
  Flame,
  ArrowRight,
  ShieldCheck,
  FileText,
  SlidersHorizontal,
  X,
  Check,
} from "lucide-react";
import { ResponseRequest, ResponseActionType } from "@/types/incident";
import { apiResponseRequests } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const ACTION_META: Record<ResponseActionType, { label: string; bg: string; text: string; border: string; icon: any }> = {
  isolate_asset: {
    label: "Isolate Asset Host",
    bg: "bg-rose-500/10",
    text: "text-rose-400",
    border: "border-rose-500/30",
    icon: WifiOff,
  },
  disable_account: {
    label: "Disable User Account",
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30",
    icon: Lock,
  },
  block_firewall_rule: {
    label: "Block Firewall ACL Rule",
    bg: "bg-purple-500/10",
    text: "text-purple-400",
    border: "border-purple-500/30",
    icon: ShieldAlert,
  },
  remediate_vulnerability: {
    label: "Remediate Vulnerability",
    bg: "bg-cyan-500/10",
    text: "text-cyan-400",
    border: "border-cyan-500/30",
    icon: ShieldCheck,
  },
  escalate_incident: {
    label: "Escalate to Executive Crisis",
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30",
    icon: Flame,
  },
};

export default function ResponseRequestsPage() {
  const [requests, setRequests] = useState<ResponseRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [actionFilter, setActionFilter] = useState<string>("all");

  // Approval / Rejection Modal State
  const [actionModal, setActionModal] = useState<{
    request: ResponseRequest;
    decision: "Approved" | "Rejected";
  } | null>(null);
  const [decisionNotes, setDecisionNotes] = useState("");
  const [submittingDecision, setSubmittingDecision] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const fetchRequests = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiResponseRequests.list();
      if (res.data) {
        setRequests(res.data);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load response requests.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, []);

  const handleOpenDecisionModal = (request: ResponseRequest, decision: "Approved" | "Rejected") => {
    setActionModal({ request, decision });
    setDecisionNotes("");
    setDecisionError(null);
  };

  const handleConfirmDecision = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!actionModal) return;
    if (decisionNotes.trim().length < 5) {
      setDecisionError("Justification notes must be at least 5 characters.");
      return;
    }

    setSubmittingDecision(true);
    setDecisionError(null);
    try {
      if (actionModal.decision === "Approved") {
        await apiResponseRequests.approve(actionModal.request.id, decisionNotes);
      } else {
        await apiResponseRequests.reject(actionModal.request.id, decisionNotes);
      }

      setActionModal(null);
      fetchRequests();
    } catch (err: any) {
      setDecisionError(err?.message || "Failed to submit decision.");
    } finally {
      setSubmittingDecision(false);
    }
  };

  const filtered = requests.filter((r) => {
    if (statusFilter !== "all" && r.status !== statusFilter) return false;
    if (actionFilter !== "all" && r.action_type !== actionFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const matchResource = r.target_resource?.toLowerCase().includes(q);
      const matchJust = r.justification?.toLowerCase().includes(q);
      const matchIncident = r.incident_id?.toLowerCase().includes(q);
      if (!matchResource && !matchJust && !matchIncident) return false;
    }
    return true;
  });

  const pendingCount = requests.filter((r) => r.status === "Pending").length;
  const approvedCount = requests.filter((r) => r.status === "Approved").length;
  const rejectedCount = requests.filter((r) => r.status === "Rejected").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Response Approvals</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Human-in-the-loop authorization workflow for high-impact host isolation, firewall rules, and account suspensions.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchRequests}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Awaiting Decision</span>
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-amber-400 tracking-tight">{pendingCount}</span>
            <span className="text-xs text-amber-400/80">requires sign-off</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Security operator approval gate</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Approved & Authorized</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-emerald-400 tracking-tight">{approvedCount}</span>
            <span className="text-xs text-slate-400">actions authorized</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Documented SOC containment actions</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Rejected Requests</span>
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <XCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-slate-300 tracking-tight">{rejectedCount}</span>
            <span className="text-xs text-rose-400">denied</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Blocked disruptive side-effects</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Safety Policy</span>
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-blue-400 tracking-tight">100%</span>
            <span className="text-xs text-slate-400">Enforced</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Zero non-consensual destructive actions</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111C2D]/60 border border-slate-800/80 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by target resource, justification, or incident ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 transition-colors"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500/60"
          >
            <option value="all">All Statuses</option>
            <option value="Pending">Pending Decision</option>
            <option value="Approved">Approved</option>
            <option value="Rejected">Rejected</option>
          </select>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500/60"
          >
            <option value="all">All Action Types</option>
            <option value="isolate_asset">Isolate Asset</option>
            <option value="disable_account">Disable Account</option>
            <option value="block_firewall_rule">Block Firewall Rule</option>
            <option value="remediate_vulnerability">Remediate Vulnerability</option>
            <option value="escalate_incident">Escalate Incident</option>
          </select>
        </div>
      </div>

      {/* Requests Feed */}
      {loading ? (
        <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
          <p className="text-sm">Loading response approval requests...</p>
        </div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-rose-500/10 border border-rose-500/20 text-center">
          <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
          <p className="text-sm text-rose-300">{error}</p>
          <button
            onClick={fetchRequests}
            className="mt-3 px-4 py-1.5 text-xs rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 transition-colors"
          >
            Retry
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-16 text-center border border-dashed border-slate-800 rounded-xl">
          <ShieldCheck className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-slate-300">No response requests found</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            All containment requests have been reviewed or no actions match current filters.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map((req) => {
            const meta = ACTION_META[req.action_type] || {
              label: req.action_type,
              bg: "bg-slate-800",
              text: "text-slate-300",
              border: "border-slate-700",
              icon: AlertTriangle,
            };
            const ActionIcon = meta.icon;

            return (
              <div
                key={req.id}
                className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 hover:border-slate-700/80 transition-all backdrop-blur-sm space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-lg ${meta.bg} border ${meta.border} ${meta.text}`}>
                      <ActionIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white tracking-tight">{meta.label}</span>
                        <span
                          className={`px-2 py-0.5 text-[10px] font-semibold rounded-full uppercase tracking-wider ${
                            req.status === "Pending"
                              ? "bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse"
                              : req.status === "Approved"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                              : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                          }`}
                        >
                          {req.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                        <span>Target:</span>
                        <code className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-blue-400 font-mono text-[11px]">
                          {req.target_resource}
                        </code>
                      </div>
                    </div>
                  </div>

                  {/* Actions for Pending */}
                  {req.status === "Pending" ? (
                    <div className="flex items-center gap-2 self-end sm:self-center">
                      <button
                        onClick={() => handleOpenDecisionModal(req, "Approved")}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20 transition-all"
                      >
                        <Check className="w-3.5 h-3.5" /> Approve Action
                      </button>
                      <button
                        onClick={() => handleOpenDecisionModal(req, "Rejected")}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-colors"
                      >
                        <X className="w-3.5 h-3.5" /> Reject
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      {req.status === "Approved" ? (
                        <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-4 h-4" /> Authorized
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5 text-rose-400 font-medium">
                          <XCircle className="w-4 h-4" /> Rejected
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Justification Box */}
                <div className="p-3.5 rounded-lg bg-[#080D18]/70 border border-slate-800/80 text-xs">
                  <span className="text-slate-400 font-medium block mb-1">Analyst Justification:</span>
                  <p className="text-slate-300 leading-relaxed">{req.justification}</p>
                </div>

                {/* Audit and Decision Trail */}
                <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-xs text-slate-500 gap-2">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span>
                      Requested: <strong className="text-slate-400">{formatDateTime(req.created_at)}</strong>
                    </span>
                    {req.requested_by && (
                      <span>
                        By: <strong className="text-slate-400 font-mono text-[11px]">{req.requested_by}</strong>
                      </span>
                    )}
                    {req.incident_id && (
                      <Link
                        href={`/incidents/${req.incident_id}`}
                        className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        View Incident Case <ArrowRight className="w-3 h-3" />
                      </Link>
                    )}
                  </div>

                  {req.approval && (
                    <div className="text-right text-xs">
                      <span className="text-slate-400">
                        {req.approval.decision} on {formatDateTime(req.approval.decided_at)}
                      </span>
                      {req.approval.decision_notes && (
                        <p className="text-slate-300 italic text-[11px] mt-0.5">
                          &quot;{req.approval.decision_notes}&quot;
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Decision Review Modal */}
      {actionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#111C2D] border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                {actionModal.decision === "Approved" ? (
                  <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    <CheckCircle2 className="w-5 h-5" />
                  </div>
                ) : (
                  <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
                    <XCircle className="w-5 h-5" />
                  </div>
                )}
                <div>
                  <h3 className="text-base font-bold text-white">
                    {actionModal.decision === "Approved" ? "Approve Containment Action" : "Reject Action Request"}
                  </h3>
                  <p className="text-xs text-slate-400">Mandatory SOC governance sign-off</p>
                </div>
              </div>
              <button
                onClick={() => setActionModal(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 rounded-lg bg-[#080D18] border border-slate-800 text-xs space-y-1.5">
              <div>
                <span className="text-slate-500">Action: </span>
                <span className="font-semibold text-slate-200">{actionModal.request.action_type}</span>
              </div>
              <div>
                <span className="text-slate-500">Target: </span>
                <code className="text-blue-400 font-mono text-[11px]">{actionModal.request.target_resource}</code>
              </div>
            </div>

            {decisionError && (
              <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300">
                {decisionError}
              </div>
            )}

            <form onSubmit={handleConfirmDecision} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Decision Justification & Audit Notes *
                </label>
                <textarea
                  rows={3}
                  required
                  placeholder={
                    actionModal.decision === "Approved"
                      ? "Detail why this containment action is justified and risks were assessed..."
                      : "Detail the rationale for declining this response action..."
                  }
                  value={decisionNotes}
                  onChange={(e) => setDecisionNotes(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080D18] border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setActionModal(null)}
                  className="px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingDecision}
                  className={`flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg text-white shadow-lg transition-all ${
                    actionModal.decision === "Approved"
                      ? "bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/20"
                      : "bg-rose-600 hover:bg-rose-500 shadow-rose-600/20"
                  } disabled:opacity-50`}
                >
                  {submittingDecision ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : actionModal.decision === "Approved" ? (
                    <Check className="w-3.5 h-3.5" />
                  ) : (
                    <X className="w-3.5 h-3.5" />
                  )}
                  Confirm {actionModal.decision}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
