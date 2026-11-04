"use client";

import { useState, useEffect } from "react";
import {
  BellRing,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  X,
  RotateCcw,
  RefreshCw,
  AlertTriangle,
  UserCheck,
  FileText,
  Clock,
  Send,
  MessageSquare,
  Flame,
  ShieldCheck,
  AlertOctagon,
  Check,
} from "lucide-react";
import { SecurityAlert, AlertStatus, SeverityLevel } from "@/types/threat-intel";
import { apiAlerts } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
};

const STATUS_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  New: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  Investigating: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Escalated: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  Resolved: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  "False Positive": { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [activeTab, setActiveTab] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");

  // Selected Alert for Triage Modal
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [triageStatus, setTriageStatus] = useState<AlertStatus>("Investigating");
  const [assigneeId, setAssigneeId] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [newNote, setNewNote] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [savingAction, setSavingAction] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiAlerts.list({
        page,
        page_size: pageSize,
        search: search || undefined,
        status: activeTab !== "all" ? activeTab : undefined,
        severity: selectedSeverity !== "all" ? selectedSeverity : undefined,
      });

      if (res.data) {
        setAlerts(res.data.items || []);
        setTotalCount(res.data.total || 0);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load security alerts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, activeTab, selectedSeverity]);

  const openTriageModal = async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setTriageStatus(alert.status);
    setAssigneeId(alert.assigned_to || "");
    setIncidentId(alert.linked_incident_id || "");
    setActionError(null);
    try {
      const res = await apiAlerts.get(alert.id);
      if (res.data) {
        setSelectedAlert(res.data);
      }
    } catch (e) {
      // fallback to current item
    }
  };

  const handleUpdateStatus = async () => {
    if (!selectedAlert) return;
    if (
      (triageStatus === "Resolved" || triageStatus === "False Positive") &&
      !newNote.trim()
    ) {
      setActionError("A resolution note is required when resolving or closing an alert.");
      return;
    }

    setSavingAction(true);
    setActionError(null);
    try {
      // If note provided, add it first
      if (newNote.trim()) {
        await apiAlerts.addNote(selectedAlert.id, newNote.trim());
      }

      const res = await apiAlerts.update(selectedAlert.id, {
        status: triageStatus,
        assigned_to: assigneeId || undefined,
      });

      if (res.error) {
        setActionError(res.error);
      } else {
        setNewNote("");
        const fresh = await apiAlerts.get(selectedAlert.id);
        if (fresh.data) setSelectedAlert(fresh.data);
        fetchAlerts();
      }
    } catch (err: any) {
      setActionError(err.message || "Failed to update alert.");
    } finally {
      setSavingAction(false);
    }
  };

  const handleLinkIncident = async () => {
    if (!selectedAlert || !incidentId) return;
    setSavingAction(true);
    try {
      const res = await apiAlerts.linkIncident(selectedAlert.id, incidentId);
      if (res.error) {
        setActionError(res.error);
      } else {
        const fresh = await apiAlerts.get(selectedAlert.id);
        if (fresh.data) setSelectedAlert(fresh.data);
        fetchAlerts();
      }
    } catch (e: any) {
      setActionError(e.message || "Failed to link incident.");
    } finally {
      setSavingAction(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert || !newNote.trim()) return;
    setSavingAction(true);
    try {
      await apiAlerts.addNote(selectedAlert.id, newNote.trim());
      setNewNote("");
      const fresh = await apiAlerts.get(selectedAlert.id);
      if (fresh.data) setSelectedAlert(fresh.data);
    } catch (err: any) {
      setActionError(err.message);
    } finally {
      setSavingAction(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Security Alerts</h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
              SOC Queue
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Automated correlation alerts, triage workflow, analyst investigation, and incident escalation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchAlerts()}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Severity Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-rose-400 mb-1">
            <span className="text-xs uppercase tracking-wider font-semibold">Critical Alerts</span>
            <AlertOctagon className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-rose-400">
            {alerts.filter((a) => a.severity === "Critical").length}
          </div>
          <span className="text-[11px] text-slate-400">Immediate response required</span>
        </div>

        <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-amber-400 mb-1">
            <span className="text-xs uppercase tracking-wider font-semibold">High Priority</span>
            <AlertTriangle className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {alerts.filter((a) => a.severity === "High").length}
          </div>
          <span className="text-[11px] text-slate-400">Investigate within 4 hours</span>
        </div>

        <div className="p-4 rounded-xl border border-sky-500/20 bg-sky-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-sky-400 mb-1">
            <span className="text-xs uppercase tracking-wider font-semibold">Medium Alerts</span>
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-sky-400">
            {alerts.filter((a) => a.severity === "Medium").length}
          </div>
          <span className="text-[11px] text-slate-400">Routine review</span>
        </div>

        <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-blue-400 mb-1">
            <span className="text-xs uppercase tracking-wider font-semibold">Under Investigation</span>
            <UserCheck className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-blue-400">
            {alerts.filter((a) => a.status === "Investigating").length}
          </div>
          <span className="text-[11px] text-slate-400">Active analyst triage</span>
        </div>
      </div>

      {/* Tabs and Filter Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-1 overflow-x-auto">
            {["all", "New", "Investigating", "Escalated", "Resolved", "False Positive"].map((tab) => (
              <button
                key={tab}
                onClick={() => {
                  setActiveTab(tab);
                  setPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                  activeTab === tab
                    ? "bg-blue-600 text-white shadow"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                }`}
              >
                {tab === "all" ? "All Alerts" : tab}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search alert title, affected asset, or correlation rule..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
          />
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-900/40">
                <th className="py-3 px-4">Alert Title</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Detection Source</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Assigned Analyst</th>
                <th className="py-3 px-4">Last Detected</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Loading SOC alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No security alerts found in current view.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => {
                  const sBadge = SEVERITY_BADGES[alert.severity] || SEVERITY_BADGES.Medium;
                  const stBadge = STATUS_BADGES[alert.status] || STATUS_BADGES.New;
                  return (
                    <tr
                      key={alert.id}
                      onClick={() => openTriageModal(alert)}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-100 max-w-md truncate">
                          {alert.title}
                        </div>
                        <div className="text-[11px] text-slate-400 max-w-md truncate mt-0.5">
                          {alert.description}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${sBadge.bg} ${sBadge.text} ${sBadge.border}`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium border ${stBadge.bg} ${stBadge.text} ${stBadge.border}`}
                        >
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 font-mono text-[11px]">
                        {alert.source}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {alert.confidence}%
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                        {alert.assigned_to ? (
                          <span className="text-cyan-400">Analyst Assigned</span>
                        ) : (
                          <span className="text-slate-600">Unassigned</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {formatDateTime(alert.last_detected_at)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            openTriageModal(alert);
                          }}
                          className="px-3 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 text-xs font-medium"
                        >
                          Triage
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {alerts.length} of {totalCount} alerts
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span>Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={alerts.length < pageSize}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Triage & Investigation Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BellRing className="h-5 w-5 text-rose-400" />
                <h2 className="text-lg font-bold text-white">Alert Triage & Investigation</h2>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              {actionError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  {actionError}
                </div>
              )}

              {/* Alert Header Summary */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                      SEVERITY_BADGES[selectedAlert.severity]?.bg
                    } ${SEVERITY_BADGES[selectedAlert.severity]?.text} ${
                      SEVERITY_BADGES[selectedAlert.severity]?.border
                    }`}
                  >
                    {selectedAlert.severity} Severity
                  </span>
                  <span className="font-mono text-slate-400">
                    Confidence: {selectedAlert.confidence}%
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">{selectedAlert.title}</h3>
                <p className="text-slate-300 leading-relaxed">{selectedAlert.description}</p>
                <div className="pt-2 flex flex-wrap items-center gap-4 text-slate-400 font-mono text-[11px]">
                  <div>Source: <span className="text-slate-200">{selectedAlert.source}</span></div>
                  <div>First: {formatDateTime(selectedAlert.first_detected_at)}</div>
                  <div>Last: {formatDateTime(selectedAlert.last_detected_at)}</div>
                </div>
              </div>

              {/* Triage Controls */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-4 rounded-xl bg-slate-900/50 border border-slate-800">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Status Workflow</label>
                  <select
                    value={triageStatus}
                    onChange={(e) => setTriageStatus(e.target.value as AlertStatus)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 font-medium"
                  >
                    <option value="New">New</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Escalated">Escalated</option>
                    <option value="Resolved">Resolved</option>
                    <option value="False Positive">False Positive</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Assignee</label>
                  <select
                    value={assigneeId}
                    onChange={(e) => setAssigneeId(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="">Unassigned</option>
                    <option value="00000000-0000-0000-0000-000000000001">Lead SOC Analyst</option>
                    <option value="00000000-0000-0000-0000-000000000002">Security Architect</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Linked Incident</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="e.g. INC-2026-001"
                      value={incidentId}
                      onChange={(e) => setIncidentId(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 font-mono text-[11px]"
                    />
                    <button
                      type="button"
                      onClick={handleLinkIncident}
                      disabled={!incidentId || savingAction}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs"
                    >
                      Link
                    </button>
                  </div>
                </div>
              </div>

              {/* Resolution Note if Resolving */}
              {(triageStatus === "Resolved" || triageStatus === "False Positive") && (
                <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300">
                  <span className="font-semibold block mb-1">Resolution Justification Required</span>
                  Please provide a detailed justification note below before marking this alert as {triageStatus}.
                </div>
              )}

              {/* Analyst Notes & Discussion */}
              <div className="space-y-3">
                <div className="flex items-center justify-between text-slate-400 font-semibold">
                  <div className="flex items-center gap-1.5">
                    <MessageSquare className="h-4 w-4" />
                    <span>Investigation Notes Timeline</span>
                  </div>
                  <span className="text-[11px] font-mono">
                    {selectedAlert.notes?.length || 0} entries
                  </span>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedAlert.notes && selectedAlert.notes.length > 0 ? (
                    selectedAlert.notes.map((n) => (
                      <div
                        key={n.id}
                        className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span className="font-mono text-cyan-400">SOC Analyst</span>
                          <span>{formatDateTime(n.created_at)}</span>
                        </div>
                        <p className="text-slate-200">{n.note}</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-500 italic p-3 text-center bg-slate-900/40 rounded-lg">
                      No analyst notes logged for this alert yet.
                    </div>
                  )}
                </div>

                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Log investigative observation or resolution reasoning..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500"
                  />
                  <button
                    type="submit"
                    disabled={!newNote.trim() || savingAction}
                    className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg flex items-center gap-1.5 disabled:opacity-40"
                  >
                    <Send className="h-3.5 w-3.5" />
                    Post
                  </button>
                </form>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Close
              </button>
              <button
                onClick={handleUpdateStatus}
                disabled={savingAction}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow disabled:opacity-40"
              >
                {savingAction ? "Saving..." : "Save Triage Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
