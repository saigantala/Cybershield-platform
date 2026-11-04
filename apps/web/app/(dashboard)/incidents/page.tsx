"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Plus,
  Search,
  Clock,
  User,
  CheckCircle2,
  ShieldAlert,
  X,
  MessageSquare,
  Flame,
  ArrowRight,
  Filter,
  RefreshCw,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
  Download,
  FileText,
  Shield,
  Layers,
  CheckSquare,
} from "lucide-react";
import { Incident, IncidentSeverity, IncidentStatus, IncidentType, IncidentPriority } from "@/types/incident";
import { apiIncidents, apiAlerts } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
};

const STATUS_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  New: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  Acknowledged: { bg: "bg-purple-500/10", text: "text-purple-400", border: "border-purple-500/30" },
  Investigating: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Containment: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  Eradication: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  Recovery: { bg: "bg-cyan-500/10", text: "text-cyan-400", border: "border-cyan-500/30" },
  Resolved: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  Closed: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function IncidentCenterPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [selectedType, setSelectedType] = useState<string>("all");

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newType, setNewType] = useState<IncidentType>("Unauthorized Access");
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>("High");
  const [newPriority, setNewPriority] = useState<IncidentPriority>("P2");
  const [newDesc, setNewDesc] = useState("");
  const [newAsset, setNewAsset] = useState("");
  const [availableAlerts, setAvailableAlerts] = useState<any[]>([]);
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiIncidents.list({
        page,
        page_size: pageSize,
        search: search || undefined,
        severity: selectedSeverity !== "all" ? selectedSeverity : undefined,
        status: selectedStatus !== "all" ? selectedStatus : undefined,
        incident_type: selectedType !== "all" ? selectedType : undefined,
      });

      if (res.data) {
        setIncidents(res.data.items || []);
        setTotalCount(res.data.total || 0);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load incident cases.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [page, selectedSeverity, selectedStatus, selectedType]);

  const openCreateModal = async () => {
    setShowCreateModal(true);
    setFormError(null);
    try {
      const res = await apiAlerts.list({ status: "New" });
      if (res.data) {
        setAvailableAlerts(res.data.items || []);
      }
    } catch (e) {
      // ignore
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      const res = await apiIncidents.create({
        title: newTitle,
        description: newDesc,
        incident_type: newType,
        severity: newSeverity,
        priority: newPriority,
        affected_assets: newAsset ? [newAsset] : [],
        initial_alert_ids: selectedAlertIds,
      });

      if (res.error) {
        setFormError(res.error);
      } else {
        setShowCreateModal(false);
        setNewTitle("");
        setNewDesc("");
        setNewAsset("");
        setSelectedAlertIds([]);
        fetchIncidents();
      }
    } catch (err: any) {
      setFormError(err.message || "Failed to create incident.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchIncidents();
  };

  // KPI Calculations
  const criticalCount = incidents.filter((i) => i.severity === "Critical").length;
  const investigatingCount = incidents.filter((i) => i.status === "Investigating" || i.status === "Containment").length;
  const resolvedCount = incidents.filter((i) => i.status === "Resolved" || i.status === "Closed").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Incident Response Center</h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
              IR Command
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Centrally investigate security incidents, coordinate containment workflows, and document forensic evidence.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchIncidents()}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
          <button
            onClick={openCreateModal}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-sm font-semibold shadow-lg shadow-blue-600/25 transition-all"
          >
            <Plus className="h-4 w-4" />
            Create Incident
          </button>
        </div>
      </div>

      {/* KPI Overview Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Total Incidents</span>
            <AlertTriangle className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">{totalCount}</div>
          <span className="text-[11px] text-slate-400">All registered cases</span>
        </div>

        <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-rose-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Critical Incidents</span>
            <Flame className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{criticalCount}</div>
          <span className="text-[11px] text-slate-400">Immediate priority P1</span>
        </div>

        <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-amber-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Active Triage</span>
            <Clock className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{investigatingCount}</div>
          <span className="text-[11px] text-slate-400">Investigation & containment</span>
        </div>

        <div className="p-4 rounded-xl border border-cyan-500/20 bg-cyan-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-cyan-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Pending Approvals</span>
            <CheckSquare className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">1 Pending</div>
          <Link href="/response-requests" className="text-[11px] text-cyan-400 hover:underline">
            View response queue &rarr;
          </Link>
        </div>

        <div className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 backdrop-blur-md">
          <div className="flex items-center justify-between text-emerald-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Resolved Cases</span>
            <CheckCircle2 className="h-4 w-4" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{resolvedCount}</div>
          <span className="text-[11px] text-slate-400">Closed or post-incident</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search incident number (e.g. CS-2026-000001), title, or keywords..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="New">New</option>
              <option value="Acknowledged">Acknowledged</option>
              <option value="Investigating">Investigating</option>
              <option value="Containment">Containment</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>

            <select
              value={selectedType}
              onChange={(e) => {
                setSelectedType(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Incident Types</option>
              <option value="Malware">Malware</option>
              <option value="Phishing">Phishing</option>
              <option value="Unauthorized Access">Unauthorized Access</option>
              <option value="Suspicious Network Activity">Network Activity</option>
              <option value="Vulnerability Exploitation">Vulnerability Exploit</option>
              <option value="Data Exposure">Data Exposure</option>
              <option value="Account Compromise">Account Compromise</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold"
            >
              Filter
            </button>

            {(search || selectedSeverity !== "all" || selectedStatus !== "all" || selectedType !== "all") && (
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSelectedSeverity("all");
                  setSelectedStatus("all");
                  setSelectedType("all");
                  setPage(1);
                }}
                className="p-2 text-slate-400 hover:text-slate-200"
                title="Reset filters"
              >
                <RotateCcw className="h-4 w-4" />
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Incident Table */}
      <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-900/40">
                <th className="py-3 px-4">Case #</th>
                <th className="py-3 px-4">Title & Context</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assigned Analyst</th>
                <th className="py-3 px-4">Detected At</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Loading incident cases...
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No incidents found matching current filters.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  const sBadge = SEVERITY_BADGES[inc.severity] || SEVERITY_BADGES.Medium;
                  const stBadge = STATUS_BADGES[inc.status] || STATUS_BADGES.New;
                  return (
                    <tr
                      key={inc.id}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-cyan-400 whitespace-nowrap">
                        <Link href={`/incidents/${inc.id}`} className="hover:underline">
                          {inc.incident_number}
                        </Link>
                      </td>
                      <td className="py-3.5 px-4">
                        <Link href={`/incidents/${inc.id}`} className="block">
                          <div className="font-semibold text-slate-100 group-hover:text-blue-400 transition-colors max-w-md truncate">
                            {inc.title}
                          </div>
                          <div className="text-[11px] text-slate-400 max-w-md truncate mt-0.5">
                            {inc.description}
                          </div>
                        </Link>
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${sBadge.bg} ${sBadge.text} ${sBadge.border}`}
                        >
                          {inc.severity}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300 font-medium">
                        {inc.incident_type}
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium border ${stBadge.bg} ${stBadge.text} ${stBadge.border}`}
                        >
                          {inc.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {inc.assigned_to ? (
                          <span className="text-slate-300 flex items-center gap-1">
                            <User className="h-3 w-3 text-cyan-400" />
                            Assigned
                          </span>
                        ) : (
                          <span className="text-slate-600">Unassigned</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {formatDateTime(inc.detected_at)}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="inline-flex items-center gap-1 px-3 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 text-xs font-semibold transition-colors"
                        >
                          <span>Investigate</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
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
            Showing {incidents.length} of {totalCount} incidents
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
              disabled={incidents.length < pageSize}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Plus className="h-5 w-5 text-blue-400" />
                <h2 className="text-lg font-bold text-white">Create Security Incident</h2>
              </div>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="p-6 space-y-4 overflow-y-auto text-xs">
              {formError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  {formError}
                </div>
              )}

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Incident Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Ingress SSH Brute Force and Privileged Esc."
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Incident Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as IncidentType)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="Malware">Malware</option>
                    <option value="Phishing">Phishing</option>
                    <option value="Unauthorized Access">Unauthorized Access</option>
                    <option value="Suspicious Network Activity">Network Activity</option>
                    <option value="Vulnerability Exploitation">Vulnerability Exploitation</option>
                    <option value="Data Exposure">Data Exposure</option>
                    <option value="Account Compromise">Account Compromise</option>
                    <option value="IoT Security Incident">IoT Incident</option>
                    <option value="Other">Other</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as IncidentPriority)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="P1">P1 (Critical Impact)</option>
                    <option value="P2">P2 (Major Concern)</option>
                    <option value="P3">P3 (Moderate Threat)</option>
                    <option value="P4">P4 (Low Risk)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Incident Description</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Detail the detection context, observed scope, and initial attack hypothesis..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Affected Asset Hostname / ID</label>
                <input
                  type="text"
                  placeholder="e.g. PROD-EDGE-FIREWALL-01 or 192.168.10.1"
                  value={newAsset}
                  onChange={(e) => setNewAsset(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                />
              </div>

              {availableAlerts.length > 0 && (
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">
                    Link Unhandled Alerts ({selectedAlertIds.length} selected)
                  </label>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto p-2 rounded-lg bg-slate-900 border border-slate-800">
                    {availableAlerts.map((a) => (
                      <label
                        key={a.id}
                        className="flex items-center gap-2 p-1.5 rounded hover:bg-slate-800/60 cursor-pointer text-slate-300"
                      >
                        <input
                          type="checkbox"
                          checked={selectedAlertIds.includes(a.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedAlertIds([...selectedAlertIds, a.id]);
                            } else {
                              setSelectedAlertIds(selectedAlertIds.filter((id) => id !== a.id));
                            }
                          }}
                          className="rounded border-slate-700 text-blue-600 focus:ring-0"
                        />
                        <span className="font-semibold text-slate-200">{a.title}</span>
                        <span className="text-slate-500 font-mono text-[10px]">({a.severity})</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              <div className="pt-2 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !newTitle || !newDesc}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
                >
                  {submitting ? "Opening Case..." : "Register Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
