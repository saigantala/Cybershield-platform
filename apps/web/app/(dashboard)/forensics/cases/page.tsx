"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  FileSearch,
  Search,
  Plus,
  Filter,
  Clock,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  X,
  RefreshCw,
  Server,
  HardDrive,
} from "lucide-react";
import { apiForensics, apiAssets } from "@/lib/api-client";
import type {
  ForensicCase,
  ForensicCaseCreate,
  ForensicCaseStatus,
  ForensicPriority,
  ForensicAssetRole,
} from "@/types/forensics";

export default function ForensicCasesPage() {
  const searchParams = useSearchParams();
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form State
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newObjective, setNewObjective] = useState("");
  const [newPriority, setNewPriority] = useState<ForensicPriority>("P2");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedRole, setSelectedRole] = useState<ForensicAssetRole>("compromised_target");
  const [availableAssets, setAvailableAssets] = useState<any[]>([]);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (searchParams.get("create") === "true") {
      setShowCreateModal(true);
    }
  }, [searchParams]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [casesRes, assetsRes] = await Promise.all([
        apiForensics.listCases(),
        apiAssets.list(),
      ]);
      if (casesRes.data) setCases(casesRes.data);
      if (assetsRes.data) setAvailableAssets(assetsRes.data.items || []);
    } catch (err) {
      console.error("Failed to load forensic cases:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newObjective || !newDescription) return;
    setCreating(true);
    try {
      const assetsLink = selectedAssetId
        ? [{ asset_id: selectedAssetId, role_in_case: selectedRole }]
        : [];

      const payload: ForensicCaseCreate = {
        title: newTitle,
        description: newDescription,
        investigation_objective: newObjective,
        priority: newPriority,
        assets: assetsLink,
      };
      const res = await apiForensics.createCase(payload);
      if (res.data) {
        setCases([res.data, ...cases]);
        setShowCreateModal(false);
        setNewTitle("");
        setNewDescription("");
        setNewObjective("");
        setSelectedAssetId("");
      }
    } catch (err) {
      console.error("Failed to create forensic case:", err);
    } finally {
      setCreating(false);
    }
  };

  const getStatusBadge = (status: ForensicCaseStatus) => {
    switch (status) {
      case "Evidence Collection":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Analysis":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "Review":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "Completed":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const filteredCases = cases.filter((c) => {
    if (statusFilter !== "All" && c.status !== statusFilter) return false;
    if (
      searchQuery &&
      !c.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !c.case_number.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !c.investigation_objective.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 shadow-lg shadow-purple-500/5">
              <FileSearch className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Forensics Investigations</h1>
              <p className="text-sm text-slate-400">
                Formal forensic case files with sequential case numbering (FOR-YYYY-XXXXX) & evidence vault isolation
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-lg shadow-purple-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            New Forensic Case
          </button>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-4 shadow-xl">
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by case #, title, objective..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500/50"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="h-3.5 w-3.5" />
            Status:
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-purple-500/50"
          >
            <option value="All">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Evidence Collection">Evidence Collection</option>
            <option value="Analysis">Analysis</option>
            <option value="Review">Review</option>
            <option value="Completed">Completed</option>
            <option value="Archived">Archived</option>
          </select>
        </div>
      </div>

      {/* Cases Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 text-center py-16 text-slate-500 text-sm">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-purple-400" />
            Loading forensic cases...
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="col-span-2 text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
            <FileSearch className="h-8 w-8 text-slate-600 mx-auto mb-2" />
            <p className="font-semibold text-slate-300">No forensic cases match the criteria</p>
            <p className="text-xs text-slate-500 mt-1">Initialize a new investigation case or adjust filters</p>
          </div>
        ) : (
          filteredCases.map((c) => (
            <Link
              key={c.id}
              href={`/forensics/cases/${c.id}`}
              className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-purple-500/40 rounded-xl p-5 shadow-xl transition flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-purple-400">{c.case_number}</span>
                    <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${getStatusBadge(c.status)}`}>
                      {c.status}
                    </span>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                    {c.priority}
                  </span>
                </div>

                <div>
                  <h3 className="text-base font-semibold text-slate-100 group-hover:text-purple-300 transition">
                    {c.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">{c.investigation_objective}</p>
                </div>

                {/* Target Asset Tags */}
                {c.assets && c.assets.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {c.assets.map((ast, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1"
                      >
                        <Server className="h-3 w-3 text-cyan-400" />
                        {ast.asset_name || "Target Host"} ({ast.role_in_case.replace("_", " ")})
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-4 mt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
                <div className="flex items-center gap-3">
                  <span>
                    <strong className="text-slate-300 font-mono">{c.evidence_count}</strong> evidence artifacts
                  </span>
                  <span>
                    <strong className="text-slate-300 font-mono">{c.reports_count}</strong> reports
                  </span>
                </div>
                <div className="flex items-center gap-1 group-hover:text-purple-400 transition font-medium">
                  Open Workspace
                  <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-1 transition" />
                </div>
              </div>
            </Link>
          ))
        )}
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-purple-400">
                <FileSearch className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Initiate Digital Forensic Case</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-6 space-y-4 max-h-[80vh] overflow-y-auto">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Case Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Domain Controller Memory Dump Analysis"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Incident Description <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Describe initial trigger, compromised services, or incident context..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Investigation Objective <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Specific evidentiary objectives (e.g. root cause, timeline, compromised credentials)..."
                  value={newObjective}
                  onChange={(e) => setNewObjective(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as ForensicPriority)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  >
                    <option value="P1">P1 - Critical Priority</option>
                    <option value="P2">P2 - High Priority</option>
                    <option value="P3">P3 - Medium Priority</option>
                    <option value="P4">P4 - Low Priority</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Target Host Role</label>
                  <select
                    value={selectedRole}
                    onChange={(e) => setSelectedRole(e.target.value as ForensicAssetRole)}
                    className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  >
                    <option value="compromised_target">Compromised Target</option>
                    <option value="pivot_host">Pivot Host</option>
                    <option value="command_control_hop">Command & Control Hop</option>
                    <option value="unauthorized_scanner">Unauthorized Scanner</option>
                    <option value="witness_system">Witness System</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Target Asset (Optional)</label>
                <select
                  value={selectedAssetId}
                  onChange={(e) => setSelectedAssetId(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="">Select an asset node...</option>
                  {availableAssets.map((ast) => (
                    <option key={ast.id} value={ast.id}>
                      {ast.hostname || ast.name} ({ast.ip_address})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-sm font-medium shadow-lg shadow-purple-500/20 transition flex items-center gap-2"
                >
                  {creating && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Open Case File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
