"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Crosshair,
  Search,
  Plus,
  Filter,
  Clock,
  ArrowRight,
  ShieldAlert,
  Flame,
  CheckCircle2,
  X,
  RefreshCw,
  FolderOpen,
} from "lucide-react";
import { apiThreatHunting } from "@/lib/api-client";
import type {
  ThreatHuntingCase,
  ThreatHuntingCaseCreate,
  ThreatHuntingCaseStatus,
  ThreatHuntingPriority,
} from "@/types/threat-hunting";

export default function ThreatHuntingCasesPage() {
  const searchParams = useSearchParams();
  const [cases, setCases] = useState<ThreatHuntingCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("All");
  const [priorityFilter, setPriorityFilter] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form State
  const [newTitle, setNewTitle] = useState("");
  const [newObjective, setNewObjective] = useState("");
  const [newHypothesis, setNewHypothesis] = useState("");
  const [newPriority, setNewPriority] = useState<ThreatHuntingPriority>("P2");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (searchParams.get("create") === "true") {
      setShowCreateModal(true);
    }
  }, [searchParams]);

  const loadCases = async () => {
    setLoading(true);
    try {
      const res = await apiThreatHunting.listCases();
      if (res.data) setCases(res.data);
    } catch (err) {
      console.error("Failed to load hunting cases:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newObjective) return;
    setCreating(true);
    try {
      const payload: ThreatHuntingCaseCreate = {
        title: newTitle,
        objective: newObjective,
        hypothesis: newHypothesis || undefined,
        priority: newPriority,
      };
      const res = await apiThreatHunting.createCase(payload);
      if (res.data) {
        setCases([res.data, ...cases]);
        setShowCreateModal(false);
        setNewTitle("");
        setNewObjective("");
        setNewHypothesis("");
      }
    } catch (err) {
      console.error("Failed to create hunting case:", err);
    } finally {
      setCreating(false);
    }
  };

  const getStatusBadge = (status: ThreatHuntingCaseStatus) => {
    switch (status) {
      case "Active":
      case "Investigating":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "Suspicious Activity Found":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "Escalated":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Completed":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-slate-700/30 text-slate-300 border-slate-700/50";
    }
  };

  const filteredCases = cases.filter((c) => {
    if (statusFilter !== "All" && c.status !== statusFilter) return false;
    if (priorityFilter !== "All" && c.priority !== priorityFilter) return false;
    if (
      searchQuery &&
      !c.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !c.case_number.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !c.objective.toLowerCase().includes(searchQuery.toLowerCase())
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
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-500/5">
              <FolderOpen className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Threat Hunting Cases</h1>
              <p className="text-sm text-slate-400">
                Track hypothesis investigations, evidence findings, and adversary interrogation timelines
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadCases}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            Create Investigation Case
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
            className="w-full pl-10 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
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
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="All">All Statuses</option>
            <option value="Draft">Draft</option>
            <option value="Active">Active</option>
            <option value="Investigating">Investigating</option>
            <option value="Suspicious Activity Found">Suspicious Activity Found</option>
            <option value="No Threat Identified">No Threat Identified</option>
            <option value="Escalated">Escalated</option>
            <option value="Completed">Completed</option>
          </select>

          <div className="flex items-center gap-1.5 text-xs text-slate-400 ml-2">
            Priority:
          </div>
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="All">All Priorities</option>
            <option value="P1">P1 - Critical</option>
            <option value="P2">P2 - High</option>
            <option value="P3">P3 - Medium</option>
            <option value="P4">P4 - Low</option>
          </select>
        </div>
      </div>

      {/* Case Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 text-center py-16 text-slate-500 text-sm">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-cyan-400" />
            Loading threat hunting cases...
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="col-span-2 text-center py-16 bg-slate-900/60 border border-slate-800/80 rounded-xl text-slate-400">
            <Crosshair className="h-8 w-8 text-slate-600 mx-auto mb-2" />
            <p className="font-semibold text-slate-300">No threat hunting cases match the criteria</p>
            <p className="text-xs text-slate-500 mt-1">Try adjusting the filters or create a new investigation</p>
          </div>
        ) : (
          filteredCases.map((c) => (
            <Link
              key={c.id}
              href={`/threat-hunting/cases/${c.id}`}
              className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-cyan-500/40 rounded-xl p-5 shadow-xl transition flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{c.case_number}</span>
                    <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${getStatusBadge(c.status)}`}>
                      {c.status}
                    </span>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                    {c.priority}
                  </span>
                </div>

                <div>
                  <h3 className="text-base font-semibold text-slate-100 group-hover:text-cyan-300 transition">
                    {c.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">{c.objective}</p>
                </div>

                {c.hypothesis && (
                  <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-800 text-xs">
                    <span className="text-[10px] uppercase font-bold text-amber-400 block mb-0.5">Analyst Hypothesis</span>
                    <p className="text-slate-300 line-clamp-2">{c.hypothesis}</p>
                  </div>
                )}
              </div>

              <div className="pt-4 mt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
                <div className="flex items-center gap-3">
                  <span>
                    <strong className="text-slate-300 font-mono">{c.findings_count}</strong> findings
                  </span>
                  <span>
                    <strong className="text-slate-300 font-mono">{c.queries_count}</strong> queries
                  </span>
                </div>
                <div className="flex items-center gap-1 group-hover:text-cyan-400 transition font-medium">
                  Workspace
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
              <div className="flex items-center gap-2 text-cyan-400">
                <Crosshair className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Initiate Threat Hunting Investigation</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Investigation Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Kerberos Ticket Forgery & Lateral Movement Search"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Investigation Objective <span className="text-rose-400">*</span>
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Define specific interrogation goals, telemetry categories, or detection targets..."
                  value={newObjective}
                  onChange={(e) => setNewObjective(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Adversary Hypothesis (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Document initial hypotheses on entry vectors, persistence techniques, or C2 patterns..."
                  value={newHypothesis}
                  onChange={(e) => setNewHypothesis(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Priority</label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value as ThreatHuntingPriority)}
                  className="w-full px-3.5 py-2 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="P1">P1 - Critical Priority</option>
                  <option value="P2">P2 - High Priority</option>
                  <option value="P3">P3 - Medium Priority</option>
                  <option value="P4">P4 - Low Priority</option>
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
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-medium shadow-lg shadow-cyan-500/20 transition flex items-center gap-2"
                >
                  {creating && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Create Investigation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
