"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  BookOpen,
  Plus,
  Search,
  CheckCircle2,
  Shield,
  Layers,
  CheckSquare,
  AlertTriangle,
  RotateCcw,
  RefreshCw,
  X,
  ChevronDown,
  ChevronUp,
  FileText,
  Lock,
  Mail,
  Bug,
  Server,
  Terminal,
  Activity,
  ArrowRight,
} from "lucide-react";
import { Playbook, PlaybookCategory } from "@/types/incident";
import { apiPlaybooks } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const CATEGORY_META: Record<string, { label: string; bg: string; text: string; border: string; icon: any }> = {
  authentication: {
    label: "Authentication",
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30",
    icon: Lock,
  },
  malware: {
    label: "Malware & C2",
    bg: "bg-rose-500/10",
    text: "text-rose-400",
    border: "border-rose-500/30",
    icon: Bug,
  },
  phishing: {
    label: "Phishing Attack",
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30",
    icon: Mail,
  },
  vulnerability: {
    label: "Vulnerability & Patching",
    bg: "bg-purple-500/10",
    text: "text-purple-400",
    border: "border-purple-500/30",
    icon: Shield,
  },
  network: {
    label: "Network & Perimeter",
    bg: "bg-cyan-500/10",
    text: "text-cyan-400",
    border: "border-cyan-500/30",
    icon: Server,
  },
  custom: {
    label: "Custom SOP",
    bg: "bg-slate-500/10",
    text: "text-slate-400",
    border: "border-slate-500/30",
    icon: Terminal,
  },
};

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Expanded cards
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState<PlaybookCategory>("custom");
  const [newDesc, setNewDesc] = useState("");
  const [newSteps, setNewSteps] = useState<
    Array<{ step_number: number; step_title: string; step_description: string; is_required: boolean }>
  >([
    {
      step_number: 1,
      step_title: "Initial Triage & Scope Verification",
      step_description: "Verify alert telemetry, determine blast radius and validate targeted asset identity.",
      is_required: true,
    },
    {
      step_number: 2,
      step_title: "Containment Action",
      step_description: "Apply tactical network perimeter blocks or isolate host from the internal broadcast domain.",
      is_required: true,
    },
    {
      step_number: 3,
      step_title: "Forensic Evidence Acquisition",
      step_description: "Capture volatile memory, disk artifact hashes, and export authentication audit logs.",
      is_required: false,
    },
  ]);
  const [submitting, setSubmitting] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const fetchPlaybooks = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiPlaybooks.list();
      if (res.data) {
        setPlaybooks(res.data);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load playbooks.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleToggleEnabled = async (playbook: Playbook) => {
    try {
      const updatedStatus = !playbook.is_enabled;
      await apiPlaybooks.update(playbook.id, { is_enabled: updatedStatus });
      setPlaybooks((prev) =>
        prev.map((p) => (p.id === playbook.id ? { ...p, is_enabled: updatedStatus } : p))
      );
    } catch (err: any) {
      alert(err?.message || "Failed to toggle playbook status.");
    }
  };

  const handleAddStep = () => {
    setNewSteps((prev) => [
      ...prev,
      {
        step_number: prev.length + 1,
        step_title: "",
        step_description: "",
        is_required: true,
      },
    ]);
  };

  const handleRemoveStep = (index: number) => {
    if (newSteps.length <= 1) return;
    const updated = newSteps.filter((_, i) => i !== index).map((s, idx) => ({ ...s, step_number: idx + 1 }));
    setNewSteps(updated);
  };

  const handleStepChange = (index: number, field: string, value: any) => {
    const updated = [...newSteps];
    updated[index] = { ...updated[index], [field]: value };
    setNewSteps(updated);
  };

  const handleCreatePlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setModalError("Playbook title is required.");
      return;
    }
    if (newSteps.some((s) => !s.step_title.trim())) {
      setModalError("All steps must have a title.");
      return;
    }

    setSubmitting(true);
    setModalError(null);
    try {
      await apiPlaybooks.create({
        playbook_name: newTitle,
        category: newCategory,
        description: newDesc,
        is_enabled: true,
        steps: newSteps,
      });

      setShowCreateModal(false);
      setNewTitle("");
      setNewDesc("");
      setNewSteps([
        {
          step_number: 1,
          step_title: "Initial Triage & Scope Verification",
          step_description: "Verify alert telemetry and determine blast radius.",
          is_required: true,
        },
      ]);
      fetchPlaybooks();
    } catch (err: any) {
      setModalError(err?.message || "Failed to create playbook.");
    } finally {
      setSubmitting(false);
    }
  };

  // Filter logic
  const filtered = playbooks.filter((p) => {
    if (selectedCategory !== "all" && p.category !== selectedCategory) return false;
    if (statusFilter === "active" && !p.is_enabled) return false;
    if (statusFilter === "disabled" && p.is_enabled) return false;
    if (search) {
      const q = search.toLowerCase();
      const matchName = p.playbook_name?.toLowerCase().includes(q);
      const matchDesc = p.description?.toLowerCase().includes(q);
      if (!matchName && !matchDesc) return false;
    }
    return true;
  });

  const totalStepsCount = playbooks.reduce((acc, curr) => acc + (curr.steps?.length || 0), 0);
  const activeCount = playbooks.filter((p) => p.is_enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Incident Response Playbooks</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Standardized operating procedures, investigation checklists, and tactical containment workflows.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchPlaybooks}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg shadow-blue-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            New Playbook
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Playbooks</span>
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{playbooks.length}</span>
            <span className="text-xs text-blue-400">cataloged</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Across 6 tactical SOC response categories</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active & Enforced</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-emerald-400 tracking-tight">{activeCount}</span>
            <span className="text-xs text-slate-400">/ {playbooks.length} total</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Ready for automated or manual incident binding</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Response Checkpoints</span>
            <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <CheckSquare className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{totalStepsCount}</span>
            <span className="text-xs text-purple-400">steps defined</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Structured containment & verification procedures</div>
        </div>

        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Governance</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-cyan-400 tracking-tight">NIST CSF</span>
            <span className="text-xs text-slate-400">RS.CO & RS.AN</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Audit-ready step logging and role attribution</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111C2D]/60 border border-slate-800/80 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search playbooks by name, category, or workflow..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 transition-colors"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500/60"
          >
            <option value="all">All Categories</option>
            <option value="authentication">Authentication</option>
            <option value="malware">Malware</option>
            <option value="phishing">Phishing</option>
            <option value="vulnerability">Vulnerability</option>
            <option value="network">Network</option>
            <option value="custom">Custom SOP</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-[#080D18]/80 border border-slate-700/60 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-blue-500/60"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active Only</option>
            <option value="disabled">Disabled Only</option>
          </select>
        </div>
      </div>

      {/* Playbooks List / Grid */}
      {loading ? (
        <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
          <p className="text-sm">Loading security response playbooks...</p>
        </div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-rose-500/10 border border-rose-500/20 text-center">
          <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
          <p className="text-sm text-rose-300">{error}</p>
          <button
            onClick={fetchPlaybooks}
            className="mt-3 px-4 py-1.5 text-xs rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 transition-colors"
          >
            Retry Loading
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-16 text-center border border-dashed border-slate-800 rounded-xl">
          <BookOpen className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-slate-300">No playbooks found</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            No playbook matches the selected filters. Create a new standard playbook or adjust your query.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filtered.map((playbook) => {
            const catMeta = CATEGORY_META[playbook.category] || CATEGORY_META.custom;
            const CatIcon = catMeta.icon;
            const isExpanded = !!expandedIds[playbook.id];

            return (
              <div
                key={playbook.id}
                className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl overflow-hidden hover:border-slate-700/80 transition-all backdrop-blur-sm"
              >
                <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <div className={`p-3 rounded-xl ${catMeta.bg} border ${catMeta.border} ${catMeta.text} shrink-0 mt-0.5`}>
                      <CatIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <h3 className="text-base font-semibold text-white tracking-tight">{playbook.playbook_name}</h3>
                        <span
                          className={`px-2.5 py-0.5 text-[11px] font-medium rounded-full border ${catMeta.bg} ${catMeta.text} ${catMeta.border}`}
                        >
                          {catMeta.label}
                        </span>
                        <span
                          className={`px-2 py-0.5 text-[10px] font-semibold rounded-full uppercase tracking-wider ${
                            playbook.is_enabled
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : "bg-slate-700/40 text-slate-400 border border-slate-600/30"
                          }`}
                        >
                          {playbook.is_enabled ? "Active" : "Disabled"}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1.5 max-w-3xl leading-relaxed">
                        {playbook.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <div className="text-right hidden sm:block">
                      <span className="text-xs font-semibold text-slate-300">
                        {playbook.steps?.length || 0} Procedures
                      </span>
                      <p className="text-[11px] text-slate-500">
                        Updated {formatDateTime(playbook.updated_at || playbook.created_at)}
                      </p>
                    </div>

                    {/* Enable/Disable toggle */}
                    <button
                      onClick={() => handleToggleEnabled(playbook)}
                      title={playbook.is_enabled ? "Disable Playbook" : "Enable Playbook"}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
                        playbook.is_enabled ? "bg-blue-600" : "bg-slate-700"
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          playbook.is_enabled ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>

                    {/* Expand checklist button */}
                    <button
                      onClick={() => toggleExpand(playbook.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-slate-700/60 transition-colors"
                    >
                      {isExpanded ? (
                        <>
                          Hide Steps <ChevronUp className="w-3.5 h-3.5" />
                        </>
                      ) : (
                        <>
                          View Steps <ChevronDown className="w-3.5 h-3.5" />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Expanded Steps Drawer */}
                {isExpanded && (
                  <div className="border-t border-slate-800/80 bg-[#080D18]/50 p-5 space-y-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Investigation & Response Action Checklist
                      </span>
                      <span className="text-xs text-slate-500">
                        {playbook.steps?.filter((s) => s.is_required).length} Required Steps
                      </span>
                    </div>

                    <div className="grid grid-cols-1 gap-2.5">
                      {playbook.steps && playbook.steps.length > 0 ? (
                        playbook.steps.map((step) => (
                          <div
                            key={step.id || step.step_number}
                            className="flex items-start gap-3 p-3 rounded-lg bg-[#111C2D]/60 border border-slate-800/60"
                          >
                            <span className="flex items-center justify-center w-6 h-6 rounded-md bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-bold shrink-0">
                              {step.step_number}
                            </span>
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-semibold text-slate-200">{step.step_title}</span>
                                {step.is_required ? (
                                  <span className="px-1.5 py-0.2 text-[9px] font-semibold rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                                    Required
                                  </span>
                                ) : (
                                  <span className="px-1.5 py-0.2 text-[9px] font-medium rounded bg-slate-800 text-slate-400">
                                    Optional
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                                {step.step_description}
                              </p>
                            </div>
                          </div>
                        ))
                      ) : (
                        <p className="text-xs text-slate-500 italic">No checklist steps defined for this playbook.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Create Playbook Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-[#111C2D] border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
                  <BookOpen className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">Create Custom Security Playbook</h2>
                  <p className="text-xs text-slate-400">Define operational checkpoints and triage procedures</p>
                </div>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreatePlaybook} className="p-5 overflow-y-auto space-y-4 flex-1">
              {modalError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300">
                  {modalError}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="sm:col-span-2">
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Playbook Name *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Ransomware Host Containment & Recovery SOP"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    className="w-full px-3 py-2 bg-[#080D18] border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Category *
                  </label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value as PlaybookCategory)}
                    className="w-full px-3 py-2 bg-[#080D18] border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="authentication">Authentication</option>
                    <option value="malware">Malware</option>
                    <option value="phishing">Phishing</option>
                    <option value="vulnerability">Vulnerability</option>
                    <option value="network">Network</option>
                    <option value="ransomware">Ransomware</option>
                    <option value="custom">Custom SOP</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                    Description
                  </label>
                  <input
                    type="text"
                    placeholder="Short summary of operating procedure"
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    className="w-full px-3 py-2 bg-[#080D18] border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Dynamic Steps List */}
              <div className="pt-2">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Procedure Checklist Steps ({newSteps.length})
                  </label>
                  <button
                    type="button"
                    onClick={handleAddStep}
                    className="flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" /> Add Step
                  </button>
                </div>

                <div className="space-y-3">
                  {newSteps.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl bg-[#080D18] border border-slate-800 space-y-2 relative"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-blue-400">Step {idx + 1}</span>
                        <div className="flex items-center gap-3">
                          <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={step.is_required}
                              onChange={(e) => handleStepChange(idx, "is_required", e.target.checked)}
                              className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
                            />
                            Required Step
                          </label>
                          {newSteps.length > 1 && (
                            <button
                              type="button"
                              onClick={() => handleRemoveStep(idx)}
                              className="text-slate-500 hover:text-rose-400 text-xs transition-colors"
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      </div>

                      <input
                        type="text"
                        placeholder="Step title (e.g. Isolate Host Network Interface)"
                        value={step.step_title}
                        onChange={(e) => handleStepChange(idx, "step_title", e.target.value)}
                        className="w-full px-3 py-1.5 bg-[#111C2D] border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                      />

                      <textarea
                        rows={2}
                        placeholder="Detailed instructions or CLI commands for analyst..."
                        value={step.step_description}
                        onChange={(e) => handleStepChange(idx, "step_description", e.target.value)}
                        className="w-full px-3 py-1.5 bg-[#111C2D] border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20 disabled:opacity-50 transition-all"
                >
                  {submitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  Save Playbook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
