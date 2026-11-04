"use client";

import { useState, useEffect } from "react";
import {
  Sliders,
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
  Plus,
  Play,
  Pause,
  Edit2,
  Clock,
  Layers,
  Code,
  Shield,
  Zap,
} from "lucide-react";
import { DetectionRule, DetectionRuleType, SeverityLevel } from "@/types/threat-intel";
import { apiDetectionRules } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
};

export default function DetectionRulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Edit Modal State
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [editThreshold, setEditThreshold] = useState<number>(5);
  const [editWindow, setEditWindow] = useState<number>(300);
  const [editSeverity, setEditSeverity] = useState<SeverityLevel>("High");
  const [saving, setSaving] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  // New Rule Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleType, setNewRuleType] = useState<DetectionRuleType>("repeated_suspicious");
  const [newSeverity, setNewSeverity] = useState<SeverityLevel>("Medium");
  const [newThreshold, setNewThreshold] = useState(5);
  const [newWindow, setNewWindow] = useState(300);
  const [newDesc, setNewDesc] = useState("");

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiDetectionRules.list();
      if (res.data) {
        setRules(res.data || []);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load detection rules.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleRule = async (rule: DetectionRule) => {
    try {
      if (rule.is_enabled) {
        await apiDetectionRules.disable(rule.id);
      } else {
        await apiDetectionRules.enable(rule.id);
      }
      fetchRules();
    } catch (e) {
      // handle error
    }
  };

  const openEditModal = (rule: DetectionRule) => {
    setEditingRule(rule);
    setEditThreshold(rule.threshold);
    setEditWindow(rule.time_window_seconds);
    setEditSeverity(rule.severity);
    setModalError(null);
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;
    setSaving(true);
    setModalError(null);
    try {
      const res = await apiDetectionRules.update(editingRule.id, {
        threshold: editThreshold,
        time_window_seconds: editWindow,
        severity: editSeverity,
      });

      if (res.error) {
        setModalError(res.error);
      } else {
        setEditingRule(null);
        fetchRules();
      }
    } catch (err: any) {
      setModalError(err.message || "Failed to update detection rule.");
    } finally {
      setSaving(false);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setModalError(null);
    try {
      const res = await apiDetectionRules.create({
        rule_name: newRuleName,
        rule_type: newRuleType,
        severity: newSeverity,
        threshold: newThreshold,
        time_window_seconds: newWindow,
        description: newDesc,
        condition_logic: { target_field: "source_ip", operator: "frequency_gt" },
      });

      if (res.error) {
        setModalError(res.error);
      } else {
        setShowCreateModal(false);
        setNewRuleName("");
        setNewDesc("");
        fetchRules();
      }
    } catch (err: any) {
      setModalError(err.message || "Failed to create rule.");
    } finally {
      setSaving(false);
    }
  };

  const activeCount = rules.filter((r) => r.is_enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Detection Rules</h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Correlation Engine
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time event correlation rules, anomaly threshold tuning, and automated security alert triggers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchRules()}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium shadow-lg shadow-blue-600/20 transition-colors"
          >
            <Plus className="h-4 w-4" />
            New Detection Rule
          </button>
        </div>
      </div>

      {/* KPI Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1">
            Total Rules
          </div>
          <div className="text-2xl font-bold text-white">{rules.length}</div>
          <span className="text-[11px] text-slate-400">Standard & custom rules</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-emerald-400 font-semibold mb-1">
            Active Rules
          </div>
          <div className="text-2xl font-bold text-emerald-400">{activeCount}</div>
          <span className="text-[11px] text-slate-400">Actively evaluating stream</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1">
            Inactive Rules
          </div>
          <div className="text-2xl font-bold text-slate-400">{rules.length - activeCount}</div>
          <span className="text-[11px] text-slate-400">Paused evaluations</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-cyan-400 font-semibold mb-1">
            Engine Health
          </div>
          <div className="text-2xl font-bold text-cyan-400">100% Operational</div>
          <span className="text-[11px] text-slate-400">Celery beat & worker synced</span>
        </div>
      </div>

      {/* Rules Catalog Table */}
      <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-900/40">
                <th className="py-3 px-4">Rule Name</th>
                <th className="py-3 px-4">Detection Logic</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Threshold</th>
                <th className="py-3 px-4">Time Window</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Loading detection rules...
                  </td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No detection rules configured.
                  </td>
                </tr>
              ) : (
                rules.map((rule) => {
                  const badge = SEVERITY_BADGES[rule.severity] || SEVERITY_BADGES.Medium;
                  return (
                    <tr
                      key={rule.id}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-100 max-w-sm">
                          {rule.rule_name}
                        </div>
                        <div className="text-[11px] text-slate-400 max-w-sm truncate mt-0.5">
                          {rule.description}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-cyan-300 bg-slate-900/60 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                          {rule.rule_type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${badge.bg} ${badge.text} ${badge.border}`}
                        >
                          {rule.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {rule.threshold} events
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {rule.time_window_seconds >= 60
                          ? `${Math.round(rule.time_window_seconds / 60)} min`
                          : `${rule.time_window_seconds}s`}
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => handleToggleRule(rule)}
                          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold transition-colors ${
                            rule.is_enabled
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20"
                              : "bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700"
                          }`}
                        >
                          {rule.is_enabled ? (
                            <>
                              <Play className="h-3 w-3 fill-current" />
                              Active
                            </>
                          ) : (
                            <>
                              <Pause className="h-3 w-3" />
                              Disabled
                            </>
                          )}
                        </button>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => openEditModal(rule)}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white"
                          title="Tune Threshold & Parameters"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Rule Modal */}
      {editingRule && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sliders className="h-5 w-5 text-blue-400" />
                <h2 className="text-lg font-bold text-white">Tune Detection Rule</h2>
              </div>
              <button
                onClick={() => setEditingRule(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSaveRule} className="p-6 space-y-4 text-xs">
              {modalError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  {modalError}
                </div>
              )}

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Rule</label>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-medium">
                  {editingRule.rule_name}
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Severity Rating</label>
                <select
                  value={editSeverity}
                  onChange={(e) => setEditSeverity(e.target.value as SeverityLevel)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Event Threshold</label>
                  <input
                    type="number"
                    min={1}
                    max={1000}
                    value={editThreshold}
                    onChange={(e) => setEditThreshold(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                  <span className="text-[10px] text-slate-500 mt-1 block">Matches required</span>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Time Window (sec)</label>
                  <input
                    type="number"
                    min={10}
                    max={86400}
                    value={editWindow}
                    onChange={(e) => setEditWindow(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                  <span className="text-[10px] text-slate-500 mt-1 block">
                    e.g. 300 = 5 minutes
                  </span>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-40"
                >
                  {saving ? "Saving..." : "Apply Tuning"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Plus className="h-5 w-5 text-blue-400" />
                <h2 className="text-lg font-bold text-white">Create Custom Detection Rule</h2>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="p-6 space-y-4 text-xs">
              {modalError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  {modalError}
                </div>
              )}

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Rapid SSH Key Rotation Anomaly"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Correlation Type</label>
                  <select
                    value={newRuleType}
                    onChange={(e) => setNewRuleType(e.target.value as DetectionRuleType)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="brute_force">Brute Force Detection</option>
                    <option value="threat_intel_match">Threat Indicator Match</option>
                    <option value="vuln_risk_correlation">Vuln Risk Correlation</option>
                    <option value="activity_anomaly">Activity Anomaly Spike</option>
                    <option value="repeated_suspicious">Repeated Suspicious Events</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Threshold</label>
                  <input
                    type="number"
                    min={1}
                    value={newThreshold}
                    onChange={(e) => setNewThreshold(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Time Window (sec)</label>
                  <input
                    type="number"
                    min={10}
                    value={newWindow}
                    onChange={(e) => setNewWindow(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Description</label>
                <textarea
                  rows={2}
                  required
                  placeholder="Explain what suspicious pattern this rule identifies..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving || !newRuleName}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-40"
                >
                  {saving ? "Creating..." : "Create Rule"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
