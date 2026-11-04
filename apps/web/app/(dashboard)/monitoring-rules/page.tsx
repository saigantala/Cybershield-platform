"use client";

import { useState, useEffect } from "react";
import {
  Sliders,
  Shield,
  Plus,
  RefreshCw,
  Edit2,
  CheckCircle,
  X,
  AlertTriangle,
  Flame,
  Clock,
  Check,
} from "lucide-react";
import { apiMonitoring } from "@/lib/api-client";
import { MonitoringRule, AnomalySeverity } from "@/types/monitoring";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_COLORS: Record<AnomalySeverity, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-blue-500/10", text: "text-cyan-400", border: "border-blue-500/30" },
  Low: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
  Informational: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function MonitoringRulesPage() {
  const [rules, setRules] = useState<MonitoringRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Edit / Create Modal state
  const [editingRule, setEditingRule] = useState<MonitoringRule | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [ruleType, setRuleType] = useState("traffic_spike");
  const [severity, setSeverity] = useState<AnomalySeverity>("Medium");
  const [threshold, setThreshold] = useState<number>(100);
  const [timeWindow, setTimeWindow] = useState<number>(300);
  const [description, setDescription] = useState("");
  const [isEnabled, setIsEnabled] = useState(true);

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    setIsLoading(true);
    const res = await apiMonitoring.listRules();
    if (res.data && res.data.length > 0) {
      setRules(res.data);
    } else {
      setRules([
        {
          id: "22000000-0000-0000-0000-000000000001",
          organization_id: "org-01",
          rule_name: "Excessive Network Byte Volume Spike",
          rule_type: "traffic_spike",
          description: "Flags sudden flow volumes exceeding 5MB within observation window",
          severity: "High",
          threshold: 5000000,
          time_window_seconds: 60,
          is_enabled: true,
          parameters: {},
          last_triggered_at: "2026-10-31T14:30:00Z",
          created_at: "2026-10-01T00:00:00Z",
          updated_at: "2026-10-31T14:30:00Z",
        },
        {
          id: "22000000-0000-0000-0000-000000000002",
          organization_id: "org-01",
          rule_name: "Unauthorized High-Risk Port Ingress",
          rule_type: "unexpected_port",
          description: "Alerts on ingress connections to unapproved ports (4444, 1337, 6667, 31337)",
          severity: "High",
          threshold: 1,
          time_window_seconds: 60,
          is_enabled: true,
          parameters: {},
          last_triggered_at: "2026-10-31T14:32:00Z",
          created_at: "2026-10-01T00:00:00Z",
          updated_at: "2026-10-31T14:32:00Z",
        },
        {
          id: "22000000-0000-0000-0000-000000000003",
          organization_id: "org-01",
          rule_name: "Suspicious Outbound Connection",
          rule_type: "suspicious_outbound",
          description: "Detects outbound sessions directed at external exploit listeners",
          severity: "Critical",
          threshold: 1,
          time_window_seconds: 60,
          is_enabled: true,
          parameters: {},
          created_at: "2026-10-01T00:00:00Z",
          updated_at: "2026-10-01T00:00:00Z",
        },
      ]);
    }
    setIsLoading(false);
  };

  const handleOpenEdit = (rule: MonitoringRule) => {
    setEditingRule(rule);
    setRuleName(rule.rule_name);
    setThreshold(rule.threshold);
    setTimeWindow(rule.time_window_seconds);
    setSeverity(rule.severity);
    setIsEnabled(rule.is_enabled);
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;

    const res = await apiMonitoring.updateRule(editingRule.id, {
      threshold,
      severity,
      time_window_seconds: timeWindow,
      is_enabled: isEnabled,
    });

    if (res.data) {
      setRules(rules.map((r) => (r.id === editingRule.id ? res.data! : r)));
    } else {
      setRules(
        rules.map((r) =>
          r.id === editingRule.id
            ? { ...r, threshold, severity, time_window_seconds: timeWindow, is_enabled: isEnabled }
            : r
        )
      );
    }
    setEditingRule(null);
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleName) return;

    const payload = {
      rule_name: ruleName,
      rule_type: ruleType,
      severity,
      threshold,
      time_window_seconds: timeWindow,
      description,
    };

    const res = await apiMonitoring.createRule(payload);
    if (res.data) {
      setRules([res.data, ...rules]);
    } else {
      const mockRule: MonitoringRule = {
        id: `rule-${Date.now()}`,
        organization_id: "org-01",
        rule_name: payload.rule_name,
        rule_type: payload.rule_type,
        severity: payload.severity,
        threshold: payload.threshold,
        time_window_seconds: payload.time_window_seconds,
        description: payload.description,
        is_enabled: true,
        parameters: {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      setRules([mockRule, ...rules]);
    }
    setIsCreating(false);
    setRuleName("");
    setDescription("");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Network Monitoring & Anomaly Detection Rules
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Configure threshold triggers, high-risk port lists, and time-window evaluation policies
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadRules()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
            title="Refresh rules"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
          <button
            onClick={() => {
              setRuleName("");
              setDescription("");
              setIsCreating(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Create Rule</span>
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
            Active Detection Policies ({rules.length})
          </h3>
          <span className="text-[10px] text-cyan-400 font-mono">
            Continuous Ingestion Evaluation
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-[#0E1726]/60">
                <th className="py-3 px-4">Rule Title & Description</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Threshold</th>
                <th className="py-3 px-4">Window</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {rules.map((rule) => {
                const colors = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.Medium;
                return (
                  <tr key={rule.id} className="hover:bg-[#162338]/50 transition-colors">
                    <td className="py-3 px-4">
                      <div>
                        <p className="font-bold text-white text-xs">{rule.rule_name}</p>
                        <p className="text-[10px] text-slate-400 line-clamp-1">{rule.description || "No description provided."}</p>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono text-cyan-400 text-xs">
                      {rule.rule_type}
                    </td>

                    <td className="py-3 px-4">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${colors.bg} ${colors.text} ${colors.border}`}>
                        {rule.severity}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-200">
                      {rule.threshold.toLocaleString()}
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400">
                      {rule.time_window_seconds}s
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          rule.is_enabled
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-slate-500/10 text-slate-400 border-slate-500/20"
                        }`}
                      >
                        {rule.is_enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleOpenEdit(rule)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600/20 text-cyan-300 border border-blue-500/30 hover:bg-blue-600 hover:text-white transition-all text-xs font-semibold"
                      >
                        <Edit2 className="h-3 w-3" />
                        <span>Tune</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Modal */}
      {editingRule && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-md p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">Tune Rule: {editingRule.rule_name}</h3>
              <button
                onClick={() => setEditingRule(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSaveEdit} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Trigger Threshold</label>
                <input
                  type="number"
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Time Window (Seconds)</label>
                <input
                  type="number"
                  value={timeWindow}
                  onChange={(e) => setTimeWindow(Number(e.target.value))}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as AnomalySeverity)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="enabledCheck"
                  checked={isEnabled}
                  onChange={(e) => setIsEnabled(e.target.checked)}
                  className="rounded bg-[#0B1220] border-slate-700 text-cyan-500 focus:ring-0"
                />
                <label htmlFor="enabledCheck" className="text-slate-300 font-semibold select-none cursor-pointer">
                  Rule Evaluation Active
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold"
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {isCreating && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">Define Anomaly Rule</h3>
              <button
                onClick={() => setIsCreating(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">Rule Title</label>
                <input
                  type="text"
                  placeholder="e.g. Unapproved SSH Port Scan Burst"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Rule Category</label>
                  <select
                    value={ruleType}
                    onChange={(e) => setRuleType(e.target.value)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value="traffic_spike">Traffic Volume Spike</option>
                    <option value="unexpected_port">Unexpected Port Ingress</option>
                    <option value="connection_failure_burst">Connection Failure Burst</option>
                    <option value="suspicious_outbound">Suspicious Outbound C2</option>
                    <option value="new_device">New Unregistered Device</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as AnomalySeverity)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
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
                  <label className="text-slate-300 font-semibold block mb-1">Threshold</label>
                  <input
                    type="number"
                    value={threshold}
                    onChange={(e) => setThreshold(Number(e.target.value))}
                    required
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">Time Window (Seconds)</label>
                  <input
                    type="number"
                    value={timeWindow}
                    onChange={(e) => setTimeWindow(Number(e.target.value))}
                    required
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">Description / Recommendation</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Context and triage guidelines when this rule triggers..."
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreating(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
