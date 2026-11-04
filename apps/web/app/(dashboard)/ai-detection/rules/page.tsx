"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Sliders,
  PlusCircle,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  Power,
  ShieldCheck,
  ArrowLeft,
  Clock,
  ExternalLink,
} from "lucide-react";
import { apiAIDetection } from "@/lib/api-client";
import type { AIDetectionRule, RuleType, DetectionSeverity } from "@/types/ai-detection";

export default function AIDetectionRulesPage() {
  const [rules, setRules] = useState<AIDetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("All");

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [ruleType, setRuleType] = useState<RuleType>("statistical_threshold");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<DetectionSeverity>("High");
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const loadRules = async () => {
    setLoading(true);
    try {
      const res = await apiAIDetection.listRules();
      if (res.data) setRules(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleToggleRule = async (rule: AIDetectionRule) => {
    try {
      const res = await apiAIDetection.updateRule(rule.id, {
        is_enabled: !rule.is_enabled,
      });
      if (res.data) {
        setNotice(`Rule "${rule.rule_name}" is now ${!rule.is_enabled ? "ENABLED" : "DISABLED"}.`);
        loadRules();
      }
    } catch (e: any) {
      alert(e.message);
    }
  };

  const handleCreateRule = async () => {
    if (!ruleName.trim()) {
      alert("Please provide a rule name.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await apiAIDetection.createRule({
        rule_name: ruleName,
        rule_type: ruleType,
        description,
        severity,
        data_sources: ["network_monitoring", "auth_events"],
        threshold_config: { variance_sigma: 3.0 },
        evaluation_interval_seconds: 300,
        is_enabled: true,
      });
      if (res.data) {
        setNotice(`Detection rule "${ruleName}" successfully created and activated.`);
        setShowCreateModal(false);
        setRuleName("");
        setDescription("");
        loadRules();
      } else {
        alert(res.error || "Failed to create rule");
      }
    } catch (e: any) {
      alert(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      r.rule_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.description && r.description.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesType = typeFilter === "All" || r.rule_type === typeFilter;
    return matchesSearch && matchesType;
  });

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
              <Sliders className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Detection Rule Management
              </h1>
              <p className="text-sm text-slate-400">
                Configure statistical thresholds, behavioral deviation gates, and IOC matching rules
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadRules}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-cyan-900/40 hover:bg-cyan-500"
          >
            <PlusCircle className="h-4 w-4" />
            Create Rule
          </button>
        </div>
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

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search detection rules by name or description..."
            className="w-full rounded-lg border border-slate-800 bg-slate-950/60 py-2 pl-9 pr-4 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-400">Rule Type:</span>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="All">All Types</option>
            <option value="statistical_threshold">Statistical Threshold</option>
            <option value="behavioral_deviation">Behavioral Deviation</option>
            <option value="ioc_matching">IOC Matching</option>
            <option value="event_correlation">Event Correlation</option>
          </select>
        </div>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            className={`flex flex-col justify-between rounded-xl border p-6 backdrop-blur-md transition-all ${
              rule.is_enabled
                ? "border-slate-800 bg-slate-900/60"
                : "border-slate-800/50 bg-slate-950/40 opacity-70"
            }`}
          >
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[11px] font-semibold text-cyan-400 uppercase tracking-wider border border-cyan-500/20 font-mono">
                  {rule.rule_type.replace("_", " ")}
                </span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                    rule.severity === "Critical"
                      ? "bg-red-500/20 text-red-300 border border-red-500/30"
                      : rule.severity === "High"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                  }`}
                >
                  {rule.severity}
                </span>
              </div>

              <h3 className="mt-3 text-base font-bold text-white">{rule.rule_name}</h3>
              <p className="mt-1 text-xs text-slate-400 line-clamp-2">
                {rule.description || "Deterministic rule evaluating security telemetry."}
              </p>

              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-300">
                <div className="text-[10px] uppercase text-slate-500 mb-1">Threshold Configuration:</div>
                <pre className="font-mono text-[11px] text-amber-300 overflow-x-auto">
                  {JSON.stringify(rule.threshold_config, null, 2)}
                </pre>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-4 text-[11px] text-slate-500">
                <span>Interval: <strong className="text-slate-300">{rule.evaluation_interval_seconds}s</strong></span>
                <span>Matches: <strong className="text-emerald-300">{rule.matched_events_count}</strong></span>
                <span>False Positives: <strong className="text-amber-400">{rule.false_positive_count}</strong></span>
              </div>
            </div>

            <div className="mt-6 border-t border-slate-800 pt-4 flex items-center justify-between">
              <span className="text-xs text-slate-400">
                Status:{" "}
                <strong className={rule.is_enabled ? "text-emerald-400" : "text-slate-500"}>
                  {rule.is_enabled ? "Active" : "Disabled"}
                </strong>
              </span>

              <button
                onClick={() => handleToggleRule(rule)}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                  rule.is_enabled
                    ? "border border-red-500/40 bg-red-950/30 text-red-300 hover:bg-red-900/50"
                    : "border border-emerald-500/40 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-900/50"
                }`}
              >
                <Power className="h-3 w-3" />
                {rule.is_enabled ? "Disable Rule" : "Enable Rule"}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white">Create Detection Rule</h3>
                <p className="text-xs text-slate-400">Define thresholds, correlation logic, and severity</p>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            <div className="mt-4 space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300">Rule Name</label>
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="e.g. Anomalous Port 3389 RDP Burst"
                  className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300">Rule Type</label>
                  <select
                    value={ruleType}
                    onChange={(e) => setRuleType(e.target.value as RuleType)}
                    className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="statistical_threshold">Statistical Threshold</option>
                    <option value="behavioral_deviation">Behavioral Deviation</option>
                    <option value="ioc_matching">IOC Matching</option>
                    <option value="event_correlation">Event Correlation</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300">Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as DetectionSeverity)}
                    className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300">Description</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Explain detection rationale and investigation recommendation..."
                  className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setShowCreateModal(false)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateRule}
                disabled={submitting}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
              >
                {submitting ? "Saving..." : "Save & Activate"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
