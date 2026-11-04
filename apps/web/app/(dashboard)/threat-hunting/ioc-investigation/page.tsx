"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Search,
  Crosshair,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Globe2,
  ExternalLink,
  ArrowRight,
  RefreshCw,
  Server,
  Layers,
  FileText,
  HelpCircle,
} from "lucide-react";
import { apiThreatHunting } from "@/lib/api-client";
import type { IOCInvestigationResponse, IOCType } from "@/types/threat-hunting";

export default function IOCInvestigationPage() {
  const [iocInput, setIocInput] = useState("198.51.100.45");
  const [typeOverride, setTypeOverride] = useState<string>("");
  const [investigating, setInvestigating] = useState(false);
  const [result, setResult] = useState<IOCInvestigationResponse | null>(null);
  const [activeTab, setActiveTab] = useState<"alerts" | "assets" | "incidents" | "hunts" | "notes">("alerts");

  const handleInvestigate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!iocInput.trim()) return;
    setInvestigating(true);
    try {
      const res = await apiThreatHunting.investigateIOC(
        iocInput.trim(),
        typeOverride ? (typeOverride as IOCType) : undefined
      );
      if (res.data) setResult(res.data);
    } catch (err) {
      console.error("IOC investigation failed:", err);
    } finally {
      setInvestigating(false);
    }
  };

  const getThreatBadge = (status: string) => {
    switch (status) {
      case "known_malicious":
        return {
          badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
          label: "Confirmed Malicious Adversary Indicator",
          icon: ShieldAlert,
        };
      case "suspicious":
        return {
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          label: "Suspicious Behavioral Deviation",
          icon: AlertTriangle,
        };
      case "unknown_unverified":
      default:
        return {
          badge: "bg-slate-700/50 text-slate-300 border-slate-600",
          label: "Unknown / Unverified (Never Assume Safe)",
          icon: HelpCircle,
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-500/5">
            <Globe2 className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Multi-Type IOC Deep Correlation</h1>
            <p className="text-sm text-slate-400">
              Cross-reference IPv4, IPv6, Domain, URL, MD5, SHA-1, and SHA-256 against global feeds & internal telemetry
            </p>
          </div>
        </div>
      </div>

      {/* IOC Search Input Box */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
        <form onSubmit={handleInvestigate} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                required
                placeholder="Enter IP address, domain, URL, MD5, SHA-1, or SHA-256 hash..."
                value={iocInput}
                onChange={(e) => setIocInput(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-800/80 border border-slate-700/80 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <select
              value={typeOverride}
              onChange={(e) => setTypeOverride(e.target.value)}
              className="bg-slate-800/80 border border-slate-700/80 text-slate-300 text-xs rounded-lg px-3 py-2.5 focus:outline-none focus:border-cyan-500 shrink-0 font-medium"
            >
              <option value="">Auto-Detect Type</option>
              <option value="ipv4">IPv4 Address</option>
              <option value="ipv6">IPv6 Address</option>
              <option value="domain">Domain Name</option>
              <option value="url">URL Address</option>
              <option value="sha256">SHA-256 Hash</option>
              <option value="sha1">SHA-1 Hash</option>
              <option value="md5">MD5 Hash</option>
            </select>

            <button
              type="submit"
              disabled={investigating}
              className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-semibold shadow-lg shadow-cyan-500/20 transition flex items-center justify-center gap-2 shrink-0 disabled:opacity-50"
            >
              {investigating ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Investigate
            </button>
          </div>

          {/* Quick Example Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Examples:</span>
            <button
              type="button"
              onClick={() => {
                setIocInput("198.51.100.42");
                setTypeOverride("ipv4");
              }}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-mono transition"
            >
              198.51.100.42 (Feed IP)
            </button>
            <button
              type="button"
              onClick={() => {
                setIocInput("c2-sync-payload.org");
                setTypeOverride("domain");
              }}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-mono transition"
            >
              c2-sync-payload.org (Domain)
            </button>
            <button
              type="button"
              onClick={() => {
                setIocInput("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                setTypeOverride("sha256");
              }}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 font-mono transition"
            >
              SHA-256 Hash
            </button>
            <button
              type="button"
              onClick={() => {
                setIocInput("unverified-safe-looking-domain.com");
                setTypeOverride("domain");
              }}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-mono transition"
            >
              Unknown Domain
            </button>
          </div>
        </form>
      </div>

      {/* Investigation Details Card */}
      {result && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl space-y-6">
            {/* Top Indicator & Threat Status */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold border border-slate-700">
                    {result.ioc_type}
                  </span>
                  <span className="text-xs text-slate-400">Confidence: {Math.round(result.confidence_score * 100)}%</span>
                </div>
                <h2 className="text-2xl font-mono font-bold text-slate-100 break-all">{result.ioc_value}</h2>
              </div>

              {/* Status Badge */}
              <div className="shrink-0">
                {(() => {
                  const badgeInfo = getThreatBadge(result.threat_status);
                  const Icon = badgeInfo.icon;
                  return (
                    <div className={`px-4 py-2 rounded-xl border flex items-center gap-2 ${badgeInfo.badge}`}>
                      <Icon className="h-5 w-5 shrink-0" />
                      <span className="text-xs font-bold uppercase tracking-wider">{badgeInfo.label}</span>
                    </div>
                  );
                })()}
              </div>
            </div>

            {/* Safety Notice if Unknown */}
            {result.threat_status === "unknown_unverified" && (
              <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/80 text-slate-300 text-xs flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-100 font-semibold block text-sm">
                    Unknown / Unverified Indicator
                  </strong>
                  <p className="mt-0.5 text-slate-400 leading-relaxed">
                    This indicator was not observed in high-confidence threat feeds or verified security incidents.
                    In accordance with SOC operating guidelines, unverified indicators must <strong>never be assumed benign</strong>.
                    Conduct behavioral triage or inspect endpoint execution logs before clearing.
                  </p>
                </div>
              </div>
            )}

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800">
                <span className="text-slate-500 block mb-1">Reputation Source</span>
                <span className="text-slate-200 font-semibold">{result.reputation_provider}</span>
              </div>
              <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800">
                <span className="text-slate-500 block mb-1">Observed Threat Types</span>
                <span className="text-slate-200 font-semibold">
                  {result.threat_types.length ? result.threat_types.join(", ") : "None Detected"}
                </span>
              </div>
              <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800">
                <span className="text-slate-500 block mb-1">Correlated Alerts</span>
                <span className="text-cyan-400 font-bold font-mono text-sm">{result.related_alerts.length}</span>
              </div>
              <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-800">
                <span className="text-slate-500 block mb-1">Related Assets</span>
                <span className="text-cyan-400 font-bold font-mono text-sm">{result.related_assets.length}</span>
              </div>
            </div>
          </div>

          {/* Correlation Tabs */}
          <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex gap-4 border-b border-slate-800 pb-3">
              <button
                onClick={() => setActiveTab("alerts")}
                className={`text-xs font-semibold pb-1 transition ${
                  activeTab === "alerts"
                    ? "text-cyan-400 border-b-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Related Alerts ({result.related_alerts.length})
              </button>
              <button
                onClick={() => setActiveTab("assets")}
                className={`text-xs font-semibold pb-1 transition ${
                  activeTab === "assets"
                    ? "text-cyan-400 border-b-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Correlated Assets ({result.related_assets.length})
              </button>
              <button
                onClick={() => setActiveTab("incidents")}
                className={`text-xs font-semibold pb-1 transition ${
                  activeTab === "incidents"
                    ? "text-cyan-400 border-b-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Incidents ({result.related_incidents.length})
              </button>
              <button
                onClick={() => setActiveTab("hunts")}
                className={`text-xs font-semibold pb-1 transition ${
                  activeTab === "hunts"
                    ? "text-cyan-400 border-b-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Hunting Cases ({result.related_hunting_cases.length})
              </button>
              <button
                onClick={() => setActiveTab("notes")}
                className={`text-xs font-semibold pb-1 transition ${
                  activeTab === "notes"
                    ? "text-cyan-400 border-b-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Analyst Notes
              </button>
            </div>

            {/* Tab: Alerts */}
            {activeTab === "alerts" && (
              <div className="space-y-2">
                {result.related_alerts.length === 0 ? (
                  <p className="text-xs text-slate-500 py-6 text-center">No alerts correlated with this indicator.</p>
                ) : (
                  result.related_alerts.map((al, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <h4 className="font-semibold text-slate-200">{al.title}</h4>
                        <span className="text-[11px] text-slate-500">
                          {al.created_at ? new Date(al.created_at).toLocaleString() : ""}
                        </span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                        {al.severity}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab: Assets */}
            {activeTab === "assets" && (
              <div className="space-y-2">
                {result.related_assets.length === 0 ? (
                  <p className="text-xs text-slate-500 py-6 text-center">No internal assets currently match this indicator.</p>
                ) : (
                  result.related_assets.map((ast, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-3">
                        <Server className="h-4 w-4 text-cyan-400" />
                        <div>
                          <h4 className="font-semibold text-slate-200">{ast.name}</h4>
                          <span className="text-[11px] font-mono text-slate-500">{ast.ip_address}</span>
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-medium">
                        {ast.criticality} Criticality
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab: Incidents */}
            {activeTab === "incidents" && (
              <div className="space-y-2">
                {result.related_incidents.length === 0 ? (
                  <p className="text-xs text-slate-500 py-6 text-center">No formal incidents linked to this indicator.</p>
                ) : (
                  result.related_incidents.map((inc, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-cyan-400 font-bold">{inc.incident_number}</span>
                          <span className="text-slate-200 font-semibold">{inc.title}</span>
                        </div>
                        <span className="text-[11px] text-slate-500">Status: {inc.status}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                        {inc.severity}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab: Hunts */}
            {activeTab === "hunts" && (
              <div className="space-y-2">
                {result.related_hunting_cases.length === 0 ? (
                  <p className="text-xs text-slate-500 py-6 text-center">No threat hunting cases linked to this indicator.</p>
                ) : (
                  result.related_hunting_cases.map((h, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <span className="font-mono text-cyan-400 font-bold mr-2">{h.case_number}</span>
                        <span className="text-slate-200 font-semibold">{h.title}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {h.status}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab: Notes */}
            {activeTab === "notes" && (
              <div className="space-y-2">
                {result.analyst_notes.map((note, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-800/40 border border-slate-800 text-xs text-slate-300">
                    {note}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
