"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  TrendingUp,
  ShieldAlert,
  ArrowLeft,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Layers,
  ArrowRight,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { apiAIDetection } from "@/lib/api-client";
import type { AIRiskPrediction } from "@/types/ai-detection";

export default function AIRiskAnalysisPage() {
  const [predictions, setPredictions] = useState<AIRiskPrediction[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [levelFilter, setLevelFilter] = useState("All");

  const loadPredictions = async () => {
    setLoading(true);
    try {
      const res = await apiAIDetection.getRiskPredictions();
      if (res.data) setPredictions(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPredictions();
  }, []);

  const filteredPredictions = predictions.filter((p) => {
    const matchesSearch =
      (p.asset_name && p.asset_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (p.asset_ip && p.asset_ip.includes(searchTerm));
    const matchesLevel = levelFilter === "All" || p.risk_level === levelFilter;
    return matchesSearch && matchesLevel;
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
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-950/40 text-amber-400">
              <TrendingUp className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Predictive Threat Risk Analysis
              </h1>
              <p className="text-sm text-slate-400">
                Transparent multi-factor asset risk scoring, threat trends, and remediation priority ranking
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadPredictions}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Safety & Uncertainty Disclaimer */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md">
        <div className="flex items-start gap-3">
          <ShieldCheck className="h-5 w-5 shrink-0 text-cyan-400 mt-0.5" />
          <div className="text-xs text-slate-300">
            <strong className="text-white font-semibold">Transparent Deterministic Scoring:</strong> CyberShield
            risk scores reflect empirical vulnerability exposure (CISA KEV), network boundary placement, and verified
            behavioral anomalies. We do not claim to predict future zero-day events with certainty.
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search assets by name or IP..."
            className="w-full rounded-lg border border-slate-800 bg-slate-950/60 py-2 pl-9 pr-4 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-400">Risk Level:</span>
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="All">All Risk Levels</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Risk Cards Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {filteredPredictions.map((pred) => (
          <div
            key={pred.id}
            className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md transition-all hover:border-slate-700"
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-cyan-300">
                  {pred.asset_ip || "192.168.10.x"}
                </span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                    pred.risk_level === "Critical"
                      ? "bg-red-500/20 text-red-300 border border-red-500/30"
                      : pred.risk_level === "High"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                  }`}
                >
                  {pred.risk_level} Risk
                </span>
              </div>

              <h3 className="mt-2 text-base font-bold text-white line-clamp-1">
                {pred.asset_name || "Enterprise Host"}
              </h3>

              {/* Score Indicator */}
              <div className="mt-4 flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <div>
                  <div className="text-[10px] uppercase text-slate-500">Risk Score</div>
                  <div className="text-2xl font-bold font-mono text-white">
                    {pred.risk_score}
                    <span className="text-xs font-normal text-slate-500"> / 100</span>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-[10px] uppercase text-slate-500">Trajectory</div>
                  <div
                    className={`text-xs font-semibold uppercase ${
                      pred.risk_trend === "increasing"
                        ? "text-red-400"
                        : pred.risk_trend === "decreasing"
                        ? "text-emerald-400"
                        : "text-slate-400"
                    }`}
                  >
                    {pred.risk_trend}
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-[10px] uppercase text-slate-500">Priority</div>
                  <div className="rounded bg-slate-800 px-2 py-0.5 text-xs font-bold text-cyan-300">
                    {pred.recommended_remediation_priority}
                  </div>
                </div>
              </div>

              {/* Contributing Factors */}
              <div className="mt-4">
                <div className="text-xs font-semibold text-slate-400 mb-2">Key Contributing Factors:</div>
                <div className="space-y-1.5">
                  {pred.contributing_factors.slice(0, 3).map((f, i) => (
                    <div key={i} className="flex items-center justify-between text-xs rounded bg-slate-950/40 p-2">
                      <span className="text-slate-300">{f.factor}</span>
                      <span className="font-mono text-amber-300 font-semibold">{f.impact}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-6 border-t border-slate-800 pt-4 flex items-center justify-between">
              <span className="text-[11px] text-slate-500">
                Confidence: <strong className="text-emerald-400">{Math.round(pred.confidence_score * 100)}%</strong>
              </span>

              <Link
                href={`/soar/playbooks?asset=${pred.asset_id}`}
                className="flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
              >
                <Zap className="h-3 w-3" />
                SOAR Playbook
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
