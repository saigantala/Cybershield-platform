"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Clock,
  RefreshCw,
  Search,
  Filter,
  Activity,
  Layers,
  FileCheck,
  Lock,
} from "lucide-react";
import { apiSystemHealth } from "@/lib/api-client";
import type { ProductionReadinessReport, ReadinessCheckItem, ReadinessCheckStatus } from "@/types/system-health";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function ProductionReadinessPage() {
  const [report, setReport] = useState<ProductionReadinessReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const loadReport = async () => {
    setLoading(true);
    try {
      const res = await apiSystemHealth.getProductionReadiness();
      if (res.data) setReport(res.data);
    } catch (e) {
      console.error("Failed to load production readiness report", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, []);

  const getStatusBadge = (status: ReadinessCheckStatus) => {
    switch (status) {
      case "Passed":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2.5 py-0.5 text-xs font-semibold text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Passed
          </span>
        );
      case "Warning":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-950/40 px-2.5 py-0.5 text-xs font-semibold text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5" />
            Warning
          </span>
        );
      case "Failed":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-950/40 px-2.5 py-0.5 text-xs font-semibold text-rose-400">
            <XCircle className="h-3.5 w-3.5" />
            Failed
          </span>
        );
      case "Not Configured":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-400">
            <HelpCircle className="h-3.5 w-3.5" />
            Not Configured
          </span>
        );
      case "Not Verified":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-purple-500/30 bg-purple-950/40 px-2.5 py-0.5 text-xs font-semibold text-purple-300">
            <Clock className="h-3.5 w-3.5" />
            Not Verified
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-400">
            {status}
          </span>
        );
    }
  };

  const getImpactBadge = (impact: string) => {
    switch (impact) {
      case "Critical":
        return (
          <span className="rounded border border-rose-500/40 bg-rose-950/50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-300">
            Critical Impact
          </span>
        );
      case "High":
        return (
          <span className="rounded border border-amber-500/40 bg-amber-950/50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-300">
            High Impact
          </span>
        );
      case "Medium":
        return (
          <span className="rounded border border-cyan-500/40 bg-cyan-950/50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-300">
            Medium
          </span>
        );
      default:
        return (
          <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
            Low
          </span>
        );
    }
  };

  const filteredItems = (report?.checklist || []).filter((item) => {
    const matchesCategory = selectedCategory === "all" || item.category === selectedCategory;
    const matchesStatus = selectedStatus === "all" || item.status === selectedStatus;
    const matchesSearch =
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.recommendation && item.recommendation.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesStatus && matchesSearch;
  });

  const categories = Array.from(new Set((report?.checklist || []).map((c) => c.category)));

  return (
    <ErrorBoundary>
      <div className="space-y-8 p-6 md:p-8">
        {/* Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <Link
              href="/system-health"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 transition-colors hover:text-white"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to System Health
            </Link>
            <div className="mt-2 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-950/40 text-emerald-400">
                <ShieldCheck className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                  Production Readiness Audit
                </h1>
                <p className="text-sm text-slate-400">
                  Comprehensive DevSecOps checklist evaluating environment entropy, RLS tenant isolation, backups, and security posture
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={loadReport}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Re-evaluate Checks
          </button>
        </div>

        {/* Score and Metric Cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Readiness Score
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-white">{report?.readiness_score ?? 0}%</span>
              <span className="text-xs text-slate-500">of {report?.total_checks ?? 12} criteria</span>
            </div>
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full bg-emerald-500 transition-all duration-500"
                style={{ width: `${report?.readiness_score ?? 0}%` }}
              />
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Checks Passed
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-3xl font-bold text-emerald-400">{report?.passed_count ?? 0}</span>
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            </div>
            <div className="mt-1 text-xs text-slate-500">Verified production gates</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Warnings
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-3xl font-bold text-amber-400">{report?.warning_count ?? 0}</span>
              <AlertTriangle className="h-5 w-5 text-amber-500" />
            </div>
            <div className="mt-1 text-xs text-slate-500">Non-blocking considerations</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Critical Failures
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-3xl font-bold text-rose-400">{report?.failed_count ?? 0}</span>
              <XCircle className="h-5 w-5 text-rose-500" />
            </div>
            <div className="mt-1 text-xs text-slate-500">Must resolve before launch</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Pending / Unverified
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-3xl font-bold text-purple-400">{report?.not_configured_count ?? 0}</span>
              <Clock className="h-5 w-5 text-purple-500" />
            </div>
            <div className="mt-1 text-xs text-slate-500">External services to confirm</div>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory("all")}
              className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                selectedCategory === "all"
                  ? "border border-cyan-500/50 bg-cyan-950/60 text-cyan-300"
                  : "border border-slate-800 bg-slate-900/40 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              All Categories
            </button>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  selectedCategory === cat
                    ? "border border-cyan-500/50 bg-cyan-950/60 text-cyan-300"
                    : "border border-slate-800 bg-slate-900/40 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search readiness criteria..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-900/60 py-1.5 pl-9 pr-4 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Checklist Cards */}
        {loading ? (
          <div className="flex h-64 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30">
            <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center text-xs text-slate-400">
            No readiness checklist items match the current filters.
          </div>
        ) : (
          <div className="space-y-4">
            {filteredItems.map((item) => (
              <div
                key={item.id}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg backdrop-blur-md transition-all hover:border-slate-700"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold text-white text-sm">{item.title}</h3>
                      {getImpactBadge(item.impact)}
                    </div>
                    <div className="text-xs text-slate-400">
                      Category: <span className="font-medium text-slate-300">{item.category}</span>
                    </div>
                  </div>

                  <div>{getStatusBadge(item.status)}</div>
                </div>

                <p className="mt-3 text-xs leading-relaxed text-slate-300">
                  {item.description}
                </p>

                {item.recommendation && (
                  <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-200">
                    <span className="font-semibold">Recommended Action: </span>
                    <span>{item.recommendation}</span>
                  </div>
                )}

                <div className="mt-4 flex items-center justify-between border-t border-slate-800/80 pt-3 text-[11px] text-slate-500">
                  <span>Audit ID: <span className="font-mono text-slate-400">{item.id}</span></span>
                  <span>Evaluated: {new Date(item.verified_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
