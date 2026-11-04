"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowLeft,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Layers,
  Shield,
  Send,
  Globe,
  Radio,
  BarChart2,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type { IntegrationHealthSummary, ProviderHealthMetric } from "@/types/integrations";

export default function IntegrationsHealthPage() {
  const [summary, setSummary] = useState<IntegrationHealthSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const loadHealth = async () => {
    setLoading(true);
    try {
      const res = await apiIntegrations.getHealthSummary();
      if (res.data) setSummary(res.data);
    } catch (e: any) {
      console.error("Failed to load health summary", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealth();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Healthy":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
            <CheckCircle2 className="h-3 w-3" />
            Healthy
          </span>
        );
      case "Degraded":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-950/40 px-2 py-0.5 text-[10px] font-medium text-amber-400">
            <AlertTriangle className="h-3 w-3" />
            Degraded
          </span>
        );
      case "Unhealthy":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-950/40 px-2 py-0.5 text-[10px] font-medium text-rose-400">
            <XCircle className="h-3 w-3" />
            Unhealthy
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/integrations"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 transition-colors hover:text-white"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Integrations
          </Link>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Activity className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Integration Health & Latency Monitor
              </h1>
              <p className="text-sm text-slate-400">
                24-hour service delivery SLAs, endpoint availability metrics, and round-trip transport latencies
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadHealth}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Run Health Diagnostics
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Fleet Health Index</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-white">
            {summary?.healthy_percent ?? 98.2}%
          </div>
          <div className="mt-1 text-xs text-slate-500">24-hour successful delivery ratio</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Connected Endpoints</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-emerald-400">
            {summary?.connected_count ?? 5} / {summary?.total_integrations_count ?? 6}
          </div>
          <div className="mt-1 text-xs text-slate-500">Live operational data pipelines</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Webhooks</span>
            <Radio className="h-4 w-4 text-purple-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-purple-400">
            {summary?.active_webhooks_count ?? 2}
          </div>
          <div className="mt-1 text-xs text-slate-500">Subscribed outbound receivers</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Delivery Failures (24h)</span>
            <AlertTriangle className="h-4 w-4 text-rose-400" />
          </div>
          <div className="mt-2 text-3xl font-bold text-rose-400">
            {summary?.failed_deliveries_24h ?? 0}
          </div>
          <div className="mt-1 text-xs text-slate-500">Exceptions or timeout aborts</div>
        </div>
      </div>

      {/* Provider Health Breakdown Table */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 shadow-xl backdrop-blur-md">
        <div className="border-b border-slate-800 p-5">
          <h2 className="text-base font-semibold text-white">Provider Endpoint Health Status</h2>
          <p className="text-xs text-slate-400">
            Live availability status and latency metrics across verified upstream security platforms.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/50 text-slate-400 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Provider / Channel</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Round-Trip Latency</th>
                <th className="py-3 px-4">24h Success Rate</th>
                <th className="py-3 px-4">Deliveries (24h)</th>
                <th className="py-3 px-4">Last Dispatched</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <RefreshCw className="mx-auto h-6 w-6 animate-spin text-cyan-400" />
                    <span className="mt-2 block text-xs">Running health probes...</span>
                  </td>
                </tr>
              ) : summary?.provider_health.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    No active integration providers configured.
                  </td>
                </tr>
              ) : (
                summary?.provider_health.map((prov) => (
                  <tr key={prov.provider} className="transition-colors hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-semibold text-white">
                      {prov.provider}
                    </td>
                    <td className="py-3 px-4">
                      {getStatusBadge(prov.status)}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-300">
                      {prov.latency_ms} ms
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full ${
                              prov.success_rate_24h > 95
                                ? "bg-emerald-500"
                                : prov.success_rate_24h > 80
                                ? "bg-amber-500"
                                : "bg-rose-500"
                            }`}
                            style={{ width: `${prov.success_rate_24h}%` }}
                          />
                        </div>
                        <span className="font-mono text-slate-300">{prov.success_rate_24h}%</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {prov.total_deliveries_24h}
                    </td>
                    <td className="py-3 px-4 text-slate-500 whitespace-nowrap">
                      {prov.last_delivery_at
                        ? new Date(prov.last_delivery_at).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                          })
                        : "Never"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
