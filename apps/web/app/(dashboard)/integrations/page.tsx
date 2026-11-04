"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Layers,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  PlusCircle,
  ExternalLink,
  Shield,
  Activity,
  Send,
  Zap,
  Globe,
  Lock,
  Search,
  Server,
  Radio,
  FileText,
  Sliders,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type {
  Integration,
  IntegrationCategory,
  IntegrationHealthSummary,
  IntegrationTestResponse,
  IntegrationSyncResponse,
} from "@/types/integrations";

export default function IntegrationsOverviewPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [healthSummary, setHealthSummary] = useState<IntegrationHealthSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; res: IntegrationTestResponse } | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<{ id: string; res: IntegrationSyncResponse } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [intRes, healthRes] = await Promise.all([
        apiIntegrations.listIntegrations(),
        apiIntegrations.getHealthSummary(),
      ]);
      if (intRes.data) setIntegrations(intRes.data);
      if (healthRes.data) setHealthSummary(healthRes.data);
    } catch (e) {
      console.error("Failed to load integrations", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTestConnection = async (integration: Integration) => {
    setTestingId(integration.id);
    setTestResult(null);
    try {
      const res = await apiIntegrations.testConnection(integration.id);
      if (res.data) {
        setTestResult({ id: integration.id, res: res.data });
        loadData();
      }
    } catch (err: any) {
      console.error("Test connection failed", err);
    } finally {
      setTestingId(null);
    }
  };

  const handleSyncNow = async (integration: Integration) => {
    setSyncingId(integration.id);
    setSyncResult(null);
    try {
      const res = await apiIntegrations.syncIntegration(integration.id, { sync_type: "manual" });
      if (res.data) {
        setSyncResult({ id: integration.id, res: res.data });
        loadData();
      }
    } catch (err: any) {
      console.error("Sync failed", err);
    } finally {
      setSyncingId(null);
    }
  };

  const filteredIntegrations = integrations.filter((item) => {
    const matchesCategory =
      selectedCategory === "all" || item.category === selectedCategory;
    const matchesSearch =
      item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.provider.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.description && item.description.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Connected":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2.5 py-0.5 text-xs font-medium text-emerald-400">
            <CheckCircle2 className="h-3 w-3" />
            Connected
          </span>
        );
      case "Pending_Configuration":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-950/40 px-2.5 py-0.5 text-xs font-medium text-amber-400">
            <Clock className="h-3 w-3" />
            Pending Config
          </span>
        );
      case "Error":
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-950/40 px-2.5 py-0.5 text-xs font-medium text-rose-400">
            <XCircle className="h-3 w-3" />
            Error
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800/60 px-2.5 py-0.5 text-xs font-medium text-slate-400">
            {status}
          </span>
        );
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "siem":
        return <Layers className="h-5 w-5 text-indigo-400" />;
      case "communication":
        return <Send className="h-5 w-5 text-emerald-400" />;
      case "threat_intelligence":
        return <Shield className="h-5 w-5 text-amber-400" />;
      case "cloud_security":
        return <Globe className="h-5 w-5 text-sky-400" />;
      case "webhooks":
        return <Zap className="h-5 w-5 text-purple-400" />;
      default:
        return <Server className="h-5 w-5 text-cyan-400" />;
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Layers className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Enterprise Integration Center
              </h1>
              <p className="text-sm text-slate-400">
                Connect SIEM forwarders, threat intelligence feeds, cloud telemetry & automated webhook web dispatchers
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Link
            href="/integrations/available"
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600/80 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 transition-all hover:bg-cyan-500"
          >
            <PlusCircle className="h-4 w-4" />
            Add Integration
          </Link>
          <Link
            href="/integrations/webhooks"
            className="flex items-center gap-2 rounded-lg border border-purple-500/40 bg-purple-950/40 px-4 py-2 text-sm font-medium text-purple-300 transition-colors hover:bg-purple-900/50"
          >
            <Radio className="h-4 w-4" />
            Webhooks
          </Link>
          <Link
            href="/integrations/logs"
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <FileText className="h-4 w-4" />
            Delivery Logs
          </Link>
          <Link
            href="/integrations/health"
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <Activity className="h-4 w-4" />
            Health
          </Link>
          <button
            onClick={loadData}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Configured Connectors</span>
            <Layers className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {healthSummary?.total_integrations_count ?? integrations.length}
          </div>
          <div className="mt-1 text-xs text-slate-500">Active enterprise data channels</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Connected Services</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400">
            {healthSummary?.connected_count ?? integrations.filter((i) => i.connection_status === "Connected").length}
          </div>
          <div className="mt-1 text-xs text-slate-500">Live operational sync pipelines</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Fleet Health Index</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {healthSummary?.healthy_percent ?? 98}%
          </div>
          <div className="mt-1 text-xs text-slate-500">Average 24h delivery SLA</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Webhook Endpoints</span>
            <Radio className="h-4 w-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-purple-400">
            {healthSummary?.active_webhooks_count ?? 2}
          </div>
          <div className="mt-1 text-xs text-slate-500">HMAC-SHA256 secured dispatchers</div>
        </div>
      </div>

      {/* Notifications / Feedback Bar */}
      {testResult && (
        <div className="flex items-center justify-between rounded-xl border border-emerald-500/40 bg-emerald-950/30 p-4 text-sm text-emerald-300 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            <div>
              <span className="font-semibold">Connection Probe Succeeded: </span>
              <span>{testResult.res.message} ({testResult.res.latency_ms}ms round-trip latency)</span>
            </div>
          </div>
          <button onClick={() => setTestResult(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {syncResult && (
        <div className="flex items-center justify-between rounded-xl border border-cyan-500/40 bg-cyan-950/30 p-4 text-sm text-cyan-300 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <RefreshCw className="h-5 w-5 text-cyan-400" />
            <div>
              <span className="font-semibold">Synchronization Finished: </span>
              <span>
                Status: {syncResult.res.status} | {syncResult.res.items_synced} security records synchronized in {syncResult.res.duration_ms}ms
              </span>
            </div>
          </div>
          <button onClick={() => setSyncResult(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Filters and Search */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-2">
          {[
            { id: "all", label: "All Connectors" },
            { id: "siem", label: "SIEM Platforms" },
            { id: "communication", label: "Communication" },
            { id: "threat_intelligence", label: "Threat Intel" },
            { id: "cloud_security", label: "Cloud Security" },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                selectedCategory === cat.id
                  ? "border border-cyan-500/50 bg-cyan-950/60 text-cyan-300 shadow-sm shadow-cyan-900/40"
                  : "border border-slate-800 bg-slate-900/40 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search integrations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-slate-800 bg-slate-900/60 py-1.5 pl-9 pr-4 text-xs text-white placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
      </div>

      {/* Integrations Grid */}
      {loading ? (
        <div className="flex h-64 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30">
          <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
        </div>
      ) : filteredIntegrations.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30 p-12 text-center">
          <Layers className="h-10 w-10 text-slate-600" />
          <h3 className="mt-4 text-base font-semibold text-white">No integrations found</h3>
          <p className="mt-1 text-sm text-slate-400">
            {searchQuery ? "Try refining your search terms" : "Configure a new connector from the marketplace"}
          </p>
          <Link
            href="/integrations/available"
            className="mt-4 inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950/40 px-4 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/40"
          >
            <PlusCircle className="h-4 w-4" />
            Browse Available Connectors
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {filteredIntegrations.map((item) => (
            <div
              key={item.id}
              className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg backdrop-blur-md transition-all hover:border-slate-700"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-slate-800 bg-slate-800/80">
                      {getCategoryIcon(item.category)}
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{item.name}</h3>
                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <span>{item.provider}</span>
                        <span>•</span>
                        <span className="capitalize">{item.category.replace("_", " ")}</span>
                      </div>
                    </div>
                  </div>
                  <div>{getStatusBadge(item.connection_status)}</div>
                </div>

                <p className="mt-4 line-clamp-2 text-xs text-slate-400">
                  {item.description || "Enterprise integration connector for security telemetry exchange."}
                </p>

                {/* Configuration Meta */}
                <div className="mt-4 space-y-2 rounded-lg border border-slate-800/80 bg-slate-950/40 p-3 text-xs">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="flex items-center gap-1.5">
                      <Lock className="h-3 w-3 text-slate-500" />
                      Credential
                    </span>
                    <span className="font-mono text-slate-300">
                      {item.secret_masked || (item.secret_configured ? "Configured" : "None required")}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="flex items-center gap-1.5">
                      <Clock className="h-3 w-3 text-slate-500" />
                      Last Sync
                    </span>
                    <span className="text-slate-300">
                      {item.last_synced_at
                        ? new Date(item.last_synced_at).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })
                        : "Never"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="mt-5 flex items-center justify-between border-t border-slate-800/80 pt-4">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTestConnection(item)}
                    disabled={testingId === item.id}
                    className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-50"
                  >
                    <Activity className={`h-3 w-3 ${testingId === item.id ? "animate-spin text-cyan-400" : ""}`} />
                    Test
                  </button>
                  <button
                    onClick={() => handleSyncNow(item)}
                    disabled={syncingId === item.id}
                    className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-50"
                  >
                    <RefreshCw className={`h-3 w-3 ${syncingId === item.id ? "animate-spin text-cyan-400" : ""}`} />
                    Sync
                  </button>
                </div>

                <Link
                  href={`/integrations/configure/${item.id}`}
                  className="flex items-center gap-1 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
                >
                  <Sliders className="h-3 w-3" />
                  Configure
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
