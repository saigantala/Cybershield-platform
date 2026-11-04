"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowLeft,
  Sliders,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  Trash2,
  Activity,
  RefreshCw,
  Lock,
  Globe,
  Save,
  AlertTriangle,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type { Integration, IntegrationTestResponse, IntegrationSyncResponse } from "@/types/integrations";

export default function ConfigureIntegrationPage({
  params,
}: {
  params: Promise<{ integrationId: string }>;
}) {
  const resolvedParams = use(params);
  const integrationId = resolvedParams.integrationId;
  const router = useRouter();

  const [integration, setIntegration] = useState<Integration | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [testResult, setTestResult] = useState<IntegrationTestResponse | null>(null);
  const [syncResult, setSyncResult] = useState<IntegrationSyncResponse | null>(null);

  // Form states
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isEnabled, setIsEnabled] = useState(true);
  const [secretKey, setSecretKey] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [customConfigJson, setCustomConfigJson] = useState("{}");

  const loadIntegration = async () => {
    setLoading(true);
    try {
      const res = await apiIntegrations.getIntegration(integrationId);
      if (res.data) {
        setIntegration(res.data);
        setName(res.data.name);
        setDescription(res.data.description || "");
        setIsEnabled(res.data.is_enabled);
        setEndpointUrl(res.data.config.endpoint_url || res.data.config.webhook_url || "");
        setCustomConfigJson(JSON.stringify(res.data.config, null, 2));
      } else {
        setFeedback({ type: "error", message: res.error || "Integration not found." });
      }
    } catch (e: any) {
      setFeedback({ type: "error", message: e.message || "Failed to load integration." });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIntegration();
  }, [integrationId]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFeedback(null);

    let parsedConfig = {};
    try {
      parsedConfig = JSON.parse(customConfigJson);
    } catch (err) {
      setFeedback({ type: "error", message: "Invalid JSON configuration format." });
      setSaving(false);
      return;
    }

    if (endpointUrl) {
      if ((parsedConfig as any).webhook_url !== undefined) {
        (parsedConfig as any).webhook_url = endpointUrl;
      } else {
        (parsedConfig as any).endpoint_url = endpointUrl;
      }
    }

    try {
      const res = await apiIntegrations.updateIntegration(integrationId, {
        name,
        description,
        is_enabled: isEnabled,
        config: parsedConfig,
        secret_key: secretKey || undefined,
      });

      if (res.data) {
        setFeedback({ type: "success", message: "Integration configuration updated successfully." });
        setIntegration(res.data);
        setSecretKey("");
      } else {
        setFeedback({ type: "error", message: res.error || "Failed to save configuration." });
      }
    } catch (err: any) {
      setFeedback({ type: "error", message: err.message || "An unexpected error occurred." });
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await apiIntegrations.testConnection(integrationId, {
        custom_endpoint: endpointUrl || undefined,
      });
      if (res.data) {
        setTestResult(res.data);
      }
    } catch (err: any) {
      setFeedback({ type: "error", message: `Test probe failed: ${err.message}` });
    } finally {
      setTesting(false);
    }
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    setSyncResult(null);
    try {
      const res = await apiIntegrations.syncIntegration(integrationId, { sync_type: "manual" });
      if (res.data) {
        setSyncResult(res.data);
      }
    } catch (err: any) {
      setFeedback({ type: "error", message: `Sync failed: ${err.message}` });
    } finally {
      setSyncing(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this integration? This action cannot be undone.")) return;

    try {
      await apiIntegrations.deleteIntegration(integrationId);
      router.push("/integrations");
    } catch (err: any) {
      setFeedback({ type: "error", message: `Delete failed: ${err.message}` });
    }
  };

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (!integration) {
    return (
      <div className="space-y-4 p-8 text-center">
        <AlertTriangle className="mx-auto h-12 w-12 text-amber-400" />
        <h2 className="text-xl font-bold text-white">Integration Not Found</h2>
        <p className="text-sm text-slate-400">The requested integration connector does not exist.</p>
        <Link href="/integrations" className="inline-block text-xs font-semibold text-cyan-400 hover:underline">
          Return to Integration Center
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-8 p-6 md:p-8">
      {/* Header */}
      <div>
        <Link
          href="/integrations"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 transition-colors hover:text-white"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Integrations
        </Link>
        <div className="mt-2 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Sliders className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Configure {integration.name}
              </h1>
              <p className="text-sm text-slate-400">
                {integration.provider} • <span className="capitalize">{integration.category.replace("_", " ")}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTestConnection}
              disabled={testing}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700 disabled:opacity-50"
            >
              <Activity className={`h-3.5 w-3.5 ${testing ? "animate-spin text-cyan-400" : ""}`} />
              Test Connection
            </button>
            <button
              onClick={handleSyncNow}
              disabled={syncing}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-600/30 px-3 py-1.5 text-xs font-semibold text-cyan-300 transition-colors hover:bg-cyan-600/50 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${syncing ? "animate-spin text-cyan-400" : ""}`} />
              Sync Now
            </button>
          </div>
        </div>
      </div>

      {feedback && (
        <div
          className={`flex items-center justify-between rounded-xl border p-4 text-xs backdrop-blur-md ${
            feedback.type === "success"
              ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-300"
              : "border-rose-500/40 bg-rose-950/30 text-rose-300"
          }`}
        >
          <span>{feedback.message}</span>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {testResult && (
        <div className="rounded-xl border border-cyan-500/40 bg-cyan-950/20 p-4 text-xs text-cyan-300">
          <div className="flex items-center gap-2 font-semibold">
            <CheckCircle2 className="h-4 w-4 text-cyan-400" />
            Connection Probe Successful: {testResult.message}
          </div>
          <div className="mt-2 text-slate-400">
            Round-trip Latency: <span className="font-mono text-cyan-200">{testResult.latency_ms} ms</span> | Status:{" "}
            <span className="font-mono text-cyan-200">{testResult.status}</span>
          </div>
        </div>
      )}

      {syncResult && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/20 p-4 text-xs text-emerald-300">
          <div className="flex items-center gap-2 font-semibold">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            Synchronization Completed: {syncResult.status}
          </div>
          <div className="mt-2 text-slate-400">
            Items Synced: <span className="font-mono text-emerald-200">{syncResult.items_synced}</span> | Duration:{" "}
            <span className="font-mono text-emerald-200">{syncResult.duration_ms} ms</span>
          </div>
        </div>
      )}

      {/* Main Settings Form */}
      <form onSubmit={handleSave} className="space-y-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md space-y-5">
          <h2 className="text-base font-semibold text-white">General Parameters</h2>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="text-xs font-semibold text-slate-300">Connector Instance Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300">Integration Slug</label>
              <input
                type="text"
                disabled
                value={integration.slug}
                className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs font-mono text-slate-500"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300">Description</label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              id="isEnabledToggle"
              checked={isEnabled}
              onChange={(e) => setIsEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
            />
            <label htmlFor="isEnabledToggle" className="text-xs font-semibold text-slate-300">
              Enable connector data pipeline (Forward security alerts & sync telemetry)
            </label>
          </div>
        </div>

        {/* Credentials & Endpoint */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md space-y-5">
          <h2 className="text-base font-semibold text-white">Connectivity & Authentication</h2>

          <div>
            <label className="text-xs font-semibold text-slate-300">Target Endpoint URL</label>
            <div className="relative mt-1">
              <Globe className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="url"
                value={endpointUrl}
                onChange={(e) => setEndpointUrl(e.target.value)}
                placeholder="https://splunk-hec.corp.internal:8088/services/collector"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-xs font-mono text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <p className="mt-1 text-[10px] text-slate-500">
              SSRF validation enforced: internal loopback (127.0.0.1) and private RFC 1918 subnets are prohibited.
            </p>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">
                Secret Token / API Key / HEC Token
              </label>
              {integration.secret_masked && (
                <span className="text-[10px] font-mono text-emerald-400">
                  Current: {integration.secret_masked}
                </span>
              )}
            </div>
            <div className="relative mt-1">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
                placeholder={integration.secret_masked ? "Leave blank to keep existing credential..." : "Paste new secret token..."}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-xs font-mono text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <p className="mt-1 text-[10px] text-slate-500">
              Stored as AES-256 encrypted ciphertext. Raw values are write-only and never exposed in REST responses.
            </p>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300">Custom Provider Configuration (JSON)</label>
            <textarea
              rows={4}
              value={customConfigJson}
              onChange={(e) => setCustomConfigJson(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs font-mono text-white focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Submit Bar */}
        <div className="flex items-center justify-end gap-3">
          <Link
            href="/integrations"
            className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700"
          >
            Cancel
          </Link>
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500 bg-cyan-600 px-5 py-2 text-xs font-semibold text-white shadow-lg shadow-cyan-900/30 hover:bg-cyan-500 disabled:opacity-50"
          >
            <Save className="h-3.5 w-3.5" />
            {saving ? "Saving Changes..." : "Save Changes"}
          </button>
        </div>
      </form>

      {/* Danger Zone */}
      <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-6 backdrop-blur-md">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-rose-200">Disconnect & Delete Integration</h3>
            <p className="mt-1 text-xs text-rose-300/80">
              Permanently purges connector credentials, sync schedules, and outbound event streaming pipelines.
            </p>
          </div>
          <button
            onClick={handleDelete}
            className="flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-600/30 px-4 py-2 text-xs font-semibold text-rose-300 hover:bg-rose-600/50"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete Connector
          </button>
        </div>
      </div>
    </div>
  );
}
