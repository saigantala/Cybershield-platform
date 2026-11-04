"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Radio,
  ArrowLeft,
  PlusCircle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Key,
  RotateCw,
  Send,
  Clock,
  Shield,
  Layers,
  ChevronRight,
  Code,
  AlertTriangle,
  Play,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type {
  WebhookEndpoint,
  WebhookEventType,
  WebhookDeliveryAttempt,
  WebhookSecretRotateResponse,
} from "@/types/integrations";

const AVAILABLE_EVENTS: { id: WebhookEventType; label: string; description: string }[] = [
  { id: "alert.created", label: "Alert Created", description: "Fires whenever a high or critical alert is detected." },
  { id: "incident.created", label: "Incident Created", description: "Dispatched upon formal incident triage." },
  { id: "incident.updated", label: "Incident Updated", description: "Status transitions, analyst notes, and severity updates." },
  { id: "vulnerability.detected", label: "Vulnerability Detected", description: "New CVE finding identified during automated scans." },
  { id: "asset.discovered", label: "Asset Discovered", description: "New host or service recognized in authorized network scopes." },
  { id: "compliance.updated", label: "Compliance Updated", description: "Control posture score changes or audit evidence uploads." },
  { id: "soar.execution_completed", label: "SOAR Completed", description: "Playbook execution pipeline completed successfully." },
  { id: "soar.execution_failed", label: "SOAR Failed", description: "Automation workflow encountered an unhandled exception." },
  { id: "report.generated", label: "Report Generated", description: "Executive summary or technical assessment report compiled." },
];

export default function WebhooksManagementPage() {
  const [webhooks, setWebhooks] = useState<WebhookEndpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedWebhook, setSelectedWebhook] = useState<WebhookEndpoint | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryAttempt[]>([]);
  const [loadingDeliveries, setLoadingDeliveries] = useState(false);

  // Modals & Actions
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState<WebhookSecretRotateResponse | null>(null);
  const [replayingId, setReplayingId] = useState<string | null>(null);
  const [replayNotice, setReplayNotice] = useState<string | null>(null);
  const [errorNotice, setErrorNotice] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [selectedEvents, setSelectedEvents] = useState<WebhookEventType[]>([
    "alert.created",
    "incident.created",
    "soar.execution_completed",
  ]);
  const [retryLimit, setRetryLimit] = useState(3);
  const [timeoutSeconds, setTimeoutSeconds] = useState(10);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const loadWebhooks = async () => {
    setLoading(true);
    try {
      const res = await apiIntegrations.listWebhooks();
      if (res.data) {
        setWebhooks(res.data);
        if (res.data.length > 0 && !selectedWebhook) {
          setSelectedWebhook(res.data[0]);
          loadDeliveries(res.data[0].id);
        }
      }
    } catch (e: any) {
      console.error("Failed to load webhooks", e);
    } finally {
      setLoading(false);
    }
  };

  const loadDeliveries = async (hookId: string) => {
    setLoadingDeliveries(true);
    try {
      const res = await apiIntegrations.listWebhookDeliveries(hookId);
      if (res.data) setDeliveries(res.data);
    } catch (e: any) {
      console.error("Failed to load deliveries", e);
    } finally {
      setLoadingDeliveries(false);
    }
  };

  useEffect(() => {
    loadWebhooks();
  }, []);

  const handleSelectWebhook = (hook: WebhookEndpoint) => {
    setSelectedWebhook(hook);
    loadDeliveries(hook.id);
  };

  const handleRotateSecret = async (hook: WebhookEndpoint) => {
    if (!confirm(`Rotate HMAC signing secret for "${hook.name}"? Receivers must update their verification key immediately.`)) {
      return;
    }

    setRotatingId(hook.id);
    setErrorNotice(null);
    try {
      const res = await apiIntegrations.rotateWebhookSecret(hook.id);
      if (res.data) {
        setRotatedSecret(res.data);
        loadWebhooks();
      } else {
        setErrorNotice(res.error || "Secret rotation failed.");
      }
    } catch (err: any) {
      setErrorNotice(err.message || "An unexpected error occurred during secret rotation.");
    } finally {
      setRotatingId(null);
    }
  };

  const handleReplayDelivery = async (deliveryId: string) => {
    if (!selectedWebhook) return;
    setReplayingId(deliveryId);
    setReplayNotice(null);
    try {
      const res = await apiIntegrations.replayWebhookDelivery(selectedWebhook.id, deliveryId);
      if (res.data && res.data.success) {
        setReplayNotice(`Delivery replayed successfully! HTTP ${res.data.http_status_code} in ${res.data.duration_ms}ms.`);
        loadDeliveries(selectedWebhook.id);
      } else {
        setErrorNotice("Replay request did not complete successfully.");
      }
    } catch (err: any) {
      setErrorNotice(err.message || "Replay failed.");
    } finally {
      setReplayingId(null);
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedEvents.length === 0) {
      setErrorNotice("Select at least one event subscription.");
      return;
    }

    setIsSubmitting(true);
    setErrorNotice(null);

    try {
      const res = await apiIntegrations.createWebhook({
        name,
        url,
        description,
        events: selectedEvents,
        retry_limit: retryLimit,
        timeout_seconds: timeoutSeconds,
        is_active: true,
      });

      if (res.data) {
        setShowCreateModal(false);
        setName("");
        setUrl("");
        setDescription("");
        loadWebhooks();
      } else {
        setErrorNotice(res.error || "Failed to create webhook endpoint.");
      }
    } catch (err: any) {
      setErrorNotice(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleEvent = (event: WebhookEventType) => {
    if (selectedEvents.includes(event)) {
      setSelectedEvents(selectedEvents.filter((e) => e !== event));
    } else {
      setSelectedEvents([...selectedEvents, event]);
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
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-purple-500/30 bg-purple-950/40 text-purple-400">
              <Radio className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Webhook Management & Outbound Dispatchers
              </h1>
              <p className="text-sm text-slate-400">
                Cryptographically signed (HMAC-SHA256) event streams with replay protection and SSRF isolation
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 rounded-lg border border-purple-500/50 bg-purple-600/80 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-purple-900/30 transition-all hover:bg-purple-500"
          >
            <PlusCircle className="h-4 w-4" />
            New Webhook
          </button>
          <button
            onClick={loadWebhooks}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Notifications */}
      {errorNotice && (
        <div className="flex items-center justify-between rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 text-xs text-rose-300">
          <span>{errorNotice}</span>
          <button onClick={() => setErrorNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {replayNotice && (
        <div className="flex items-center justify-between rounded-xl border border-emerald-500/40 bg-emerald-950/30 p-4 text-xs text-emerald-300">
          <span>{replayNotice}</span>
          <button onClick={() => setReplayNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {rotatedSecret && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-950/30 p-5 text-xs text-amber-200">
          <div className="flex items-center gap-2 font-semibold text-amber-100">
            <Key className="h-4 w-4 text-amber-400" />
            New Signing Secret Generated — Copy Immediately!
          </div>
          <p className="mt-2 text-amber-300/80">
            For security reasons, this secret will not be presented in plaintext again.
          </p>
          <div className="mt-3 flex items-center gap-3">
            <code className="rounded border border-amber-500/30 bg-black/60 px-3 py-1.5 font-mono text-sm text-amber-300">
              {rotatedSecret.new_secret}
            </code>
            <button
              onClick={() => {
                navigator.clipboard.writeText(rotatedSecret.new_secret);
                alert("Copied to clipboard!");
              }}
              className="rounded border border-amber-500/40 bg-amber-600/30 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-600/50"
            >
              Copy Secret
            </button>
            <button
              onClick={() => setRotatedSecret(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Webhooks List */}
        <div className="space-y-4 lg:col-span-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Configured Endpoints ({webhooks.length})
          </h2>

          {loading ? (
            <div className="flex h-64 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/30">
              <RefreshCw className="h-6 w-6 animate-spin text-purple-400" />
            </div>
          ) : webhooks.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center">
              <Radio className="mx-auto h-8 w-8 text-slate-600" />
              <p className="mt-2 text-xs text-slate-400">No webhooks registered yet.</p>
            </div>
          ) : (
            webhooks.map((hook) => {
              const isSelected = selectedWebhook?.id === hook.id;
              return (
                <div
                  key={hook.id}
                  onClick={() => handleSelectWebhook(hook)}
                  className={`cursor-pointer rounded-xl border p-5 transition-all ${
                    isSelected
                      ? "border-purple-500/60 bg-purple-950/20 shadow-lg shadow-purple-950/40"
                      : "border-slate-800 bg-slate-900/60 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-white">{hook.name}</h3>
                        {hook.is_active ? (
                          <span className="rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                            Active
                          </span>
                        ) : (
                          <span className="rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] text-slate-400">
                            Disabled
                          </span>
                        )}
                      </div>
                      <p className="mt-1 font-mono text-xs text-purple-300/80 truncate max-w-sm sm:max-w-md">
                        {hook.url}
                      </p>
                    </div>

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRotateSecret(hook);
                      }}
                      disabled={rotatingId === hook.id}
                      className="flex items-center gap-1 rounded border border-slate-700 bg-slate-800/80 px-2 py-1 text-[10px] font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-50"
                      title="Rotate signing secret"
                    >
                      <RotateCw className={`h-3 w-3 ${rotatingId === hook.id ? "animate-spin text-purple-400" : ""}`} />
                      Rotate Key
                    </button>
                  </div>

                  <p className="mt-3 text-xs text-slate-400 line-clamp-2">
                    {hook.description || "Outbound notification webhook endpoint."}
                  </p>

                  {/* Subscribed Events Badges */}
                  <div className="mt-3 flex flex-wrap gap-1">
                    {hook.events.map((ev) => (
                      <span
                        key={ev}
                        className="rounded border border-purple-500/20 bg-purple-950/40 px-2 py-0.5 text-[10px] text-purple-300"
                      >
                        {ev}
                      </span>
                    ))}
                  </div>

                  <div className="mt-4 flex items-center justify-between border-t border-slate-800/80 pt-3 text-[11px] text-slate-500">
                    <span>Secret: <span className="font-mono text-slate-400">{hook.secret_preview}</span></span>
                    <span>Retries: {hook.retry_limit} • Timeout: {hook.timeout_seconds}s</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Selected Webhook Deliveries & HMAC Specs */}
        <div className="space-y-6 lg:col-span-6">
          {selectedWebhook ? (
            <>
              {/* Delivery History */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Send className="h-4 w-4 text-purple-400" />
                    <h3 className="text-sm font-semibold text-white">
                      Delivery History ({deliveries.length})
                    </h3>
                  </div>
                  <button
                    onClick={() => loadDeliveries(selectedWebhook.id)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${loadingDeliveries ? "animate-spin" : ""}`} />
                  </button>
                </div>

                {loadingDeliveries ? (
                  <div className="flex h-48 items-center justify-center">
                    <RefreshCw className="h-6 w-6 animate-spin text-purple-400" />
                  </div>
                ) : deliveries.length === 0 ? (
                  <p className="mt-4 text-xs text-slate-500">No delivery attempts recorded for this endpoint yet.</p>
                ) : (
                  <div className="mt-4 divide-y divide-slate-800/80">
                    {deliveries.map((attempt) => (
                      <div key={attempt.id} className="py-3 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {attempt.status === "Delivered" ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-rose-400" />
                            )}
                            <span className="font-mono text-slate-300">
                              HTTP {attempt.http_status_code || "---"}
                            </span>
                            <span className="text-slate-500">•</span>
                            <span className="text-slate-400">{attempt.duration_ms}ms</span>
                          </div>

                          <button
                            onClick={() => handleReplayDelivery(attempt.id)}
                            disabled={replayingId === attempt.id}
                            className="flex items-center gap-1 text-[11px] font-semibold text-purple-400 hover:text-purple-300 disabled:opacity-50"
                          >
                            <Play className={`h-3 w-3 ${replayingId === attempt.id ? "animate-spin" : ""}`} />
                            Replay
                          </button>
                        </div>

                        <div className="mt-1 font-mono text-[11px] text-slate-500 truncate">
                          Idempotency: {attempt.idempotency_key}
                        </div>
                        {attempt.error_message && (
                          <div className="mt-1 text-[11px] text-rose-400">{attempt.error_message}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* HMAC-SHA256 Verification Guide Card */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold text-white">Signature Verification Guide</h3>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">
                  Every outgoing webhook contains a <code className="text-cyan-300">CyberShield-Signature</code> header
                  formatted as <code className="text-cyan-300">t=TIMESTAMP,v1=HMAC_SHA256_HEX</code>.
                </p>

                <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300">
                  <span className="text-purple-400"># Verify in Node.js</span>
                  <br />
                  const canonical = `t=$&#123;timestamp&#125;.$&#123;rawBody&#125;`;
                  <br />
                  const expected = crypto.createHmac(&apos;sha256&apos;, secret).update(canonical).digest(&apos;hex&apos;);
                </div>
              </div>
            </>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center text-xs text-slate-500">
              Select a webhook endpoint to inspect delivery logs and configuration.
            </div>
          )}
        </div>
      </div>

      {/* New Webhook Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Register Webhook Endpoint</h3>
                <p className="mt-1 text-xs text-slate-400">
                  Receive realtime JSON events signed with HMAC-SHA256.
                </p>
              </div>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateWebhook} className="mt-5 space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300">Endpoint Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SOC PagerDuty Webhook Bridge"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-purple-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300">Target URL (HTTPS Recommended)</label>
                <input
                  type="url"
                  required
                  placeholder="https://api.yourdomain.com/webhooks/cybershield"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-white focus:border-purple-500 focus:outline-none"
                />
                <span className="mt-1 block text-[10px] text-slate-500">
                  SSRF Protection: Requests to 127.0.0.1, localhost, and internal subnets are blocked.
                </span>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300">Description (Optional)</label>
                <input
                  type="text"
                  placeholder="Purpose or target system description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-purple-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300">Subscribed Events</label>
                <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 max-h-48 overflow-y-auto pr-1">
                  {AVAILABLE_EVENTS.map((ev) => (
                    <label
                      key={ev.id}
                      className={`flex cursor-pointer items-start gap-2 rounded-lg border p-2 text-xs transition-colors ${
                        selectedEvents.includes(ev.id)
                          ? "border-purple-500/50 bg-purple-950/40 text-purple-200"
                          : "border-slate-800 bg-slate-950 text-slate-400 hover:bg-slate-900"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedEvents.includes(ev.id)}
                        onChange={() => toggleEvent(ev.id)}
                        className="mt-0.5 h-3.5 w-3.5 rounded border-slate-700 bg-slate-950 text-purple-600 focus:ring-purple-500"
                      />
                      <div>
                        <div className="font-semibold">{ev.label}</div>
                        <div className="text-[10px] text-slate-500 leading-tight">{ev.description}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-300">Retry Limit</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={retryLimit}
                    onChange={(e) => setRetryLimit(Number(e.target.value))}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300">Timeout (Seconds)</label>
                  <input
                    type="number"
                    min={5}
                    max={30}
                    value={timeoutSeconds}
                    onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                    className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-white"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="rounded-lg border border-purple-500 bg-purple-600 px-4 py-2 text-xs font-semibold text-white hover:bg-purple-500 disabled:opacity-50"
                >
                  {isSubmitting ? "Registering..." : "Create Webhook"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
