"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Bell,
  Mail,
  Webhook,
  Send,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  PlusCircle,
  Copy,
  Terminal,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { NotificationTemplate, NotificationDelivery } from "@/types/soar";

export default function SOARNotificationsPage() {
  const [templates, setTemplates] = useState<NotificationTemplate[]>([]);
  const [loading, setLoading] = useState(true);

  // Test Dispatch Form
  const [testChannel, setTestChannel] = useState<"in_app" | "email" | "webhook">("webhook");
  const [recipient, setRecipient] = useState("https://hooks.slack.com/services/T000/B000/XYZ");
  const [subject, setSubject] = useState("SOC Test Alert Notification");
  const [body, setBody] = useState(
    '{"event": "soar_test_dispatch", "timestamp": "2026-11-02T11:00:00Z", "status": "Success"}'
  );
  const [dispatching, setDispatching] = useState(false);
  const [deliveryResult, setDeliveryResult] = useState<NotificationDelivery | null>(null);

  const loadTemplates = async () => {
    setLoading(true);
    try {
      const res = await apiSOAR.listNotifications();
      if (res.data) setTemplates(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTemplates();
  }, []);

  const handleTestDispatch = async () => {
    if (!recipient.trim() || !body.trim()) {
      alert("Please fill in recipient and message body.");
      return;
    }
    setDispatching(true);
    setDeliveryResult(null);
    try {
      const res = await apiSOAR.testNotification({
        channel: testChannel,
        recipient,
        subject: testChannel === "email" ? subject : undefined,
        body,
      });
      if (res.data) {
        setDeliveryResult(res.data);
      } else {
        alert(res.error || "Dispatch failed");
      }
    } catch (e: any) {
      alert(e.message);
    } finally {
      setDispatching(false);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Bell className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                SOAR Notification & Webhook Channels
              </h1>
              <p className="text-sm text-slate-400">
                Configure automated alert dispatchers, SIEM webhook destinations, and SOC incident notifications
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadTemplates}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Configured Templates Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {templates.map((tpl) => (
          <div
            key={tpl.id}
            className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md"
          >
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {tpl.channel === "webhook" ? (
                    <Webhook className="h-4 w-4 text-cyan-400" />
                  ) : tpl.channel === "email" ? (
                    <Mail className="h-4 w-4 text-violet-400" />
                  ) : (
                    <Bell className="h-4 w-4 text-emerald-400" />
                  )}
                  <span className="font-mono text-xs uppercase text-slate-300">
                    {tpl.channel}
                  </span>
                </div>
                {tpl.is_default && (
                  <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold text-cyan-400 border border-cyan-500/20">
                    Default Template
                  </span>
                )}
              </div>

              <h3 className="mt-3 text-base font-bold text-white">{tpl.template_name}</h3>
              {tpl.subject && (
                <div className="mt-1 text-xs text-slate-400">
                  Subject: <span className="text-slate-300 font-mono">{tpl.subject}</span>
                </div>
              )}

              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3 font-mono text-xs text-slate-300">
                <div className="text-[10px] uppercase text-slate-500 mb-1">Body Template:</div>
                <div className="line-clamp-4">{tpl.body_template}</div>
              </div>
            </div>

            <div className="mt-4 text-[11px] text-slate-500">
              Created: {new Date(tpl.created_at).toLocaleDateString()}
            </div>
          </div>
        ))}
      </div>

      {/* Live Test Dispatcher Form */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <h2 className="text-base font-bold text-white">Live Notification Dispatch Tester</h2>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Simulate a real automated notification delivery event to verify webhooks or email gateways
        </p>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div>
            <label className="text-xs font-medium text-slate-300">Target Channel</label>
            <select
              value={testChannel}
              onChange={(e) => {
                const ch = e.target.value as "in_app" | "email" | "webhook";
                setTestChannel(ch);
                if (ch === "email") {
                  setRecipient("soc-alert@apexcyberdefense.io");
                } else if (ch === "webhook") {
                  setRecipient("https://hooks.slack.com/services/T000/B000/XYZ");
                } else {
                  setRecipient("soc-inbox");
                }
              }}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="webhook">Webhook / SIEM Endpoint</option>
              <option value="email">Email Notification</option>
              <option value="in_app">In-App SOC Notification</option>
            </select>
          </div>

          <div className="lg:col-span-2">
            <label className="text-xs font-medium text-slate-300">Recipient URL or Address</label>
            <input
              type="text"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {testChannel === "email" && (
            <div className="lg:col-span-3">
              <label className="text-xs font-medium text-slate-300">Subject</label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/80 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
              />
            </div>
          )}

          <div className="lg:col-span-3">
            <label className="text-xs font-medium text-slate-300">Payload / Message Body</label>
            <textarea
              rows={4}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/80 p-3 font-mono text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="mt-6 flex items-center justify-between">
          <div>
            {deliveryResult && (
              <div className="flex items-center gap-2 text-xs text-emerald-300 font-medium">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>
                  Delivered successfully to <code className="text-white">{deliveryResult.recipient}</code> via{" "}
                  <strong>{deliveryResult.channel}</strong>. Delivery ID: {deliveryResult.id.slice(0, 8)}
                </span>
              </div>
            )}
          </div>

          <button
            onClick={handleTestDispatch}
            disabled={dispatching}
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-cyan-950/50 hover:bg-cyan-500 disabled:opacity-50"
          >
            <Send className={`h-4 w-4 ${dispatching ? "animate-spin" : ""}`} />
            {dispatching ? "Dispatching..." : "Send Test Message"}
          </button>
        </div>
      </div>
    </div>
  );
}
