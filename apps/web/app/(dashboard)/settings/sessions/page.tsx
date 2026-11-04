"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Laptop,
  Smartphone,
  Tablet,
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Trash2,
  RefreshCw,
  ArrowLeft,
  CheckCircle2,
  Radio,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type { SessionMetadata } from "@/types/identity";

export default function SessionsSettingsPage() {
  const [sessions, setSessions] = useState<SessionMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const loadSessions = async () => {
    try {
      setLoading(true);
      const res = await apiIdentity.listSessions();
      if (res.data) {
        setSessions(res.data);
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const handleRevokeSession = async (sessionId: string) => {
    try {
      setRevokingId(sessionId);
      setStatusMessage(null);
      const res = await apiIdentity.revokeSession(sessionId, "User terminated from portal");
      if (res.data?.success) {
        setStatusMessage({ type: "success", text: "Session terminated immediately." });
        setSessions((prev) => prev.filter((s) => s.id !== sessionId));
      } else {
        setStatusMessage({ type: "error", text: res.error || "Failed to revoke session." });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to revoke session." });
    } finally {
      setRevokingId(null);
    }
  };

  const handleRevokeAll = async () => {
    if (!confirm("Are you sure you want to terminate all other active sessions? You will stay logged in on this device.")) {
      return;
    }

    try {
      setRevokingAll(true);
      setStatusMessage(null);
      const res = await apiIdentity.revokeAllSessions();
      if (res.data?.success) {
        setStatusMessage({
          type: "success",
          text: `Terminated ${res.data.revoked_count} active sessions across other devices.`,
        });
        loadSessions();
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to revoke all sessions." });
    } finally {
      setRevokingAll(false);
    }
  };

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType.toLowerCase()) {
      case "mobile":
        return <Smartphone className="w-5 h-5 text-emerald-400" />;
      case "tablet":
        return <Tablet className="w-5 h-5 text-purple-400" />;
      default:
        return <Laptop className="w-5 h-5 text-cyan-400" />;
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <Link
            href="/settings/security"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 mb-2 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Security Overview
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Laptop className="w-6 h-6 text-amber-400" />
            Active Sessions & Device Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Review active logins, identify unrecognized devices or geographical anomalies, and remotely revoke access.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadSessions}
            disabled={loading}
            className="p-2 text-slate-400 hover:text-white rounded-xl bg-slate-900 border border-slate-800 transition-colors"
            title="Refresh Sessions"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={handleRevokeAll}
            disabled={revokingAll}
            className="px-4 py-2 text-xs font-semibold text-rose-300 hover:text-rose-100 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 rounded-xl transition-all shadow-md shadow-rose-950/40 cursor-pointer whitespace-nowrap"
          >
            {revokingAll ? "Revoking..." : "Revoke All Other Sessions"}
          </button>
        </div>
      </div>

      {statusMessage && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-sm ${
            statusMessage.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-200"
              : "bg-rose-950/40 border-rose-500/40 text-rose-200"
          }`}
        >
          {statusMessage.type === "success" ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Session Security Policies Summary Bar */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Idle Session Expiration: <strong>60 Minutes</strong></span>
        </div>
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-purple-400" />
          <span>Maximum Lifetime: <strong>24 Hours</strong></span>
        </div>
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Max Concurrent Devices: <strong>5 per User</strong></span>
        </div>
      </div>

      {/* Sessions List */}
      <div className="space-y-3">
        {sessions.map((sess) => (
          <div
            key={sess.id}
            className={`p-5 rounded-2xl border transition-all ${
              sess.is_suspicious
                ? "bg-rose-950/20 border-rose-500/40 shadow-lg shadow-rose-950/20"
                : sess.is_current
                ? "bg-slate-900/70 border-cyan-500/40 shadow-md shadow-cyan-950/20"
                : "bg-slate-900/40 border-slate-800"
            }`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="p-2.5 rounded-xl bg-slate-800/80 border border-slate-700/60 mt-0.5">
                  {getDeviceIcon(sess.device_type)}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white">
                      {sess.browser || "Unknown Browser"} on {sess.os || "Unknown OS"}
                    </h3>
                    {sess.is_current && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                        Current Session
                      </span>
                    )}
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-300 uppercase">
                      {sess.aal_level}
                    </span>
                  </div>

                  <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                    <span className="flex items-center gap-1 font-mono">
                      IP: {sess.ip_address}
                    </span>
                    {sess.approx_location && (
                      <span className="flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5" />
                        {sess.approx_location}
                      </span>
                    )}
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      Active {new Date(sess.last_active_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>

                  {sess.is_suspicious && (
                    <div className="mt-2.5 p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                      <div className="flex items-center gap-1.5 font-semibold text-rose-400 mb-0.5">
                        <AlertTriangle className="w-3.5 h-3.5" /> Suspicious Login Anomaly Detected
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-[11px]">
                        {sess.suspicion_reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>

              {!sess.is_current && (
                <button
                  onClick={() => handleRevokeSession(sess.id)}
                  disabled={revokingId === sess.id}
                  className="px-3.5 py-1.5 text-xs font-semibold text-rose-400 hover:text-white bg-rose-950/30 hover:bg-rose-900/60 border border-rose-800/40 rounded-xl transition-colors flex items-center gap-1.5 self-start sm:self-center cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  {revokingId === sess.id ? "Terminating..." : "Revoke"}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
