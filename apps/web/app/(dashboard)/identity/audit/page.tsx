"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ArrowLeft,
  Filter,
  Lock,
  Search,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type { IdentityAuditEvent } from "@/types/identity";

export default function IdentityAuditPage() {
  const [events, setEvents] = useState<IdentityAuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  const loadAuditLogs = async () => {
    try {
      setLoading(true);
      const res = await apiIdentity.listAuditLog({
        limit: 100,
        eventType: filterType || undefined,
      });
      if (res.data) {
        setEvents(res.data);
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [filterType]);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "success":
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase">
            Success
          </span>
        );
      case "warning":
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20 uppercase">
            Warning
          </span>
        );
      case "failure":
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase">
            Failure
          </span>
        );
      case "denied":
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20 uppercase">
            Denied
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 uppercase">
            {status}
          </span>
        );
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.event_type.toLowerCase().includes(q) ||
      (ev.user_email && ev.user_email.toLowerCase().includes(q)) ||
      ev.ip_address.includes(q) ||
      ev.correlation_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 max-w-6xl">
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
            <Fingerprint className="w-6 h-6 text-purple-400" />
            Identity & Authentication Audit Trail
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Immutable forensic ledger recording login attempts, MFA challenges, SSO federations, session revocations, and Zero Trust policy decisions.
          </p>
        </div>
        <button
          onClick={loadAuditLogs}
          disabled={loading}
          className="p-2 text-slate-400 hover:text-white rounded-xl bg-slate-900 border border-slate-800 transition-colors self-start sm:self-center"
          title="Refresh Audit Logs"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* Zero Credentials Redaction Banner */}
      <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/20 flex items-center gap-3 text-xs text-cyan-300">
        <Lock className="w-4 h-4 shrink-0 text-cyan-400" />
        <span>
          <strong>Zero Exposure Assurance:</strong> All passwords, TOTP secret tokens, client secrets, and plaintext recovery codes are cryptographically scrubbed and strictly omitted from audit logging.
        </span>
      </div>

      {/* Controls Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/40 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search email, IP, event, correlation..."
            className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">All Event Types</option>
            <option value="login_success">login_success</option>
            <option value="mfa_challenge_success">mfa_challenge_success</option>
            <option value="mfa_challenge_failure">mfa_challenge_failure</option>
            <option value="mfa_enrolled">mfa_enrolled</option>
            <option value="step_up_success">step_up_success</option>
            <option value="sso_login_success">sso_login_success</option>
            <option value="session_revoked">session_revoked</option>
            <option value="zero_trust_access_denied">zero_trust_access_denied</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Event Type</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3">Actor / Email</th>
              <th className="py-2.5 px-3">Client IP</th>
              <th className="py-2.5 px-3">Correlation ID</th>
              <th className="py-2.5 px-3">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                  No matching identity audit events found.
                </td>
              </tr>
            ) : (
              filteredEvents.map((ev) => (
                <tr key={ev.id} className="hover:bg-slate-800/20">
                  <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                    {new Date(ev.created_at).toLocaleString([], {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    })}
                  </td>
                  <td className="py-3 px-3 text-cyan-300 font-semibold">{ev.event_type}</td>
                  <td className="py-3 px-3">{getStatusBadge(ev.status)}</td>
                  <td className="py-3 px-3 text-white font-sans text-xs">{ev.user_email || "System"}</td>
                  <td className="py-3 px-3 text-slate-300">{ev.ip_address}</td>
                  <td className="py-3 px-3 text-slate-500 text-[11px] truncate max-w-[120px]" title={ev.correlation_id}>
                    {ev.correlation_id}
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px] font-sans truncate max-w-xs" title={JSON.stringify(ev.details)}>
                    {JSON.stringify(ev.details)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
