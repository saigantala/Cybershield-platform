"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  FileText,
  ArrowLeft,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  Filter,
  Layers,
} from "lucide-react";
import { apiIntegrations } from "@/lib/api-client";
import type { IntegrationDeliveryLog } from "@/types/integrations";

export default function IntegrationLogsPage() {
  const [logs, setLogs] = useState<IntegrationDeliveryLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const loadLogs = async () => {
    setLoading(true);
    try {
      const res = await apiIntegrations.listDeliveryLogs();
      if (res.data) setLogs(res.data);
    } catch (e: any) {
      console.error("Failed to load delivery logs", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
    const matchesStatus = statusFilter === "all" || log.status.toLowerCase() === statusFilter.toLowerCase();
    const matchesSearch =
      log.event_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (log.payload_summary && log.payload_summary.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (log.error_message && log.error_message.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesStatus && matchesSearch;
  });

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
              <FileText className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Integration Delivery Logs
              </h1>
              <p className="text-sm text-slate-400">
                Audited real-time log of security events forwarded to SIEMs, cloud targets, and webhook subscribers
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadLogs}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh Logs
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-2">
          {["all", "Delivered", "Failed", "Retrying"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                statusFilter === st
                  ? "border border-cyan-500/50 bg-cyan-950/60 text-cyan-300"
                  : "border border-slate-800 bg-slate-900/40 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {st === "all" ? "All Deliveries" : st}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search event type, error..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-slate-800 bg-slate-900/60 py-1.5 pl-9 pr-4 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Logs Table */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 shadow-xl backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/50 text-slate-400 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">HTTP Code</th>
                <th className="py-3 px-4">Latency</th>
                <th className="py-3 px-4">Payload Summary</th>
                <th className="py-3 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <RefreshCw className="mx-auto h-6 w-6 animate-spin text-cyan-400" />
                    <span className="mt-2 block text-xs">Loading delivery logs...</span>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    No delivery logs matching the current filter.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="transition-colors hover:bg-slate-800/40">
                    <td className="py-3 px-4">
                      {log.status === "Delivered" ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          Delivered
                        </span>
                      ) : log.status === "Failed" ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-950/40 px-2 py-0.5 text-[10px] font-medium text-rose-400">
                          <XCircle className="h-3 w-3" />
                          Failed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-950/40 px-2 py-0.5 text-[10px] font-medium text-amber-400">
                          <Clock className="h-3 w-3" />
                          Retrying
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-300">
                      {log.event_type}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      {log.http_status_code ? (
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] ${
                            log.http_status_code < 300
                              ? "bg-emerald-950 text-emerald-300"
                              : "bg-rose-950 text-rose-300"
                          }`}
                        >
                          {log.http_status_code}
                        </span>
                      ) : (
                        <span className="text-slate-500">---</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {log.duration_ms} ms
                    </td>
                    <td className="py-3 px-4 max-w-xs truncate text-slate-300 font-mono text-[11px]">
                      {log.payload_summary || "---"}
                      {log.error_message && (
                        <span className="block text-rose-400 text-[10px]">{log.error_message}</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-500 whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString([], {
                        month: "short",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
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
