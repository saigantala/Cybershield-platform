"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  PlaySquare,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  RefreshCw,
  ExternalLink,
  Ban,
  Activity,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { SOARExecution } from "@/types/soar";

export default function SOARExecutionsPage() {
  const [executions, setExecutions] = useState<SOARExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [cancellingId, setCancellingId] = useState<string | null>(null);

  const loadExecutions = async () => {
    setLoading(true);
    try {
      const res = await apiSOAR.listExecutions(
        statusFilter !== "All" ? statusFilter : undefined
      );
      if (res.data) setExecutions(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadExecutions();
  }, [statusFilter]);

  const handleCancelExecution = async (id: string) => {
    if (!confirm("Are you sure you want to cancel this in-progress execution?")) return;
    setCancellingId(id);
    try {
      await apiSOAR.cancelExecution(id);
      loadExecutions();
    } catch (e) {
      console.error(e);
    } finally {
      setCancellingId(null);
    }
  };

  const filteredExecutions = executions.filter((exec) => {
    const matchesSearch =
      exec.workflow_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      exec.trigger_source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      exec.id.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-950/40 text-emerald-400">
              <PlaySquare className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                SOAR Execution Register
              </h1>
              <p className="text-sm text-slate-400">
                Audited timeline of automated playbook runs, step payloads, and containment decisions
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadExecutions}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by playbook name, trigger source, or execution ID..."
            className="w-full rounded-lg border border-slate-800 bg-slate-950/60 py-2 pl-9 pr-4 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-slate-400">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="All">All Statuses</option>
            <option value="Completed">Completed</option>
            <option value="Waiting_Approval">Waiting Approval</option>
            <option value="Running">Running</option>
            <option value="Failed">Failed</option>
            <option value="Cancelled">Cancelled</option>
          </select>
        </div>
      </div>

      {/* Executions Table */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="border-b border-slate-800 bg-slate-950/50 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-6 py-4">Execution ID</th>
                <th className="px-6 py-4">Playbook</th>
                <th className="px-6 py-4">Trigger Source</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Steps</th>
                <th className="px-6 py-4">Duration</th>
                <th className="px-6 py-4">Started At</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredExecutions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center text-xs text-slate-500">
                    No executions found matching your filter criteria.
                  </td>
                </tr>
              ) : (
                filteredExecutions.map((exec) => (
                  <tr key={exec.id} className="transition-colors hover:bg-slate-850/40">
                    <td className="px-6 py-4 font-mono text-xs text-slate-400">
                      <Link
                        href={`/soar/executions/${exec.id}`}
                        className="text-cyan-400 hover:underline"
                      >
                        {exec.id.slice(0, 8)}...
                      </Link>
                    </td>
                    <td className="px-6 py-4 font-medium text-white">
                      {exec.workflow_name}
                    </td>
                    <td className="px-6 py-4 text-xs font-mono text-amber-300">
                      {exec.trigger_source}
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                          exec.status === "Completed"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : exec.status === "Waiting_Approval"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : exec.status === "Cancelled"
                            ? "bg-slate-700 text-slate-400"
                            : "bg-red-500/20 text-red-300 border border-red-500/30"
                        }`}
                      >
                        {exec.status.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs font-semibold text-slate-300">
                      {exec.steps_executed_count} steps
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400">
                      {exec.duration_ms ? `${exec.duration_ms} ms` : "—"}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400">
                      {new Date(exec.started_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {exec.status === "Waiting_Approval" && (
                          <button
                            onClick={() => handleCancelExecution(exec.id)}
                            disabled={cancellingId === exec.id}
                            className="flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-xs text-red-400 hover:bg-red-950/40"
                          >
                            <Ban className="h-3 w-3" />
                            Cancel
                          </button>
                        )}
                        <Link
                          href={`/soar/executions/${exec.id}`}
                          className="flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-xs font-medium text-cyan-300 hover:bg-slate-700"
                        >
                          Audit Details
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </div>
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
