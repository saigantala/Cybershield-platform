"use client";

import { useState, useMemo } from "react";
import {
  Activity,
  Search,
  Filter,
  Lock,
  Calendar,
  User,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from "lucide-react";
import { mockAuditLogs } from "@/lib/mockData";
import { AuditLog } from "@cybershield/shared-types";
import { formatDateTime } from "@/lib/utils";

export default function AuditLogsPage() {
  const [logs] = useState<AuditLog[]>(mockAuditLogs);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedAction, setSelectedAction] = useState("all");
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(6);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesSearch =
        log.userEmail.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.ipAddress.includes(searchTerm);

      const matchesAction =
        selectedAction === "all" || log.action === selectedAction;

      return matchesSearch && matchesAction;
    });
  }, [logs, searchTerm, selectedAction]);

  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredLogs.slice(start, start + pageSize);
  }, [filteredLogs, currentPage, pageSize]);

  const getActionBadge = (action: string) => {
    if (action.includes("LOGIN")) {
      return "text-cyan-400 bg-cyan-500/10 border-cyan-500/20";
    }
    if (action.includes("SCAN")) {
      return "text-blue-400 bg-blue-500/10 border-blue-500/20";
    }
    if (action.includes("SCOPE") || action.includes("APPROVED")) {
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
    }
    if (action.includes("CANCEL") || action.includes("REVOKE")) {
      return "text-rose-400 bg-rose-500/10 border-rose-500/20";
    }
    return "text-amber-400 bg-amber-500/10 border-amber-500/20";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Security Audit Logs
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, append-only record of user logins, scan actions, permission changes, and configuration updates
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
          <Lock className="h-3.5 w-3.5" />
          <span>Append-Only Ledger Active</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-glass rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-96">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by operator email, IP, or action..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-[#111C2D] border border-blue-500/20 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedAction}
            onChange={(e) => {
              setSelectedAction(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#111C2D] border border-blue-500/20 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Event Categories</option>
            <option value="USER_LOGIN_SUCCESS">Login Events</option>
            <option value="SCAN_STARTED">Scan Actions</option>
            <option value="SCOPE_APPROVED">Scope Configuration</option>
            <option value="FINDING_STATUS_UPDATE">Finding Status Updates</option>
          </select>

          <span className="text-xs text-slate-400 font-mono">
            {filteredLogs.length} events logged
          </span>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0B1220]/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Operator</th>
                <th className="py-3 px-4">Action Event</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4">Details & Payload</th>
                <th className="py-3 px-4 text-right">Origin IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {paginatedLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#162338]/40 transition-colors">
                  <td className="py-3 px-4 font-mono text-slate-300 text-[11px] whitespace-nowrap">
                    {formatDateTime(log.timestamp)}
                  </td>

                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5">
                      <User className="h-3 w-3 text-cyan-400 shrink-0" />
                      <span className="text-white font-mono text-[11px]">
                        {log.userEmail}
                      </span>
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getActionBadge(
                        log.action
                      )}`}
                    >
                      {log.action}
                    </span>
                  </td>

                  <td className="py-3 px-4 font-mono text-slate-300 text-[11px] uppercase">
                    {log.resourceType}
                  </td>

                  <td className="py-3 px-4 text-slate-200">
                    {log.details}
                  </td>

                  <td className="py-3 px-4 font-mono text-cyan-400 text-right">
                    {log.ipAddress}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-3 bg-[#0B1220]/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-white">{(currentPage - 1) * pageSize + 1}</strong> to{" "}
            <strong className="text-white">{Math.min(currentPage * pageSize, filteredLogs.length)}</strong> of{" "}
            <strong className="text-white">{filteredLogs.length}</strong> events
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(Math.max(currentPage - 1, 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="font-mono px-2">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(currentPage + 1, totalPages))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
