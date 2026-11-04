"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Radar, ArrowUpRight, Plus, Activity } from "lucide-react";
import { apiScans } from "@/lib/api-client";
import { getStatusBadge, formatDateTime } from "@/lib/utils";

interface ScanRow {
  id: string;
  title: string;
  targetScope: string;
  type: string;
  startedAt: string;
  status: string;
  hostsDiscovered?: number;
}

export function RecentScansTable() {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadScans() {
      try {
        const res = await apiScans.list();
        if (res.data && Array.isArray(res.data)) {
          const mapped: ScanRow[] = res.data.slice(0, 5).map((s: any) => ({
            id: s.id,
            title: s.title || "Network Discovery Sweep",
            targetScope: s.target_scope || "127.0.0.1/32",
            type: s.scan_type || s.type || "discovery",
            startedAt: s.created_at || s.started_at || new Date().toISOString(),
            status: s.status || "completed",
            hostsDiscovered: s.hosts_discovered ?? s.discovered_hosts_count ?? 0,
          }));
          setScans(mapped);
          setIsLoading(false);
          return;
        }
      } catch (e) {
        // Fall back gracefully
      }
      setScans([]);
      setIsLoading(false);
    }
    loadScans();
  }, []);

  return (
    <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-500/10 text-cyan-400 border border-blue-500/20">
            <Radar className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Recent Scan Activity
            </h3>
            <p className="text-xs text-slate-400">
              Live automated sweeps and historical assessment runs
            </p>
          </div>
        </div>

        <Link
          href="/scans"
          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium hover:underline"
        >
          View all scans <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {scans.length === 0 ? (
        <div className="py-10 text-center flex flex-col items-center justify-center">
          <Radar className="h-8 w-8 text-slate-500 mb-2 opacity-50" />
          <p className="text-xs font-semibold text-slate-300">No Scan History</p>
          <p className="text-[11px] text-slate-500 mt-1 max-w-sm mb-4">
            No discovery sweeps or vulnerability assessments have been executed for this organization.
          </p>
          <Link
            href="/scans"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/30 text-xs font-medium text-cyan-400 hover:bg-blue-600/30 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Launch First Scan</span>
          </Link>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2.5 px-3">Scan Name</th>
                <th className="py-2.5 px-3">Target Scope</th>
                <th className="py-2.5 px-3">Scan Type</th>
                <th className="py-2.5 px-3">Execution Date</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Hosts Identified</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-[#162338]/50 transition-colors">
                  <td className="py-3 px-3">
                    <span className="text-white font-semibold flex items-center gap-1.5">
                      {scan.title}
                    </span>
                  </td>

                  <td className="py-3 px-3 font-mono text-cyan-400 text-[11px]">
                    {scan.targetScope}
                  </td>

                  <td className="py-3 px-3 capitalize text-slate-300">
                    {scan.type.replace("_", " ")}
                  </td>

                  <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                    {formatDateTime(scan.startedAt)}
                  </td>

                  <td className="py-3 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                        scan.status
                      )}`}
                    >
                      {scan.status}
                    </span>
                  </td>

                  <td className="py-3 px-3 text-right font-mono text-[11px] text-cyan-300">
                    {scan.hostsDiscovered ?? 0} hosts
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
