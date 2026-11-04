import Link from "next/link";
import { Radar, ArrowUpRight } from "lucide-react";
import { mockScans } from "@/lib/mockData";
import { getStatusBadge, formatDateTime } from "@/lib/utils";

export function RecentScansTable() {
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

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
              <th className="py-2.5 px-3">Scan Name</th>
              <th className="py-2.5 px-3">Target Scope</th>
              <th className="py-2.5 px-3">Scan Type</th>
              <th className="py-2.5 px-3">Execution Date</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3 text-right">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-medium">
            {mockScans.map((scan) => (
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

                <td className="py-3 px-3 text-right font-mono text-[11px]">
                  {scan.status === "completed" || scan.status === "running" ? (
                    <span>
                      <strong className="text-rose-400 font-bold">
                        {scan.findingsCount.critical}C
                      </strong>{" "}
                      /{" "}
                      <strong className="text-amber-400 font-bold">
                        {scan.findingsCount.high}H
                      </strong>{" "}
                      /{" "}
                      <span className="text-sky-400">
                        {scan.findingsCount.medium}M
                      </span>
                    </span>
                  ) : (
                    <span className="text-slate-500">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
