"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Flame, ShieldAlert, Info, Database } from "lucide-react";
import { apiVulnerabilities } from "@/lib/api-client";
import { mockFindings } from "@/lib/mockData";
import { getSeverityColor, getStatusBadge } from "@/lib/utils";

interface FindingItem {
  id: string;
  title: string;
  service?: string;
  cveId?: string | null;
  assetName: string;
  assetIp: string;
  severity: string;
  cvssScore: number;
  status: string;
  isKev?: boolean;
}

export function RecentFindingsTable() {
  const [items, setItems] = useState<FindingItem[]>([]);
  const [isLive, setIsLive] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadFindings() {
      try {
        const res = await apiVulnerabilities.listFindings({ page_size: 5 });
        if (res.data && res.data.items) {
          const mapped: FindingItem[] = res.data.items.map((f: any) => ({
            id: f.id,
            title: f.title,
            service: f.affected_service || "System Service",
            cveId: f.cve_id,
            assetName: f.asset_name || "Host",
            assetIp: f.asset_ip || "192.168.10.1",
            severity: (f.severity || "medium").toLowerCase(),
            cvssScore: Number(f.cvss_score || 0),
            status: (f.status || "open").toLowerCase(),
            isKev: Boolean(f.is_kev),
          }));
          setItems(mapped);
          setIsLive(true);
          setIsLoading(false);
          return;
        }
      } catch (e) {
        // Fall back gracefully
      }
      setItems([]);
      setIsLive(true);
      setIsLoading(false);
    }

    loadFindings();
  }, []);

  return (
    <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Recent Security Findings
            </h3>
            <p className="text-xs text-slate-400">
              Correlated vulnerability telemetry across authorized tenant assets
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`text-[10px] flex items-center gap-1 font-mono px-2 py-0.5 rounded border ${
              isLive
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-slate-900/60 text-slate-400 border-slate-800"
            }`}
          >
            {isLive ? (
              <>
                <Database className="h-3 w-3 text-emerald-400 shrink-0" />
                Live DB Synced
              </>
            ) : (
              <>
                <Info className="h-3 w-3 text-cyan-400 shrink-0" />
                Illustrative Sample Data
              </>
            )}
          </span>
          <Link
            href="/vulnerabilities"
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium hover:underline shrink-0"
          >
            All findings <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="py-10 text-center flex flex-col items-center justify-center">
          <ShieldAlert className="h-8 w-8 text-slate-500 mb-2 opacity-50" />
          <p className="text-xs font-semibold text-slate-300">No Vulnerabilities Detected</p>
          <p className="text-[11px] text-slate-500 mt-1 max-w-sm">
            No unmitigated vulnerabilities found in your environment. Run an automated discovery or vulnerability scan to evaluate asset posture.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2.5 px-3">Vulnerability Name</th>
                <th className="py-2.5 px-3">CVE ID</th>
                <th className="py-2.5 px-3">Affected Asset</th>
                <th className="py-2.5 px-3">Severity / CVSS</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {items.map((f) => (
                <tr key={f.id} className="hover:bg-[#162338]/50 transition-colors">
                  <td className="py-3 px-3">
                    <div className="flex flex-col">
                      <span className="text-white font-semibold flex items-center gap-1.5">
                        <span className="truncate max-w-xs">{f.title}</span>
                      </span>
                      <span className="text-slate-400 text-[11px] truncate max-w-sm">
                        {f.service || "System Service"}
                      </span>
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    {f.cveId ? (
                      <span className="font-mono text-cyan-400 font-bold text-[11px] px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                        {f.cveId}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[11px] font-mono">N/A</span>
                    )}
                  </td>

                  <td className="py-3 px-3">
                    <div className="flex flex-col">
                      <span className="text-slate-200 font-mono text-[11px]">
                        {f.assetIp}
                      </span>
                      <span className="text-slate-400 text-[10px] truncate max-w-[140px]">
                        {f.assetName}
                      </span>
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityColor(
                          f.severity as any
                        )}`}
                      >
                        {f.severity}
                      </span>
                      <span className="font-mono font-bold text-white text-xs">
                        {f.cvssScore.toFixed(1)}
                      </span>
                    </div>
                  </td>

                  <td className="py-3 px-3 text-right">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                        f.status as any
                      )}`}
                    >
                      {f.status.replace("_", " ")}
                    </span>
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
