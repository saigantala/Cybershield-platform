"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertCircle, Clock, ArrowRight, ShieldCheck } from "lucide-react";
import { apiIncidents } from "@/lib/api-client";
import { getSeverityColor, getStatusBadge } from "@/lib/utils";

interface IncidentItem {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assignedToName?: string;
  createdAt: string;
}

export function ActiveIncidentsWidget() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadIncidents() {
      try {
        const res = await apiIncidents.list({ page: 1, page_size: 4 });
        if (res.data && res.data.items) {
          const mapped: IncidentItem[] = res.data.items
            .filter((i: any) => i.status !== "Closed" && i.status !== "Resolved")
            .map((i: any) => ({
              id: i.id,
              title: i.title || "Security Incident",
              description: i.description || "Active security incident under analyst triage.",
              severity: (i.severity || "medium").toLowerCase(),
              status: i.status || "Open",
              assignedToName: i.assigned_to_email ? i.assigned_to_email.split("@")[0] : "Unassigned",
              createdAt: i.created_at || new Date().toISOString(),
            }));
          setIncidents(mapped);
          setIsLoading(false);
          return;
        }
      } catch (e) {
        // Fall back gracefully
      }
      setIncidents([]);
      setIsLoading(false);
    }
    loadIncidents();
  }, []);

  return (
    <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertCircle className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Active Security Incidents
            </h3>
            <p className="text-xs text-slate-400">
              Open investigation threads under analyst triage
            </p>
          </div>
        </div>

        <Link
          href="/incidents"
          className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 hover:underline"
        >
          Incident Room <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {incidents.length === 0 ? (
        <div className="py-8 text-center flex flex-col items-center justify-center">
          <ShieldCheck className="h-8 w-8 text-emerald-400 mb-2 opacity-60" />
          <p className="text-xs font-semibold text-slate-200">No Active Incidents</p>
          <p className="text-[11px] text-slate-500 mt-1 max-w-xs">
            All triage queues are currently clear. No high-priority containment actions required.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              className="p-3.5 rounded-lg bg-[#111C2D] border border-slate-800 hover:border-blue-500/40 transition-all flex flex-col justify-between gap-2.5"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h4 className="text-xs font-bold text-slate-100 line-clamp-1">
                    {inc.title}
                  </h4>
                  <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                    {inc.description}
                  </p>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[9px] uppercase font-bold border shrink-0 ${getSeverityColor(
                    inc.severity as any
                  )}`}
                >
                  {inc.severity}
                </span>
              </div>

              <div className="flex items-center justify-between text-[11px] pt-2 border-t border-slate-800/80">
                <div className="flex items-center gap-2 text-slate-400">
                  <span>Assignee:</span>
                  <span className="text-cyan-300 font-medium">
                    {inc.assignedToName || "Unassigned"}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[9px] uppercase font-bold border ${getStatusBadge(
                      inc.status as any
                    )}`}
                  >
                    {inc.status}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
