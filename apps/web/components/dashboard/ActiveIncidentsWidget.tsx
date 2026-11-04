import Link from "next/link";
import { AlertCircle, Clock, ArrowRight } from "lucide-react";
import { mockIncidents } from "@/lib/mockData";
import { getSeverityColor, getStatusBadge } from "@/lib/utils";

export function ActiveIncidentsWidget() {
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

      <div className="space-y-3">
        {mockIncidents.map((inc) => (
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
                  inc.severity
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
                    inc.status
                  )}`}
                >
                  {inc.status}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
