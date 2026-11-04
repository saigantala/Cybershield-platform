"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Clock,
  Filter,
  Download,
  RefreshCw,
  Search,
  ShieldAlert,
  Server,
  Network,
  Lock,
  FolderArchive,
  AlertTriangle,
  ChevronDown,
  Layers,
  FileCode,
  X,
} from "lucide-react";
import { apiForensics } from "@/lib/api-client";
import type {
  ForensicTimelineEvent,
  ForensicTimelineFilter,
} from "@/types/forensics";

export default function ForensicTimelinePage() {
  const [events, setEvents] = useState<ForensicTimelineEvent[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [selectedSource, setSelectedSource] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  // Inspect Event Details
  const [activeEvent, setActiveEvent] = useState<ForensicTimelineEvent | null>(null);

  const loadTimeline = async () => {
    setLoading(true);
    try {
      const filter: ForensicTimelineFilter = {
        event_category: selectedSource || undefined,
        severity: selectedSeverity || undefined,
        limit: 100,
        offset: 0,
      };
      const res = await apiForensics.queryTimeline(filter);
      if (res.data) {
        setEvents(res.data.events);
        setTotalCount(res.data.total_count);
      }
    } catch (err) {
      console.error("Failed to load timeline:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTimeline();
  }, [selectedSource, selectedSeverity]);

  const getSourceIcon = (source: string) => {
    switch (source.toLowerCase()) {
      case "auth":
        return <Lock className="h-4 w-4 text-amber-400" />;
      case "network":
        return <Network className="h-4 w-4 text-cyan-400" />;
      case "alert":
        return <AlertTriangle className="h-4 w-4 text-rose-400" />;
      case "evidence":
        return <FolderArchive className="h-4 w-4 text-purple-400" />;
      case "incident":
        return <ShieldAlert className="h-4 w-4 text-orange-400" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "high":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "medium":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      default:
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/40";
    }
  };

  const filteredEvents = events.filter((e) => {
    if (
      searchFilter &&
      !e.title.toLowerCase().includes(searchFilter.toLowerCase()) &&
      !e.description.toLowerCase().includes(searchFilter.toLowerCase()) &&
      !e.indicators.some((ind) => ind.toLowerCase().includes(searchFilter.toLowerCase()))
    ) {
      return false;
    }
    return true;
  });

  const handleExportCSV = () => {
    if (!events.length) return;
    const headers = ["Timestamp", "Source", "Event Type", "Severity", "Title", "Description", "Indicators"];
    const rows = events.map((e) => [
      e.timestamp,
      e.event_source,
      e.event_type,
      e.severity,
      `"${e.title.replace(/"/g, '""')}"`,
      `"${e.description.replace(/"/g, '""')}"`,
      `"${e.indicators.join("; ")}"`,
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `forensic_timeline_reconstruction_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-500/5">
              <Clock className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Forensic Timeline Reconstruction</h1>
              <p className="text-sm text-slate-400">
                Correlate adversary activity chronologically across authentication, network metadata, security alerts, and evidence custody
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadTimeline}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleExportCSV}
            disabled={!events.length}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-cyan-300 border border-cyan-500/30 transition text-sm font-medium disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            Export Timeline CSV
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-4 shadow-xl">
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Filter timeline by title, description, or IP/IOC..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="h-3.5 w-3.5" />
            Source:
          </div>
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500/50 font-medium"
          >
            <option value="">All Security Feeds</option>
            <option value="auth">Authentication & Kerberos</option>
            <option value="network">Network Traffic & C2</option>
            <option value="alert">Security Alerts</option>
            <option value="incident">Incident Milestones</option>
            <option value="evidence">Evidence Custody Logs</option>
          </select>

          <div className="flex items-center gap-1.5 text-xs text-slate-400 ml-2">
            Severity:
          </div>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-800/70 border border-slate-700/60 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500/50 font-medium"
          >
            <option value="">Any Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Informational">Informational</option>
          </select>
        </div>
      </div>

      {/* Chronological Timeline Stream */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl">
        {loading ? (
          <div className="text-center py-20 text-slate-500 text-sm">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-cyan-400" />
            Reconstructing multi-source chronological timeline...
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="text-center py-20 text-slate-500 text-sm">
            No events matched your timeline filters.
          </div>
        ) : (
          <div className="relative pl-6 border-l-2 border-slate-800 space-y-6">
            {filteredEvents.map((e, idx) => (
              <div key={e.id || idx} className="relative group">
                {/* Node Dot */}
                <div className="absolute -left-[31px] top-1.5 h-4 w-4 rounded-full bg-slate-900 border-2 border-cyan-500/80 group-hover:border-cyan-400 group-hover:scale-125 transition flex items-center justify-center">
                  <div className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                </div>

                <div className="p-4 rounded-xl bg-slate-800/40 hover:bg-slate-800/70 border border-slate-700/50 hover:border-cyan-500/40 transition space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="p-1 rounded bg-slate-800 border border-slate-700">
                        {getSourceIcon(e.event_source)}
                      </span>
                      <span className="font-mono text-cyan-300 font-semibold text-[11px]">
                        {new Date(e.timestamp).toLocaleString()}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 uppercase font-bold">
                        {e.event_source}
                      </span>
                    </div>

                    <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold ${getSeverityBadge(e.severity)} w-fit`}>
                      {e.severity}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">{e.title}</h3>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{e.description}</p>
                  </div>

                  {/* Indicators and Details */}
                  <div className="pt-2 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 text-xs">
                    <div className="flex flex-wrap gap-1.5">
                      {e.indicators.map((ind, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-700/80 text-[10px] font-mono"
                        >
                          {ind}
                        </span>
                      ))}
                    </div>

                    <button
                      onClick={() => setActiveEvent(e)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition"
                    >
                      Inspect Raw Telemetry &rarr;
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Raw Event Detail Modal */}
      {activeEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-cyan-400">
                <FileCode className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Timeline Event Detail</h3>
              </div>
              <button
                onClick={() => setActiveEvent(null)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <span className="font-mono text-xs text-cyan-400 font-semibold block mb-0.5">
                  {new Date(activeEvent.timestamp).toISOString()}
                </span>
                <h4 className="text-base font-bold text-slate-100">{activeEvent.title}</h4>
                <p className="text-xs text-slate-400 mt-1">{activeEvent.description}</p>
              </div>

              <div>
                <label className="text-xs uppercase font-bold text-slate-400 block mb-1">
                  Raw Event Context
                </label>
                <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto max-h-60">
                  {JSON.stringify(activeEvent.raw_details || {}, null, 2)}
                </pre>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setActiveEvent(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
