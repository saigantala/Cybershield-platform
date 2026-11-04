"use client";

import { useState, useEffect } from "react";
import {
  Radio,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  X,
  RotateCcw,
  RefreshCw,
  Plus,
  Activity,
  Server,
  User,
  Zap,
  Clock,
  Layers,
} from "lucide-react";
import { SecurityEvent, SeverityLevel } from "@/types/threat-intel";
import { apiSecurityEvents } from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  Info: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function SecurityMonitoringPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedEventType, setSelectedEventType] = useState<string>("all");
  const [selectedSource, setSelectedSource] = useState<string>("all");

  // State Modals
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [showIngestModal, setShowIngestModal] = useState(false);

  // Manual Ingest Form State
  const [ingestEventType, setIngestEventType] = useState("authentication_failure");
  const [ingestSeverity, setIngestSeverity] = useState<SeverityLevel>("High");
  const [ingestSource, setIngestSource] = useState("SSH Daemon");
  const [ingestSrcIp, setIngestSrcIp] = useState("192.168.1.105");
  const [ingestDstIp, setIngestDstIp] = useState("10.0.0.15");
  const [ingestUsername, setIngestUsername] = useState("root");
  const [ingestHostname, setIngestHostname] = useState("prod-edge-bastion");
  const [ingestDesc, setIngestDesc] = useState("Repeated failed password authentication attempt for root.");
  const [submitting, setSubmitting] = useState(false);
  const [ingestResult, setIngestResult] = useState<string | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiSecurityEvents.list({
        page,
        page_size: pageSize,
        search: search || undefined,
        severity: selectedSeverity !== "all" ? selectedSeverity : undefined,
        event_type: selectedEventType !== "all" ? selectedEventType : undefined,
        source: selectedSource !== "all" ? selectedSource : undefined,
      });

      if (res.data) {
        setEvents(res.data.items || []);
        setTotalCount(res.data.total || 0);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load security event stream.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, selectedSeverity, selectedEventType, selectedSource]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchEvents();
  };

  const handleIngestEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setIngestResult(null);
    try {
      const res = await apiSecurityEvents.ingest({
        event_type: ingestEventType,
        severity: ingestSeverity,
        source: ingestSource,
        source_ip: ingestSrcIp || undefined,
        destination_ip: ingestDstIp || undefined,
        username: ingestUsername || undefined,
        hostname: ingestHostname || undefined,
        event_description: ingestDesc,
        metadata: {
          client_agent: "CyberShield Ingestion Simulator",
          protocol: "TCP",
          simulated_at: new Date().toISOString(),
        },
      });

      if (res.error) {
        setIngestResult(`Error: ${res.error}`);
      } else {
        setIngestResult("Security Event ingested and evaluated against detection rules!");
        setTimeout(() => {
          setShowIngestModal(false);
          setIngestResult(null);
          fetchEvents();
        }, 1200);
      }
    } catch (err: any) {
      setIngestResult(`Failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Security Event Monitoring</h1>
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live Ingestion
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time normalized security event stream, cross-source telemetry ingestion, and correlation triggers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchEvents()}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium shadow-lg shadow-blue-600/20 transition-colors"
          >
            <Zap className="h-4 w-4" />
            Simulate Event
          </button>
        </div>
      </div>

      {/* KPI Stream Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold mb-1">
            Total Ingested Events
          </div>
          <div className="text-2xl font-bold text-white">{totalCount}</div>
          <span className="text-[11px] text-slate-400">Stream records in database</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-rose-400 font-semibold mb-1">
            Critical Severity
          </div>
          <div className="text-2xl font-bold text-rose-400">
            {events.filter((e) => e.severity === "Critical").length}
          </div>
          <span className="text-[11px] text-slate-400">High priority telemetry</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-amber-400 font-semibold mb-1">
            Auth Anomaly Events
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {events.filter((e) => e.event_type.includes("auth")).length}
          </div>
          <span className="text-[11px] text-slate-400">Failed logins / SSH alerts</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="text-xs uppercase tracking-wider text-cyan-400 font-semibold mb-1">
            Correlation Trigger
          </div>
          <div className="text-2xl font-bold text-cyan-400">Active</div>
          <span className="text-[11px] text-slate-400">Automated rule evaluation</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search event description, IP address, user, or hostname..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 transition-colors"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>

            <select
              value={selectedEventType}
              onChange={(e) => {
                setSelectedEventType(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Event Types</option>
              <option value="authentication_failure">Authentication Failure</option>
              <option value="threat_indicator_match">Threat Indicator Match</option>
              <option value="vuln_exploit_attempt">Vulnerability Exploit</option>
              <option value="network_probe">Network Recon Probe</option>
              <option value="activity_burst">Activity Anomaly Burst</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium"
            >
              Filter
            </button>

            {(search || selectedSeverity !== "all" || selectedEventType !== "all") && (
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSelectedSeverity("all");
                  setSelectedEventType("all");
                  setPage(1);
                }}
                className="p-2 text-slate-400 hover:text-slate-200"
                title="Reset filters"
              >
                <RotateCcw className="h-4 w-4" />
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Events Stream Table */}
      <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-900/40">
                <th className="py-3 px-4">Event Timestamp (UTC)</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Source System</th>
                <th className="py-3 px-4">Observable Traffic</th>
                <th className="py-3 px-4">Target / User</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Ingesting event telemetry...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No security events found matching current criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const badge = SEVERITY_BADGES[ev.severity] || SEVERITY_BADGES.Medium;
                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    >
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {formatDateTime(ev.event_timestamp)}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${badge.bg} ${badge.text} ${badge.border}`}
                        >
                          {ev.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-cyan-300 bg-slate-900/60 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                          {ev.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 whitespace-nowrap font-medium">
                        {ev.source}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {ev.source_ip ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-amber-400">{ev.source_ip}</span>
                            {ev.destination_ip && (
                              <>
                                <span className="text-slate-600">&rarr;</span>
                                <span className="text-slate-400">{ev.destination_ip}</span>
                              </>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600">Localhost / None</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        <div className="flex items-center gap-2">
                          {ev.username && (
                            <span className="flex items-center gap-1 text-slate-300 font-mono">
                              <User className="h-3 w-3 text-slate-500" />
                              {ev.username}
                            </span>
                          )}
                          {ev.hostname && (
                            <span className="flex items-center gap-1 text-slate-400 font-mono">
                              <Server className="h-3 w-3 text-slate-500" />
                              {ev.hostname}
                            </span>
                          )}
                          {!ev.username && !ev.hostname && <span className="text-slate-600">-</span>}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-sm truncate">
                        {ev.event_description}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(ev);
                          }}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                        >
                          Payload
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {events.length} of {totalCount} events
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span>Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={events.length < pageSize}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Event Details Drawer Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Radio className="h-5 w-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-white">Event Ingestion Payload</h2>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Severity</span>
                  <span
                    className={`font-bold ${
                      SEVERITY_BADGES[selectedEvent.severity]?.text || "text-slate-200"
                    }`}
                  >
                    {selectedEvent.severity}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Type</span>
                  <span className="font-mono font-bold text-cyan-300">
                    {selectedEvent.event_type}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Source</span>
                  <span className="font-medium text-slate-200">
                    {selectedEvent.source}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Target User</span>
                  <span className="font-mono font-medium text-amber-300">
                    {selectedEvent.username || "None"}
                  </span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">
                  Event Description
                </div>
                <div className="text-slate-200 leading-relaxed">
                  {selectedEvent.event_description}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-slate-400 font-semibold">Observed Network Endpoints</div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between font-mono text-slate-300">
                  <div>Source: <span className="text-amber-400">{selectedEvent.source_ip || "N/A"}</span></div>
                  <div>Destination: <span className="text-slate-400">{selectedEvent.destination_ip || "N/A"}</span></div>
                  <div>Host: <span className="text-cyan-300">{selectedEvent.hostname || "N/A"}</span></div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-slate-400 font-semibold">Raw Metadata JSON</div>
                <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-60">
                  {JSON.stringify(selectedEvent.metadata || {}, null, 2)}
                </pre>
              </div>

              <div className="pt-2 text-slate-400">
                Timestamp: <span className="font-mono text-slate-300">{formatDateTime(selectedEvent.event_timestamp)}</span>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Ingest / Simulation Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-amber-400" />
                <h2 className="text-lg font-bold text-white">Simulate Ingested Event</h2>
              </div>
              <button onClick={() => setShowIngestModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleIngestEvent} className="p-6 space-y-4 text-xs">
              {ingestResult && (
                <div
                  className={`p-3 rounded-lg border ${
                    ingestResult.startsWith("Error") || ingestResult.startsWith("Failed")
                      ? "bg-rose-500/10 border-rose-500/20 text-rose-400"
                      : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                  }`}
                >
                  {ingestResult}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Event Type</label>
                  <select
                    value={ingestEventType}
                    onChange={(e) => setIngestEventType(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="authentication_failure">Authentication Failure</option>
                    <option value="threat_indicator_match">Threat Indicator Match</option>
                    <option value="vuln_exploit_attempt">Exploit Attempt</option>
                    <option value="activity_burst">Activity Anomaly Burst</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Severity</label>
                  <select
                    value={ingestSeverity}
                    onChange={(e) => setIngestSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Source Ingestion System</label>
                <input
                  type="text"
                  required
                  value={ingestSource}
                  onChange={(e) => setIngestSource(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Source IP</label>
                  <input
                    type="text"
                    value={ingestSrcIp}
                    onChange={(e) => setIngestSrcIp(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Destination IP</label>
                  <input
                    type="text"
                    value={ingestDstIp}
                    onChange={(e) => setIngestDstIp(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Target Username</label>
                  <input
                    type="text"
                    value={ingestUsername}
                    onChange={(e) => setIngestUsername(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Target Hostname</label>
                  <input
                    type="text"
                    value={ingestHostname}
                    onChange={(e) => setIngestHostname(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Event Description</label>
                <textarea
                  rows={2}
                  required
                  value={ingestDesc}
                  onChange={(e) => setIngestDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-40"
                >
                  {submitting ? "Ingesting..." : "Send Event"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
