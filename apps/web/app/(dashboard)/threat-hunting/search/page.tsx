"use client";
export const dynamic = 'force-dynamic';

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Search,
  Filter,
  Terminal,
  Play,
  Bookmark,
  Download,
  Clock,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  Layers,
  FileCode,
  X,
} from "lucide-react";
import { apiThreatHunting } from "@/lib/api-client";
import type {
  ThreatHuntingQueryParam,
  ThreatHuntingQueryResult,
  ThreatHuntingQueryResultItem,
  ThreatHuntingQueryResponse,
} from "@/types/threat-hunting";

function ThreatHuntingSearchContent() {
  const searchParams = useSearchParams();
  const caseIdParam = searchParams.get("caseId");

  // Query Filter States
  const [sourceIp, setSourceIp] = useState("");
  const [destIp, setDestIp] = useState("");
  const [port, setPort] = useState<string>("");
  const [protocol, setProtocol] = useState("");
  const [eventCategory, setEventCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [iocValue, setIocValue] = useState("");
  const [detectionRule, setDetectionRule] = useState("");
  const [timeRangeHours, setTimeRangeHours] = useState<number>(72);
  const [operator, setOperator] = useState<"AND" | "OR">("AND");

  // Execution States
  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState<ThreatHuntingQueryResult | null>(null);
  const [savedQueries, setSavedQueries] = useState<ThreatHuntingQueryResponse[]>([]);
  const [savingQuery, setSavingQuery] = useState(false);
  const [saveQueryName, setSaveQueryName] = useState("");
  const [showSaveModal, setShowSaveModal] = useState(false);

  // Raw Payload Modal
  const [inspectEvent, setInspectEvent] = useState<ThreatHuntingQueryResultItem | null>(null);

  const loadSavedQueries = async () => {
    try {
      const res = await apiThreatHunting.listQueries();
      if (res.data) setSavedQueries(res.data);
    } catch (err) {
      console.error("Failed to load saved queries:", err);
    }
  };

  const handleExecuteSearch = async (offset = 0) => {
    setExecuting(true);
    try {
      const params: ThreatHuntingQueryParam = {
        source_ip: sourceIp || undefined,
        destination_ip: destIp || undefined,
        port: port ? parseInt(port, 10) : undefined,
        protocol: protocol || undefined,
        event_category: eventCategory || undefined,
        severity: severity || undefined,
        ioc_value: iocValue || undefined,
        detection_rule: detectionRule || undefined,
        time_range_hours: timeRangeHours,
        operator,
        limit: 50,
        offset,
      };
      const res = await apiThreatHunting.executeSearch(params);
      if (res.data) {
        setResult(res.data);
      }
    } catch (err) {
      console.error("Query execution failed:", err);
    } finally {
      setExecuting(false);
    }
  };

  useEffect(() => {
    loadSavedQueries();
    // Run default query
    handleExecuteSearch();
  }, []);

  const handleApplySavedQuery = (q: ThreatHuntingQueryResponse) => {
    const p = q.filter_params;
    setSourceIp(p.source_ip || "");
    setDestIp(p.destination_ip || "");
    setPort(p.port ? String(p.port) : "");
    setProtocol(p.protocol || "");
    setEventCategory(p.event_category || "");
    setSeverity(p.severity || "");
    setIocValue(p.ioc_value || "");
    setDetectionRule(p.detection_rule || "");
    setOperator(p.operator || "AND");
  };

  const handleSaveCurrentQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!saveQueryName) return;
    setSavingQuery(true);
    try {
      const filter_params = {
        source_ip: sourceIp || undefined,
        destination_ip: destIp || undefined,
        port: port ? parseInt(port, 10) : undefined,
        protocol: protocol || undefined,
        event_category: eventCategory || undefined,
        severity: severity || undefined,
        ioc_value: iocValue || undefined,
        detection_rule: detectionRule || undefined,
        operator,
      };
      const res = await apiThreatHunting.saveQuery({
        name: saveQueryName,
        hunting_case_id: caseIdParam || undefined,
        filter_params,
      });
      if (res.data) {
        setSavedQueries([res.data, ...savedQueries]);
        setShowSaveModal(false);
        setSaveQueryName("");
      }
    } catch (err) {
      console.error("Failed to save query:", err);
    } finally {
      setSavingQuery(false);
    }
  };

  const handleExportCSV = () => {
    if (!result?.events.length) return;
    const headers = ["Timestamp", "Category", "Event Type", "Severity", "Source IP", "Destination IP", "Port", "Protocol", "Summary"];
    const rows = result.events.map((e) => [
      e.timestamp,
      e.event_category,
      e.event_type,
      e.severity,
      e.source_ip || "",
      e.destination_ip || "",
      e.port || "",
      e.protocol || "",
      `"${(e.summary || "").replace(/"/g, '""')}"`,
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat_hunting_export_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-500/5">
              <Terminal className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Threat Hunting Query Engine</h1>
              <p className="text-sm text-slate-400">
                Interrogate multi-source network flows, auth logs, alerts & host telemetry without arbitrary execution risk
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {caseIdParam && (
            <Link
              href={`/threat-hunting/cases/${caseIdParam}`}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 text-cyan-400 border border-slate-700 hover:border-cyan-500/40 transition font-mono"
            >
              Linked Case Active
            </Link>
          )}
          <button
            onClick={() => setShowSaveModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 text-sm font-medium transition"
          >
            <Bookmark className="h-4 w-4" />
            Save Query
          </button>
          <button
            onClick={handleExportCSV}
            disabled={!result?.events.length}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 text-sm font-medium transition disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Query Builder Form */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider">
            <Filter className="h-4 w-4" /> Structured Query Parameters
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Logic:</span>
            <div className="inline-flex rounded-lg bg-slate-800 p-0.5 border border-slate-700">
              <button
                type="button"
                onClick={() => setOperator("AND")}
                className={`px-3 py-1 text-xs font-bold rounded-md transition ${
                  operator === "AND"
                    ? "bg-cyan-500 text-slate-900 shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                AND
              </button>
              <button
                type="button"
                onClick={() => setOperator("OR")}
                className={`px-3 py-1 text-xs font-bold rounded-md transition ${
                  operator === "OR"
                    ? "bg-cyan-500 text-slate-900 shadow"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                OR
              </button>
            </div>
          </div>
        </div>

        {/* Inputs Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="text-slate-400 block mb-1">Source IP</label>
            <input
              type="text"
              placeholder="e.g. 192.168.10.45"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Destination IP</label>
            <input
              type="text"
              placeholder="e.g. 198.51.100.45"
              value={destIp}
              onChange={(e) => setDestIp(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Port</label>
            <input
              type="number"
              placeholder="e.g. 443, 88, 4444"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">Any Protocol</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="DNS">DNS</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Event Category</label>
            <select
              value={eventCategory}
              onChange={(e) => setEventCategory(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Categories</option>
              <option value="network">Network Traffic</option>
              <option value="auth">Authentication & Identity</option>
              <option value="alert">Security Alert</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">Any Severity</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">IOC Value / String</label>
            <input
              type="text"
              placeholder="e.g. c2-sync-payload.org"
              value={iocValue}
              onChange={(e) => setIocValue(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Time Horizon</label>
            <select
              value={timeRangeHours}
              onChange={(e) => setTimeRangeHours(Number(e.target.value))}
              className="w-full px-3 py-2 bg-slate-800/60 border border-slate-700/60 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value={6}>Last 6 Hours</option>
              <option value={24}>Last 24 Hours</option>
              <option value={72}>Last 3 Days</option>
              <option value={168}>Last 7 Days</option>
            </select>
          </div>
        </div>

        {/* Action Button Bar */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800/80">
          {/* Saved Queries Pills */}
          <div className="flex items-center gap-2 overflow-x-auto max-w-xl pb-1">
            <span className="text-xs text-slate-500 shrink-0">Saved Queries:</span>
            {savedQueries.map((sq) => (
              <button
                key={sq.id}
                onClick={() => handleApplySavedQuery(sq)}
                className="shrink-0 text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:border-cyan-500/40 transition"
              >
                {sq.name}
              </button>
            ))}
          </div>

          <button
            onClick={() => handleExecuteSearch(0)}
            disabled={executing}
            className="flex items-center gap-2 px-6 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-sm shadow-lg shadow-cyan-500/20 transition disabled:opacity-50"
          >
            {executing ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Execute Hunt Query
          </button>
        </div>
      </div>

      {/* Query Execution Telemetry Stats */}
      {result && (
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <div>
            Showing <strong className="text-slate-200 font-mono">{result.events.length}</strong> matching records out of{" "}
            <strong className="text-cyan-400 font-mono">{result.total_matches}</strong> total events
          </div>
          <div className="flex items-center gap-1 font-mono text-slate-500">
            <Clock className="h-3.5 w-3.5" />
            Execution: {result.execution_time_ms} ms
          </div>
        </div>
      )}

      {/* Results Table */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-800/60 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Source &rarr; Dest</th>
                <th className="py-3 px-4">Port / Proto</th>
                <th className="py-3 px-4">Telemetry Summary</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {!result || result.events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-16 text-slate-500">
                    {executing ? "Interrogating telemetry logs..." : "No events matched your search criteria."}
                  </td>
                </tr>
              ) : (
                result.events.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 capitalize font-sans text-[11px]">
                        {e.event_category}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-bold">
                        {e.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      <span>{e.source_ip || "0.0.0.0"}</span> &rarr;{" "}
                      <span className="text-cyan-300">{e.destination_ip || "0.0.0.0"}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {e.port ? `${e.port} / ` : ""}
                      {e.protocol || "IP"}
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-sans max-w-md truncate">
                      {e.summary}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setInspectEvent(e)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 transition"
                        title="View Raw Telemetry Payload"
                      >
                        <FileCode className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Payload Inspector Modal */}
      {inspectEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-cyan-400">
                <FileCode className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Telemetry Payload Inspector</h3>
              </div>
              <button
                onClick={() => setInspectEvent(null)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <h4 className="text-sm font-semibold text-slate-200">{inspectEvent.summary}</h4>
                <p className="text-xs text-slate-400 font-mono">
                  {new Date(inspectEvent.timestamp).toISOString()} &bull; {inspectEvent.event_category} &bull; {inspectEvent.event_type}
                </p>
              </div>

              <div>
                <label className="text-xs uppercase font-bold text-slate-400 block mb-1">
                  Raw Event JSON
                </label>
                <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto max-h-72">
                  {JSON.stringify(inspectEvent.raw_payload || {}, null, 2)}
                </pre>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setInspectEvent(null)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Save Query Modal */}
      {showSaveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2 text-cyan-400">
                <Bookmark className="h-5 w-5" />
                <h3 className="font-semibold text-slate-100">Save Search Criteria</h3>
              </div>
              <button
                onClick={() => setShowSaveModal(false)}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleSaveCurrentQuery} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Query Name <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. CobaltStrike High-Entropy Flows"
                  value={saveQueryName}
                  onChange={(e) => setSaveQueryName(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowSaveModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingQuery}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium shadow-lg shadow-cyan-500/20 transition flex items-center gap-2"
                >
                  {savingQuery && <RefreshCw className="h-4 w-4 animate-spin" />}
                  Save Query
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ThreatHuntingSearchPage() {
  return (
    <Suspense fallback={null}>
      <ThreatHuntingSearchContent />
    </Suspense>
  );
}
