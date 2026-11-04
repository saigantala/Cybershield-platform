"use client";

import { useState, useEffect } from "react";
import {
  AlertTriangle,
  Flame,
  Shield,
  Search,
  Filter,
  RefreshCw,
  Eye,
  CheckCircle,
  X,
  ExternalLink,
  Clock,
  Layers,
  Activity,
  ArrowUpRight,
} from "lucide-react";
import { apiNetwork } from "@/lib/api-client";
import { NetworkAnomaly, AnomalySeverity, AnomalyStatus } from "@/types/monitoring";
import { formatDateTime } from "@/lib/utils";
import Link from "next/link";

const SEVERITY_COLORS: Record<AnomalySeverity, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-blue-500/10", text: "text-cyan-400", border: "border-blue-500/30" },
  Low: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
  Informational: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function NetworkAnomaliesPage() {
  const [anomalies, setAnomalies] = useState<NetworkAnomaly[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedAnomaly, setSelectedAnomaly] = useState<NetworkAnomaly | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  useEffect(() => {
    loadAnomalies();
  }, [statusFilter]);

  const loadAnomalies = async () => {
    setIsLoading(true);
    const filter = statusFilter === "all" ? undefined : statusFilter;
    const res = await apiNetwork.getAnomalies(filter);
    if (res.data) {
      setAnomalies(res.data);
    } else {
      // Fallback
      setAnomalies([
        {
          id: "anom-01",
          detected_at: new Date(Date.now() - 3600000).toISOString(),
          source_asset: "192.168.10.1",
          event_category: "unexpected_port",
          severity: "High",
          rule_name: "Unauthorized High-Risk Port Ingress",
          evidence: {
            destination_port: 4444,
            service_tag: "Metasploit/Suspicious",
            source_ip: "198.51.100.42",
            destination_ip: "192.168.10.1",
            protocol: "TCP",
          },
          confidence: 92,
          recommended_investigation: "Inspect firewall gateway logs for unauthorized ingress probe on Metasploit port 4444 from 198.51.100.42.",
          status: "Open",
        },
        {
          id: "anom-02",
          detected_at: new Date(Date.now() - 7200000).toISOString(),
          source_asset: "192.168.10.2",
          event_category: "traffic_spike",
          severity: "Medium",
          rule_name: "Excessive Network Byte Volume Spike",
          evidence: {
            byte_count: 14800000,
            threshold: 5000000,
            source_ip: "192.168.10.2",
            destination_ip: "203.0.113.195",
            packet_count: 11200,
          },
          confidence: 85,
          recommended_investigation: "Audit sudden 14.8 MB database backup sync to external destination 203.0.113.195.",
          status: "Investigating",
        },
      ]);
    }
    setIsLoading(false);
  };

  const handleUpdateStatus = (anomalyId: string, newStatus: AnomalyStatus) => {
    setAnomalies(
      anomalies.map((a) => (a.id === anomalyId ? { ...a, status: newStatus } : a))
    );
    if (selectedAnomaly && selectedAnomaly.id === anomalyId) {
      setSelectedAnomaly({ ...selectedAnomaly, status: newStatus });
    }
  };

  const filtered = anomalies.filter((a) => {
    const matchesCat = categoryFilter === "all" || a.event_category === categoryFilter;
    return matchesCat;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-rose-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Network Anomaly Detection & Investigation
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic rule-based anomaly detection engine correlating traffic spikes, unauthorized ports, and unexpected egress
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadAnomalies()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
            title="Refresh anomalies"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
          <Link
            href="/monitoring-rules"
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600/20 border border-blue-500/30 text-cyan-300 hover:bg-blue-600 hover:text-white transition-all text-xs font-semibold"
          >
            <span>Tuning Rules</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="soc-glass rounded-xl p-3 border border-blue-500/20 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-[#0B1220] border border-blue-500/20 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Anomaly Categories</option>
            <option value="unexpected_port">Unexpected Port Ingress</option>
            <option value="traffic_spike">Traffic Volume Spike</option>
            <option value="suspicious_outbound">Suspicious Outbound C2</option>
            <option value="connection_failure">Connection Failure Burst</option>
            <option value="new_device">New Unregistered Device</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#0B1220] border border-blue-500/20 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="Dismissed">Dismissed</option>
          </select>
        </div>

        <span className="text-xs font-mono text-cyan-400">
          {filtered.length} Anomaly Events Evaluated
        </span>
      </div>

      {/* Anomalies Table */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-[#0E1726]/60">
                <th className="py-3 px-4">Detection Rule / Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Source Asset</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Detected Timestamp</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    No active anomalies matching the selected filters.
                  </td>
                </tr>
              ) : (
                filtered.map((anom) => {
                  const colors = SEVERITY_COLORS[anom.severity] || SEVERITY_COLORS.Informational;
                  return (
                    <tr key={anom.id} className="hover:bg-[#162338]/50 transition-colors">
                      <td className="py-3 px-4">
                        <div>
                          <p className="font-bold text-white text-xs">{anom.rule_name}</p>
                          <p className="text-[10px] font-mono text-slate-400">{anom.event_category}</p>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${colors.bg} ${colors.text} ${colors.border}`}>
                          {anom.severity}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-mono text-cyan-400 text-xs">
                        {anom.source_asset}
                      </td>

                      <td className="py-3 px-4">
                        <span className="font-mono text-slate-300 font-bold">{anom.confidence}%</span>
                      </td>

                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {formatDateTime(anom.detected_at)}
                      </td>

                      <td className="py-3 px-4">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                            anom.status === "Open"
                              ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                              : anom.status === "Investigating"
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                              : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          }`}
                        >
                          {anom.status}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedAnomaly(anom)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600/20 text-cyan-300 border border-blue-500/30 hover:bg-blue-600 hover:text-white transition-all text-xs font-semibold"
                        >
                          <Eye className="h-3 w-3" />
                          <span>Investigate</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Investigation Drawer Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-cyan-500/40 rounded-xl w-full max-w-xl p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-rose-400" />
                <div>
                  <h3 className="text-base font-bold text-white">Anomaly Investigation Drawer</h3>
                  <p className="text-[10px] font-mono text-slate-400">ID: {selectedAnomaly.id}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3">
              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-white text-sm">{selectedAnomaly.rule_name}</h4>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                      SEVERITY_COLORS[selectedAnomaly.severity].bg
                    } ${SEVERITY_COLORS[selectedAnomaly.severity].text} ${
                      SEVERITY_COLORS[selectedAnomaly.severity].border
                    }`}
                  >
                    {selectedAnomaly.severity}
                  </span>
                </div>
                <p className="text-slate-400 text-xs">Category: {selectedAnomaly.event_category}</p>
                <p className="text-slate-200 text-xs leading-relaxed">
                  {selectedAnomaly.recommended_investigation}
                </p>
              </div>

              {/* Evidence Inspector */}
              <div>
                <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1.5 font-mono">
                  Captured Packet Flow Evidence (JSON)
                </h5>
                <pre className="p-3 rounded-lg bg-[#070B14] border border-blue-500/20 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                  {JSON.stringify(selectedAnomaly.evidence, null, 2)}
                </pre>
              </div>

              {/* Status Triage Controls */}
              <div className="p-3 rounded-lg bg-[#0B1220] border border-blue-500/20 space-y-2">
                <h5 className="text-[11px] font-bold text-white">Update Investigation Status:</h5>
                <div className="flex flex-wrap gap-2">
                  {(["Open", "Investigating", "Resolved", "Dismissed"] as AnomalyStatus[]).map((st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateStatus(selectedAnomaly.id, st)}
                      className={`px-3 py-1 rounded text-xs font-semibold border transition-all ${
                        selectedAnomaly.status === st
                          ? "bg-cyan-500/20 border-cyan-400 text-cyan-300"
                          : "bg-slate-800 border-slate-700 text-slate-400 hover:text-white"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
