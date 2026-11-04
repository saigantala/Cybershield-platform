"use client";

import { useState, useEffect } from "react";
import {
  Network,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  RefreshCw,
  Layers,
  Shield,
  Download,
  Server,
  Filter,
  BarChart3,
  Globe2,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { apiNetwork } from "@/lib/api-client";
import { TrafficAnalytics, ProtocolBreakdown, TopTalker, TopPort } from "@/types/monitoring";

const PROTO_COLORS: Record<string, string> = {
  HTTPS: "#06B6D4",
  TCP: "#3B82F6",
  UDP: "#8B5CF6",
  DNS: "#10B981",
  SSH: "#F59E0B",
  OTHER: "#64748B",
};

export default function NetworkMonitoringPage() {
  const [timeWindow, setTimeWindow] = useState<number>(3600); // 1 hour
  const [analytics, setAnalytics] = useState<TrafficAnalytics | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadTrafficData();
  }, [timeWindow]);

  const loadTrafficData = async () => {
    setIsLoading(true);
    const res = await apiNetwork.getTraffic(timeWindow);
    if (res.data) {
      setAnalytics(res.data);
    } else {
      // Fallback data
      setAnalytics({
        total_packets: 14280,
        total_bytes: 18450000,
        upload_bytes: 6840000,
        download_bytes: 11610000,
        current_throughput_kbps: 472.5,
        traffic_trend: [
          { time: "10:00", upload_kbps: 120, download_kbps: 340, packet_count: 450 },
          { time: "10:10", upload_kbps: 145, download_kbps: 390, packet_count: 510 },
          { time: "10:20", upload_kbps: 180, download_kbps: 420, packet_count: 580 },
          { time: "10:30", upload_kbps: 130, download_kbps: 360, packet_count: 460 },
          { time: "10:40", upload_kbps: 195, download_kbps: 510, packet_count: 670 },
          { time: "10:50", upload_kbps: 200, download_kbps: 480, packet_count: 620 },
        ],
        top_destination_ports: [
          { port: 443, service: "HTTPS", count: 680, bytes: 8900000 },
          { port: 5432, service: "PostgreSQL", count: 430, bytes: 4800000 },
          { port: 80, service: "HTTP", count: 210, bytes: 1200000 },
          { port: 22, service: "SSH", count: 115, bytes: 620000 },
          { port: 53, service: "DNS", count: 350, bytes: 410000 },
        ],
        top_talkers: [
          { ip_address: "192.168.10.1", hostname: "fw-01.edge", total_bytes: 6500000, packet_count: 5200, direction: "Inbound" },
          { ip_address: "192.168.10.2", hostname: "db-01.core", total_bytes: 4800000, packet_count: 3900, direction: "Internal" },
          { ip_address: "10.0.1.5", hostname: "edge-nginx-01", total_bytes: 3200000, packet_count: 2600, direction: "Outbound" },
          { ip_address: "203.0.113.88", hostname: "external-vpn", total_bytes: 1900000, packet_count: 1400, direction: "Inbound" },
        ],
        protocol_breakdown: [
          { protocol: "HTTPS", percentage: 49.8, byte_count: 9200000, packet_count: 7100 },
          { protocol: "TCP", percentage: 24.9, byte_count: 4600000, packet_count: 3900 },
          { protocol: "UDP", percentage: 13.0, byte_count: 2400000, packet_count: 2100 },
          { protocol: "DNS", percentage: 7.9, byte_count: 1450000, packet_count: 1180 },
          { protocol: "SSH", percentage: 4.4, byte_count: 800000, packet_count: 350 },
        ],
      });
    }
    setIsLoading(false);
  };

  const handleExportCSV = () => {
    if (!analytics) return;
    const rows = [
      ["IP Address", "Hostname", "Total Bytes", "Packet Count", "Direction"],
      ...analytics.top_talkers.map((t) => [t.ip_address, t.hostname || "", t.total_bytes, t.packet_count, t.direction]),
    ];
    const csvContent = "data:text/csv;charset=utf-8," + rows.map((e) => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cybershield_traffic_talkers_${timeWindow}s.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Network Traffic & Packet Flow Analytics
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Aggregated metadata, protocol distributions, and top communicating devices across authorized subnets
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Time window selector */}
          <div className="flex items-center bg-[#0B1220] p-1 rounded-lg border border-blue-500/20 text-xs">
            {[
              { label: "15M", val: 900 },
              { label: "1H", val: 3600 },
              { label: "6H", val: 21600 },
              { label: "24H", val: 86400 },
            ].map((opt) => (
              <button
                key={opt.val}
                onClick={() => setTimeWindow(opt.val)}
                className={`px-3 py-1 rounded font-semibold transition-all ${
                  timeWindow === opt.val
                    ? "bg-blue-600 text-white shadow-sm"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => loadTrafficData()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
            title="Refresh traffic analytics"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>

          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600/20 border border-blue-500/30 text-cyan-300 hover:bg-blue-600 hover:text-white transition-all text-xs font-semibold"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Traffic KPI Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-glass rounded-xl p-4 border border-blue-500/20 space-y-1">
          <div className="flex items-center justify-between text-cyan-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Total Volume</span>
            <Activity className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {((analytics?.total_bytes ?? 0) / (1024 * 1024)).toFixed(2)} MB
          </p>
          <p className="text-[10px] text-slate-400">
            {analytics?.total_packets.toLocaleString() ?? 0} flow packets
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-cyan-500/20 space-y-1">
          <div className="flex items-center justify-between text-cyan-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Inbound Transfer</span>
            <ArrowDownLeft className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {((analytics?.download_bytes ?? 0) / (1024 * 1024)).toFixed(2)} MB
          </p>
          <p className="text-[10px] text-cyan-400 font-semibold">
            {analytics ? Math.round((analytics.download_bytes / (analytics.total_bytes || 1)) * 100) : 63}% of Total
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-blue-500/20 space-y-1">
          <div className="flex items-center justify-between text-blue-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Outbound Transfer</span>
            <ArrowUpRight className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {((analytics?.upload_bytes ?? 0) / (1024 * 1024)).toFixed(2)} MB
          </p>
          <p className="text-[10px] text-blue-400 font-semibold">
            {analytics ? Math.round((analytics.upload_bytes / (analytics.total_bytes || 1)) * 100) : 37}% of Total
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-emerald-500/20 space-y-1">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Throughput Rate</span>
            <Network className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {analytics?.current_throughput_kbps ?? 472.5}
            <span className="text-xs text-slate-500 font-normal ml-1">kbps</span>
          </p>
          <p className="text-[10px] text-emerald-400">
            Nominal interface bandwidth
          </p>
        </div>
      </div>

      {/* Traffic Trend & Protocol Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Bandwidth Trajectory Area Chart */}
        <div className="lg:col-span-8 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Throughput Volume Trend Over Time
              </h3>
              <p className="text-[11px] text-slate-400">
                Bidirectional transfer telemetry for observation period
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-cyan-400 border border-blue-500/20">
              Sampled Every 6m
            </span>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics?.traffic_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="netInboundGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="netOutboundGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" opacity={0.6} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0B1220",
                    borderColor: "#1E293B",
                    borderRadius: "8px",
                    fontSize: "11px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="download_kbps"
                  name="Inbound (kbps)"
                  stroke="#06B6D4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#netInboundGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="upload_kbps"
                  name="Outbound (kbps)"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#netOutboundGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Breakdown */}
        <div className="lg:col-span-4 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Protocol Distribution
            </h3>
            <Layers className="h-4 w-4 text-cyan-400" />
          </div>

          <div className="space-y-3 pt-2">
            {(analytics?.protocol_breakdown || []).map((proto) => (
              <div key={proto.protocol} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300 font-semibold">{proto.protocol}</span>
                  <span className="text-cyan-400 font-bold">{proto.percentage}%</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${proto.percentage}%`,
                      backgroundColor: PROTO_COLORS[proto.protocol] || "#3B82F6",
                    }}
                  />
                </div>
                <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                  <span>{(proto.byte_count / (1024 * 1024)).toFixed(2)} MB</span>
                  <span>{proto.packet_count} pkts</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Talkers & Top Destination Ports Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Top Talkers Table */}
        <div className="lg:col-span-7 soc-glass rounded-xl overflow-hidden border border-blue-500/20">
          <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Top Communicating Devices (Top Talkers)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">By Transmitted Bytes</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-[#0E1726]/60">
                  <th className="py-3 px-4">Communicating IP / Host</th>
                  <th className="py-3 px-4">Direction</th>
                  <th className="py-3 px-4">Volume</th>
                  <th className="py-3 px-4 text-right">Packets</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium font-mono">
                {(analytics?.top_talkers || []).map((talker, idx) => (
                  <tr key={idx} className="hover:bg-[#162338]/50 transition-colors">
                    <td className="py-3 px-4">
                      <div>
                        <p className="font-bold text-white">{talker.ip_address}</p>
                        <p className="text-[10px] text-slate-400 font-sans">{talker.hostname || "Endpoint"}</p>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-cyan-400 border border-blue-500/30">
                        {talker.direction}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      {(talker.total_bytes / (1024 * 1024)).toFixed(2)} MB
                    </td>
                    <td className="py-3 px-4 text-right text-slate-400">
                      {talker.packet_count.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Destination Ports Table */}
        <div className="lg:col-span-5 soc-glass rounded-xl overflow-hidden border border-blue-500/20">
          <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Top Ingress / Egress Ports
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Service Profiling</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-[#0E1726]/60">
                  <th className="py-3 px-4">Port / Service</th>
                  <th className="py-3 px-4">Flow Count</th>
                  <th className="py-3 px-4 text-right">Data Volume</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium font-mono">
                {(analytics?.top_destination_ports || []).map((p, idx) => (
                  <tr key={idx} className="hover:bg-[#162338]/50 transition-colors">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-cyan-400">:{p.port}</span>
                        <span className="text-[10px] text-slate-400 font-sans font-medium">({p.service})</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {p.count.toLocaleString()} flows
                    </td>
                    <td className="py-3 px-4 text-right text-slate-200">
                      {(p.bytes / (1024 * 1024)).toFixed(2)} MB
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
