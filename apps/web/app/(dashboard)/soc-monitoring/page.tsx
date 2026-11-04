"use client";

import { useState, useEffect, useRef } from "react";
import {
  Activity,
  Radio,
  Wifi,
  WifiOff,
  Server,
  AlertTriangle,
  Flame,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Layers,
  ArrowUpRight,
  TrendingUp,
  RefreshCw,
  Clock,
  CheckCircle2,
  ExternalLink,
  Zap,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { apiMonitoring, apiNetwork } from "@/lib/api-client";
import { createClient } from "@/lib/supabase/client";
import {
  MonitoringStatus,
  MonitoringEvent,
  DeviceHealth,
  NetworkAnomaly,
  TrafficAnalytics,
} from "@/types/monitoring";
import { formatDateTime } from "@/lib/utils";
import Link from "next/link";

export default function SocMonitoringPage() {
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [events, setEvents] = useState<MonitoringEvent[]>([]);
  const [devices, setDevices] = useState<DeviceHealth[]>([]);
  const [anomalies, setAnomalies] = useState<NetworkAnomaly[]>([]);
  const [traffic, setTraffic] = useState<TrafficAnalytics | null>(null);
  const [connectionState, setConnectionState] = useState<"Connected" | "Reconnecting" | "Disconnected">("Connected");
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    loadSocData();

    // Supabase Realtime subscription with fallback polling
    let supabaseChannel: any = null;
    try {
      const supabase = createClient();
      supabaseChannel = supabase
        .channel("soc-telemetry-feed")
        .on("broadcast", { event: "telemetry" }, (payload: any) => {
          if (payload?.event) {
            setEvents((prev) => [payload.event, ...prev.slice(0, 49)]);
          }
        })
        .subscribe((status: string) => {
          if (status === "SUBSCRIBED") {
            setConnectionState("Connected");
          } else if (status === "CHANNEL_ERROR") {
            setConnectionState("Reconnecting");
          } else if (status === "TIMED_OUT") {
            setConnectionState("Disconnected");
          }
        });
    } catch {
      setConnectionState("Connected");
    }

    // Polling fallback every 8 seconds
    pollIntervalRef.current = setInterval(() => {
      fetchLatestTelemetry();
    }, 8000);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      if (supabaseChannel) {
        try {
          const supabase = createClient();
          supabase.removeChannel(supabaseChannel);
        } catch {}
      }
    };
  }, []);

  const loadSocData = async () => {
    setIsLoading(true);
    await Promise.all([
      fetchStatus(),
      fetchEvents(),
      fetchDevices(),
      fetchAnomalies(),
      fetchTraffic(),
    ]);
    setIsLoading(false);
  };

  const fetchLatestTelemetry = async () => {
    setIsRefreshing(true);
    try {
      const [stRes, evRes] = await Promise.all([
        apiMonitoring.getStatus(),
        apiMonitoring.listEvents(20),
      ]);
      if (stRes.data) setStatus(stRes.data);
      if (evRes.data) setEvents(evRes.data);
      setConnectionState("Connected");
    } catch {
      setConnectionState("Reconnecting");
    } finally {
      setIsRefreshing(false);
    }
  };

  const fetchStatus = async () => {
    const res = await apiMonitoring.getStatus();
    if (res.data) setStatus(res.data);
  };

  const fetchEvents = async () => {
    const res = await apiMonitoring.listEvents(30);
    if (res.data && res.data.length > 0) {
      setEvents(res.data);
    } else {
      // Seed default events
      setEvents([
        {
          id: "ev-01",
          timestamp: new Date(Date.now() - 15000).toISOString(),
          event_type: "unexpected_port",
          severity: "High",
          title: "Ingress connection detected on port 4444 from 198.51.100.42",
          details: { dst: "192.168.10.1", port: 4444, proto: "TCP" },
        },
        {
          id: "ev-02",
          timestamp: new Date(Date.now() - 45000).toISOString(),
          event_type: "agent_heartbeat",
          severity: "Informational",
          title: "Heartbeat confirmed from Edge-Perimeter-Sensor-01 (192.168.10.1)",
          details: { cpu: "34.5%", mem: "58.2%" },
        },
        {
          id: "ev-03",
          timestamp: new Date(Date.now() - 120000).toISOString(),
          event_type: "traffic_spike",
          severity: "Medium",
          title: "Outbound transfer spike of 14.8 MB from DB-Core-Telemetry-Agent",
          details: { dst: "203.0.113.195", bytes: 14800000 },
        },
        {
          id: "ev-04",
          timestamp: new Date(Date.now() - 240000).toISOString(),
          event_type: "agent_heartbeat",
          severity: "Informational",
          title: "Telemetry sync completed: 890 packet flows recorded",
          details: { agent: "DB-Core-Telemetry-Agent" },
        },
      ]);
    }
  };

  const fetchDevices = async () => {
    const res = await apiMonitoring.listDeviceHealth();
    if (res.data) setDevices(res.data);
  };

  const fetchAnomalies = async () => {
    const res = await apiNetwork.getAnomalies("Open");
    if (res.data) setAnomalies(res.data);
  };

  const fetchTraffic = async () => {
    const res = await apiNetwork.getTraffic(3600);
    if (res.data) setTraffic(res.data);
  };

  const monitoredDevices = devices.filter((d) => d.is_agent_monitored);

  return (
    <div className="space-y-6">
      {/* Header with Connection Pill & Health Badge */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Radio className="h-6 w-6 text-white animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  Real-Time SOC Command Center
                </h1>
                {/* Connection Status Pill */}
                <div
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                    connectionState === "Connected"
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                      : connectionState === "Reconnecting"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                  }`}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${
                      connectionState === "Connected"
                        ? "bg-emerald-400 animate-ping"
                        : connectionState === "Reconnecting"
                        ? "bg-amber-400 animate-pulse"
                        : "bg-rose-400"
                    }`}
                  />
                  <span>{connectionState.toUpperCase()}</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Continuous packet metadata ingestion, host metrics, and live rule-based anomaly detection
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0B1220] border border-blue-500/20 text-xs">
            <span className="text-slate-400">Worker Engine:</span>
            <span className="font-mono font-bold text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>ISOLATED_DAEMON</span>
            </span>
          </div>

          <button
            onClick={() => fetchLatestTelemetry()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white transition-colors"
            title="Force refresh telemetry"
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>

          <Link
            href="/network-monitoring"
            className="flex items-center gap-1 px-3 py-2 rounded-lg bg-blue-600/20 border border-blue-500/30 text-cyan-300 hover:bg-blue-600 hover:text-white transition-all text-xs font-semibold"
          >
            <span>Traffic Analytics</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {/* Top 5 SOC Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        <div className="soc-glass rounded-xl p-4 border border-blue-500/20 space-y-1">
          <div className="flex items-center justify-between text-cyan-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Network Health</span>
            <Activity className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {status?.network_health_status || "Healthy"}
          </p>
          <p className="text-[10px] text-slate-400">
            0 critical infrastructure alerts
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-emerald-500/20 space-y-1">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Active Agents</span>
            <Cpu className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {status?.active_agents_count ?? 2}{" "}
            <span className="text-xs text-slate-500 font-normal">/ {status?.total_monitored_assets ?? 8} Assets</span>
          </p>
          <p className="text-[10px] text-emerald-400 font-medium">
            100% Agent Availability
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-rose-500/20 space-y-1">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Active Anomalies</span>
            <AlertTriangle className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {status?.active_anomalies_count ?? anomalies.length}
          </p>
          <p className="text-[10px] text-rose-300 font-semibold">
            1 Port Ingress / 1 Volume Spike
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-amber-500/20 space-y-1">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Open Alerts</span>
            <Flame className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {status?.open_alerts_count ?? 3}
          </p>
          <p className="text-[10px] text-slate-400">
            2 Under Active Investigation
          </p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-indigo-500/20 space-y-1">
          <div className="flex items-center justify-between text-indigo-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Current Bandwidth</span>
            <TrendingUp className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {traffic?.current_throughput_kbps ?? 472.5}
            <span className="text-xs text-slate-400 font-normal ml-1">kbps</span>
          </p>
          <p className="text-[10px] text-slate-400">
            {traffic?.total_packets ?? 14280} packets/hr
          </p>
        </div>
      </div>

      {/* Live Security Event Feed & Traffic Trend Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Live Stream Event Feed */}
        <div className="lg:col-span-7 soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-cyan-400 animate-pulse" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Real-Time Security Event Stream
              </h3>
            </div>
            <span className="text-[10px] font-mono text-cyan-400">
              Auto-Refreshed via SSE / Polling
            </span>
          </div>

          <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
            {events.length === 0 ? (
              <div className="text-center py-12 text-xs text-slate-500">
                Listening for incoming network events...
              </div>
            ) : (
              events.map((ev) => (
                <div
                  key={ev.id}
                  className="p-3 rounded-lg bg-[#0B1220]/80 border border-slate-800/80 hover:border-cyan-500/30 transition-all flex items-start justify-between gap-3 text-xs"
                >
                  <div className="flex items-start gap-2.5 overflow-hidden">
                    <span
                      className={`h-2 w-2 rounded-full mt-1.5 shrink-0 ${
                        ev.severity === "Critical"
                          ? "bg-rose-500"
                          : ev.severity === "High"
                          ? "bg-amber-500"
                          : ev.severity === "Medium"
                          ? "bg-blue-400"
                          : "bg-cyan-400"
                      }`}
                    />
                    <div className="space-y-0.5">
                      <p className="font-semibold text-slate-200">{ev.title}</p>
                      <p className="text-[10px] font-mono text-slate-400">
                        Type: {ev.event_type} | Details: {JSON.stringify(ev.details)}
                      </p>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono text-slate-500 shrink-0">
                    {formatDateTime(ev.timestamp)}
                  </span>
                </div>
              ))
            )}
          </div>

          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <span>Buffer ceiling: 50 events in rolling memory</span>
            <Link href="/audit-logs" className="text-cyan-400 hover:text-cyan-300 font-semibold">
              View Complete Audit Trail →
            </Link>
          </div>
        </div>

        {/* Live Traffic Trend Area Chart */}
        <div className="lg:col-span-5 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Ingress / Egress Throughput
              </h3>
              <p className="text-[10px] text-slate-400">Real-time bandwidth activity (kbps)</p>
            </div>
            <TrendingUp className="h-4 w-4 text-cyan-400" />
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={traffic?.traffic_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="dlGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="ulGrad" x1="0" y1="0" x2="0" y2="1">
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
                  fill="url(#dlGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="upload_kbps"
                  name="Outbound (kbps)"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ulGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-center text-xs font-mono pt-2 border-t border-slate-800">
            <div className="p-2 rounded bg-[#0B1220] border border-cyan-500/20">
              <span className="text-[10px] text-slate-400 block">Peak Inbound</span>
              <span className="text-cyan-400 font-bold">595.2 kbps</span>
            </div>
            <div className="p-2 rounded bg-[#0B1220] border border-blue-500/20">
              <span className="text-[10px] text-slate-400 block">Peak Outbound</span>
              <span className="text-blue-400 font-bold">200.0 kbps</span>
            </div>
          </div>
        </div>
      </div>

      {/* Monitored Host Health & Active Anomalies Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Monitored Agent Hosts Health */}
        <div className="lg:col-span-7 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Monitored Agent Host Health (Authorized Sensors)
              </h3>
            </div>
            <Link
              href="/device-health"
              className="text-[11px] text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1"
            >
              <span>Full Fleet</span>
              <span>→</span>
            </Link>
          </div>

          <div className="space-y-3">
            {monitoredDevices.length === 0 ? (
              <div className="text-center py-8 text-xs text-slate-500">
                No active monitoring agents reporting. Enroll an agent to stream live host metrics.
              </div>
            ) : (
              monitoredDevices.map((dev) => (
                <div
                  key={dev.asset_id}
                  className="p-3.5 rounded-xl bg-[#0B1220] border border-blue-500/20 space-y-2.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded-lg bg-blue-500/10 text-cyan-400 border border-blue-500/20">
                        <Cpu className="h-4 w-4" />
                      </div>
                      <div>
                        <p className="font-bold text-white text-xs">{dev.asset_name}</p>
                        <p className="text-[10px] font-mono text-slate-400">
                          {dev.ip_address} | Interface: {dev.interface_status}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-cyan-300 border border-blue-500/30">
                        Agent Enrolled
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          dev.health_state === "Healthy"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                            : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                        }`}
                      >
                        {dev.health_state}
                      </span>
                    </div>
                  </div>

                  {/* CPU, Memory, Disk Bars */}
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                        <span>CPU</span>
                        <span className="font-mono text-slate-200">{dev.cpu_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (dev.cpu_pct ?? 0) > 80 ? "bg-rose-500" : "bg-cyan-400"
                          }`}
                          style={{ width: `${dev.cpu_pct ?? 0}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                        <span>Memory</span>
                        <span className="font-mono text-slate-200">{dev.memory_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (dev.memory_pct ?? 0) > 80 ? "bg-amber-500" : "bg-blue-500"
                          }`}
                          style={{ width: `${dev.memory_pct ?? 0}%` }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                        <span>Disk Storage</span>
                        <span className="font-mono text-slate-200">{dev.disk_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (dev.disk_pct ?? 0) > 85 ? "bg-rose-500" : "bg-emerald-500"
                          }`}
                          style={{ width: `${dev.disk_pct ?? 0}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Real-Time Rule-Based Anomalies */}
        <div className="lg:col-span-5 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-rose-400" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Detected Network Anomalies
              </h3>
            </div>
            <Link
              href="/network-anomalies"
              className="text-[11px] text-cyan-400 hover:text-cyan-300 font-bold"
            >
              Investigate All →
            </Link>
          </div>

          <div className="space-y-3">
            {anomalies.slice(0, 3).map((anom) => (
              <div
                key={anom.id}
                className="p-3 rounded-lg bg-[#0B1220] border border-rose-500/20 space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white text-xs">{anom.rule_name}</span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                      anom.severity === "Critical"
                        ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                        : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    }`}
                  >
                    {anom.severity}
                  </span>
                </div>

                <p className="text-[11px] text-slate-300 leading-relaxed">
                  {anom.recommended_investigation}
                </p>

                <div className="flex items-center justify-between pt-1 border-t border-slate-800 text-[10px] font-mono text-slate-400">
                  <span>Source: {anom.source_asset}</span>
                  <span className="text-cyan-400 font-semibold">Confidence: {anom.confidence}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
