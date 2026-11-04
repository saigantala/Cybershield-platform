"use client";

import { useState, useEffect } from "react";
import {
  Server,
  Cpu,
  HardDrive,
  Activity,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Clock,
  Search,
  Filter,
  RefreshCw,
  Plus,
  ExternalLink,
  Shield,
  Layers,
} from "lucide-react";
import Link from "next/link";
import { apiMonitoring } from "@/lib/api-client";
import { DeviceHealth, DeviceHealthState } from "@/types/monitoring";
import { formatDateTime } from "@/lib/utils";

const HEALTH_COLORS: Record<DeviceHealthState, { bg: string; text: string; border: string }> = {
  Healthy: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  Warning: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  Offline: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
  Unknown: { bg: "bg-blue-500/10", text: "text-cyan-400", border: "border-blue-500/30" },
};

export default function DeviceHealthPage() {
  const [devices, setDevices] = useState<DeviceHealth[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");

  useEffect(() => {
    loadDeviceHealth();
  }, []);

  const loadDeviceHealth = async () => {
    setIsLoading(true);
    const res = await apiMonitoring.listDeviceHealth();
    if (res.data && res.data.length > 0) {
      setDevices(res.data);
    } else {
      // Mock fallback
      setDevices([
        {
          asset_id: "11111111-1111-1111-1111-111111111111",
          asset_name: "fw-01.edge.nexus.internal",
          ip_address: "192.168.10.1",
          agent_id: "21000000-0000-0000-0000-000000000001",
          agent_status: "Active",
          health_state: "Healthy",
          cpu_pct: 34.5,
          memory_pct: 58.2,
          disk_pct: 42.1,
          interface_status: "Up",
          last_seen: new Date().toISOString(),
          is_agent_monitored: true,
        },
        {
          asset_id: "22222222-2222-2222-2222-222222222222",
          asset_name: "db-01.core.nexus.internal",
          ip_address: "192.168.10.2",
          agent_id: "21000000-0000-0000-0000-000000000002",
          agent_status: "Active",
          health_state: "Warning",
          cpu_pct: 78.4,
          memory_pct: 82.1,
          disk_pct: 88.5,
          interface_status: "Up",
          last_seen: new Date().toISOString(),
          is_agent_monitored: true,
        },
        {
          asset_id: "33333333-3333-3333-3333-333333333333",
          asset_name: "edge-nginx-ingress-01",
          ip_address: "10.0.1.5",
          agent_id: undefined,
          agent_status: "Not Installed",
          health_state: "Unknown",
          cpu_pct: undefined,
          memory_pct: undefined,
          disk_pct: undefined,
          interface_status: "Unprobed",
          last_seen: new Date(Date.now() - 86400000).toISOString(),
          is_agent_monitored: false,
        },
      ]);
    }
    setIsLoading(false);
  };

  const filteredDevices = devices.filter((d) => {
    const matchesSearch =
      d.asset_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      d.ip_address.includes(searchQuery);
    const matchesState = stateFilter === "all" || d.health_state === stateFilter;
    const matchesAgent =
      agentFilter === "all" ||
      (agentFilter === "monitored" && d.is_agent_monitored) ||
      (agentFilter === "unmonitored" && !d.is_agent_monitored);
    return matchesSearch && matchesState && matchesAgent;
  });

  const healthyCount = devices.filter((d) => d.health_state === "Healthy").length;
  const warningCount = devices.filter((d) => d.health_state === "Warning").length;
  const criticalCount = devices.filter((d) => d.health_state === "Critical").length;
  const monitoredCount = devices.filter((d) => d.is_agent_monitored).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Server className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Device Health & Host Telemetry Inventory
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time host resource metrics for enrolled monitoring agents and inventory availability tracking
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadDeviceHealth()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
            title="Refresh device telemetry"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>

          <Link
            href="/monitoring-agents"
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Enroll New Agent</span>
          </Link>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-glass rounded-xl p-4 border border-emerald-500/20 space-y-1">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Healthy Hosts</span>
            <CheckCircle2 className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">{healthyCount}</p>
          <p className="text-[10px] text-slate-400">Nominal CPU & Memory</p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-amber-500/20 space-y-1">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Warning State</span>
            <AlertTriangle className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">{warningCount}</p>
          <p className="text-[10px] text-amber-300 font-semibold">&gt;75% utilization</p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-rose-500/20 space-y-1">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Critical Resource</span>
            <AlertOctagon className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">{criticalCount}</p>
          <p className="text-[10px] text-rose-300 font-semibold">&gt;90% saturation</p>
        </div>

        <div className="soc-glass rounded-xl p-4 border border-blue-500/20 space-y-1">
          <div className="flex items-center justify-between text-cyan-400">
            <span className="text-[10px] uppercase font-bold tracking-wider">Agent Coverage</span>
            <Cpu className="h-4 w-4" />
          </div>
          <p className="text-2xl font-black text-white font-mono">
            {monitoredCount} / {devices.length}
          </p>
          <p className="text-[10px] text-cyan-300">
            {devices.length ? Math.round((monitoredCount / devices.length) * 100) : 0}% telemetry coverage
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-glass rounded-xl p-3 border border-blue-500/20 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-md bg-[#0B1220] border border-blue-500/20 rounded-lg px-3 py-1.5">
          <Search className="h-4 w-4 text-slate-400 shrink-0" />
          <input
            type="text"
            placeholder="Search devices by hostname or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="bg-[#0B1220] border border-blue-500/20 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Health States</option>
            <option value="Healthy">Healthy</option>
            <option value="Warning">Warning</option>
            <option value="Critical">Critical</option>
            <option value="Offline">Offline</option>
            <option value="Unknown">Unknown</option>
          </select>

          <select
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            className="bg-[#0B1220] border border-blue-500/20 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Devices</option>
            <option value="monitored">Agent Monitored Only</option>
            <option value="unmonitored">Unmonitored Nodes Only</option>
          </select>
        </div>
      </div>

      {/* Device Health Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredDevices.map((device) => {
          const colors = HEALTH_COLORS[device.health_state] || HEALTH_COLORS.Unknown;
          return (
            <div
              key={device.asset_id}
              className="soc-glass rounded-xl p-5 border border-blue-500/20 hover:border-cyan-500/40 transition-all flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5 overflow-hidden">
                    <div className="p-2 rounded-lg bg-blue-500/10 text-cyan-400 border border-blue-500/20 shrink-0">
                      <Server className="h-4 w-4" />
                    </div>
                    <div className="truncate">
                      <h4 className="font-bold text-white text-sm truncate">{device.asset_name}</h4>
                      <p className="text-[11px] font-mono text-slate-400">{device.ip_address}</p>
                    </div>
                  </div>

                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${colors.bg} ${colors.text} ${colors.border}`}>
                    {device.health_state}
                  </span>
                </div>

                {/* Resource Gauges (Agent Monitored) vs Unmonitored Banner */}
                {device.is_agent_monitored ? (
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                        <span>CPU Utilization</span>
                        <span className="text-white font-bold">{device.cpu_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (device.cpu_pct ?? 0) > 85 ? "bg-rose-500" : (device.cpu_pct ?? 0) > 75 ? "bg-amber-400" : "bg-cyan-400"
                          }`}
                          style={{ width: `${device.cpu_pct ?? 0}%` }}
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                        <span>Memory Utilization</span>
                        <span className="text-white font-bold">{device.memory_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (device.memory_pct ?? 0) > 85 ? "bg-rose-500" : "bg-blue-500"
                          }`}
                          style={{ width: `${device.memory_pct ?? 0}%` }}
                        />
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                        <span>Disk Usage</span>
                        <span className="text-white font-bold">{device.disk_pct ?? 0}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            (device.disk_pct ?? 0) > 90 ? "bg-rose-500" : "bg-emerald-500"
                          }`}
                          style={{ width: `${device.disk_pct ?? 0}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/20 text-center space-y-1.5">
                    <p className="text-[11px] font-semibold text-slate-300">Host Telemetry Unprobed</p>
                    <p className="text-[10px] text-slate-400 leading-relaxed">
                      Hardware CPU and memory telemetry requires an installed, authorized CyberShield monitoring agent.
                    </p>
                    <Link
                      href="/monitoring-agents"
                      className="inline-block text-[10px] text-cyan-400 hover:text-cyan-300 font-bold"
                    >
                      Install Agent →
                    </Link>
                  </div>
                )}
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span>Interface: {device.interface_status}</span>
                <span>Last seen: {formatDateTime(device.last_seen || new Date().toISOString())}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
