"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  BarChart3,
  TrendingUp,
  Shield,
  Activity,
  AlertTriangle,
  Clock,
  Download,
  Calendar,
  RefreshCw,
  Server,
  Bug,
  ShieldAlert,
  Flame,
  Radio,
  CheckCircle2,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  OverviewAnalytics,
  AssetAnalytics,
  VulnerabilityAnalytics,
  AlertAnalytics,
  IncidentAnalytics,
  ThreatIntelAnalytics,
} from "@/types/analytics";
import { apiAnalytics } from "@/lib/api-client";

const COLORS = ["#3B82F6", "#06B6D4", "#F59E0B", "#EF4444", "#10B981", "#8B5CF6"];

export default function AnalyticsDashboardPage() {
  const [dateRange, setDateRange] = useState<"7d" | "30d" | "90d">("30d");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Analytics states
  const [overview, setOverview] = useState<OverviewAnalytics | null>(null);
  const [assetData, setAssetData] = useState<AssetAnalytics | null>(null);
  const [vulnData, setVulnData] = useState<VulnerabilityAnalytics | null>(null);
  const [alertData, setAlertData] = useState<AlertAnalytics | null>(null);
  const [incidentData, setIncidentData] = useState<IncidentAnalytics | null>(null);
  const [intelData, setIntelData] = useState<ThreatIntelAnalytics | null>(null);

  const fetchAnalytics = async () => {
    setLoading(true);
    setError(null);
    try {
      const [ovRes, astRes, vRes, alRes, incRes, tiRes] = await Promise.all([
        apiAnalytics.getOverview(),
        apiAnalytics.getAssets(),
        apiAnalytics.getVulnerabilities(),
        apiAnalytics.getAlerts(),
        apiAnalytics.getIncidents(),
        apiAnalytics.getThreatIntelligence(),
      ]);

      if (ovRes.data) setOverview(ovRes.data);
      if (astRes.data) setAssetData(astRes.data);
      if (vRes.data) setVulnData(vRes.data);
      if (alRes.data) setAlertData(alRes.data);
      if (incRes.data) setIncidentData(incRes.data);
      if (tiRes.data) setIntelData(tiRes.data);
    } catch (err: any) {
      setError(err?.message || "Failed to load security analytics telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [dateRange]);

  const handleExportCSV = () => {
    if (!overview) return;
    const rows = [
      ["Metric", "Value"],
      ["Security Posture Score", `${overview.posture_score}/100`],
      ["Posture Grade", overview.posture_grade],
      ["Total Assets", overview.total_assets],
      ["Active Assets", overview.active_assets],
      ["Total Vulnerabilities", overview.total_vulnerabilities],
      ["Critical Vulnerabilities", overview.critical_vulnerabilities],
      ["CISA KEV Count", overview.cisa_kev_vulnerabilities],
      ["Open Incidents", overview.open_incidents],
      ["Mean Time to Detect (min)", overview.mean_time_to_detect_minutes],
      ["Mean Time to Resolve (min)", overview.mean_time_to_resolve_minutes],
    ];
    const csvContent =
      "data:text/csv;charset=utf-8," + rows.map((e) => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cybershield-analytics-${dateRange}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <BarChart3 className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Analytics</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic posture modeling, alert velocity, vulnerability trends, and resolution telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Date Selector */}
          <div className="flex rounded-lg bg-[#111C2D] border border-slate-700/80 p-0.5 text-xs">
            {(["7d", "30d", "90d"] as const).map((r) => (
              <button
                key={r}
                onClick={() => setDateRange(r)}
                className={`px-3 py-1 rounded-md transition-all font-medium ${
                  dateRange === r
                    ? "bg-blue-600 text-white shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>

          <button
            onClick={fetchAnalytics}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/50 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>

          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg shadow-blue-500/20 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      {overview && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Posture Score
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-emerald-400 tracking-tight">
                {overview.posture_score}
              </span>
              <span className="text-xs text-slate-500">/ 100</span>
              <span className="ml-auto px-2 py-0.5 text-xs font-bold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Grade {overview.posture_grade}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-2">Enterprise risk tolerance aligned</p>
          </div>

          <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Critical Findings
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-rose-400 tracking-tight">
                {overview.critical_vulnerabilities}
              </span>
              <span className="text-xs text-rose-400/80">urgent</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-2">{overview.cisa_kev_vulnerabilities} in CISA KEV catalog</p>
          </div>

          <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Mean Time to Detect
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-cyan-400 font-mono tracking-tight">
                {overview.mean_time_to_detect_minutes}
              </span>
              <span className="text-xs text-slate-400">minutes</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-2">Target SLA: &lt; 15.0 min</p>
          </div>

          <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Mean Time to Resolve
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-purple-400 font-mono tracking-tight">
                {overview.mean_time_to_resolve_minutes}
              </span>
              <span className="text-xs text-slate-400">minutes</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-2">Automated correlation gate</p>
          </div>

          <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Active Incidents
            </span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-amber-400 tracking-tight">
                {overview.open_incidents}
              </span>
              <span className="text-xs text-amber-400/80">in triage</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-2">Under active SOC investigation</p>
          </div>
        </div>
      )}

      {/* Main Charts Row 1: Vulnerability Velocity & Device Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Velocity Trend */}
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">Vulnerability Velocity Trend</h3>
              <p className="text-xs text-slate-400">New vs. Resolved findings over time</p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
              TIME-SERIES
            </span>
          </div>

          <div className="h-64 w-full">
            {vulnData && vulnData.trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={vulnData.trend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="newColor" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="resColor" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                  <XAxis dataKey="date" stroke="#64748B" fontSize={10} />
                  <YAxis stroke="#64748B" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#080D18",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px" }} />
                  <Area
                    type="monotone"
                    dataKey="new"
                    name="Discovered"
                    stroke="#3B82F6"
                    fillOpacity={1}
                    fill="url(#newColor)"
                  />
                  <Area
                    type="monotone"
                    dataKey="resolved"
                    name="Remediated"
                    stroke="#10B981"
                    fillOpacity={1}
                    fill="url(#resColor)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Insufficient trend records for this window.
              </div>
            )}
          </div>
        </div>

        {/* Asset Device Distribution */}
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">Monitored Device Distribution</h3>
              <p className="text-xs text-slate-400">Classified endpoints by operational type</p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              INVENTORY
            </span>
          </div>

          <div className="h-64 w-full">
            {assetData && assetData.device_type_distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={assetData.device_type_distribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                  <XAxis dataKey="name" stroke="#64748B" fontSize={10} />
                  <YAxis stroke="#64748B" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#080D18",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" name="Devices" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No asset inventory discovered.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main Charts Row 2: Alert Source Breakdown & Highest Risk Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Sources & False Positive Rate */}
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">Alert Ingestion Channels</h3>
              <p className="text-xs text-slate-400">
                Source attribution • False-Positive Rate: <strong className="text-cyan-400">{alertData?.false_positive_rate || 0}%</strong>
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
              TELEMETRY
            </span>
          </div>

          <div className="h-64 w-full flex items-center justify-center">
            {alertData && alertData.source_distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={alertData.source_distribution}
                    dataKey="count"
                    nameKey="source"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={({ name, percent }: any) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    labelLine={false}
                  >
                    {alertData.source_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#080D18",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500">No alert telemetry captured.</div>
            )}
          </div>
        </div>

        {/* Highest Risk Assets Table */}
        <div className="bg-[#111C2D]/80 border border-slate-800/80 rounded-2xl p-5 backdrop-blur-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">Highest-Risk Assets</h3>
              <p className="text-xs text-slate-400">Endpoints presenting highest exposure priority</p>
            </div>
            <Link
              href="/assets"
              className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
            >
              View All &rarr;
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider">
                  <th className="pb-2.5">Asset Name</th>
                  <th className="pb-2.5">IP Address</th>
                  <th className="pb-2.5">Type</th>
                  <th className="pb-2.5 text-right">Risk Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assetData && assetData.highest_risk_assets.length > 0 ? (
                  assetData.highest_risk_assets.map((ast) => (
                    <tr key={ast.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 font-medium text-slate-200">{ast.name}</td>
                      <td className="py-2.5 font-mono text-slate-400">{ast.ip}</td>
                      <td className="py-2.5 text-slate-400">{ast.device_type}</td>
                      <td className="py-2.5 text-right">
                        <span
                          className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                            ast.risk_level === "Critical"
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          }`}
                        >
                          {ast.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-slate-500">
                      No assets found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
