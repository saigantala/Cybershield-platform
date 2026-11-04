"use client";

import Link from "next/link";
import {
  Server,
  Bug,
  AlertOctagon,
  ShieldCheck,
  Radar,
  ArrowRight,
  Shield,
  Download,
  Activity,
  Layers,
  Cpu,
  Radio,
  Flame,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  mockPostureMetrics,
  mockScanScopes,
  mockScans,
} from "@/lib/mockData";
import { getAssetSummaryStats } from "@/lib/assets/asset-service";
import { apiVulnerabilities, apiThreatIntel, apiAlerts, apiIncidents, apiResponseRequests } from "@/lib/api-client";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { PostureScoreCard } from "@/components/dashboard/PostureScoreCard";
import { VulnerabilityCharts } from "@/components/dashboard/VulnerabilityCharts";
import { RecentFindingsTable } from "@/components/dashboard/RecentFindingsTable";
import { RecentScansTable } from "@/components/dashboard/RecentScansTable";

export default function SecurityOverviewPage() {
  const activeScan = mockScans.find((s) => s.status === "running");

  const [assetStats, setAssetStats] = useState({
    total: 248,
    active: 186,
    critical: 8,
    unassessed: 14,
    isLiveDb: false,
  });

  const [vulnStats, setVulnStats] = useState({
    total: 42,
    critical: 8,
    kevCount: 4,
    isLiveDb: false,
  });

  const [threatIntelStats, setThreatIntelStats] = useState({
    totalIocs: 3,
    highConfidence: 2,
    activeAlerts: 2,
    isLiveDb: false,
  });

  const [incidentStats, setIncidentStats] = useState({
    total: 1,
    active: 1,
    pendingApprovals: 1,
    isLiveDb: false,
  });

  useEffect(() => {
    async function loadLiveStats() {
      try {
        const stats = await getAssetSummaryStats();
        if (stats.total > 0) {
          setAssetStats({
            total: stats.total,
            active: stats.active,
            critical: stats.critical,
            unassessed: stats.unassessed,
            isLiveDb: true,
          });
        }
      } catch (e) {
        // Fall back to sample values
      }

      try {
        const vRes = await apiVulnerabilities.getOverview();
        if (vRes.data && !vRes.error) {
          setVulnStats({
            total: vRes.data.total_findings,
            critical: vRes.data.critical_count,
            kevCount: vRes.data.kev_count,
            isLiveDb: true,
          });
        }
      } catch (e) {
        // Fall back to sample values
      }

      try {
        const [tRes, aRes] = await Promise.all([
          apiThreatIntel.getOverview(),
          apiAlerts.list({ status: "New" }),
        ]);

        if (tRes.data) {
          const totalIocs = tRes.data.total_indicators;
          const highConf = tRes.data.high_confidence_count;
          setThreatIntelStats((prev) => ({
            ...prev,
            totalIocs: totalIocs ?? prev.totalIocs,
            highConfidence: highConf ?? prev.highConfidence,
            isLiveDb: true,
          }));
        }

        if (aRes.data) {
          const alertTotal = aRes.data.total ?? aRes.data.items?.length;
          setThreatIntelStats((prev) => ({
            ...prev,
            activeAlerts: alertTotal ?? prev.activeAlerts,
            isLiveDb: true,
          }));
        }

        const [incRes, reqRes] = await Promise.all([
          apiIncidents.list({ page: 1, page_size: 10 }),
          apiResponseRequests.list(),
        ]);

        if (incRes.data) {
          const totalIncidents = incRes.data.total ?? incRes.data.items?.length ?? 1;
          const activeIncidents = incRes.data.items?.filter((i: any) => i.status !== "Closed" && i.status !== "Resolved").length ?? 1;
          setIncidentStats((prev) => ({
            ...prev,
            total: totalIncidents,
            active: activeIncidents,
            isLiveDb: true,
          }));
        }

        if (reqRes.data) {
          const pending = reqRes.data.filter((r: any) => r.status === "Pending").length;
          setIncidentStats((prev) => ({
            ...prev,
            pendingApprovals: pending,
            isLiveDb: true,
          }));
        }
      } catch (e) {
        // keep fallback
      }
    }
    loadLiveStats();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Threat Command Strip (Inspired by Querytel Sentinel & SentinelX reference images) */}
      <div className="soc-glass rounded-xl p-3 border border-blue-500/20 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
        <div className="flex items-center gap-2 border-r border-slate-800 pr-2">
          <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center font-mono font-bold text-emerald-400 text-xs">
            14
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              Global Cyber Risk
            </span>
            <span className="text-emerald-400 font-bold text-xs">LOW THREAT</span>
          </div>
        </div>

        <div className="flex items-center gap-2 border-r border-slate-800 pr-2">
          <div className="h-7 w-7 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center font-mono font-bold text-cyan-400 text-xs">
            MTTD
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              Mean Time to Detect
            </span>
            <span className="text-white font-mono font-bold">4.2 min</span>
          </div>
        </div>

        <div className="flex items-center gap-2 border-r border-slate-800 pr-2">
          <div className="h-7 w-7 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center font-mono font-bold text-purple-400 text-xs">
            MTTR
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              Mean Time to Resolve
            </span>
            <span className="text-white font-mono font-bold">6.8 min</span>
          </div>
        </div>

        <div className="flex items-center gap-2 border-r border-slate-800 pr-2">
          <div className="h-7 w-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center font-mono font-bold text-cyan-400 text-xs">
            <Radio className="h-3.5 w-3.5" />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              Kill Chain Defense
            </span>
            <span className="text-cyan-400 font-bold">NONE ACTIVE</span>
          </div>
        </div>

        <div className="flex items-center gap-2 border-r border-slate-800 pr-2">
          <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center font-mono font-bold text-emerald-400 text-xs">
            <ShieldCheck className="h-3.5 w-3.5" />
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              AI Shield
            </span>
            <span className="text-emerald-400 font-bold">L7 PROTECTED</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="h-7 w-7 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center font-mono font-bold text-amber-400 text-xs">
            DEF
          </div>
          <div>
            <span className="text-[10px] text-slate-400 block uppercase font-mono">
              Readiness State
            </span>
            <span className="text-amber-400 font-bold">DEFCON 4</span>
          </div>
        </div>
      </div>

      {/* Page Header (Exact prompt wording) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22D3EE]" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Security Operations Center
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-semibold uppercase">
              Live Real-Time
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Monitor your infrastructure and security posture.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/reports"
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#111C2D] border border-blue-500/30 text-xs font-semibold text-slate-200 hover:text-white hover:border-blue-500/60 transition-colors"
          >
            <Download className="h-3.5 w-3.5 text-cyan-400" />
            <span>Generate Report</span>
          </Link>

          <Link
            href="/scans"
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Radar className="h-3.5 w-3.5" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Top 5 Metric Cards (Exact Prompt Requirements) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Total Assets"
          value={assetStats.total}
          subtitle={assetStats.isLiveDb ? "Live Supabase Inventory" : "Monitored in inventory"}
          icon={Server}
          accentColor="blue"
          trend={{ value: assetStats.isLiveDb ? "Live DB Synced" : "+12% vs prior month", positive: true }}
        />

        <MetricCard
          title="Active Devices"
          value={assetStats.active}
          subtitle={assetStats.isLiveDb ? "Online endpoints" : "Online & heartbeat active"}
          icon={Activity}
          accentColor="cyan"
          trend={{ value: `${Math.round((assetStats.active / (assetStats.total || 1)) * 100)}% active`, positive: true }}
        />

        <MetricCard
          title="Vulnerabilities"
          value={vulnStats.total}
          subtitle={vulnStats.isLiveDb ? "Live Supabase Findings" : "Open finding catalog"}
          icon={Bug}
          accentColor="amber"
          trend={{ value: vulnStats.isLiveDb ? "Live DB Synced" : "-5% from last sweep", positive: true }}
        />

        <MetricCard
          title="Critical Findings"
          value={vulnStats.critical}
          subtitle={`${vulnStats.kevCount} in CISA KEV catalog`}
          icon={AlertOctagon}
          accentColor="rose"
          badge="Urgent"
          trend={{ value: vulnStats.isLiveDb ? "Real-time Telemetry" : "+2 new today", positive: false }}
        />

        <MetricCard
          title="Security Score"
          value="86/100"
          subtitle="Enterprise posture rating"
          icon={ShieldCheck}
          accentColor="emerald"
          badge="Grade A"
          trend={{ value: "+4% improvement", positive: true }}
        />
      </div>

      {/* Threat Intelligence & Active Correlation Alert Strip */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 shrink-0">
            <Radio className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">Threat Intelligence & Correlation Grid</span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                ACTIVE MONITORING
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Tracking <span className="text-white font-semibold font-mono">{threatIntelStats.totalIocs}</span> validated IOCs across external feeds with <span className="text-rose-400 font-semibold font-mono">{threatIntelStats.activeAlerts}</span> unhandled alerts.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Link
            href="/threat-intelligence"
            className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors"
          >
            Threat Intel
          </Link>
          <Link
            href="/security-monitoring"
            className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors"
          >
            Events Stream
          </Link>
          <Link
            href="/alerts"
            className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white shadow shadow-rose-600/30 transition-colors"
          >
            View Alerts ({threatIntelStats.activeAlerts})
          </Link>
        </div>
      </div>

      {/* Incident Response & Containment Workflow Strip */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">Incident Response & Containment</span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                ACTIVE DEFENSE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              <span className="text-white font-semibold font-mono">{incidentStats.total}</span> active incident investigations, with <span className="text-amber-400 font-semibold font-mono">{incidentStats.pendingApprovals}</span> response containment actions awaiting human approval.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Link
            href="/playbooks"
            className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors"
          >
            Playbooks
          </Link>
          <Link
            href="/response-requests"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-xs font-semibold text-amber-300 transition-colors"
          >
            <span>Approvals</span>
            {incidentStats.pendingApprovals > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950">
                {incidentStats.pendingApprovals}
              </span>
            )}
          </Link>
          <Link
            href="/incidents"
            className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-xs font-semibold text-white shadow shadow-blue-500/25 transition-all"
          >
            Incident Command
          </Link>
        </div>
      </div>

      {/* Part 3: Security Charts (Donut, Line, Bar) */}
      <VulnerabilityCharts />

      {/* Part 4 & 5: Recent Scan Activity & Recent Security Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentScansTable />
        <RecentFindingsTable />
      </div>
    </div>
  );
}
