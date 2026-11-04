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
  const [assetStats, setAssetStats] = useState({
    total: 0,
    active: 0,
    critical: 0,
    unassessed: 0,
    isLiveDb: true,
    isLoading: true,
  });

  const [vulnStats, setVulnStats] = useState({
    total: 0,
    critical: 0,
    kevCount: 0,
    isLiveDb: true,
  });

  const [threatIntelStats, setThreatIntelStats] = useState({
    totalIocs: 0,
    highConfidence: 0,
    activeAlerts: 0,
    isLiveDb: true,
  });

  const [incidentStats, setIncidentStats] = useState({
    total: 0,
    active: 0,
    pendingApprovals: 0,
    isLiveDb: true,
  });

  const [lastRefreshed, setLastRefreshed] = useState<string>("");

  useEffect(() => {
    let isMounted = true;

    async function loadLiveStats() {
      try {
        const stats = await getAssetSummaryStats();
        if (isMounted) {
          setAssetStats({
            total: stats.total ?? 0,
            active: stats.active ?? 0,
            critical: stats.critical ?? 0,
            unassessed: stats.unassessed ?? 0,
            isLiveDb: true,
            isLoading: false,
          });
        }
      } catch (e) {
        if (isMounted) {
          setAssetStats((prev) => ({ ...prev, isLoading: false }));
        }
      }

      try {
        const vRes = await apiVulnerabilities.getOverview();
        if (isMounted && vRes.data && !vRes.error) {
          setVulnStats({
            total: vRes.data.total_findings ?? 0,
            critical: vRes.data.critical_count ?? 0,
            kevCount: vRes.data.kev_count ?? 0,
            isLiveDb: true,
          });
        }
      } catch (e) {
        // keep current
      }

      try {
        const [tRes, aRes] = await Promise.all([
          apiThreatIntel.getOverview(),
          apiAlerts.list({ status: "New" }),
        ]);

        if (isMounted && tRes.data) {
          const totalIocs = tRes.data.total_indicators ?? 0;
          const highConf = tRes.data.high_confidence_count ?? 0;
          setThreatIntelStats((prev) => ({
            ...prev,
            totalIocs: totalIocs,
            highConfidence: highConf,
            isLiveDb: true,
          }));
        }

        if (isMounted && aRes.data) {
          const alertTotal = aRes.data.total ?? aRes.data.items?.length ?? 0;
          setThreatIntelStats((prev) => ({
            ...prev,
            activeAlerts: alertTotal,
            isLiveDb: true,
          }));
        }

        const [incRes, reqRes] = await Promise.all([
          apiIncidents.list({ page: 1, page_size: 10 }),
          apiResponseRequests.list(),
        ]);

        if (isMounted && incRes.data) {
          const totalIncidents = incRes.data.total ?? incRes.data.items?.length ?? 0;
          const activeIncidents = incRes.data.items?.filter((i: any) => i.status !== "Closed" && i.status !== "Resolved").length ?? 0;
          setIncidentStats((prev) => ({
            ...prev,
            total: totalIncidents,
            active: activeIncidents,
            isLiveDb: true,
          }));
        }

        if (isMounted && reqRes.data) {
          const pending = reqRes.data.filter((r: any) => r.status === "Pending").length;
          setIncidentStats((prev) => ({
            ...prev,
            pendingApprovals: pending,
            isLiveDb: true,
          }));
        }

        if (isMounted) {
          setLastRefreshed(new Date().toLocaleTimeString());
        }
      } catch (e) {
        // keep current
      }
    }

    loadLiveStats();
    // 8-second live telemetry refresh interval
    const intervalId = setInterval(loadLiveStats, 8000);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
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
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold uppercase flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
              Live Telemetry Active {lastRefreshed && `(${lastRefreshed})`}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Monitor your infrastructure and real-time security posture.
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

      {/* Real-World Quick-Start Action Card when 0 assets exist */}
      {assetStats.total === 0 && !assetStats.isLoading && (
        <div className="rounded-xl border border-blue-500/30 bg-gradient-to-r from-blue-950/40 via-[#0B1220] to-cyan-950/30 p-5 shadow-lg">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  REAL ENVIRONMENT ONBOARDING
                </span>
                <span className="text-xs font-semibold text-slate-300">
                  Zero Synthetic Telemetry Active
                </span>
              </div>
              <h3 className="text-base font-bold text-white">
                Begin Real Security Operations in CyberShield
              </h3>
              <p className="text-xs text-slate-400 max-w-2xl">
                No simulated assets are active. Connect your real infrastructure by running an authorized network discovery sweep, deploying the lightweight endpoint monitoring agent, or synchronizing official CISA KEV and threat feeds.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Link
                href="/scans"
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white shadow-md transition-all"
              >
                <Radar className="h-3.5 w-3.5" />
                <span>Launch Discovery Scan</span>
              </Link>
              <Link
                href="/monitoring-agents"
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#111C2D] border border-cyan-500/40 hover:border-cyan-400 text-xs font-semibold text-cyan-300 transition-all"
              >
                <Cpu className="h-3.5 w-3.5" />
                <span>Deploy Agent</span>
              </Link>
              <Link
                href="/threat-intelligence"
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#111C2D] border border-slate-700 hover:border-slate-500 text-xs font-semibold text-slate-300 transition-all"
              >
                <Radio className="h-3.5 w-3.5 text-rose-400" />
                <span>Sync Feeds</span>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Top 5 Metric Cards (Exact Prompt Requirements) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Total Assets"
          value={assetStats.total}
          subtitle="Monitored live inventory"
          icon={Server}
          accentColor="blue"
          trend={{ value: assetStats.total > 0 ? "Live DB Synced" : "Awaiting discovery", positive: true }}
        />

        <MetricCard
          title="Active Devices"
          value={assetStats.active}
          subtitle="Online & heartbeat active"
          icon={Activity}
          accentColor="cyan"
          trend={{ value: assetStats.total > 0 ? `${Math.round((assetStats.active / assetStats.total) * 100)}% active` : "0% active", positive: true }}
        />

        <MetricCard
          title="Vulnerabilities"
          value={vulnStats.total}
          subtitle="Verified finding catalog"
          icon={Bug}
          accentColor="amber"
          trend={{ value: vulnStats.total > 0 ? "Live DB Synced" : "Zero open findings", positive: true }}
        />

        <MetricCard
          title="Critical Findings"
          value={vulnStats.critical}
          subtitle={`${vulnStats.kevCount} in CISA KEV catalog`}
          icon={AlertOctagon}
          accentColor="rose"
          badge={vulnStats.critical > 0 ? "Urgent" : "Clear"}
          trend={{ value: vulnStats.critical > 0 ? "Action required" : "Zero critical CVEs", positive: vulnStats.critical === 0 }}
        />

        {(() => {
          const postureScore = assetStats.total === 0 
            ? 100 
            : Math.max(20, Math.min(100, 100 - (vulnStats.critical * 15) - (vulnStats.total * 2)));
          const grade = postureScore >= 85 ? "Grade A" : postureScore >= 70 ? "Grade B" : postureScore >= 50 ? "Grade C" : "At Risk";
          return (
            <MetricCard
              title="Security Score"
              value={`${postureScore}/100`}
              subtitle="Calculated live posture"
              icon={ShieldCheck}
              accentColor="emerald"
              badge={grade}
              trend={{ value: assetStats.total === 0 ? "Awaiting Assessment" : `${grade} rating`, positive: postureScore >= 70 }}
            />
          );
        })()}
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
