"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Crosshair,
  Search,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Plus,
  Flame,
  Filter,
  RefreshCw,
  Terminal,
  Activity,
  Layers,
  FileText,
} from "lucide-react";
import { apiThreatHunting } from "@/lib/api-client";
import type {
  ThreatHuntingCase,
  ThreatHuntingFinding,
  ThreatHuntingDashboardStats,
} from "@/types/threat-hunting";

export default function ThreatHuntingOverviewPage() {
  const [stats, setStats] = useState<ThreatHuntingDashboardStats | null>(null);
  const [cases, setCases] = useState<ThreatHuntingCase[]>([]);
  const [findings, setFindings] = useState<ThreatHuntingFinding[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsRes, casesRes, findingsRes] = await Promise.all([
        apiThreatHunting.getStats(),
        apiThreatHunting.listCases(),
        apiThreatHunting.listFindings(),
      ]);
      if (statsRes.data) setStats(statsRes.data);
      if (casesRes.data) setCases(casesRes.data);
      if (findingsRes.data) setFindings(findingsRes.data);
    } catch (err) {
      console.error("Failed to load threat hunting data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Active":
      case "Investigating":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "Suspicious Activity Found":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse";
      case "Escalated":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Completed":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-slate-700/30 text-slate-300 border-slate-700/50";
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-lg shadow-cyan-500/5">
              <Crosshair className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Advanced Threat Hunting Center</h1>
              <p className="text-sm text-slate-400">
                Proactive hypothesis-driven telemetry interrogation, adversary behavior correlation & IOC discovery
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60 transition text-sm font-medium"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            href="/threat-hunting/search"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-cyan-300 border border-cyan-500/30 transition text-sm font-medium"
          >
            <Search className="h-4 w-4" />
            Query Engine
          </Link>
          <Link
            href="/threat-hunting/cases?create=true"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            New Investigation
          </Link>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Total Hunting Cases</span>
            <Crosshair className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">{stats?.total_cases ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Multi-tenant hypothesis investigations</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Active Interrogations</span>
            <Activity className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{stats?.active_investigations ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Under active analyst evaluation</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Suspicious Activity</span>
            <Flame className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{stats?.suspicious_found ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Adversary signals detected</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Confirmed Threats</span>
            <ShieldAlert className="h-4 w-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-orange-400">{stats?.confirmed_threats ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Facts isolated from hypotheses</p>
        </div>
      </div>

      {/* Quick Launchpad Navigation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/threat-hunting/search"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-cyan-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 group-hover:bg-cyan-500/20 transition">
                <Terminal className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-cyan-300 transition">
                  Structured Query Engine
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Filter network flows, ports, protocols & raw telemetry</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>

        <Link
          href="/threat-hunting/ioc-investigation"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-emerald-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 group-hover:bg-emerald-500/20 transition">
                <Search className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-emerald-300 transition">
                  IOC Deep Investigation
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Search IPv4, IPv6, Domains, URLs, Hashes & Feeds</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>

        <Link
          href="/forensics"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-purple-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 group-hover:bg-purple-500/20 transition">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-purple-300 transition">
                  Digital Forensics Vault
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Chain of custody, static log AST & forensic reports</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>
      </div>

      {/* Main Grid: Active Cases & Latest Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Cases (2 Cols) */}
        <div className="lg:col-span-2 bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Hunting Cases</h2>
              <p className="text-xs text-slate-400">Targeted hypothesis investigations and scope parameters</p>
            </div>
            <Link
              href="/threat-hunting/cases"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition"
            >
              View All Cases
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="space-y-3">
            {cases.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-sm">No threat hunting cases registered yet.</div>
            ) : (
              cases.slice(0, 4).map((c) => (
                <Link
                  key={c.id}
                  href={`/threat-hunting/cases/${c.id}`}
                  className="block p-4 rounded-lg bg-slate-800/40 hover:bg-slate-800/70 border border-slate-700/50 hover:border-cyan-500/30 transition group"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-cyan-400 font-bold">{c.case_number}</span>
                        <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${getStatusBadge(c.status)}`}>
                          {c.status}
                        </span>
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-300 font-semibold">
                          {c.priority}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200 group-hover:text-cyan-300 transition">
                        {c.title}
                      </h4>
                      <p className="text-xs text-slate-400 line-clamp-1">{c.objective}</p>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="text-xs text-slate-400 flex items-center justify-end gap-1">
                        <Clock className="h-3.5 w-3.5" />
                        {new Date(c.created_at).toLocaleDateString()}
                      </div>
                      <span className="text-xs text-slate-500 mt-1 inline-block">
                        {c.findings_count} findings
                      </span>
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Latest Findings (1 Col) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Discovered Findings</h2>
              <p className="text-xs text-slate-400">Confirmed indicators & behavioral anomalies</p>
            </div>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
              {findings.length}
            </span>
          </div>

          <div className="space-y-3">
            {findings.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-sm">No findings documented yet.</div>
            ) : (
              findings.slice(0, 4).map((f) => (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg bg-slate-800/30 border border-slate-800 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase tracking-wider font-semibold ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                    {f.is_confirmed ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> Confirmed Fact
                      </span>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">
                        Analyst Hypothesis
                      </span>
                    )}
                  </div>
                  <h5 className="text-xs font-semibold text-slate-200">{f.title}</h5>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{f.evidence_summary}</p>
                  {f.mitre_technique_id && (
                    <div className="pt-1 flex items-center gap-1.5">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                        {f.mitre_technique_id}
                      </span>
                      <span className="text-[11px] text-slate-500">{f.mitre_tactic_name}</span>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
