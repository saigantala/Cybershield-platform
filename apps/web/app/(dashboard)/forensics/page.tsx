"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  FileSearch,
  FolderArchive,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ArrowRight,
  Plus,
  RefreshCw,
  Activity,
  Layers,
  FileText,
  FileCode,
  HardDrive,
  Network,
} from "lucide-react";
import { apiForensics } from "@/lib/api-client";
import type {
  ForensicCase,
  ForensicEvidenceItem,
  ForensicsDashboardStats,
} from "@/types/forensics";

export default function ForensicsOverviewPage() {
  const [stats, setStats] = useState<ForensicsDashboardStats | null>(null);
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [evidenceList, setEvidenceList] = useState<ForensicEvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsRes, casesRes, evRes] = await Promise.all([
        apiForensics.getStats(),
        apiForensics.listCases(),
        apiForensics.listEvidence(),
      ]);
      if (statsRes.data) setStats(statsRes.data);
      if (casesRes.data) setCases(casesRes.data);
      if (evRes.data) setEvidenceList(evRes.data);
    } catch (err) {
      console.error("Failed to load forensics overview:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Evidence Collection":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "Analysis":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "Review":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "Completed":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 shadow-lg shadow-purple-500/5">
              <FileSearch className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Digital Forensics Center</h1>
              <p className="text-sm text-slate-400">
                Tamper-evident chain of custody, bit-stream artifact preservation, safe static AST analysis & forensic reporting
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
            href="/forensics/evidence"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/90 hover:bg-slate-700/90 text-purple-300 border border-purple-500/30 transition text-sm font-medium"
          >
            <FolderArchive className="h-4 w-4" />
            Evidence Vault
          </Link>
          <Link
            href="/forensics/cases?create=true"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-lg shadow-purple-500/20 text-sm font-medium transition"
          >
            <Plus className="h-4 w-4" />
            New Forensic Case
          </Link>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Forensic Cases</span>
            <FileSearch className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">{stats?.total_cases ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">{stats?.open_cases ?? 0} open or collecting</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">In Active Analysis</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">{stats?.in_analysis ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Safe static log & packet parsing</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Preserved Evidence</span>
            <HardDrive className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{stats?.total_evidence_items ?? 0}</div>
          <p className="text-xs text-slate-400 mt-1">Bitstream artifacts in vault</p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Chain Integrity</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">100% Intact</div>
          <p className="text-xs text-slate-400 mt-1">Cryptographic hash chains verified</p>
        </div>
      </div>

      {/* Quick Launchpad Navigation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/forensics/evidence"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-purple-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 group-hover:bg-purple-500/20 transition">
                <FolderArchive className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-purple-300 transition">
                  Evidence Vault & Custody Chain
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">SHA-256 blocks, immutable logs & verification</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>

        <Link
          href="/forensics/timeline"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-cyan-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 group-hover:bg-cyan-500/20 transition">
                <Clock className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-cyan-300 transition">
                  Multi-Source Timeline Analysis
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Reconstruct adversary steps across 8 security feeds</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>

        <Link
          href="/forensics/reports"
          className="group bg-slate-900/60 backdrop-blur-md border border-slate-800/80 hover:border-emerald-500/40 rounded-xl p-5 transition shadow-xl"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 group-hover:bg-emerald-500/20 transition">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100 group-hover:text-emerald-300 transition">
                  Formal Forensic Reports
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Standardized 14-section evidentiary deliverables</p>
              </div>
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-1 transition" />
          </div>
        </Link>
      </div>

      {/* Main Grid: Cases & Vault Items */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Forensic Cases (2 Cols) */}
        <div className="lg:col-span-2 bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Forensics Investigations</h2>
              <p className="text-xs text-slate-400">Formal cases with sequential IDs & assigned investigators</p>
            </div>
            <Link
              href="/forensics/cases"
              className="text-xs text-purple-400 hover:text-purple-300 font-medium flex items-center gap-1 transition"
            >
              View All Cases
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="space-y-3">
            {cases.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-sm">No forensic cases recorded yet.</div>
            ) : (
              cases.slice(0, 4).map((c) => (
                <Link
                  key={c.id}
                  href={`/forensics/cases/${c.id}`}
                  className="block p-4 rounded-lg bg-slate-800/40 hover:bg-slate-800/70 border border-slate-700/50 hover:border-purple-500/30 transition group"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-purple-400 font-bold">{c.case_number}</span>
                        <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${getStatusBadge(c.status)}`}>
                          {c.status}
                        </span>
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-300 font-semibold">
                          {c.priority}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200 group-hover:text-purple-300 transition">
                        {c.title}
                      </h4>
                      <p className="text-xs text-slate-400 line-clamp-1">{c.investigation_objective}</p>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="text-xs text-slate-400 flex items-center justify-end gap-1">
                        <Clock className="h-3.5 w-3.5" />
                        {new Date(c.created_at).toLocaleDateString()}
                      </div>
                      <span className="text-xs text-slate-500 mt-1 inline-block">
                        {c.evidence_count} evidence items
                      </span>
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Evidence Vault Preview (1 Col) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800/80 rounded-xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Preserved Artifacts</h2>
              <p className="text-xs text-slate-400">Verified cryptographic bitstreams</p>
            </div>
            <Link
              href="/forensics/evidence"
              className="text-xs text-purple-400 hover:text-purple-300 font-medium"
            >
              Vault
            </Link>
          </div>

          <div className="space-y-3">
            {evidenceList.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-sm">No evidence artifacts stored yet.</div>
            ) : (
              evidenceList.slice(0, 4).map((e) => (
                <div
                  key={e.id}
                  className="p-3.5 rounded-lg bg-slate-800/30 border border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] uppercase font-bold text-slate-400">
                      {e.category.replace("_", " ")}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3" /> {e.integrity_status}
                    </span>
                  </div>
                  <h5 className="text-xs font-semibold text-slate-200 truncate">{e.evidence_name}</h5>
                  <p className="text-[11px] font-mono text-purple-300/80 truncate">
                    SHA-256: {e.sha256_hash.slice(0, 16)}...
                  </p>
                  <span className="text-[10px] text-slate-500 block">
                    {(e.file_size / (1024 * 1024)).toFixed(2)} MB &bull; {e.original_filename}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
