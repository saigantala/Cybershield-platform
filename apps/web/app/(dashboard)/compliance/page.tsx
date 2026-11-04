"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Award,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ArrowRight,
  TrendingUp,
  FileText,
  ExternalLink,
  RefreshCw,
  FolderLock,
  ListCheck,
} from "lucide-react";
import { apiCompliance, apiAnalytics } from "@/lib/api-client";
import type { ComplianceFramework, ComplianceSummary } from "@/types/compliance";

export default function ComplianceOverviewPage() {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    const [sumRes, fwRes] = await Promise.all([
      apiAnalytics.getCompliance(),
      apiCompliance.getFrameworks(),
    ]);

    if (sumRes.data) {
      setSummary(sumRes.data);
    } else {
      // Mock fallback
      setSummary({
        organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
        overall_compliance_score: 68.5,
        total_controls: 17,
        implemented_count: 8,
        partially_implemented_count: 6,
        not_assessed_count: 3,
        not_applicable_count: 0,
        framework_breakdown: [],
        overdue_assessments_count: 1,
        recent_activity: [],
      });
    }

    if (fwRes.data && fwRes.data.length > 0) {
      setFrameworks(fwRes.data);
    } else {
      setFrameworks([
        {
          id: "80000000-0000-0000-0000-000000000001",
          framework_code: "NIST_CSF_2_0",
          name: "NIST Cybersecurity Framework",
          version: "2.0",
          description: "Federal and critical infrastructure risk management baseline",
          category: "Federal & Critical Infrastructure",
          total_controls: 5,
          implemented_controls: 3,
          partially_implemented: 1,
          not_assessed: 1,
          completion_percentage: 70.0,
        },
        {
          id: "80000000-0000-0000-0000-000000000002",
          framework_code: "CIS_CONTROLS_V8",
          name: "CIS Critical Security Controls",
          version: "v8",
          description: "Prioritized safeguards against widespread modern attack vectors",
          category: "Industry Best Practice",
          total_controls: 4,
          implemented_controls: 2,
          partially_implemented: 2,
          not_assessed: 0,
          completion_percentage: 75.0,
        },
        {
          id: "80000000-0000-0000-0000-000000000003",
          framework_code: "OWASP_TOP_10_2021",
          name: "OWASP Top 10 Application Security",
          version: "2021",
          description: "Broad consensus on the most critical web application vulnerabilities",
          category: "Application Security",
          total_controls: 4,
          implemented_controls: 2,
          partially_implemented: 1,
          not_assessed: 1,
          completion_percentage: 62.5,
        },
        {
          id: "80000000-0000-0000-0000-000000000004",
          framework_code: "ISO_27001_2022",
          name: "ISO/IEC 27001 Information Security",
          version: "2022",
          description: "Global ISMS management and technical control specification",
          category: "International Standard",
          total_controls: 4,
          implemented_controls: 1,
          partially_implemented: 2,
          not_assessed: 1,
          completion_percentage: 50.0,
        },
      ]);
    }

    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <span className="text-cyan-400 font-medium">Compliance Management</span>
            <span>/</span>
            <span>Governance Overview</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Award className="h-6 w-6 text-cyan-400" />
            Compliance Governance & Audit Readiness
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Map security telemetry and evidence against NIST CSF 2.0, CIS Controls v8, OWASP Top 10, and ISO/IEC 27001.
          </p>
        </div>

        {/* Sub-Navigation Links */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          <Link
            href="/compliance"
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5"
          >
            <ShieldCheck className="h-4 w-4" />
            Overview
          </Link>
          <Link
            href="/compliance/frameworks"
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <Layers className="h-4 w-4" />
            Frameworks
          </Link>
          <Link
            href="/compliance/assessments"
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <ListCheck className="h-4 w-4" />
            Assessments
          </Link>
          <Link
            href="/compliance/evidence"
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <FolderLock className="h-4 w-4" />
            Evidence Vault
          </Link>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Overall Compliance</span>
            <Award className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-black text-white font-mono">
            {summary?.overall_compliance_score || 68.5}%
          </div>
          <div className="text-[11px] text-cyan-400 font-medium">Weighted Implementation</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Implemented Controls</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-black text-white font-mono">
            {summary?.implemented_count || 8}
          </div>
          <div className="text-[11px] text-emerald-400 font-medium">Fully verified & audited</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Partially Implemented</span>
            <TrendingUp className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-3xl font-black text-white font-mono">
            {summary?.partially_implemented_count || 6}
          </div>
          <div className="text-[11px] text-amber-400 font-medium">Remediation in progress</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Unassessed Controls</span>
            <Layers className="h-4 w-4 text-slate-400" />
          </div>
          <div className="text-3xl font-black text-white font-mono">
            {summary?.not_assessed_count || 3}
          </div>
          <div className="text-[11px] text-slate-400 font-medium">Pending initial review</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Overdue Reviews</span>
            <Clock className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-3xl font-black text-white font-mono">
            {summary?.overdue_assessments_count || 0}
          </div>
          <div className="text-[11px] text-rose-400 font-medium">Review date elapsed</div>
        </div>
      </div>

      {/* Framework Completion Cards */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            Framework-Wise Implementation Progress
          </h2>
          <Link
            href="/compliance/frameworks"
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            Explore All Frameworks <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {frameworks.map((fw) => (
            <div
              key={fw.id}
              className="p-5 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-4 hover:border-cyan-500/30 transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                      {fw.version}
                    </span>
                    <h3 className="text-sm font-bold text-white">{fw.name}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                    {fw.description}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-lg font-black text-white font-mono">
                    {fw.completion_percentage}%
                  </div>
                  <div className="text-[10px] text-slate-400">Complete</div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="space-y-1.5">
                <div className="h-2 rounded-full bg-slate-800 overflow-hidden flex">
                  <div
                    className="h-full bg-emerald-400 transition-all duration-500"
                    style={{
                      width: `${(fw.implemented_controls / Math.max(fw.total_controls, 1)) * 100}%`,
                    }}
                    title={`${fw.implemented_controls} Implemented`}
                  />
                  <div
                    className="h-full bg-amber-400 transition-all duration-500"
                    style={{
                      width: `${(fw.partially_implemented / Math.max(fw.total_controls, 1)) * 100}%`,
                    }}
                    title={`${fw.partially_implemented} Partial`}
                  />
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1">
                  <span>{fw.implemented_controls} Implemented</span>
                  <span>{fw.partially_implemented} Partial</span>
                  <span>{fw.not_assessed} Unassessed</span>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                <span className="text-slate-500 font-mono">{fw.framework_code}</span>
                <Link
                  href={`/compliance/assessments?framework=${fw.framework_code}`}
                  className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
                >
                  View Controls <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Certification & Audit Disclaimer Notice */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start gap-3">
        <ShieldCheck className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 space-y-1">
          <div className="font-semibold text-white">Compliance Telemetry & Verification Notice</div>
          <p className="leading-relaxed">
            CyberShield compliance ratings reflect continuous telemetry correlation, control owner attestations, and cryptographic evidence hashes. These scores serve as internal audit readiness indicators and do not constitute formal third-party regulatory certification.
          </p>
        </div>
      </div>
    </div>
  );
}
