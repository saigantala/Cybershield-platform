"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Layers,
  Award,
  CheckCircle2,
  Clock,
  ExternalLink,
  ArrowRight,
  Shield,
  FileText,
  Building2,
  Lock,
} from "lucide-react";
import { apiCompliance } from "@/lib/api-client";
import type { ComplianceFramework } from "@/types/compliance";

export default function ComplianceFrameworksPage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFw = async () => {
      setLoading(true);
      const res = await apiCompliance.getFrameworks();
      if (res.data && res.data.length > 0) {
        setFrameworks(res.data);
      } else {
        setFrameworks([
          {
            id: "80000000-0000-0000-0000-000000000001",
            framework_code: "NIST_CSF_2_0",
            name: "NIST Cybersecurity Framework",
            version: "2.0",
            description: "National Institute of Standards and Technology Framework for Improving Critical Infrastructure Cybersecurity across Identify, Protect, Detect, Respond, and Recover.",
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
            description: "Center for Internet Security prioritized safeguards defining prescriptive, actionable steps to stop modern ransomware and breach tactics.",
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
            description: "Authoritative awareness guide documenting consensus on the top 10 most critical web and API security vulnerabilities.",
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
            description: "International standard specifying the requirements for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS).",
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
    fetchFw();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/compliance" className="hover:text-cyan-400 transition-colors">
              Compliance
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Frameworks</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Layers className="h-6 w-6 text-cyan-400" />
            Security & Regulatory Frameworks Catalog
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Pre-mapped standard cybersecurity frameworks with verified control IDs and domain categorizations.
          </p>
        </div>

        <Link
          href="/compliance/assessments"
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-1.5 transition-all self-start md:self-auto"
        >
          View All Control Assessments
        </Link>
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {frameworks.map((fw) => (
          <div
            key={fw.id}
            className="p-6 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-4 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="px-2.5 py-1 rounded-md text-xs font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                  {fw.framework_code}
                </span>
                <span className="text-xs text-slate-400 font-mono">Version {fw.version}</span>
              </div>

              <div>
                <h3 className="text-base font-bold text-white">{fw.name}</h3>
                <div className="text-xs text-slate-500 mt-0.5 font-medium">{fw.category}</div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed min-h-[48px]">
                {fw.description}
              </p>

              {/* Progress Summary */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Implementation Completion</span>
                  <span className="text-white font-mono font-bold">
                    {fw.completion_percentage}%
                  </span>
                </div>
                <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-500"
                    style={{ width: `${fw.completion_percentage}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                  <span>{fw.implemented_controls} Implemented</span>
                  <span>{fw.partially_implemented} Partial</span>
                  <span>{fw.not_assessed} Unassessed</span>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-xs text-slate-500 font-mono">
                {fw.total_controls} Verified Controls
              </span>
              <Link
                href={`/compliance/assessments?framework=${fw.framework_code}`}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
              >
                Assess Controls <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
