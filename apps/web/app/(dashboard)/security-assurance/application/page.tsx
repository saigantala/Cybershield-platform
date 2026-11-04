"use client";

import { useEffect, useState } from "react";
import {
  Globe,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  Shield,
  Layers,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityAssessment, SecurityCheck } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function ApplicationAssurancePage() {
  const [assessments, setAssessments] = useState<SecurityAssessment[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null);
  const [checks, setChecks] = useState<SecurityCheck[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [selectedCheck, setSelectedCheck] = useState<SecurityCheck | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const loadAssessments = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.listAssessments();
      if (res.data && res.data.length > 0) {
        setAssessments(res.data);
        const appAssessment = res.data.find((a) => a.assessment_type === "application") || res.data[0];
        setSelectedAssessmentId(appAssessment.id);
        await loadChecks(appAssessment.id);
      }
    } catch (err) {
      console.error("Failed to load assessments", err);
    } finally {
      setLoading(false);
    }
  };

  const loadChecks = async (assId: string) => {
    try {
      const res = await apiSecurityAssurance.getAssessmentChecks(assId);
      if (res.data) setChecks(res.data);
    } catch (err) {
      console.error("Failed to load checks", err);
    }
  };

  useEffect(() => {
    loadAssessments();
  }, []);

  const handleRunAssessment = async () => {
    setRunning(true);
    try {
      const res = await apiSecurityAssurance.runAssessment({
        assessment_name: "Application OWASP Verification Run",
        assessment_type: "application",
        target_environment: "production",
      });
      if (res.data) {
        await loadAssessments();
      }
    } catch (err) {
      console.error("Failed to run assessment", err);
    } finally {
      setRunning(false);
    }
  };

  const filteredChecks = checks.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.check_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.owasp_category && c.owasp_category.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesStatus = statusFilter === "all" || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Globe className="w-7 h-7 text-cyan-400" />
              Application Security & OWASP Top 10 / ASVS Matrix
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Deterministic verification against OWASP Top 10:2021 and OWASP ASVS 4.0 standard controls.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRunAssessment}
              disabled={running}
              className="flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950/40 transition-all disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {running ? "Evaluating OWASP Checks..." : "Run Application Assessment"}
            </button>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {/* Filters & Search */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search checks, codes, OWASP categories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Statuses</option>
              <option value="pass">Passed</option>
              <option value="fail">Failed</option>
              <option value="warn">Warning</option>
            </select>
          </div>
        </div>

        {/* Checks Table & Drawer Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Active Verification Rules ({filteredChecks.length})
              </span>
              <span className="text-[11px] text-slate-500">Click a check to inspect evidence</span>
            </div>
            <div className="divide-y divide-slate-800/60 max-h-[600px] overflow-y-auto">
              {filteredChecks.map((check) => (
                <div
                  key={check.id}
                  onClick={() => setSelectedCheck(check)}
                  className={`p-3.5 flex items-start justify-between cursor-pointer transition-colors ${
                    selectedCheck?.id === check.id ? "bg-slate-800/60 border-l-2 border-cyan-400" : "hover:bg-slate-800/20"
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-cyan-400 font-semibold">{check.check_code}</span>
                      <span className="text-xs font-medium text-white">{check.name}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-2">
                      <span>{check.owasp_category || check.category}</span>
                      <span>•</span>
                      <span className="text-slate-300">{check.target_component}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        check.status === "pass"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : check.status === "warn"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                      }`}
                    >
                      {check.status}
                    </span>
                    <ChevronRight className="w-4 h-4 text-slate-600" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence Details Drawer */}
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
            {selectedCheck ? (
              <div className="space-y-4">
                <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block">
                      {selectedCheck.check_code}
                    </span>
                    <h3 className="text-sm font-semibold text-white mt-0.5">{selectedCheck.name}</h3>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                      selectedCheck.status === "pass"
                        ? "bg-emerald-500/10 text-emerald-400"
                        : "bg-rose-500/10 text-rose-400"
                    }`}
                  >
                    {selectedCheck.status}
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-slate-400 block mb-1">Description</span>
                    <p className="text-slate-300 leading-relaxed">{selectedCheck.description}</p>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Target Component</span>
                    <span className="text-slate-200 font-medium">{selectedCheck.target_component}</span>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">OWASP Mapping</span>
                    <span className="text-cyan-300 font-mono">{selectedCheck.owasp_category || "N/A"}</span>
                  </div>

                  {selectedCheck.remediation && (
                    <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                      <span className="text-emerald-400 font-semibold block mb-1">Remediation Guidance</span>
                      <p className="text-slate-300">{selectedCheck.remediation}</p>
                    </div>
                  )}

                  {selectedCheck.evidence_data && (
                    <div>
                      <span className="text-slate-400 block mb-1">Raw Telemetry & Evidence</span>
                      <pre className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                        {JSON.stringify(selectedCheck.evidence_data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500">
                <Shield className="w-10 h-10 mb-2 stroke-1" />
                <p className="text-xs">Select any verification check to inspect test evidence and remediation recommendations.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
