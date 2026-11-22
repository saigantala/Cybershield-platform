"use client";

import { useEffect, useState } from "react";
import {
  Terminal,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Layers,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Server,
  Zap,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { SecurityTestRun, SecurityTestResult } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function ApiSecurityPage() {
  const defaultTargetHost =
    process.env.NEXT_PUBLIC_API_URL?.replace(/\/api\/v1\/?$/, "") ||
    "http://localhost:8000";
  const [targetHost, setTargetHost] = useState(defaultTargetHost);
  const [includeFuzzing, setIncludeFuzzing] = useState(true);
  const [testRuns, setTestRuns] = useState<SecurityTestRun[]>([]);
  const [latestRun, setLatestRun] = useState<SecurityTestRun | null>(null);
  const [running, setRunning] = useState(false);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);

  const loadTestRuns = async () => {
    try {
      const res = await apiSecurityAssurance.listTestRuns();
      if (res.data && res.data.length > 0) {
        setTestRuns(res.data);
        setLatestRun(res.data[0]);
      }
    } catch (err) {
      console.error("Failed to load test runs", err);
    }
  };

  useEffect(() => {
    loadTestRuns();
  }, []);

  const handleRunSuite = async () => {
    setRunning(true);
    try {
      const res = await apiSecurityAssurance.runApiSecuritySuite({
        target_host: targetHost,
        include_fuzzing: includeFuzzing,
      });
      if (res.data) {
        setLatestRun(res.data);
        await loadTestRuns();
      }
    } catch (err) {
      console.error("Failed to dispatch API security suite", err);
    } finally {
      setRunning(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedTestId(expandedTestId === id ? null : id);
  };

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Terminal className="w-7 h-7 text-emerald-400" />
              API Security Validation & Fuzzing Suite
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Automated tests for BOLA cross-tenant isolation, BFLA RBAC boundaries, JWT integrity, SQLi/Command injection defenses, and Zero Trust step-up.
            </p>
          </div>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {/* Target Host Configuration & Run Controller */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-5">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 flex-1">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                  Target Service Host
                </label>
                <input
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="flex items-center gap-3 pt-6">
                <input
                  type="checkbox"
                  id="fuzzingCheckbox"
                  checked={includeFuzzing}
                  onChange={(e) => setIncludeFuzzing(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-0"
                />
                <label htmlFor="fuzzingCheckbox" className="text-xs text-slate-300 cursor-pointer">
                  Include Input Sanitization & SQLi/Injection Fuzzing
                </label>
              </div>
            </div>

            <button
              onClick={handleRunSuite}
              disabled={running}
              className="flex items-center gap-2 px-5 py-2.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-950/40 transition-all disabled:opacity-50 whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {running ? "Executing 8 Target Probes..." : "Dispatch API Pentest Suite"}
            </button>
          </div>
        </div>

        {/* Latest Run Metric Highlights */}
        {latestRun && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Total Test Probes</span>
              <span className="text-2xl font-bold text-white">{latestRun.total_tests}</span>
            </div>
            <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Passed Probes</span>
              <span className="text-2xl font-bold text-emerald-400">{latestRun.passed_tests}</span>
            </div>
            <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Failed Probes</span>
              <span className="text-2xl font-bold text-rose-400">{latestRun.failed_tests}</span>
            </div>
            <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Total Execution Time</span>
              <span className="text-2xl font-bold text-cyan-400">{latestRun.duration_ms} ms</span>
            </div>
          </div>
        )}

        {/* Test Results Table */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">
              API Security Verification Matrix & Probe Log
            </span>
            <span className="text-[11px] text-slate-500">Live test executions with simulated & real assertions</span>
          </div>

          <div className="divide-y divide-slate-800/60">
            {latestRun?.results && latestRun.results.length > 0 ? (
              latestRun.results.map((result) => {
                const isExpanded = expandedTestId === result.id;
                return (
                  <div key={result.id} className="p-4 hover:bg-slate-800/20 transition-colors">
                    <div
                      className="flex items-center justify-between cursor-pointer"
                      onClick={() => toggleExpand(result.id)}
                    >
                      <div className="space-y-1 flex-1 pr-4">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            result.passed ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}>
                            {result.test_category}
                          </span>
                          <span className="text-xs font-semibold text-white">{result.test_name}</span>
                        </div>
                        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                          <span className="text-slate-300 font-bold">{result.http_method}</span>
                          <span>{result.endpoint}</span>
                          <span>•</span>
                          <span>Status: <span className="text-slate-200">{result.actual_status}</span> (expected {result.expected_status})</span>
                          <span>•</span>
                          <span className="text-slate-500">{result.execution_time_ms}ms</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span
                          className={`flex items-center gap-1 text-xs font-semibold ${
                            result.passed ? "text-emerald-400" : "text-rose-400"
                          }`}
                        >
                          {result.passed ? (
                            <>
                              <CheckCircle2 className="w-4 h-4" /> Passed
                            </>
                          ) : (
                            <>
                              <XCircle className="w-4 h-4" /> Failed
                            </>
                          )}
                        </span>
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-slate-400" />
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-slate-800/60 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                          <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                            Response Telemetry & Verification Summary
                          </span>
                          <p className="text-slate-300 font-mono text-[11px] leading-relaxed">
                            {result.response_summary}
                          </p>
                        </div>
                        <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                          <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                            Request Probe Payload
                          </span>
                          <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto">
                            {JSON.stringify(result.request_payload || {}, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs">
                No active API test runs found. Click "Dispatch API Pentest Suite" above to execute tests.
              </div>
            )}
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
