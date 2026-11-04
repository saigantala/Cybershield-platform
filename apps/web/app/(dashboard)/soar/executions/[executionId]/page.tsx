"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  PlaySquare,
  Clock,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  ShieldAlert,
  ClipboardCheck,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Terminal,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { SOARExecutionDetail, SOARExecutionStepItem } from "@/types/soar";

export default function SOARExecutionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const executionId = params.executionId as string;

  const [detail, setDetail] = useState<SOARExecutionDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedStepId, setExpandedStepId] = useState<string | null>(null);

  const loadDetail = async () => {
    setLoading(true);
    try {
      const res = await apiSOAR.getExecution(executionId);
      if (res.data) {
        setDetail(res.data);
        if (res.data.steps.length > 0) {
          setExpandedStepId(res.data.steps[0].id);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (executionId) {
      loadDetail();
    }
  }, [executionId]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center text-slate-400">
        <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="p-8 text-center text-slate-400">
        Execution record not found.
        <div className="mt-4">
          <Link href="/soar/executions" className="text-cyan-400 hover:underline">
            Back to Execution Register
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div>
        <Link
          href="/soar/executions"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Execution Register
        </Link>

        <div className="mt-2 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <PlaySquare className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                  {detail.workflow_name}
                </h1>
                <span
                  className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                    detail.status === "Completed"
                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                      : detail.status === "Waiting_Approval"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      : detail.status === "Cancelled"
                      ? "bg-slate-700 text-slate-400"
                      : "bg-red-500/20 text-red-300 border border-red-500/30"
                  }`}
                >
                  {detail.status.replace("_", " ")}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Execution ID: <code className="text-slate-300">{detail.id}</code>
              </p>
            </div>
          </div>

          <button
            onClick={loadDetail}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Waiting Approval Alert */}
      {detail.status === "Waiting_Approval" && (
        <div className="flex flex-col gap-4 rounded-xl border border-amber-500/40 bg-amber-950/20 p-5 backdrop-blur-md sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            <div>
              <h3 className="font-semibold text-amber-200">Execution Paused: Awaiting Action Authorization</h3>
              <p className="text-xs text-amber-300/80">
                A disruptive response action is pending review in the SOAR Approvals inbox.
              </p>
            </div>
          </div>
          <Link
            href="/soar/approvals"
            className="flex items-center gap-2 rounded-lg border border-amber-500/50 bg-amber-600/40 px-4 py-2 text-xs font-semibold text-amber-200 hover:bg-amber-600/60"
          >
            <ClipboardCheck className="h-4 w-4" />
            Go to Approvals
          </Link>
        </div>
      )}

      {/* Metadata Overview Card */}
      <div className="grid grid-cols-1 gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <span className="text-xs font-medium text-slate-400">Trigger Source</span>
          <div className="mt-1 font-mono text-sm text-amber-300">{detail.trigger_source}</div>
        </div>
        <div>
          <span className="text-xs font-medium text-slate-400">Started At</span>
          <div className="mt-1 text-sm text-white">
            {new Date(detail.started_at).toLocaleString()}
          </div>
        </div>
        <div>
          <span className="text-xs font-medium text-slate-400">Execution Velocity</span>
          <div className="mt-1 text-sm text-cyan-400 font-semibold">
            {detail.duration_ms ? `${detail.duration_ms} ms` : "In Progress"}
          </div>
        </div>
        <div>
          <span className="text-xs font-medium text-slate-400">Steps Executed</span>
          <div className="mt-1 text-sm text-emerald-400 font-semibold">
            {detail.steps_executed_count} of {detail.steps.length} Steps
          </div>
        </div>
      </div>

      {/* Step by Step Execution Timeline */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
        <h2 className="text-base font-bold text-white">Step-by-Step Execution Pipeline</h2>
        <p className="text-xs text-slate-400">
          Chronological execution trace, input parameters, and response payloads
        </p>

        <div className="mt-6 space-y-4">
          {detail.steps.map((step, idx) => {
            const isExpanded = expandedStepId === step.id;
            return (
              <div
                key={step.id}
                className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60 transition-colors"
              >
                <div
                  onClick={() => setExpandedStepId(isExpanded ? null : step.id)}
                  className="flex cursor-pointer items-center justify-between p-4 hover:bg-slate-900/60"
                >
                  <div className="flex items-center gap-3">
                    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-slate-300">
                      {idx + 1}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white">{step.step_name}</span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                          {step.step_type}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-500">
                        Started: {new Date(step.started_at).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        step.status === "Completed"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : step.status === "Waiting_Approval"
                          ? "bg-amber-500/20 text-amber-300"
                          : "bg-red-500/20 text-red-300"
                      }`}
                    >
                      {step.status}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="border-t border-slate-800/80 bg-slate-900/40 p-4">
                    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                      <div>
                        <div className="text-xs font-semibold text-slate-400 mb-1">Input Payload</div>
                        <pre className="max-h-48 overflow-auto rounded bg-slate-950 p-3 font-mono text-xs text-slate-300">
                          {JSON.stringify(step.input_payload, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-400 mb-1">Output Payload</div>
                        <pre className="max-h-48 overflow-auto rounded bg-slate-950 p-3 font-mono text-xs text-cyan-300">
                          {JSON.stringify(step.output_payload, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Redacted Execution Log Console */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <h2 className="text-base font-bold text-white">Execution Audit Logs</h2>
        </div>

        <div className="mt-4 max-h-72 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs">
          {detail.logs.length === 0 ? (
            <div className="text-slate-500">No logs emitted during this execution.</div>
          ) : (
            detail.logs.map((log) => (
              <div key={log.id} className="py-1 flex items-start gap-2">
                <span className="text-slate-500 shrink-0">
                  [{new Date(log.timestamp).toLocaleTimeString()}]
                </span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                    log.log_level === "INFO"
                      ? "text-cyan-400"
                      : log.log_level === "ACTION"
                      ? "text-amber-400"
                      : "text-red-400"
                  }`}
                >
                  {log.log_level}
                </span>
                <span className="text-slate-300">{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
