"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Zap,
  Workflow,
  ClipboardCheck,
  PlaySquare,
  BarChart3,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Play,
  ArrowRight,
  ShieldAlert,
  Send,
  RefreshCw,
  PlusCircle,
  ExternalLink,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { SOARWorkflow, SOARExecution, SOARApproval, SOARAnalytics } from "@/types/soar";

export default function SOAROverviewPage() {
  const [analytics, setAnalytics] = useState<SOARAnalytics | null>(null);
  const [workflows, setWorkflows] = useState<SOARWorkflow[]>([]);
  const [recentExecutions, setRecentExecutions] = useState<SOARExecution[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<SOARApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [executingWfId, setExecutingWfId] = useState<string | null>(null);
  const [executionNotice, setExecutionNotice] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [analyticsRes, wfRes, execRes, appRes] = await Promise.all([
        apiSOAR.getAnalytics(),
        apiSOAR.listWorkflows(),
        apiSOAR.listExecutions(),
        apiSOAR.listApprovals("Pending"),
      ]);

      if (analyticsRes.data) setAnalytics(analyticsRes.data);
      if (wfRes.data) setWorkflows(wfRes.data);
      if (execRes.data) setRecentExecutions(execRes.data.slice(0, 6));
      if (appRes.data) setPendingApprovals(appRes.data);
    } catch (e) {
      console.error("Failed to load SOAR overview data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunPlaybook = async (wf: SOARWorkflow) => {
    setExecutingWfId(wf.id);
    setExecutionNotice(null);
    try {
      const res = await apiSOAR.executeWorkflow(wf.id, {
        trigger_source: "manual_soc_hub",
        input_context: {
          asset_ip: "192.168.10.45",
          severity: "High",
          triggered_by: "SOC Engineer (Manual Run)",
        },
      });
      if (res.data) {
        setExecutionNotice(`Playbook "${wf.name}" executed! Status: ${res.data.status}`);
        loadData();
      } else {
        setExecutionNotice(`Execution trigger failed: ${res.error || "Unknown error"}`);
      }
    } catch (err: any) {
      setExecutionNotice(`Error: ${err.message}`);
    } finally {
      setExecutingWfId(null);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Zap className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                SOAR Automation Hub
              </h1>
              <p className="text-sm text-slate-400">
                Security Orchestration, Automation & Response: automated alert triage, gated containment & playbook execution
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            href="/soar/playbooks/new"
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600/80 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 transition-all hover:bg-cyan-500"
          >
            <PlusCircle className="h-4 w-4" />
            Build Playbook
          </Link>
        </div>
      </div>

      {executionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-cyan-500/40 bg-cyan-950/40 p-4 text-sm text-cyan-300 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-cyan-400" />
            <span>{executionNotice}</span>
          </div>
          <button onClick={() => setExecutionNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Pending Approvals Critical Notice */}
      {pendingApprovals.length > 0 && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-950/20 p-5 backdrop-blur-md">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/20 text-amber-400">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-semibold text-amber-200">
                  {pendingApprovals.length} Disruptive Action Approval{pendingApprovals.length > 1 ? "s" : ""} Pending Review
                </h3>
                <p className="mt-1 text-sm text-amber-300/80">
                  Critical containment actions (host isolation, account suspension, firewall ACLs) require human analyst authorization.
                </p>
              </div>
            </div>
            <Link
              href="/soar/approvals"
              className="inline-flex items-center gap-2 rounded-lg border border-amber-500/50 bg-amber-600/30 px-4 py-2 text-sm font-semibold text-amber-200 transition-colors hover:bg-amber-600/50"
            >
              Review Approvals Inbox
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      )}

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Active Playbooks</span>
            <Workflow className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {workflows.filter((w) => w.status === "Published").length}
            <span className="ml-2 text-xs font-normal text-slate-400">/ {workflows.length} total</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">Autonomous workflow pipelines</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Total Executions</span>
            <PlaySquare className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {analytics?.total_playbook_executions || recentExecutions.length}
          </div>
          <p className="mt-1 text-xs text-emerald-400">
            {analytics ? `${analytics.automation_success_rate}% success rate` : "Automated security actions"}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Mean Velocity (MTTE)</span>
            <Clock className="h-4 w-4 text-violet-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {analytics ? `${analytics.average_execution_time_ms} ms` : "850 ms"}
          </div>
          <p className="mt-1 text-xs text-slate-400">Sub-second incident triage</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Pending Approvals</span>
            <ClipboardCheck className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white">
            {pendingApprovals.length}
          </div>
          <p className="mt-1 text-xs text-amber-400">Human-in-the-loop gates</p>
        </div>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Link
          href="/soar/playbooks"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 backdrop-blur-md transition-all hover:border-cyan-500/50 hover:bg-slate-900/70"
        >
          <div className="flex items-center justify-between">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
              <Workflow className="h-5 w-5" />
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 transition-transform group-hover:translate-x-1 group-hover:text-cyan-400" />
          </div>
          <h3 className="mt-3 font-semibold text-white">Playbooks Catalog</h3>
          <p className="mt-1 text-xs text-slate-400">
            Configure automated incident triage and remediation workflows.
          </p>
        </Link>

        <Link
          href="/soar/approvals"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 backdrop-blur-md transition-all hover:border-amber-500/50 hover:bg-slate-900/70"
        >
          <div className="flex items-center justify-between">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400">
              <ClipboardCheck className="h-5 w-5" />
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 transition-transform group-hover:translate-x-1 group-hover:text-amber-400" />
          </div>
          <h3 className="mt-3 font-semibold text-white">Action Approvals</h3>
          <p className="mt-1 text-xs text-slate-400">
            Review host isolations, ACL changes, and account suspensions.
          </p>
        </Link>

        <Link
          href="/soar/executions"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 backdrop-blur-md transition-all hover:border-emerald-500/50 hover:bg-slate-900/70"
        >
          <div className="flex items-center justify-between">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
              <PlaySquare className="h-5 w-5" />
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 transition-transform group-hover:translate-x-1 group-hover:text-emerald-400" />
          </div>
          <h3 className="mt-3 font-semibold text-white">Execution History</h3>
          <p className="mt-1 text-xs text-slate-400">
            Step-by-step logs, audit payloads, and error tracing.
          </p>
        </Link>

        <Link
          href="/soar/analytics"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 backdrop-blur-md transition-all hover:border-violet-500/50 hover:bg-slate-900/70"
        >
          <div className="flex items-center justify-between">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-500/10 text-violet-400">
              <BarChart3 className="h-5 w-5" />
            </div>
            <ArrowRight className="h-4 w-4 text-slate-500 transition-transform group-hover:translate-x-1 group-hover:text-violet-400" />
          </div>
          <h3 className="mt-3 font-semibold text-white">SOAR Analytics</h3>
          <p className="mt-1 text-xs text-slate-400">
            Metrics on automation velocity, MTTE, and top triggered playbooks.
          </p>
        </Link>
      </div>

      {/* Main Grid: Active Playbooks & Live Executions */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Playbooks Section */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
            <div>
              <h2 className="text-lg font-bold text-white">Active Security Playbooks</h2>
              <p className="text-xs text-slate-400">Pre-seeded & custom response workflows</p>
            </div>
            <Link
              href="/soar/playbooks"
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              View All ({workflows.length})
            </Link>
          </div>

          <div className="mt-4 space-y-3">
            {workflows.slice(0, 5).map((wf) => (
              <div
                key={wf.id}
                className="flex flex-col justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-4 transition-colors hover:border-slate-700 sm:flex-row sm:items-center"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white">{wf.name}</span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        wf.status === "Published"
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                          : "bg-slate-700 text-slate-300"
                      }`}
                    >
                      {wf.status}
                    </span>
                  </div>
                  <p className="mt-1 line-clamp-1 text-xs text-slate-400">
                    {wf.description || "Automated response playbook"}
                  </p>
                  <div className="mt-2 flex items-center gap-4 text-[11px] text-slate-500">
                    <span>Trigger: <code className="text-slate-300">{wf.trigger_type}</code></span>
                    <span>Steps: <strong className="text-slate-300">{wf.steps?.length || 0}</strong></span>
                    <span>Category: <span className="capitalize text-slate-300">{wf.category.replace("_", " ")}</span></span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleRunPlaybook(wf)}
                    disabled={executingWfId === wf.id}
                    className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-3 py-1.5 text-xs font-semibold text-cyan-300 transition-colors hover:bg-cyan-900/60 disabled:opacity-50"
                  >
                    <Play className={`h-3 w-3 ${executingWfId === wf.id ? "animate-spin" : ""}`} />
                    {executingWfId === wf.id ? "Running..." : "Test Run"}
                  </button>
                  <Link
                    href={`/soar/playbooks/new?clone=${wf.id}`}
                    className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700"
                  >
                    Inspect
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Executions Feed */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
            <div>
              <h2 className="text-lg font-bold text-white">Recent Executions</h2>
              <p className="text-xs text-slate-400">Live operational execution audit</p>
            </div>
            <Link
              href="/soar/executions"
              className="text-xs font-medium text-emerald-400 hover:text-emerald-300"
            >
              All Executions
            </Link>
          </div>

          <div className="mt-4 space-y-3">
            {recentExecutions.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No recent executions recorded. Run a playbook above to start.
              </div>
            ) : (
              recentExecutions.map((exec) => (
                <Link
                  key={exec.id}
                  href={`/soar/executions/${exec.id}`}
                  className="block rounded-lg border border-slate-800/80 bg-slate-950/40 p-3 transition-colors hover:border-slate-700 hover:bg-slate-900/60"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 line-clamp-1">
                      {exec.workflow_name}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                        exec.status === "Completed"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : exec.status === "Waiting_Approval"
                          ? "bg-amber-500/20 text-amber-300"
                          : exec.status === "Cancelled"
                          ? "bg-slate-700 text-slate-400"
                          : "bg-red-500/20 text-red-300"
                      }`}
                    >
                      {exec.status.replace("_", " ")}
                    </span>
                  </div>

                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
                    <span>Source: {exec.trigger_source}</span>
                    <span>{exec.duration_ms ? `${exec.duration_ms}ms` : "In Progress"}</span>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
