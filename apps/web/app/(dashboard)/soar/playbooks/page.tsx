"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Workflow,
  PlusCircle,
  Play,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ChevronRight,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  Code,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type { SOARWorkflow, WorkflowCategory, WorkflowStatus } from "@/types/soar";

export default function SOARPlaybooksPage() {
  const [workflows, setWorkflows] = useState<SOARWorkflow[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("All");
  const [categoryFilter, setCategoryFilter] = useState<string>("All");
  const [selectedWorkflow, setSelectedWorkflow] = useState<SOARWorkflow | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [executingId, setExecutingId] = useState<string | null>(null);

  const loadWorkflows = async () => {
    setLoading(true);
    try {
      const res = await apiSOAR.listWorkflows(statusFilter !== "All" ? statusFilter : undefined);
      if (res.data) setWorkflows(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadWorkflows();
  }, [statusFilter]);

  const handlePublish = async (id: string, name: string) => {
    try {
      const res = await apiSOAR.publishWorkflow(id);
      if (res.data) {
        setActionNotice(`Playbook "${name}" successfully published for automated execution.`);
        loadWorkflows();
      } else {
        setActionNotice(`Publishing failed: ${res.error}`);
      }
    } catch (e: any) {
      setActionNotice(`Error: ${e.message}`);
    }
  };

  const handleTestRun = async (wf: SOARWorkflow) => {
    setExecutingId(wf.id);
    setActionNotice(null);
    try {
      const res = await apiSOAR.executeWorkflow(wf.id, {
        trigger_source: "manual_catalog_run",
        input_context: {
          asset_ip: "10.0.4.120",
          event_type: wf.trigger_type,
          tested_by: "SOC Lead",
        },
      });
      if (res.data) {
        setActionNotice(`Execution started: ID ${res.data.id.slice(0, 8)}... Status: ${res.data.status}`);
      } else {
        setActionNotice(`Failed to execute: ${res.error}`);
      }
    } catch (e: any) {
      setActionNotice(`Error: ${e.message}`);
    } finally {
      setExecutingId(null);
    }
  };

  const filteredWorkflows = workflows.filter((w) => {
    const matchesSearch =
      w.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (w.description && w.description.toLowerCase().includes(searchTerm.toLowerCase())) ||
      w.trigger_type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = categoryFilter === "All" || w.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Workflow className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                SOAR Playbooks Catalog
              </h1>
              <p className="text-sm text-slate-400">
                Automated security orchestration playbooks and conditional incident response workflows
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={loadWorkflows}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            href="/soar/playbooks/new"
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600/80 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 transition-all hover:bg-cyan-500"
          >
            <PlusCircle className="h-4 w-4" />
            Create Playbook
          </Link>
        </div>
      </div>

      {actionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-cyan-500/40 bg-cyan-950/40 p-4 text-sm text-cyan-300">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-cyan-400" />
            <span>{actionNotice}</span>
          </div>
          <button onClick={() => setActionNotice(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-md md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search playbooks by title, trigger, or description..."
            className="w-full rounded-lg border border-slate-800 bg-slate-950/60 py-2 pl-9 pr-4 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-400">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="All">All Categories</option>
              <option value="incident_response">Incident Response</option>
              <option value="vulnerability_management">Vulnerability Mgmt</option>
              <option value="threat_hunting">Threat Hunting</option>
              <option value="network_security">Network Security</option>
              <option value="identity_access">Identity & Access</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="All">All Statuses</option>
              <option value="Published">Published</option>
              <option value="Draft">Draft</option>
              <option value="Archived">Archived</option>
            </select>
          </div>
        </div>
      </div>

      {/* Playbooks Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {filteredWorkflows.map((wf) => (
          <div
            key={wf.id}
            className="flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md transition-all hover:border-slate-700"
          >
            <div>
              {/* Header tags */}
              <div className="flex items-center justify-between gap-2">
                <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[11px] font-semibold text-cyan-400 capitalize border border-cyan-500/20">
                  {wf.category.replace("_", " ")}
                </span>
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

              <h3 className="mt-3 text-lg font-bold text-white line-clamp-1">{wf.name}</h3>
              <p className="mt-1 text-xs text-slate-400 line-clamp-2">
                {wf.description || "Automated response playbook workflow."}
              </p>

              {/* Trigger Info */}
              <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <div className="text-[11px] font-medium text-slate-500">Trigger Condition:</div>
                <div className="mt-1 font-mono text-xs text-amber-300 line-clamp-1">
                  {wf.trigger_type}
                </div>
              </div>

              {/* Steps timeline pill */}
              <div className="mt-4">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Execution Pipeline:</span>
                  <span className="font-semibold text-white">{wf.steps?.length || 0} Steps</span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {wf.steps?.slice(0, 4).map((s, idx) => (
                    <span
                      key={idx}
                      className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-300 border border-slate-700/60"
                    >
                      {idx + 1}. {s.name}
                    </span>
                  ))}
                  {wf.steps && wf.steps.length > 4 && (
                    <span className="rounded bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">
                      +{wf.steps.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Actions footer */}
            <div className="mt-6 border-t border-slate-800/80 pt-4">
              <div className="flex items-center justify-between gap-2">
                <button
                  onClick={() => setSelectedWorkflow(wf)}
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300"
                >
                  View Steps
                </button>

                <div className="flex items-center gap-2">
                  {wf.status === "Draft" && (
                    <button
                      onClick={() => handlePublish(wf.id, wf.name)}
                      className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-900/60"
                    >
                      Publish
                    </button>
                  )}
                  <button
                    onClick={() => handleTestRun(wf)}
                    disabled={executingId === wf.id}
                    className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/60 disabled:opacity-50"
                  >
                    <Play className={`h-3 w-3 ${executingId === wf.id ? "animate-spin" : ""}`} />
                    Test Run
                  </button>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Modal: View Step Sequence */}
      {selectedWorkflow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white">{selectedWorkflow.name}</h3>
                <p className="text-xs text-slate-400">Step execution sequence and configuration</p>
              </div>
              <button
                onClick={() => setSelectedWorkflow(null)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            <div className="mt-4 space-y-3">
              {selectedWorkflow.steps?.map((step) => (
                <div
                  key={step.step_order}
                  className="rounded-lg border border-slate-800 bg-slate-950/50 p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-500/20 text-xs font-bold text-cyan-400">
                        {step.step_order}
                      </span>
                      <span className="font-semibold text-white">{step.name}</span>
                    </div>
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                      {step.step_type}
                    </span>
                  </div>

                  {Object.keys(step.parameters || {}).length > 0 && (
                    <pre className="mt-3 overflow-x-auto rounded bg-slate-900/90 p-2 text-[11px] font-mono text-slate-300">
                      {JSON.stringify(step.parameters, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setSelectedWorkflow(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
