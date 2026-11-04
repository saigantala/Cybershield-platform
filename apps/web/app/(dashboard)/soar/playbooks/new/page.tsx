"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Workflow,
  PlusCircle,
  Trash2,
  ArrowUp,
  ArrowDown,
  CheckCircle2,
  AlertTriangle,
  Save,
  ArrowLeft,
  ShieldCheck,
  Send,
  Zap,
} from "lucide-react";
import { apiSOAR } from "@/lib/api-client";
import type {
  WorkflowTriggerType,
  WorkflowStepType,
  WorkflowCategory,
  SOARStepConfig,
} from "@/types/soar";

const STEP_TYPE_OPTIONS: { type: WorkflowStepType; label: string; desc: string }[] = [
  { type: "condition", label: "Conditional Branch", desc: "Evaluate logic and branch execution" },
  { type: "severity_check", label: "Severity Filter", desc: "Check if event meets threshold" },
  { type: "asset_lookup", label: "Asset Enrichment", desc: "Query asset inventory for host context" },
  { type: "threat_intel_lookup", label: "Threat Intel Query", desc: "Check IP/Domain against IOC feeds" },
  { type: "vulnerability_lookup", label: "Vulnerability Scan", desc: "Query known CVEs for target asset" },
  { type: "create_incident", label: "Create Incident", desc: "Raise tracked SOC incident in CyberShield" },
  { type: "add_incident_note", label: "Add Incident Note", desc: "Append automated triage findings" },
  { type: "assign_analyst", label: "Assign Analyst", desc: "Route ticket to on-duty SOC responder" },
  { type: "send_notification", label: "Send Notification", desc: "Dispatch email, Slack, or webhook" },
  { type: "request_approval", label: "Request Human Approval", desc: "Gate disruptive actions with human signoff" },
  { type: "generate_report", label: "Generate Report", desc: "Produce forensic PDF compliance artifact" },
  { type: "end_workflow", label: "Conclude Workflow", desc: "Successfully finish playbook execution" },
];

export default function NewPlaybookBuilderPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<WorkflowCategory>("incident_response");
  const [triggerType, setTriggerType] = useState<WorkflowTriggerType>("new_critical_alert");

  const [steps, setSteps] = useState<SOARStepConfig[]>([
    {
      step_order: 1,
      name: "Ingest Alert Trigger",
      step_type: "trigger",
      parameters: { event_source: "siem_alerts", minimum_severity: "High" },
    },
    {
      step_order: 2,
      name: "Enrich Host Asset Context",
      step_type: "asset_lookup",
      parameters: { lookup_field: "ip_address" },
    },
    {
      step_order: 3,
      name: "Gate Containment Action",
      step_type: "request_approval",
      parameters: {
        action_type: "asset_isolation",
        urgency: "High",
        justification: "Isolate compromised endpoint to prevent lateral movement",
      },
    },
    {
      step_order: 4,
      name: "Conclude Response",
      step_type: "end_workflow",
      parameters: { summary: "Incident gated and containment triaged" },
    },
  ]);

  const [saving, setSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAddStep = (type: WorkflowStepType) => {
    const nextOrder = steps.length + 1;
    let defaultParams: Record<string, any> = {};

    if (type === "request_approval") {
      defaultParams = {
        action_type: "asset_isolation",
        urgency: "High",
        justification: "Require analyst authorization before disruptive response",
      };
    } else if (type === "create_incident") {
      defaultParams = {
        title: "Automated SOAR Incident",
        severity: "High",
        incident_type: "Malware",
      };
    } else if (type === "send_notification") {
      defaultParams = {
        channel: "in_app",
        recipient: "soc-team@cybershield.local",
      };
    } else if (type === "severity_check") {
      defaultParams = { minimum_severity: "High" };
    }

    setSteps([
      ...steps,
      {
        step_order: nextOrder,
        name: `Execute ${type.replace("_", " ")}`,
        step_type: type,
        parameters: defaultParams,
      },
    ]);
  };

  const handleRemoveStep = (index: number) => {
    if (index === 0) {
      setErrorMsg("Step 1 must remain a 'trigger' step.");
      return;
    }
    const updated = steps.filter((_, i) => i !== index).map((s, idx) => ({
      ...s,
      step_order: idx + 1,
    }));
    setSteps(updated);
  };

  const handleMoveStep = (index: number, direction: "up" | "down") => {
    if (index === 0 || (index === 1 && direction === "up")) {
      setErrorMsg("Step 1 must remain the initial 'trigger' step.");
      return;
    }
    const newIdx = direction === "up" ? index - 1 : index + 1;
    if (newIdx < 1 || newIdx >= steps.length) return;

    const copy = [...steps];
    const temp = copy[index];
    copy[index] = copy[newIdx];
    copy[newIdx] = temp;

    setSteps(copy.map((s, idx) => ({ ...s, step_order: idx + 1 })));
  };

  const handleUpdateStepName = (index: number, newName: string) => {
    const copy = [...steps];
    copy[index].name = newName;
    setSteps(copy);
  };

  const handleUpdateStepParam = (index: number, key: string, val: any) => {
    const copy = [...steps];
    copy[index].parameters = { ...copy[index].parameters, [key]: val };
    setSteps(copy);
  };

  const handleSave = async (publish: boolean = false) => {
    setErrorMsg(null);
    if (!name.trim()) {
      setErrorMsg("Please provide a name for this playbook.");
      return;
    }
    if (steps.length < 2) {
      setErrorMsg("Playbook must contain at least 2 steps (Trigger + Action/End).");
      return;
    }
    if (steps[0].step_type !== "trigger") {
      setErrorMsg("First step of playbook must be of type 'trigger'.");
      return;
    }

    setSaving(true);
    try {
      const res = await apiSOAR.createWorkflow({
        name,
        description,
        category,
        trigger_type: triggerType,
        steps,
        is_enabled: true,
      });

      if (res.data) {
        if (publish) {
          await apiSOAR.publishWorkflow(res.data.id);
        }
        router.push("/soar/playbooks");
      } else {
        setErrorMsg(res.error || "Failed to create playbook");
      }
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8 p-6 md:p-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/soar/playbooks"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-200"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Playbooks
          </Link>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
              <Zap className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white md:text-3xl">
                Visual Playbook Builder
              </h1>
              <p className="text-sm text-slate-400">
                Design automated SOC triage, conditional actions, and gated containment workflows
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => handleSave(false)}
            disabled={saving}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            Save Draft
          </button>
          <button
            onClick={() => handleSave(true)}
            disabled={saving}
            className="flex items-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-600 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-cyan-900/40 hover:bg-cyan-500 disabled:opacity-50"
          >
            <CheckCircle2 className="h-4 w-4" />
            Publish Playbook
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center justify-between rounded-xl border border-red-500/40 bg-red-950/40 p-4 text-sm text-red-300">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Playbook Configuration Form */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
        <h2 className="text-base font-bold text-white">Playbook Specification</h2>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-slate-300">Playbook Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Automated EDR Ransomware Containment"
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Category</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value as WorkflowCategory)}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="incident_response">Incident Response</option>
              <option value="vulnerability_management">Vulnerability Management</option>
              <option value="threat_hunting">Threat Hunting</option>
              <option value="network_security">Network Security</option>
              <option value="identity_access">Identity & Access</option>
              <option value="custom">Custom Workflow</option>
            </select>
          </div>

          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-slate-300">Description</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Explain the security objective and operational steps taken..."
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300">Trigger Event</label>
            <select
              value={triggerType}
              onChange={(e) => setTriggerType(e.target.value as WorkflowTriggerType)}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="new_critical_alert">New Critical Alert</option>
              <option value="new_high_vulnerability">New High Vulnerability</option>
              <option value="suspicious_network_activity">Suspicious Network Activity</option>
              <option value="threat_intel_ioc_match">Threat Intel IOC Match</option>
              <option value="repeated_auth_failures">Repeated Auth Failures</option>
              <option value="unauthorized_asset_detected">Unauthorized Asset Detected</option>
              <option value="manual_investigation">Manual Investigation</option>
            </select>
          </div>
        </div>
      </div>

      {/* Visual Execution Stepper */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-bold text-white">Workflow Step Pipeline</h2>
            <p className="text-xs text-slate-400">Sequential and gated actions executed by CyberShield SOAR</p>
          </div>
          <span className="rounded bg-cyan-500/10 px-2 py-1 text-xs font-mono text-cyan-400">
            {steps.length} Steps Defined
          </span>
        </div>

        <div className="mt-6 space-y-4">
          {steps.map((step, idx) => (
            <div
              key={idx}
              className={`rounded-xl border p-4 transition-all ${
                step.step_type === "request_approval"
                  ? "border-amber-500/40 bg-amber-950/10"
                  : step.step_type === "trigger"
                  ? "border-cyan-500/40 bg-cyan-950/10"
                  : "border-slate-800 bg-slate-950/50"
              }`}
            >
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-white">
                    {step.step_order}
                  </span>
                  <div>
                    <input
                      type="text"
                      value={step.name}
                      onChange={(e) => handleUpdateStepName(idx, e.target.value)}
                      className="rounded border border-transparent bg-transparent px-2 py-1 font-semibold text-white hover:border-slate-700 focus:border-cyan-500 focus:bg-slate-900 focus:outline-none"
                    />
                    <div className="flex items-center gap-2 px-2 text-[11px] text-slate-500">
                      <span>Type: <strong className="text-slate-300 font-mono">{step.step_type}</strong></span>
                      {step.step_type === "request_approval" && (
                        <span className="rounded bg-amber-500/20 px-1.5 py-0.2 text-[10px] font-bold text-amber-300">
                          HUMAN-IN-THE-LOOP GATE
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleMoveStep(idx, "up")}
                    disabled={idx <= 1}
                    className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white disabled:opacity-30"
                  >
                    <ArrowUp className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleMoveStep(idx, "down")}
                    disabled={idx === 0 || idx === steps.length - 1}
                    className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white disabled:opacity-30"
                  >
                    <ArrowDown className="h-4 w-4" />
                  </button>
                  {idx > 0 && (
                    <button
                      onClick={() => handleRemoveStep(idx)}
                      className="rounded p-1.5 text-red-400 hover:bg-red-950/50 hover:text-red-300"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>

              {/* Step Parameters Form */}
              <div className="mt-4 grid grid-cols-1 gap-3 border-t border-slate-800/80 pt-3 sm:grid-cols-3">
                {step.step_type === "request_approval" && (
                  <>
                    <div>
                      <label className="text-[11px] text-slate-400">Action to Authorize</label>
                      <select
                        value={step.parameters.action_type || "asset_isolation"}
                        onChange={(e) => handleUpdateStepParam(idx, "action_type", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      >
                        <option value="asset_isolation">Isolate Host Endpoint</option>
                        <option value="account_suspension">Suspend Compromised Account</option>
                        <option value="firewall_rule_review">Firewall ACL Block</option>
                        <option value="block_indicator">Block IOC Feed Indicator</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400">Urgency Level</label>
                      <select
                        value={step.parameters.urgency || "High"}
                        onChange={(e) => handleUpdateStepParam(idx, "urgency", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      >
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400">Target Identifier / IP</label>
                      <input
                        type="text"
                        value={step.parameters.target_resource || "192.168.10.45"}
                        onChange={(e) => handleUpdateStepParam(idx, "target_resource", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      />
                    </div>
                  </>
                )}

                {step.step_type === "create_incident" && (
                  <>
                    <div>
                      <label className="text-[11px] text-slate-400">Incident Severity</label>
                      <select
                        value={step.parameters.severity || "High"}
                        onChange={(e) => handleUpdateStepParam(idx, "severity", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      >
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400">Incident Classification</label>
                      <input
                        type="text"
                        value={step.parameters.incident_type || "Malware"}
                        onChange={(e) => handleUpdateStepParam(idx, "incident_type", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      />
                    </div>
                  </>
                )}

                {step.step_type === "send_notification" && (
                  <>
                    <div>
                      <label className="text-[11px] text-slate-400">Notification Channel</label>
                      <select
                        value={step.parameters.channel || "in_app"}
                        onChange={(e) => handleUpdateStepParam(idx, "channel", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      >
                        <option value="in_app">In-App SOC Notification</option>
                        <option value="email">Email Alert</option>
                        <option value="webhook">Webhook / Slack</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400">Recipient / Endpoint</label>
                      <input
                        type="text"
                        value={step.parameters.recipient || "soc-alerts@cybershield.local"}
                        onChange={(e) => handleUpdateStepParam(idx, "recipient", e.target.value)}
                        className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                      />
                    </div>
                  </>
                )}

                {step.step_type === "severity_check" && (
                  <div>
                    <label className="text-[11px] text-slate-400">Minimum Severity Gate</label>
                    <select
                      value={step.parameters.minimum_severity || "High"}
                      onChange={(e) => handleUpdateStepParam(idx, "minimum_severity", e.target.value)}
                      className="mt-1 w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-white"
                    >
                      <option value="Critical">Critical Only</option>
                      <option value="High">High or Critical</option>
                      <option value="Medium">Medium and Above</option>
                    </select>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Add Step Tool Palette */}
        <div className="mt-8 border-t border-slate-800 pt-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Add Modular Step to Workflow
          </h3>
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {STEP_TYPE_OPTIONS.map((opt) => (
              <button
                key={opt.type}
                onClick={() => handleAddStep(opt.type)}
                className="flex flex-col items-start rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-left transition-colors hover:border-cyan-500/50 hover:bg-slate-900"
              >
                <div className="flex items-center gap-1.5 font-semibold text-white text-xs">
                  <PlusCircle className="h-3.5 w-3.5 text-cyan-400" />
                  {opt.label}
                </div>
                <p className="mt-1 text-[11px] text-slate-400 line-clamp-1">{opt.desc}</p>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
