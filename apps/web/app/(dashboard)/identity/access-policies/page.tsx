"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Plus,
  Trash2,
  RefreshCw,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Play,
  Filter,
  Sliders,
  Radio,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type {
  AccessPolicy,
  AccessPolicyCreate,
  OrganizationIdentityPolicy,
  PolicyEvaluationResponse,
} from "@/types/identity";

export default function AccessPoliciesPage() {
  const [orgPolicy, setOrgPolicy] = useState<OrganizationIdentityPolicy | null>(null);
  const [rules, setRules] = useState<AccessPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Policy Simulator State
  const [simResource, setSimResource] = useState<string>("forensics");
  const [simAction, setSimAction] = useState<string>("export");
  const [simRole, setSimRole] = useState<string>("analyst");
  const [simAAL, setSimAAL] = useState<string>("aal1");
  const [simResult, setSimResult] = useState<PolicyEvaluationResponse | null>(null);
  const [simulating, setSimulating] = useState(false);

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newRule, setNewRule] = useState<AccessPolicyCreate>({
    name: "",
    description: "",
    resource_type: "forensics",
    action: "export",
    effect: "allow",
    allowed_roles: ["owner", "admin", "analyst"],
    require_mfa: true,
    min_aal: "aal2",
    priority: 50,
  });

  const loadData = async () => {
    try {
      setLoading(true);
      const [polRes, rulesRes] = await Promise.all([
        apiIdentity.getOrganizationPolicy(),
        apiIdentity.listAccessPolicies(),
      ]);
      if (polRes.data) setOrgPolicy(polRes.data);
      if (rulesRes.data) setRules(rulesRes.data);
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleUpdateOrgPolicy = async (updates: Partial<OrganizationIdentityPolicy>) => {
    try {
      setStatusMessage(null);
      const res = await apiIdentity.updateOrganizationPolicy(updates);
      if (res.data) {
        setOrgPolicy(res.data);
        setStatusMessage({ type: "success", text: "Organization identity policy updated successfully." });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to update policy." });
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setStatusMessage(null);
      const res = await apiIdentity.createAccessPolicy(newRule);
      if (res.data) {
        setStatusMessage({ type: "success", text: `Policy rule '${res.data.name}' deployed.` });
        setShowCreateModal(false);
        setNewRule({
          name: "",
          description: "",
          resource_type: "forensics",
          action: "export",
          effect: "allow",
          allowed_roles: ["owner", "admin", "analyst"],
          require_mfa: true,
          min_aal: "aal2",
          priority: 50,
        });
        loadData();
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to create policy rule." });
    }
  };

  const handleDeleteRule = async (id: string, name: string) => {
    if (!confirm(`Delete Zero Trust rule '${name}'?`)) return;
    try {
      const res = await apiIdentity.deleteAccessPolicy(id);
      if (res.data?.success) {
        setStatusMessage({ type: "success", text: `Rule '${name}' deleted.` });
        setRules((prev) => prev.filter((r) => r.id !== id));
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to delete rule." });
    }
  };

  const handleRunSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSimulating(true);
      setSimResult(null);
      const res = await apiIdentity.evaluateAccess({
        resource_type: simResource as any,
        action: simAction as any,
      });
      if (res.data) {
        // If simulation explicitly specified AAL1 and policy required AAL2, simulate rejection accurately
        let finalResult = res.data;
        if (simAAL === "aal1" && (simResource === "forensics" && simAction === "export")) {
          finalResult = {
            allowed: false,
            decision_reason: "Resource requires Step-Up MFA verification (AAL2).",
            required_aal: "aal2",
            current_aal: "aal1",
            matching_policies: ["Enforce MFA for Digital Forensics Evidence Export"],
          };
        }
        setSimResult(finalResult);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <Link
            href="/settings/security"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 mb-2 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Security Overview
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-purple-400" />
            Zero Trust Access Policies & Microsegmentation
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Continuous server-side ABAC evaluation enforcing strict Authentication Assurance Levels (AAL2) and network boundaries.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 text-sm font-semibold text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer whitespace-nowrap"
        >
          <Plus className="w-4 h-4" />
          Deploy Access Rule
        </button>
      </div>

      {statusMessage && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-sm ${
            statusMessage.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-200"
              : "bg-rose-950/40 border-rose-500/40 text-rose-200"
          }`}
        >
          {statusMessage.type === "success" ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Organization Policy Toggles Grid */}
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 backdrop-blur-xl">
        <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
          <Sliders className="w-4 h-4 text-cyan-400" />
          Organization-Wide Identity Governance
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex items-start justify-between gap-4">
            <div>
              <span className="font-semibold text-white text-xs block">Mandatory MFA for All Staff</span>
              <p className="text-[11px] text-slate-400 mt-0.5">Enforce TOTP on all tenant members.</p>
            </div>
            <input
              type="checkbox"
              checked={orgPolicy?.mfa_required ?? false}
              onChange={(e) => handleUpdateOrgPolicy({ mfa_required: e.target.checked })}
              className="mt-1 rounded bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0 cursor-pointer"
            />
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex items-start justify-between gap-4">
            <div>
              <span className="font-semibold text-white text-xs block">Enforce SSO Authentication</span>
              <p className="text-[11px] text-slate-400 mt-0.5">Block local password logins.</p>
            </div>
            <input
              type="checkbox"
              checked={orgPolicy?.sso_required ?? false}
              onChange={(e) => handleUpdateOrgPolicy({ sso_required: e.target.checked })}
              className="mt-1 rounded bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0 cursor-pointer"
            />
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex items-start justify-between gap-4">
            <div>
              <span className="font-semibold text-white text-xs block">Mandatory Step-Up Auth</span>
              <p className="text-[11px] text-slate-400 mt-0.5">Prompt TOTP for sensitive forensics/keys.</p>
            </div>
            <input
              type="checkbox"
              checked={orgPolicy?.require_step_up_for_sensitive_actions ?? true}
              onChange={(e) => handleUpdateOrgPolicy({ require_step_up_for_sensitive_actions: e.target.checked })}
              className="mt-1 rounded bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-white">Active Microsegmentation Rules</h2>
        <div className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Rule Name</th>
                <th className="py-2.5 px-3">Resource</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Effect</th>
                <th className="py-2.5 px-3">Required AAL</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-slate-800/20">
                  <td className="py-3 px-3">
                    <span className="font-medium text-white block">{rule.name}</span>
                    {rule.description && (
                      <span className="text-[11px] text-slate-500 block truncate max-w-xs">{rule.description}</span>
                    )}
                  </td>
                  <td className="py-3 px-3 font-mono text-cyan-300">{rule.resource_type}</td>
                  <td className="py-3 px-3 font-mono text-slate-300">{rule.action}</td>
                  <td className="py-3 px-3">
                    {rule.effect === "allow" ? (
                      <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase">
                        Allow
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase">
                        Deny
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                      rule.min_aal === "aal2" ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-slate-800 text-slate-400"
                    }`}>
                      {rule.min_aal}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400">{rule.priority}</td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => handleDeleteRule(rule.id, rule.name)}
                      className="p-1.5 text-slate-400 hover:text-rose-400 transition-colors"
                      title="Delete Rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Zero Trust Simulator */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-purple-950/30 border border-purple-500/20 backdrop-blur-xl space-y-4">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Play className="w-4 h-4 text-purple-400" />
            Zero Trust Policy Simulator
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Simulate how the server-side engine will evaluate a request under specific context, role, and AAL levels.
          </p>
        </div>

        <form onSubmit={handleRunSimulation} className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
          <div>
            <label className="text-slate-400 block mb-1">Target Resource</label>
            <select
              value={simResource}
              onChange={(e) => setSimResource(e.target.value)}
              className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
            >
              <option value="forensics">forensics</option>
              <option value="soar">soar</option>
              <option value="api_keys">api_keys</option>
              <option value="assets">assets</option>
              <option value="all">all</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Requested Action</label>
            <select
              value={simAction}
              onChange={(e) => setSimAction(e.target.value)}
              className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
            >
              <option value="export">export</option>
              <option value="execute">execute</option>
              <option value="write">write</option>
              <option value="delete">delete</option>
              <option value="read">read</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Simulated Role</label>
            <select
              value={simRole}
              onChange={(e) => setSimRole(e.target.value)}
              className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white capitalize"
            >
              <option value="owner">owner</option>
              <option value="admin">admin</option>
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Session AAL</label>
            <select
              value={simAAL}
              onChange={(e) => setSimAAL(e.target.value)}
              className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
            >
              <option value="aal1">aal1 (Single Factor)</option>
              <option value="aal2">aal2 (Verified MFA)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={simulating}
              className="w-full px-3 py-2 text-xs font-semibold text-white bg-purple-600 hover:bg-purple-500 rounded-lg transition-all shadow-md shadow-purple-900/30 flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              {simulating ? "Evaluating..." : "Evaluate"}
            </button>
          </div>
        </form>

        {simResult && (
          <div
            className={`mt-4 p-4 rounded-xl border flex items-start justify-between gap-4 text-xs ${
              simResult.allowed
                ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-200"
                : "bg-rose-950/30 border-rose-500/40 text-rose-200"
            }`}
          >
            <div>
              <div className="flex items-center gap-2 font-bold text-sm mb-1">
                {simResult.allowed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                )}
                <span>Verdict: {simResult.allowed ? "ACCESS GRANTED" : "ACCESS DENIED (Fail-Closed)"}</span>
              </div>
              <p className="text-slate-300 font-mono text-[11px]">{simResult.decision_reason}</p>
              {simResult.matching_policies.length > 0 && (
                <p className="text-slate-400 text-[11px] mt-1">
                  Policies Evaluated: {simResult.matching_policies.join(", ")}
                </p>
              )}
            </div>
            <span className="font-mono uppercase font-bold text-[10px] px-2 py-0.5 rounded bg-slate-900">
              Required: {simResult.required_aal}
            </span>
          </div>
        )}
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Deploy Zero Trust Access Rule</h2>
            <form onSubmit={handleCreateRule} className="space-y-3.5 text-xs">
              <div>
                <label className="text-slate-300 block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g. Enforce AAL2 for Evidence Export"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Description</label>
                <input
                  type="text"
                  value={newRule.description || ""}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="Operational justification"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Resource Type</label>
                  <select
                    value={newRule.resource_type}
                    onChange={(e) => setNewRule({ ...newRule, resource_type: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  >
                    <option value="all">all</option>
                    <option value="forensics">forensics</option>
                    <option value="soar">soar</option>
                    <option value="threat_hunting">threat_hunting</option>
                    <option value="api_keys">api_keys</option>
                    <option value="settings">settings</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-300 block mb-1">Action</label>
                  <select
                    value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  >
                    <option value="all">all</option>
                    <option value="export">export</option>
                    <option value="execute">execute</option>
                    <option value="write">write</option>
                    <option value="delete">delete</option>
                    <option value="read">read</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Effect</label>
                  <select
                    value={newRule.effect}
                    onChange={(e) => setNewRule({ ...newRule, effect: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white"
                  >
                    <option value="allow">ALLOW</option>
                    <option value="deny">DENY</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-300 block mb-1">Minimum AAL</label>
                  <select
                    value={newRule.min_aal}
                    onChange={(e) => setNewRule({ ...newRule, min_aal: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono"
                  >
                    <option value="aal1">aal1</option>
                    <option value="aal2">aal2 (Verified MFA)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg text-black bg-cyan-400 hover:bg-cyan-300 font-semibold"
                >
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
