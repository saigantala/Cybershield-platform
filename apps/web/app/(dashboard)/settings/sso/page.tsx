"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Globe,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Plus,
  RefreshCw,
  Trash2,
  ArrowLeft,
  Copy,
  Check,
  Radio,
  ExternalLink,
  Lock,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type {
  SSOProvider,
  SSOProviderCreate,
  DomainVerification,
} from "@/types/identity";

export default function SSOSettingsPage() {
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [domains, setDomains] = useState<DomainVerification[]>([]);
  const [loading, setLoading] = useState(true);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<any | null>(null);

  // Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // New Provider Form
  const [formData, setFormData] = useState<SSOProviderCreate>({
    name: "",
    provider_type: "azure_ad",
    issuer_url: "",
    client_id: "",
    client_secret: "",
    domains: [],
    enforce_sso: false,
    default_role: "analyst",
  });
  const [domainChips, setDomainChips] = useState("");

  const loadData = async () => {
    try {
      setLoading(true);
      const [provRes, domRes] = await Promise.all([
        apiIdentity.listSSOProviders(),
        apiIdentity.listDomainVerifications(),
      ]);
      if (provRes.data) setProviders(provRes.data);
      if (domRes.data) setDomains(domRes.data);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTestConnection = async (providerId: string) => {
    try {
      setTestingId(providerId);
      setTestResult(null);
      const res = await apiIdentity.testSSOConnection(providerId);
      if (res.data) {
        setTestResult(res.data);
      } else {
        setStatusMessage({ type: "error", text: res.error || "Connection test failed." });
      }
    } catch (e: any) {
      setStatusMessage({ type: "error", text: e?.message || "Connection test failed." });
    } finally {
      setTestingId(null);
    }
  };

  const handleCreateProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setStatusMessage(null);
      const domainList = domainChips
        .split(",")
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean);

      const payload: SSOProviderCreate = {
        ...formData,
        domains: domainList,
      };

      const res = await apiIdentity.createSSOProvider(payload);
      if (res.data) {
        setStatusMessage({ type: "success", text: `SSO Provider '${res.data.name}' configured successfully.` });
        setShowCreateModal(false);
        setFormData({
          name: "",
          provider_type: "azure_ad",
          issuer_url: "",
          client_id: "",
          client_secret: "",
          domains: [],
          enforce_sso: false,
          default_role: "analyst",
        });
        setDomainChips("");
        loadData();
      } else {
        setStatusMessage({ type: "error", text: res.error || "Failed to configure provider" });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to create provider." });
    }
  };

  const handleDeleteProvider = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to remove identity provider '${name}'?`)) return;
    try {
      const res = await apiIdentity.deleteSSOProvider(id);
      if (res.data?.success) {
        setStatusMessage({ type: "success", text: `Provider '${name}' removed.` });
        loadData();
      } else {
        setStatusMessage({ type: "error", text: res.error || "Failed to delete provider" });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to delete provider." });
    }
  };

  const handleInitiateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainInput.trim()) return;
    try {
      const res = await apiIdentity.initiateDomainVerification(newDomainInput.trim());
      if (res.data) {
        setStatusMessage({ type: "success", text: `Verification challenge created for ${newDomainInput}.` });
        setNewDomainInput("");
        loadData();
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Failed to challenge domain." });
    }
  };

  const handleVerifyDomain = async (domainName: string) => {
    try {
      const res = await apiIdentity.verifyDomain(domainName);
      if (res.data?.status === "verified") {
        setStatusMessage({ type: "success", text: `Domain '${domainName}' verified successfully!` });
        loadData();
      } else {
        setStatusMessage({ type: "error", text: "DNS TXT record not found or propagation pending." });
      }
    } catch (err: any) {
      setStatusMessage({ type: "error", text: err?.message || "Verification failed." });
    }
  };

  const copyToken = (tok: string) => {
    navigator.clipboard.writeText(tok);
    setCopiedToken(tok);
    setTimeout(() => setCopiedToken(null), 2000);
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
            <Globe className="w-6 h-6 text-blue-400" />
            Enterprise Single Sign-On (SSO)
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Centralize enterprise authentication via Microsoft Entra ID, Okta, Google Workspace, or custom OIDC / SAML 2.0.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 text-sm font-semibold text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer whitespace-nowrap"
        >
          <Plus className="w-4 h-4" />
          Configure New IdP
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

      {/* Test Connection Result Banner */}
      {testResult && (
        <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/40 text-xs text-slate-200">
          <div className="flex items-center justify-between font-semibold text-cyan-300 mb-2">
            <span>Connection Test: {testResult.provider_name}</span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              {testResult.discovery_status}
            </span>
          </div>
          <p className="text-slate-300">{testResult.message}</p>
          <div className="mt-2 text-slate-400 font-mono text-[11px] grid grid-cols-2 gap-2 pt-2 border-t border-slate-800">
            <span>Issuer: {testResult.details.issuer}</span>
            <span>Protocol: {testResult.details.protocol}</span>
          </div>
        </div>
      )}

      {/* Configured Identity Providers Grid */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-white">Configured Identity Providers</h2>
        {providers.length === 0 ? (
          <div className="p-8 rounded-2xl bg-slate-900/30 border border-slate-800 text-center text-slate-400">
            No SSO providers configured yet. Click "Configure New IdP" to get started.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {providers.map((p) => (
              <div
                key={p.id}
                className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 capitalize">
                      {p.provider_type.replace("_", " ")}
                    </span>
                    <div className="flex items-center gap-2">
                      {p.is_enabled ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Operational
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-slate-500 font-medium">
                          Disabled
                        </span>
                      )}
                    </div>
                  </div>
                  <h3 className="font-semibold text-white text-base">{p.name}</h3>
                  <div className="mt-3 space-y-1.5 text-xs text-slate-400">
                    <p className="truncate">Issuer: <span className="font-mono text-slate-300">{p.issuer_url}</span></p>
                    <p>Client ID: <span className="font-mono text-slate-300">{p.client_id}</span></p>
                    <p>Client Secret: <span className="font-mono text-slate-400">{p.client_secret_masked}</span> {p.client_secret_last4 && `(ends in ${p.client_secret_last4})`}</p>
                    <p>Default Role: <span className="font-medium text-white capitalize">{p.default_role}</span></p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {p.domains.map((dom, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-cyan-300 font-mono">
                          {dom}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-between">
                  <button
                    onClick={() => handleTestConnection(p.id)}
                    disabled={testingId === p.id}
                    className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${testingId === p.id ? "animate-spin" : ""}`} />
                    Test Connection
                  </button>
                  <button
                    onClick={() => handleDeleteProvider(p.id, p.name)}
                    className="p-1.5 text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
                    title="Delete Provider"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Domain Verification Center */}
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 backdrop-blur-xl space-y-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Domain Ownership Verification</h2>
          <p className="text-xs text-slate-400 mt-1">
            Publish DNS TXT records to verify company domain ownership before enabling automatic SSO routing.
          </p>
        </div>

        {/* Add Domain Form */}
        <form onSubmit={handleInitiateDomain} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={newDomainInput}
            onChange={(e) => setNewDomainInput(e.target.value)}
            placeholder="e.g. company.com"
            className="flex-1 px-4 py-2 text-sm rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
          />
          <button
            type="submit"
            className="px-4 py-2 text-xs font-semibold text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl transition-all shadow-md cursor-pointer whitespace-nowrap"
          >
            Add Domain Challenge
          </button>
        </form>

        {/* Domains Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Domain</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">DNS TXT Record Expected</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {domains.map((dom) => (
                <tr key={dom.id} className="hover:bg-slate-800/20">
                  <td className="py-3 px-3 font-medium text-white">{dom.domain_name}</td>
                  <td className="py-3 px-3">
                    {dom.status === "verified" ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Verified
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-amber-400 font-semibold">
                        Pending DNS Check
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <code className="px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300 select-all">
                        {dom.verification_token}
                      </code>
                      <button
                        onClick={() => copyToken(dom.verification_token)}
                        className="text-slate-400 hover:text-white"
                        title="Copy Record"
                      >
                        {copiedToken === dom.verification_token ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-right">
                    {dom.status !== "verified" && (
                      <button
                        onClick={() => handleVerifyDomain(dom.domain_name)}
                        className="px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 hover:bg-cyan-900/60 transition-colors"
                      >
                        Verify Now
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Configure IdP Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Configure Identity Provider</h2>
            <form onSubmit={handleCreateProvider} className="space-y-3.5 text-xs">
              <div>
                <label className="text-slate-300 block mb-1">Display Name</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g. Corporate Microsoft Entra"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Provider Type</label>
                  <select
                    value={formData.provider_type}
                    onChange={(e) => setFormData({ ...formData, provider_type: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="azure_ad">Microsoft Entra ID</option>
                    <option value="okta">Okta Workforce</option>
                    <option value="google_workspace">Google Workspace</option>
                    <option value="oidc">Generic OIDC 1.0</option>
                    <option value="saml2">SAML 2.0</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-300 block mb-1">Default JIT Role</label>
                  <select
                    value={formData.default_role}
                    onChange={(e) => setFormData({ ...formData, default_role: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="analyst">Security Analyst</option>
                    <option value="viewer">Viewer (Read-Only)</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Issuer / Discovery URL</label>
                <input
                  type="url"
                  required
                  value={formData.issuer_url}
                  onChange={(e) => setFormData({ ...formData, issuer_url: e.target.value })}
                  placeholder="https://login.microsoftonline.com/{tenant_id}/v2.0"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400 font-mono text-[11px]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Client ID</label>
                  <input
                    type="text"
                    required
                    value={formData.client_id}
                    onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400 font-mono text-[11px]"
                  />
                </div>
                <div>
                  <label className="text-slate-300 block mb-1">Client Secret</label>
                  <input
                    type="password"
                    value={formData.client_secret}
                    onChange={(e) => setFormData({ ...formData, client_secret: e.target.value })}
                    placeholder="••••••••••••"
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400 font-mono text-[11px]"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Authorized Domains (comma-separated)</label>
                <input
                  type="text"
                  value={domainChips}
                  onChange={(e) => setDomainChips(e.target.value)}
                  placeholder="apexcyberdefense.io, corp.apexcyber.com"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="enforce_sso"
                  checked={formData.enforce_sso}
                  onChange={(e) => setFormData({ ...formData, enforce_sso: e.target.checked })}
                  className="rounded bg-slate-950 border-slate-800 text-cyan-400 focus:ring-0"
                />
                <label htmlFor="enforce_sso" className="text-slate-300">
                  Enforce SSO for matching domain emails (blocks password logins)
                </label>
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
                  Save Identity Provider
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
