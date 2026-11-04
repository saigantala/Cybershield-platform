"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Key,
  Plus,
  Copy,
  Check,
  RefreshCw,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Clock,
  Lock,
  X,
  Eye,
  EyeOff,
} from "lucide-react";
import { apiApiKeys } from "@/lib/api-client";
import type { APIKey, APIKeyCreated } from "@/types/saas";

export default function ApiKeysSettingsPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Create Key Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>([
    "read:assets",
    "read:vulnerabilities",
    "read:scans",
  ]);
  const [expiresInDays, setExpiresInDays] = useState(90);
  const [creating, setCreating] = useState(false);

  // Reveal Modal
  const [createdKeyData, setCreatedKeyData] = useState<APIKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);

  const loadKeys = async () => {
    setLoading(true);
    const res = await apiApiKeys.list();
    if (res.data) {
      setKeys(res.data);
    } else {
      // Mock fallback
      setKeys([
        {
          id: "72000000-0000-0000-0000-000000000001",
          organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          key_name: "Production SOC CI/CD",
          key_prefix: "cs_live_9f8a",
          scopes: ["read:assets", "write:scans", "read:vulnerabilities"],
          created_at: "2026-10-01T10:00:00Z",
          expires_at: "2026-12-31T23:59:59Z",
          last_used_at: "2 hours ago",
          is_revoked: false,
        },
      ]);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadKeys();
  }, []);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setActionError(null);

    const res = await apiApiKeys.create({
      key_name: keyName,
      scopes: selectedScopes,
      expires_in_days: expiresInDays,
    });
    setCreating(false);

    if (res.data) {
      setShowCreateModal(false);
      setKeyName("");
      setCreatedKeyData(res.data);
      loadKeys();
    } else if (res.error) {
      setActionError(res.error);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm("Are you sure you want to permanently revoke this API key? Automated systems using it will immediately fail.")) return;
    const res = await apiApiKeys.revoke(keyId);
    if (res.data) {
      setActionSuccess("API Key revoked successfully");
      loadKeys();
      setTimeout(() => setActionSuccess(null), 3000);
    } else if (res.error) {
      setActionError(res.error);
    }
  };

  const handleRotateKey = async (keyId: string) => {
    if (!confirm("Rotating this key will revoke the current secret and issue a new one immediately. Proceed?")) return;
    const res = await apiApiKeys.rotate(keyId);
    if (res.data) {
      setCreatedKeyData(res.data);
      loadKeys();
    } else if (res.error) {
      setActionError(res.error);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleScope = (scope: string) => {
    if (selectedScopes.includes(scope)) {
      setSelectedScopes(selectedScopes.filter((s) => s !== scope));
    } else {
      setSelectedScopes([...selectedScopes, scope]);
    }
  };

  const availableScopes = [
    { id: "read:assets", label: "Read Assets & Topology", desc: "View discovered endpoints" },
    { id: "write:assets", label: "Mutate Assets", desc: "Tag and edit device metadata" },
    { id: "read:scans", label: "Read Scans", desc: "Query discovery execution telemetry" },
    { id: "write:scans", label: "Trigger Scans", desc: "Initiate network & vuln discovery" },
    { id: "read:vulnerabilities", label: "Read CVEs & Findings", desc: "Access vulnerability findings" },
    { id: "write:vulnerabilities", label: "Remediate Findings", desc: "Update remediation workflows" },
    { id: "read:threat_intel", label: "Read Threat Intel", desc: "Access CISA KEV & IOC feeds" },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/settings" className="hover:text-cyan-400 transition-colors">
              Settings
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">API Keys</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Key className="h-6 w-6 text-cyan-400" />
            API Keys & Programmatic Credentials
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Manage cryptographically hashed secrets for SOC automation, CLI pipelines, and external integrations.
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-2 transition-all self-start md:self-auto"
        >
          <Plus className="h-4 w-4" />
          Generate New Key
        </button>
      </div>

      {actionSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-xs">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{actionSuccess}</span>
        </div>
      )}
      {actionError && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-rose-300 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Security Guidance Alert */}
      <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-500/30 flex items-start gap-3">
        <Lock className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-white">SHA-256 Cryptographic Storage</div>
          <p className="text-slate-400 leading-relaxed">
            Raw API keys are displayed only once upon generation and are hashed before persistence. Store your key securely in CI/CD secrets managers or encrypted environment variables.
          </p>
        </div>
      </div>

      {/* API Keys Table */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Key className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Registered API Keys ({keys.length})</h2>
          </div>
          <span className="text-xs text-slate-400">Scoped access tokens</span>
        </div>

        {keys.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No API keys created yet. Generate a key to begin integrating external SOC pipelines.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">Key Name</th>
                  <th className="py-3 px-4 font-semibold">Prefix</th>
                  <th className="py-3 px-4 font-semibold">Authorized Scopes</th>
                  <th className="py-3 px-4 font-semibold">Created</th>
                  <th className="py-3 px-4 font-semibold">Expires</th>
                  <th className="py-3 px-4 font-semibold">Last Used</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {keys.map((k) => (
                  <tr key={k.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-3.5 px-4 font-medium text-white">{k.key_name}</td>
                    <td className="py-3.5 px-4 font-mono text-cyan-400 font-semibold">
                      {k.key_prefix}...
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {k.scopes.map((s) => (
                          <span
                            key={s}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 font-mono text-slate-300"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono">
                      {new Date(k.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono">
                      {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "Never"}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                      {k.last_used_at || "Never"}
                    </td>
                    <td className="py-3.5 px-4">
                      {k.is_revoked ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                          Revoked
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          Active
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      {!k.is_revoked && (
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleRotateKey(k.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                            title="Rotate Key"
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => handleRevokeKey(k.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                            title="Revoke Key"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg p-6 rounded-2xl bg-[#111C2D] border border-cyan-500/30 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Key className="h-4 w-4 text-cyan-400" />
                Generate Programmatic API Key
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateKey} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Descriptive Key Name</label>
                <input
                  type="text"
                  placeholder="e.g. GitHub Actions Perimeter Auditor"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Expiration Period</label>
                <select
                  value={expiresInDays}
                  onChange={(e) => setExpiresInDays(Number(e.target.value))}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value={30}>30 Days (Recommended for short automated tasks)</option>
                  <option value={60}>60 Days</option>
                  <option value={90}>90 Days (Enterprise Standard)</option>
                  <option value={180}>180 Days</option>
                  <option value={365}>1 Year (Maximum)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-medium text-slate-300">Telemetry Scopes</label>
                <div className="grid grid-cols-1 gap-2 max-h-48 overflow-y-auto pr-1">
                  {availableScopes.map((scope) => {
                    const checked = selectedScopes.includes(scope.id);
                    return (
                      <div
                        key={scope.id}
                        onClick={() => toggleScope(scope.id)}
                        className={`p-2.5 rounded-xl border cursor-pointer flex items-center justify-between text-xs transition-colors ${
                          checked
                            ? "bg-cyan-500/10 border-cyan-500/40 text-white"
                            : "bg-slate-900/60 border-slate-800 text-slate-400 hover:bg-slate-800/60"
                        }`}
                      >
                        <div>
                          <div className="font-semibold">{scope.label}</div>
                          <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                            {scope.id}
                          </div>
                        </div>
                        <input
                          type="checkbox"
                          checked={checked}
                          readOnly
                          className="rounded text-cyan-500 focus:ring-0"
                        />
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  {creating ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Plus className="h-3.5 w-3.5" />
                  )}
                  Generate Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reveal Raw Key Modal */}
      {createdKeyData && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg p-6 rounded-2xl bg-[#111C2D] border border-cyan-500/50 shadow-2xl space-y-5">
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
              <CheckCircle2 className="h-5 w-5" />
              API Key Generated Successfully
            </div>

            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4" />
                Copy your key now. It will never be displayed again!
              </div>
              <p className="text-[11px] text-amber-400/90 leading-relaxed">
                For security reasons, CyberShield hashes all API credentials immediately upon generation. If you lose this key, you will need to rotate or generate a new one.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Raw Secret Key</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={createdKeyData.raw_api_key}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-cyan-500/40 text-xs font-mono text-cyan-300 select-all"
                />
                <button
                  onClick={() => copyToClipboard(createdKeyData.raw_api_key)}
                  className="px-3.5 py-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 text-xs font-bold transition-colors"
                >
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setCreatedKeyData(null)}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-white transition-colors"
              >
                I Have Stored the Key Safely
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
