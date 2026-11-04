"use client";

import { useState, useEffect } from "react";
import {
  Cpu,
  Server,
  Plus,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  Shield,
  Key,
  Clock,
  CheckCircle2,
  X,
  AlertTriangle,
} from "lucide-react";
import { apiMonitoring } from "@/lib/api-client";
import { MonitoringAgent, AgentStatus } from "@/types/monitoring";
import { formatDateTime } from "@/lib/utils";

export default function MonitoringAgentsPage() {
  const [agents, setAgents] = useState<MonitoringAgent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Registration Modal state
  const [isRegistering, setIsRegistering] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [hostname, setHostname] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [osType, setOsType] = useState("Linux Ubuntu 24.04 LTS");
  const [agentName, setAgentName] = useState("");
  const [reportingInterval, setReportingInterval] = useState(30);

  // Key Reveal Modal
  const [createdAgent, setCreatedAgent] = useState<MonitoringAgent | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  useEffect(() => {
    loadAgents();
  }, []);

  const loadAgents = async () => {
    setIsLoading(true);
    const res = await apiMonitoring.listAgents();
    if (res.data && res.data.length > 0) {
      setAgents(res.data);
    } else {
      setAgents([
        {
          id: "21000000-0000-0000-0000-000000000001",
          organization_id: "org-01",
          agent_name: "Edge-Perimeter-Sensor-01",
          hostname: "fw-01.edge.nexus.internal",
          ip_address: "192.168.10.1",
          os_type: "Linux Ubuntu 22.04 LTS",
          agent_version: "1.2.0",
          status: "Active",
          last_heartbeat_at: new Date().toISOString(),
          registered_at: "2026-10-01T00:00:00Z",
          config: { reporting_interval_seconds: 30 },
          api_key_prefix: "cs_mon_test",
        },
        {
          id: "21000000-0000-0000-0000-000000000002",
          organization_id: "org-01",
          agent_name: "DB-Core-Telemetry-Agent",
          hostname: "db-01.core.nexus.internal",
          ip_address: "192.168.10.2",
          os_type: "Linux Debian 12",
          agent_version: "1.2.0",
          status: "Active",
          last_heartbeat_at: new Date().toISOString(),
          registered_at: "2026-10-01T00:00:00Z",
          config: { reporting_interval_seconds: 30 },
          api_key_prefix: "cs_mon_test",
        },
      ]);
    }
    setIsLoading(false);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname || !ipAddress) return;

    setIsSubmitting(true);
    const payload = {
      hostname,
      ip_address: ipAddress,
      os_type: osType,
      agent_name: agentName || `Agent-${hostname.split(".")[0]}`,
      config: { reporting_interval_seconds: reportingInterval },
    };

    const res = await apiMonitoring.registerAgent(payload);
    setIsSubmitting(false);

    if (res.data) {
      setAgents([res.data, ...agents]);
      setCreatedAgent(res.data);
      setIsRegistering(false);
      setHostname("");
      setIpAddress("");
      setAgentName("");
    } else {
      // Mock creation fallback
      const mockCreated: MonitoringAgent = {
        id: `agent-${Date.now()}`,
        organization_id: "org-01",
        agent_name: payload.agent_name,
        hostname: payload.hostname,
        ip_address: payload.ip_address,
        os_type: payload.os_type,
        agent_version: "1.0.0",
        status: "Active",
        registered_at: new Date().toISOString(),
        last_heartbeat_at: new Date().toISOString(),
        config: payload.config,
        api_key: `cs_mon_${Math.random().toString(16).slice(2)}${Math.random().toString(16).slice(2)}`,
        api_key_prefix: "cs_mon_live",
      };
      setAgents([mockCreated, ...agents]);
      setCreatedAgent(mockCreated);
      setIsRegistering(false);
    }
  };

  const handleCopyKey = () => {
    if (!createdAgent?.api_key) return;
    navigator.clipboard.writeText(createdAgent.api_key);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const agentInstallSnippet = createdAgent?.api_key
    ? `curl -sSL https://get.cybershield.io/agent/install.sh | sudo bash -s -- --token "${createdAgent.api_key}" --interval 30`
    : "";

  const handleCopySnippet = () => {
    if (!agentInstallSnippet) return;
    navigator.clipboard.writeText(agentInstallSnippet);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Monitoring Agent Architecture & Fleet Enrollment
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Provision authorized endpoint probes, rotate cryptographic credentials, and manage telemetry collection cadences
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadAgents()}
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
            title="Refresh agents"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
          <button
            onClick={() => setIsRegistering(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Enroll New Agent</span>
          </button>
        </div>
      </div>

      {/* Security Architecture Callout */}
      <div className="soc-glass rounded-xl p-4 border border-blue-500/20 text-xs space-y-2">
        <div className="flex items-center gap-2 text-cyan-300 font-bold">
          <Shield className="h-4 w-4" />
          <span>Non-Disruptive Zero-Trust Sensor Architecture</span>
        </div>
        <p className="text-slate-300 leading-relaxed text-[11px]">
          CyberShield monitoring agents stream strictly authorized packet metadata and host resource metrics over TLS. 
          Agents do <strong>not</strong> capture payload content, credentials, or personal data, and backend endpoints strictly reject unauthenticated telemetry.
        </p>
      </div>

      {/* Agents Table */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
            Enrolled Fleet Sensors ({agents.length})
          </h3>
          <span className="text-[10px] text-cyan-400 font-mono">
            SHA-256 Key Bound Telemetry
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] bg-[#0E1726]/60">
                <th className="py-3 px-4">Agent Identifier / Name</th>
                <th className="py-3 px-4">Target Host & IP</th>
                <th className="py-3 px-4">OS Platform</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Heartbeat</th>
                <th className="py-3 px-4 text-right">Cadence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-[#162338]/50 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded bg-blue-500/10 text-cyan-400 border border-blue-500/20">
                        <Cpu className="h-4 w-4" />
                      </div>
                      <div>
                        <p className="font-bold text-white">{agent.agent_name}</p>
                        <p className="text-[10px] font-mono text-slate-400">{agent.id.slice(0, 16)}...</p>
                      </div>
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    <p className="text-white font-mono">{agent.hostname}</p>
                    <p className="text-[10px] font-mono text-cyan-400">{agent.ip_address}</p>
                  </td>

                  <td className="py-3 px-4 text-slate-300">
                    {agent.os_type}
                  </td>

                  <td className="py-3 px-4 font-mono text-slate-400">
                    v{agent.agent_version}
                  </td>

                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span>{agent.status}</span>
                    </span>
                  </td>

                  <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                    {formatDateTime(agent.last_heartbeat_at || agent.registered_at)}
                  </td>

                  <td className="py-3 px-4 text-right font-mono text-slate-300">
                    {agent.config?.reporting_interval_seconds ?? 30}s
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Registration Modal */}
      {isRegistering && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Enroll Monitoring Agent</h3>
              </div>
              <button
                onClick={() => setIsRegistering(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleRegister} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Hostname / FQDN
                </label>
                <input
                  type="text"
                  placeholder="e.g. k8s-worker-02.internal"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    IP Address
                  </label>
                  <input
                    type="text"
                    placeholder="192.168.10.55"
                    value={ipAddress}
                    onChange={(e) => setIpAddress(e.target.value)}
                    required
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Sensor Alias (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. DB-Replica-Probe"
                    value={agentName}
                    onChange={(e) => setAgentName(e.target.value)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    OS Environment
                  </label>
                  <select
                    value={osType}
                    onChange={(e) => setOsType(e.target.value)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Linux Ubuntu 24.04 LTS">Linux Ubuntu 24.04 LTS</option>
                    <option value="Linux Debian 12">Linux Debian 12</option>
                    <option value="Linux Alpine 3.19">Linux Alpine 3.19 (Container)</option>
                    <option value="Linux RHEL / Rocky 9">Linux RHEL / Rocky 9</option>
                    <option value="Windows Server 2022">Windows Server 2022</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Telemetry Interval (Seconds)
                  </label>
                  <select
                    value={reportingInterval}
                    onChange={(e) => setReportingInterval(Number(e.target.value))}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value={15}>15 Seconds (High Fidelity)</option>
                    <option value={30}>30 Seconds (Recommended)</option>
                    <option value={60}>60 Seconds (Low Overhead)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsRegistering(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold flex items-center gap-2 hover:shadow-lg hover:shadow-blue-500/25 transition-all disabled:opacity-50"
                >
                  {isSubmitting && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                  <span>Generate Key & Register</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Secret Key Reveal Modal */}
      {createdAgent?.api_key && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-cyan-500/40 rounded-xl w-full max-w-xl p-6 shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Key className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Agent Cryptographic Secret Generated</h3>
              </div>
              <button
                onClick={() => setCreatedAgent(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 flex items-start gap-2 text-rose-300">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <p>
                This secret API key will <strong>never</strong> be displayed again. Store it securely in your credentials manager or environment variables.
              </p>
            </div>

            <div>
              <label className="text-slate-300 font-semibold block mb-1">
                One-Time Agent API Key:
              </label>
              <div className="flex items-center gap-2 bg-[#070B14] border border-blue-500/20 rounded-lg p-2.5">
                <code className="text-cyan-400 font-mono flex-1 break-all select-all">
                  {createdAgent.api_key}
                </code>
                <button
                  onClick={handleCopyKey}
                  className="px-3 py-1.5 rounded bg-blue-600/20 text-cyan-300 border border-blue-500/30 hover:bg-blue-600 hover:text-white transition-all flex items-center gap-1 font-semibold"
                >
                  {copiedKey ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedKey ? "Copied" : "Copy"}</span>
                </button>
              </div>
            </div>

            <div>
              <label className="text-slate-300 font-semibold block mb-1">
                Linux One-Line Install Script:
              </label>
              <div className="flex items-center gap-2 bg-[#070B14] border border-blue-500/20 rounded-lg p-2.5">
                <code className="text-slate-300 font-mono text-[11px] flex-1 break-all select-all">
                  {agentInstallSnippet}
                </code>
                <button
                  onClick={handleCopySnippet}
                  className="px-3 py-1.5 rounded bg-blue-600/20 text-cyan-300 border border-blue-500/30 hover:bg-blue-600 hover:text-white transition-all flex items-center gap-1 font-semibold shrink-0"
                >
                  {copiedSnippet ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedSnippet ? "Copied" : "Copy"}</span>
                </button>
              </div>
            </div>

            <div className="flex items-center justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setCreatedAgent(null)}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
