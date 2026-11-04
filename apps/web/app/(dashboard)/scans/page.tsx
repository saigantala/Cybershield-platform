"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import {
  Radar,
  Play,
  Square,
  AlertTriangle,
  Clock,
  Shield,
  Terminal,
  Plus,
  RefreshCw,
  Info,
  CheckCircle2,
  XCircle,
  FileCheck2,
  Lock,
  Layers,
} from "lucide-react";
import { mockScans, mockScanScopes } from "@/lib/mockData";
import { Scan, ScanProfile, ScanType } from "@cybershield/shared-types";
import { getStatusBadge, formatDateTime } from "@/lib/utils";
import { apiScans, apiScopes } from "@/lib/api-client";

interface ScopeRecord {
  id: string;
  scope_name: string;
  cidr_range: string;
  authorization_status: "Approved" | "Pending" | "Rejected" | "Expired" | string;
  authorization_basis?: string;
  max_scan_rate?: number;
  expires_at?: string;
  created_at?: string;
}

export default function ScanCenterPage() {
  const [activeTab, setActiveTab] = useState<"orchestrator" | "scopes">("orchestrator");
  const [scans, setScans] = useState<Scan[]>(mockScans);
  const [selectedScan, setSelectedScan] = useState<Scan>(mockScans[0]);
  const [scopes, setScopes] = useState<ScopeRecord[]>([]);
  const [isLoadingScopes, setIsLoadingScopes] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [isRegisteringScope, setIsRegisteringScope] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // New Scan Form State
  const [scanTitle, setScanTitle] = useState("");
  const [scanType, setScanType] = useState<ScanType>("network_discovery");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("fast_discovery");
  const [selectedScopeId, setSelectedScopeId] = useState<string>("");
  const [authorizedConfirmation, setAuthorizedConfirmation] = useState(false);

  // New Scope Form State
  const [newScopeName, setNewScopeName] = useState("");
  const [newScopeCidr, setNewScopeCidr] = useState("");
  const [newScopeBasis, setNewScopeBasis] = useState("");
  const [newScopeMaxRate, setNewScopeMaxRate] = useState(1000);

  // Live timeline events for selected scan
  const [liveEvents, setLiveEvents] = useState<Array<{ id?: string; event_type: string; message: string; created_at?: string }>>([]);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const showNotification = (type: "success" | "error", message: string) => {
    setActionFeedback({ type, message });
    setTimeout(() => setActionFeedback(null), 5000);
  };

  // 1. Fetch Scopes from backend
  const fetchScopes = useCallback(async () => {
    setIsLoadingScopes(true);
    try {
      const res = await apiScopes.list();
      if (res.data && Array.isArray(res.data) && res.data.length > 0) {
        setScopes(res.data);
        if (!selectedScopeId) {
          const firstApproved = res.data.find((s) => s.authorization_status === "Approved");
          if (firstApproved) setSelectedScopeId(firstApproved.id);
        }
      } else {
        // Fallback to mock scopes mapped to schema
        const mappedMock = mockScanScopes.map((ms) => ({
          id: ms.id,
          scope_name: ms.description || `Scope ${ms.target}`,
          cidr_range: ms.target,
          authorization_status: ms.status === "approved" ? "Approved" : "Pending",
          authorization_basis: "Internal Infrastructure Charter RFC 1918",
          max_scan_rate: 1000,
          expires_at: new Date(Date.now() + 86400000 * 90).toISOString(),
          created_at: ms.createdAt,
        }));
        setScopes(mappedMock);
        if (!selectedScopeId && mappedMock.length > 0) {
          setSelectedScopeId(mappedMock[0].id);
        }
      }
    } catch (err: any) {
      console.warn("Failed to load scopes, using fallback:", err);
    } finally {
      setIsLoadingScopes(false);
    }
  }, [selectedScopeId]);

  // 2. Fetch Scans from backend
  const fetchScans = useCallback(async () => {
    try {
      const res = await apiScans.list();
      if (res.data && Array.isArray(res.data) && res.data.length > 0) {
        const mapped: Scan[] = res.data.map((s: any) => ({
          id: s.id,
          organizationId: s.organization_id,
          title: s.title,
          type: s.type,
          profile: s.profile,
          targetScope: s.target_scope,
          status: s.status,
          progress: s.progress,
          startedAt: s.started_at,
          completedAt: s.completed_at,
          hostsDiscovered: s.hosts_discovered,
          findingsCount: s.findings_count || { critical: 0, high: 0, medium: 0, low: 0 },
          initiatedBy: s.initiated_by,
          logs: [],
        }));
        setScans(mapped);
        if (!selectedScan && mapped.length > 0) {
          setSelectedScan(mapped[0]);
        }
      }
    } catch (err) {
      console.warn("Using local scans fallback:", err);
    }
  }, [selectedScan]);

  // 3. Poll Scan Events for selected scan
  const fetchEvents = useCallback(async (scanId: string) => {
    try {
      const res = await apiScans.getEvents(scanId);
      if (res.data && Array.isArray(res.data) && res.data.length > 0) {
        setLiveEvents(res.data);
      }
    } catch (err) {
      // Ignore background poll errors
    }
  }, []);

  useEffect(() => {
    fetchScopes();
    fetchScans();
  }, [fetchScopes, fetchScans]);

  // Active polling for running scan
  useEffect(() => {
    if (!selectedScan) return;

    fetchEvents(selectedScan.id);

    if (selectedScan.status === "running" || selectedScan.status === "queued") {
      pollRef.current = setInterval(async () => {
        fetchEvents(selectedScan.id);
        const scanRes = await apiScans.get(selectedScan.id);
        if (scanRes.data) {
          setSelectedScan((prev) => ({
            ...prev,
            status: scanRes.data.status,
            progress: scanRes.data.progress,
            hostsDiscovered: scanRes.data.hosts_discovered,
          }));
          setScans((prev) =>
            prev.map((s) =>
              s.id === scanRes.data.id
                ? {
                    ...s,
                    status: scanRes.data.status,
                    progress: scanRes.data.progress,
                    hostsDiscovered: scanRes.data.hosts_discovered,
                  }
                : s
            )
          );
        }
      }, 2500);
    }

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [selectedScan, fetchEvents]);

  // Filter approved scopes
  const approvedScopes = scopes.filter((s) => s.authorization_status === "Approved");
  const activeSelectedScope = scopes.find((s) => s.id === selectedScopeId);

  // Handle Launch Scan
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanTitle || !selectedScopeId || !authorizedConfirmation) {
      showNotification("error", "You must confirm explicit authorization before launching any scan.");
      return;
    }

    const scopeRecord = scopes.find((s) => s.id === selectedScopeId);
    if (!scopeRecord || scopeRecord.authorization_status !== "Approved") {
      showNotification("error", "Target scope must hold an active 'Approved' status.");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await apiScans.create({
        title: scanTitle,
        type: scanType,
        profile: scanProfile,
        target_scope: scopeRecord.cidr_range,
        scope_id: scopeRecord.id,
      });

      if (res.error) {
        showNotification("error", res.error);
        setIsSubmitting(false);
        return;
      }

      const launchedScan: Scan = {
        id: res.data?.id || `scan-${Date.now()}`,
        organizationId: res.data?.organization_id || "org-01",
        title: scanTitle,
        type: scanType,
        profile: scanProfile,
        targetScope: scopeRecord.cidr_range,
        status: "running",
        progress: 15,
        startedAt: new Date().toISOString(),
        hostsDiscovered: 0,
        findingsCount: { critical: 0, high: 0, medium: 0, low: 0 },
        initiatedBy: "security-operator@cybershield.internal",
        logs: [
          `[${new Date().toISOString()}] Scan authorized under scope '${scopeRecord.scope_name}' (${scopeRecord.cidr_range})`,
          `[${new Date().toISOString()}] Background worker executing discovery pipeline...`,
        ],
      };

      setScans([launchedScan, ...scans]);
      setSelectedScan(launchedScan);
      setIsLaunching(false);
      setScanTitle("");
      setAuthorizedConfirmation(false);
      showNotification("success", `Authorized discovery job dispatched for ${scopeRecord.cidr_range}`);
    } catch (err: any) {
      showNotification("error", err.message || "Failed to launch scan");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle Scope Registration
  const handleRegisterScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScopeName || !newScopeCidr || !newScopeBasis) {
      showNotification("error", "All scope fields are required.");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await apiScopes.create({
        scope_name: newScopeName,
        cidr_range: newScopeCidr,
        authorization_basis: newScopeBasis,
        max_scan_rate: newScopeMaxRate,
      });

      if (res.error) {
        showNotification("error", res.error);
        setIsSubmitting(false);
        return;
      }

      showNotification("success", `Scope '${newScopeName}' registered and submitted for authorization.`);
      setIsRegisteringScope(false);
      setNewScopeName("");
      setNewScopeCidr("");
      setNewScopeBasis("");
      await fetchScopes();
    } catch (err: any) {
      showNotification("error", err.message || "Failed to register scope");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle Scope Approval (Admin/Owner Action)
  const handleApproveScope = async (scopeId: string) => {
    try {
      const res = await apiScopes.approve(scopeId);
      if (res.error) {
        showNotification("error", res.error);
        return;
      }
      showNotification("success", "Scope authorization approved for security assessments.");
      await fetchScopes();
    } catch (err: any) {
      showNotification("error", err.message || "Scope approval failed");
    }
  };

  // Handle Cancel Scan
  const handleCancelScan = async (id: string) => {
    try {
      await apiScans.cancel(id);
      showNotification("success", "Scan cancellation signal delivered to worker.");
      setScans((prev) =>
        prev.map((s) => (s.id === id ? { ...s, status: "cancelled" } : s))
      );
      if (selectedScan.id === id) {
        setSelectedScan((prev) => ({ ...prev, status: "cancelled" }));
      }
      fetchEvents(id);
    } catch (err: any) {
      showNotification("error", err.message || "Failed to cancel scan");
    }
  };

  return (
    <div className="space-y-6">
      {/* Feedback Notification */}
      {actionFeedback && (
        <div
          className={`p-3.5 rounded-xl border flex items-center justify-between text-xs font-semibold animate-in fade-in duration-200 ${
            actionFeedback.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-rose-500/10 border-rose-500/30 text-rose-300"
          }`}
        >
          <div className="flex items-center gap-2">
            {actionFeedback.type === "success" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : (
              <AlertTriangle className="h-4 w-4 shrink-0" />
            )}
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Radar className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Scan Center & Assessment Orchestrator
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Authorized RFC 1918 discovery sweeps, scope governance, and live timeline telemetry
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="flex rounded-lg bg-[#0B1220] p-1 border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab("orchestrator")}
              className={`px-3 py-1.5 rounded-md font-semibold transition-all ${
                activeTab === "orchestrator"
                  ? "bg-blue-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Active Orchestrator
            </button>
            <button
              onClick={() => setActiveTab("scopes")}
              className={`px-3 py-1.5 rounded-md font-semibold transition-all flex items-center gap-1.5 ${
                activeTab === "scopes"
                  ? "bg-blue-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Shield className="h-3.5 w-3.5" />
              <span>Scope Governance ({scopes.length})</span>
            </button>
          </div>

          <button
            onClick={() => setIsLaunching(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>Launch Authorized Scan</span>
          </button>
        </div>
      </div>

      {/* Scope Governance Tab */}
      {activeTab === "scopes" ? (
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <Lock className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-sm font-bold text-white">
                  Authorized Scope Management Policy
                </h3>
                <p className="text-xs text-slate-300 mt-0.5">
                  Only private networks (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, max /16)
                  with registered authorization can be evaluated. Public internet scanning is strictly blocked.
                </p>
              </div>
            </div>
            <button
              onClick={() => setIsRegisteringScope(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white transition-colors shrink-0"
            >
              <Plus className="h-4 w-4" />
              <span>Register New Scope</span>
            </button>
          </div>

          {/* Scopes Table */}
          <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
            <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Network Scopes Register
              </h3>
              <span className="text-[10px] font-mono text-slate-400">
                {scopes.length} Registered Ranges
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                    <th className="py-2.5 px-4">Scope Name</th>
                    <th className="py-2.5 px-4">CIDR Subnet</th>
                    <th className="py-2.5 px-4">Authorization Status</th>
                    <th className="py-2.5 px-4">Authorization Basis</th>
                    <th className="py-2.5 px-4">Max Rate</th>
                    <th className="py-2.5 px-4">Expiration</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-medium">
                  {scopes.map((s) => (
                    <tr key={s.id} className="hover:bg-[#162338]/40 transition-colors">
                      <td className="py-3 px-4 font-bold text-white">{s.scope_name}</td>
                      <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                        {s.cidr_range}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                            s.authorization_status === "Approved"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                              : s.authorization_status === "Pending"
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                              : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                          }`}
                        >
                          {s.authorization_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-[200px] truncate" title={s.authorization_basis}>
                        {s.authorization_basis || "Standard RFC 1918 Scope"}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {s.max_scan_rate || 1000} pps
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {s.expires_at ? formatDateTime(s.expires_at) : "90 days"}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {s.authorization_status === "Pending" ? (
                          <button
                            onClick={() => handleApproveScope(s.id)}
                            className="px-2.5 py-1 rounded bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600 hover:text-white text-[11px] font-bold transition-all"
                          >
                            Approve Scope
                          </button>
                        ) : (
                          <span className="text-[11px] text-slate-500 font-mono">
                            Authorized
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        /* Active Orchestrator Tab */
        <div className="space-y-6">
          {/* Main Grid: Active Scan Monitor & Realtime Terminal */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Selected Scan Detail Card */}
            <div className="lg:col-span-1 soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    Selected Scan Operation
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                      selectedScan.status
                    )}`}
                  >
                    {selectedScan.status}
                  </span>
                </div>

                <div>
                  <h3 className="font-bold text-base text-white">{selectedScan.title}</h3>
                  <p className="text-xs font-mono text-cyan-400 mt-1">
                    Target CIDR: {selectedScan.targetScope}
                  </p>
                </div>

                {/* Progress Bar */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Pipeline Progress</span>
                    <span className="font-mono text-cyan-400 font-bold">
                      {selectedScan.progress}%
                    </span>
                  </div>
                  <div className="w-full bg-[#080D18] h-2.5 rounded-full overflow-hidden border border-slate-800 p-0.5">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-300"
                      style={{ width: `${selectedScan.progress}%` }}
                    />
                  </div>
                </div>

                {/* Scan Metrics */}
                <div className="grid grid-cols-2 gap-3 text-xs pt-2">
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Type</span>
                    <span className="font-semibold text-slate-200 capitalize">
                      {selectedScan.type.replace("_", " ")}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Profile</span>
                    <span className="font-semibold text-slate-200 capitalize">
                      {selectedScan.profile.replace("_", " ")}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Discovered Hosts</span>
                    <span className="font-mono text-cyan-400 font-bold">
                      {selectedScan.hostsDiscovered} Endpoints
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0B1220] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Started At</span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {formatDateTime(selectedScan.startedAt)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Cancellation Button */}
              <div className="pt-4 border-t border-slate-800 mt-4">
                {selectedScan.status === "running" || selectedScan.status === "queued" ? (
                  <button
                    onClick={() => handleCancelScan(selectedScan.id)}
                    className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-rose-600/20 text-rose-300 border border-rose-500/40 hover:bg-rose-600 hover:text-white text-xs font-bold transition-all"
                  >
                    <Square className="h-3.5 w-3.5 fill-current" />
                    <span>Halt & Cancel Scan</span>
                  </button>
                ) : (
                  <div className="text-center text-[11px] text-slate-400 font-mono">
                    Scan execution finished ({selectedScan.status})
                  </div>
                )}
              </div>
            </div>

            {/* Real-time Scan Execution Logs & Timeline */}
            <div className="lg:col-span-2 soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                    Live Telemetry Console & Scan Events
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  {selectedScan.status === "running" && (
                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
                      <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                      LISTENING
                    </span>
                  )}
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    SCAN_ID: {selectedScan.id.substring(0, 8)}...
                  </span>
                </div>
              </div>

              <div className="flex-1 bg-[#060A12] border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-slate-300 overflow-y-auto max-h-[340px] space-y-1.5 select-text">
                {liveEvents.length > 0 ? (
                  liveEvents.map((ev, idx) => (
                    <div
                      key={ev.id || idx}
                      className={
                        ev.event_type === "error"
                          ? "text-rose-400 font-bold"
                          : ev.event_type === "cancelled"
                          ? "text-amber-400"
                          : ev.event_type === "completed"
                          ? "text-emerald-400 font-bold"
                          : "text-slate-300"
                      }
                    >
                      <span className="text-slate-500 mr-2">
                        [{ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : "LIVE"}]
                      </span>
                      <span className="text-cyan-400 uppercase font-semibold mr-1.5">
                        [{ev.event_type}]
                      </span>
                      {ev.message}
                    </div>
                  ))
                ) : selectedScan.logs && selectedScan.logs.length > 0 ? (
                  selectedScan.logs.map((log, index) => (
                    <div
                      key={index}
                      className={
                        log.includes("CRITICAL") || log.includes("STOPPED")
                          ? "text-rose-400 font-bold"
                          : log.includes("DEMO")
                          ? "text-amber-400 font-semibold"
                          : "text-slate-300"
                      }
                    >
                      {log}
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500 italic py-6 text-center">
                    Awaiting worker telemetry events for scan {selectedScan.id}...
                  </div>
                )}

                {selectedScan.status === "running" && (
                  <div className="text-cyan-400 flex items-center gap-2 animate-pulse pt-2">
                    <span className="h-2 w-2 rounded-full bg-cyan-400" />
                    <span>Executing discovery engine against authorized scope...</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Scan History Table */}
          <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
            <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Scan Assessment History
              </h3>
              <span className="text-[10px] font-mono text-slate-400">
                {scans.length} Recorded Security Sweeps
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                    <th className="py-2.5 px-4">Scan Name</th>
                    <th className="py-2.5 px-4">Scan Type</th>
                    <th className="py-2.5 px-4">Target Subnet</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Hosts Discovered</th>
                    <th className="py-2.5 px-4">Started At</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-medium">
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      onClick={() => {
                        setSelectedScan(scan);
                        fetchEvents(scan.id);
                      }}
                      className={`hover:bg-[#162338]/40 transition-colors cursor-pointer ${
                        selectedScan.id === scan.id ? "bg-[#162338]/60" : ""
                      }`}
                    >
                      <td className="py-3 px-4 font-bold text-white">{scan.title}</td>
                      <td className="py-3 px-4 capitalize text-slate-300">
                        {scan.type.replace("_", " ")}
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                        {scan.targetScope}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getStatusBadge(
                            scan.status
                          )}`}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-200">
                        {scan.hostsDiscovered} Endpoints
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {formatDateTime(scan.startedAt)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedScan(scan);
                            fetchEvents(scan.id);
                          }}
                          className="text-cyan-400 hover:text-cyan-300 font-semibold text-xs hover:underline"
                        >
                          Inspect Telemetry
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Launch Scan Modal with Mandatory Authorization Verification */}
      {isLaunching && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Radar className="h-5 w-5 text-cyan-400" />
                Configure Authorized Network Discovery
              </h3>
              <button
                onClick={() => setIsLaunching(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Scan Title
                </label>
                <input
                  type="text"
                  placeholder="e.g. Q4 Core Infrastructure Discovery"
                  value={scanTitle}
                  onChange={(e) => setScanTitle(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Target Scope (Select Registered Range)
                </label>
                {approvedScopes.length > 0 ? (
                  <select
                    value={selectedScopeId}
                    onChange={(e) => setSelectedScopeId(e.target.value)}
                    required
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                  >
                    {approvedScopes.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.scope_name} — {s.cidr_range} (Approved)
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-[11px]">
                    No approved scopes available. Please register and approve a private RFC 1918 scope before scanning.
                  </div>
                )}
                {activeSelectedScope && (
                  <p className="text-[10px] text-slate-400 mt-1 font-mono">
                    Active CIDR: {activeSelectedScope.cidr_range} • Rate: {activeSelectedScope.max_scan_rate || 1000} pps
                  </p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Assessment Type
                  </label>
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value as ScanType)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value="network_discovery">Network Discovery</option>
                    <option value="vulnerability_assessment">Vulnerability Assessment</option>
                    <option value="web_baseline">Web Application Baseline</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Discovery Profile
                  </label>
                  <select
                    value={scanProfile}
                    onChange={(e) => setScanProfile(e.target.value as ScanProfile)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                  >
                    <option value="fast_discovery">Fast Discovery (Non-intrusive)</option>
                    <option value="comprehensive_audit">Comprehensive Audit (Standard)</option>
                    <option value="web_baseline_safe">Safe Web Baseline</option>
                  </select>
                </div>
              </div>

              {/* Strict Legal and Policy Authorization Checkbox */}
              <div className="p-3.5 rounded-lg bg-blue-950/30 border border-blue-500/30 space-y-2">
                <label className="flex items-start gap-2.5 cursor-pointer text-slate-200">
                  <input
                    type="checkbox"
                    checked={authorizedConfirmation}
                    onChange={(e) => setAuthorizedConfirmation(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 bg-[#0B1220] text-cyan-500 focus:ring-cyan-400 shrink-0"
                  />
                  <span className="text-[11px] leading-relaxed text-slate-300">
                    <strong className="text-white block mb-0.5">Authorization Certification:</strong>
                    I confirm and certify that I have explicit authorization to assess this target scope
                    in accordance with organizational cybersecurity policy, legal agreements, and scope boundaries.
                  </span>
                </label>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsLaunching(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!authorizedConfirmation || approvedScopes.length === 0 || isSubmitting}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg hover:shadow-blue-500/25 transition-all flex items-center gap-1.5"
                >
                  {isSubmitting ? (
                    <>
                      <div className="h-3 w-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Dispatching...</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5 fill-current" />
                      <span>Dispatch Scan Worker</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Scope Registration Modal */}
      {isRegisteringScope && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Shield className="h-5 w-5 text-cyan-400" />
                Register Authorized Network Scope
              </h3>
              <button
                onClick={() => setIsRegisteringScope(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRegisterScope} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Scope Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. Corporate Engineering Subnet"
                  value={newScopeName}
                  onChange={(e) => setNewScopeName(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  CIDR Network Range (RFC 1918 Private Ranges Only)
                </label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.0/24, 10.0.0.0/16"
                  value={newScopeCidr}
                  onChange={(e) => setNewScopeCidr(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                />
                <span className="text-[10px] text-slate-400 mt-1 block">
                  Permitted ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Max prefix: /16).
                </span>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Authorization Basis / Charter Reference
                </label>
                <textarea
                  placeholder="e.g. CISO Security Assessment Authorization Memo Ref #SEC-2026-Q4"
                  value={newScopeBasis}
                  onChange={(e) => setNewScopeBasis(e.target.value)}
                  required
                  rows={3}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Max Discovery Packet Rate (pps)
                </label>
                <input
                  type="number"
                  min={100}
                  max={5000}
                  value={newScopeMaxRate}
                  onChange={(e) => setNewScopeMaxRate(parseInt(e.target.value, 10) || 1000)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsRegisteringScope(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold"
                >
                  {isSubmitting ? "Submitting..." : "Submit For Approval"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
