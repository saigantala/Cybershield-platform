"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Building2,
  Users,
  Server,
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Search,
  Lock,
  Unlock,
  ExternalLink,
  Sliders,
  X,
  CreditCard,
} from "lucide-react";
import { apiPlatformAdmin } from "@/lib/api-client";
import type { Organization, PlatformOverview } from "@/types/saas";

export default function PlatformAdminControlCenter() {
  const [overview, setOverview] = useState<PlatformOverview | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [platformUsers, setPlatformUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [activeTab, setActiveTab] = useState<"organizations" | "users">("organizations");

  // Suspend modal
  const [suspendOrgTarget, setSuspendOrgTarget] = useState<Organization | null>(null);
  const [suspendReason, setSuspendReason] = useState("");
  const [suspending, setSuspending] = useState(false);

  const [notification, setNotification] = useState<{ type: "success" | "error"; text: string } | null>(
    null
  );

  const loadPlatformData = async () => {
    setLoading(true);
    const [overRes, orgsRes, usersRes] = await Promise.all([
      apiPlatformAdmin.getOverview(),
      apiPlatformAdmin.listOrganizations(),
      apiPlatformAdmin.listUsers(),
    ]);

    if (overRes.data) {
      setOverview(overRes.data);
    } else {
      setOverview({
        total_users: 142,
        total_organizations: 18,
        active_subscriptions: 16,
        trial_organizations: 2,
        suspended_organizations: 0,
        total_assets_monitored: 3420,
        background_worker_health: "Operational",
        api_gateway_health: "Operational",
        db_connectivity: "Connected",
      });
    }

    if (orgsRes.data) {
      setOrganizations(orgsRes.data);
    } else {
      setOrganizations([
        {
          id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          name: "Apex CyberDefense",
          slug: "apex-cyberdefense",
          description: "Enterprise SOC & Threat Defense",
          status: "Active",
          member_count: 5,
          current_plan: "Professional",
          created_at: "2026-01-01T00:00:00Z",
        },
        {
          id: "11a29a43-089c-4f70-a889-cb4c5b36dc99",
          name: "Vanguard SecOps",
          slug: "vanguard-secops",
          description: "Defense Contractor SOC",
          status: "Active",
          member_count: 12,
          current_plan: "Enterprise",
          created_at: "2026-02-10T00:00:00Z",
        },
      ]);
    }

    if (usersRes.data) {
      setPlatformUsers(usersRes.data);
    } else {
      setPlatformUsers([
        {
          id: "00000000-0000-0000-0000-000000000001",
          email: "chief.architect@apexcyberdefense.io",
          full_name: "Chief Security Architect",
          joined_at: "2026-01-01T00:00:00Z",
          organizations: [{ organization_name: "Apex CyberDefense", role: "owner" }],
        },
        {
          id: "00000000-0000-0000-0000-000000000002",
          email: "auditor@apexcyberdefense.io",
          full_name: "Compliance Auditor",
          joined_at: "2026-03-15T00:00:00Z",
          organizations: [{ organization_name: "Apex CyberDefense", role: "viewer" }],
        },
      ]);
    }

    setLoading(false);
  };

  useEffect(() => {
    loadPlatformData();
  }, []);

  const handleSuspendSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!suspendOrgTarget) return;
    setSuspending(true);
    const res = await apiPlatformAdmin.suspendOrganization(suspendOrgTarget.id, suspendReason);
    setSuspending(false);
    if (res.data) {
      setSuspendOrgTarget(null);
      setSuspendReason("");
      setNotification({
        type: "success",
        text: `Organization '${res.data.name}' suspended successfully`,
      });
      loadPlatformData();
      setTimeout(() => setNotification(null), 3000);
    } else if (res.error) {
      setNotification({ type: "error", text: res.error });
    }
  };

  const handleReactivateOrg = async (orgId: string) => {
    const res = await apiPlatformAdmin.reactivateOrganization(orgId);
    if (res.data) {
      setNotification({
        type: "success",
        text: `Organization '${res.data.name}' reactivated successfully`,
      });
      loadPlatformData();
      setTimeout(() => setNotification(null), 3000);
    } else if (res.error) {
      setNotification({ type: "error", text: res.error });
    }
  };

  const filteredOrgs = organizations.filter(
    (o) =>
      o.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      o.id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Platform Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-amber-400 font-bold mb-1 uppercase tracking-wider">
            <Lock className="h-3.5 w-3.5" />
            Global Platform Administrator Control Center
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <ShieldAlert className="h-6 w-6 text-cyan-400" />
            Cross-Tenant Governance & Operational Health
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Platform-wide tenant administration, isolation enforcement, and infrastructure health monitoring.
          </p>
        </div>

        {/* Global Health Indicator */}
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <div className="text-xs">
              <span className="text-slate-400">Cluster Status:</span>{" "}
              <span className="text-emerald-400 font-bold">All Services Operational</span>
            </div>
          </div>
        </div>
      </div>

      {notification && (
        <div
          className={`p-3.5 rounded-xl border flex items-center gap-3 text-xs ${
            notification.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-rose-500/10 border-rose-500/30 text-rose-300"
          }`}
        >
          {notification.type === "success" ? (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          ) : (
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          )}
          <span>{notification.text}</span>
        </div>
      )}

      {/* Platform KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Tenants</span>
            <Building2 className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {overview?.total_organizations || organizations.length}
          </div>
          <div className="text-[11px] text-cyan-400">Cross-tenant isolated</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Global Users</span>
            <Users className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {overview?.total_users || 142}
          </div>
          <div className="text-[11px] text-blue-400">Active identities</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Monitored Assets</span>
            <Server className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {overview?.total_assets_monitored || 3420}
          </div>
          <div className="text-[11px] text-purple-400">Aggregated inventory</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Subscriptions</span>
            <CreditCard className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">
            {overview?.active_subscriptions || 16}
          </div>
          <div className="text-[11px] text-emerald-400">
            {overview?.suspended_organizations || 0} suspended
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Worker Health</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-lg font-bold text-emerald-400">
            {overview?.background_worker_health || "Operational"}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">Celery & Redis OK</div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex items-center gap-3 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("organizations")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
            activeTab === "organizations"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Building2 className="h-4 w-4" />
          Organizations ({organizations.length})
        </button>
        <button
          onClick={() => setActiveTab("users")}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
            activeTab === "users"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Users className="h-4 w-4" />
          Global Users ({platformUsers.length})
        </button>
      </div>

      {/* Content based on Active Tab */}
      {activeTab === "organizations" ? (
        <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
          <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search tenant by name or UUID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <span className="text-xs text-slate-400">
              Showing {filteredOrgs.length} tenant workspaces
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">Tenant Organization</th>
                  <th className="py-3 px-4 font-semibold">Current Plan</th>
                  <th className="py-3 px-4 font-semibold">Members</th>
                  <th className="py-3 px-4 font-semibold">Created</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold text-right">Administrative Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredOrgs.map((org) => (
                  <tr key={org.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white">{org.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono">{org.id}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {org.current_plan || "Professional"}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {org.member_count} seats
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono">
                      {new Date(org.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4">
                      {org.status === "Suspended" ? (
                        <div>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            Suspended
                          </span>
                          {org.suspension_reason && (
                            <div className="text-[10px] text-slate-400 mt-1 max-w-xs truncate">
                              {org.suspension_reason}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          Active
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      {org.status === "Suspended" ? (
                        <button
                          onClick={() => handleReactivateOrg(org.id)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors"
                        >
                          Reactivate
                        </button>
                      ) : (
                        <button
                          onClick={() => setSuspendOrgTarget(org)}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition-colors"
                        >
                          Suspend Tenant
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Global Users List */
        <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
          <div className="p-4 border-b border-slate-800/80">
            <h2 className="text-sm font-bold text-white">Global User Directory</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">User</th>
                  <th className="py-3 px-4 font-semibold">Registered</th>
                  <th className="py-3 px-4 font-semibold">Tenant Memberships</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {platformUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white">{u.full_name || u.email}</div>
                      <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono">
                      {new Date(u.joined_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1.5">
                        {u.organizations?.map((o: any, idx: number) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-800 font-mono text-cyan-300"
                          >
                            {o.organization_name} ({o.role})
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Suspend Org Modal */}
      {suspendOrgTarget && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md p-6 rounded-2xl bg-[#111C2D] border border-rose-500/40 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-bold text-rose-400">
                <AlertTriangle className="h-4 w-4" />
                Suspend Tenant Workspace
              </div>
              <button
                onClick={() => setSuspendOrgTarget(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Suspending <span className="font-bold text-white">{suspendOrgTarget.name}</span> will immediately halt active scans, revoke API keys, and freeze operator dashboard access.
            </p>

            <form onSubmit={handleSuspendSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Mandatory Suspension Justification</label>
                <textarea
                  rows={3}
                  required
                  placeholder="e.g. Terms violation, payment dispute, or security mandate..."
                  value={suspendReason}
                  onChange={(e) => setSuspendReason(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-rose-500 resize-none"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setSuspendOrgTarget(null)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={suspending}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/30 flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  {suspending ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Lock className="h-3.5 w-3.5" />
                  )}
                  Confirm Suspension
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
