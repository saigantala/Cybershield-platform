"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Users,
  UserPlus,
  Shield,
  Trash2,
  Mail,
  Clock,
  AlertCircle,
  CheckCircle2,
  RefreshCw,
  Building2,
  CreditCard,
  Key,
  ShieldAlert,
  Send,
  X,
} from "lucide-react";
import { apiTeam, apiSubscriptions } from "@/lib/api-client";
import type { OrganizationMember, OrganizationInvitation, SubscriptionUsage } from "@/types/saas";

export default function TeamSettingsPage() {
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [usage, setUsage] = useState<SubscriptionUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Invite modal state
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "analyst" | "viewer">("analyst");
  const [inviting, setInviting] = useState(false);

  const loadTeamData = async () => {
    setLoading(true);
    setActionError(null);

    const [membersRes, invRes, usageRes] = await Promise.all([
      apiTeam.listMembers(),
      apiTeam.listInvitations(),
      apiSubscriptions.getUsage(),
    ]);

    if (membersRes.data) {
      setMembers(membersRes.data);
    } else {
      // Mock fallback
      setMembers([
        {
          id: "f5b39a43-089c-4f70-a889-cb4c5b36dc33",
          user_id: "00000000-0000-0000-0000-000000000001",
          organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          email: "chief.architect@apexcyberdefense.io",
          role: "owner",
          full_name: "Chief Security Architect",
          joined_at: "2026-01-01T00:00:00Z",
          last_active: "Just now",
        },
        {
          id: "a1b2c3d4-089c-4f70-a889-cb4c5b36dc44",
          user_id: "00000000-0000-0000-0000-000000000002",
          organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          email: "auditor@apexcyberdefense.io",
          role: "viewer",
          full_name: "Compliance Auditor",
          joined_at: "2026-03-15T00:00:00Z",
          last_active: "2 hours ago",
        },
      ]);
    }

    if (invRes.data) {
      setInvitations(invRes.data);
    } else {
      setInvitations([
        {
          id: "71000000-0000-0000-0000-000000000001",
          organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
          email: "sarah.connor@cyberdefense.org",
          role: "analyst",
          status: "Pending",
          expires_at: "2026-11-07T00:00:00Z",
          created_at: "2026-10-31T12:00:00Z",
        },
      ]);
    }

    if (usageRes.data) {
      setUsage(usageRes.data);
    } else {
      setUsage({
        organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
        plan_code: "PROFESSIONAL",
        assets_used: 12,
        assets_limit: 250,
        members_used: 2,
        members_limit: 10,
        monthly_scans_used: 8,
        monthly_scans_limit: 100,
        ai_requests_used: 14,
        ai_requests_limit: 1000,
        period_start: "2026-10-01",
        period_end: "2026-11-01",
      });
    }

    setLoading(false);
  };

  useEffect(() => {
    loadTeamData();
  }, []);

  const handleRoleChange = async (memberId: string, newRole: string) => {
    setActionError(null);
    setActionSuccess(null);
    const res = await apiTeam.updateMemberRole(memberId, newRole);
    if (res.error) {
      setActionError(res.error);
    } else {
      setActionSuccess(`Role updated to ${newRole}`);
      loadTeamData();
      setTimeout(() => setActionSuccess(null), 3000);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!confirm("Are you sure you want to remove this member from the organization?")) return;
    setActionError(null);
    setActionSuccess(null);
    const res = await apiTeam.removeMember(memberId);
    if (res.error) {
      setActionError(res.error);
    } else {
      setActionSuccess("Member removed from organization");
      loadTeamData();
      setTimeout(() => setActionSuccess(null), 3000);
    }
  };

  const handleInviteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviting(true);
    setActionError(null);
    const res = await apiTeam.inviteMember({
      email: inviteEmail,
      role: inviteRole,
    });
    setInviting(false);
    if (res.error) {
      setActionError(res.error);
    } else {
      setShowInviteModal(false);
      setInviteEmail("");
      setActionSuccess(`Invitation sent to ${inviteEmail}`);
      loadTeamData();
      setTimeout(() => setActionSuccess(null), 3000);
    }
  };

  const handleResendInvitation = async (invId: string) => {
    const res = await apiTeam.resendInvitation(invId);
    if (res.error) {
      setActionError(res.error);
    } else {
      setActionSuccess("Invitation refreshed and resent");
      loadTeamData();
      setTimeout(() => setActionSuccess(null), 3000);
    }
  };

  const handleCancelInvitation = async (invId: string) => {
    const res = await apiTeam.cancelInvitation(invId);
    if (res.error) {
      setActionError(res.error);
    } else {
      setActionSuccess("Invitation cancelled");
      loadTeamData();
      setTimeout(() => setActionSuccess(null), 3000);
    }
  };

  const roleColors: Record<string, string> = {
    owner: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    admin: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    analyst: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    viewer: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Breadcrumb */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/settings" className="hover:text-cyan-400 transition-colors">
              Settings
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Team & RBAC</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Users className="h-6 w-6 text-cyan-400" />
            Team Members & Centralized Access Control
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Manage operational seat allocation, role-based authorization, and team analyst onboarding.
          </p>
        </div>

        {/* Action Button & Quota Pill */}
        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs flex items-center gap-2">
            <span className="text-slate-400">Team Seats:</span>
            <span className="text-white font-mono font-bold">
              {usage?.members_used || members.length} / {usage?.members_limit || 10}
            </span>
          </div>

          <button
            onClick={() => setShowInviteModal(true)}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-2 transition-all"
          >
            <UserPlus className="h-4 w-4" />
            Invite Member
          </button>
        </div>
      </div>

      {/* Action Notifications */}
      {actionError && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-rose-300 text-xs">
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{actionError}</span>
        </div>
      )}
      {actionSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-xs">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Members Table */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Active Team Members ({members.length})</h2>
          </div>
          <span className="text-xs text-slate-400">
            Least-privilege RBAC enforced by PostgreSQL Row Level Security
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">User</th>
                <th className="py-3 px-4 font-semibold">Role & Permissions</th>
                <th className="py-3 px-4 font-semibold">Joined</th>
                <th className="py-3 px-4 font-semibold">Last Active</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {members.map((member) => (
                <tr key={member.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-600/30 to-cyan-500/30 border border-cyan-500/30 flex items-center justify-center font-bold text-xs text-cyan-300">
                        {member.email.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <div className="font-semibold text-white">
                          {member.full_name || member.email.split("@")[0]}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">{member.email}</div>
                      </div>
                    </div>
                  </td>

                  <td className="py-3.5 px-4">
                    <select
                      value={member.role}
                      onChange={(e) => handleRoleChange(member.id, e.target.value)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-semibold border focus:outline-none focus:border-cyan-400 bg-slate-900 cursor-pointer ${
                        roleColors[member.role] || "text-slate-300 border-slate-700"
                      }`}
                    >
                      <option value="owner">Owner (Full Control)</option>
                      <option value="admin">Admin (Manage Assets & Scans)</option>
                      <option value="analyst">Analyst (Investigate & Remediate)</option>
                      <option value="viewer">Viewer (Read-Only Telemetry)</option>
                    </select>
                  </td>

                  <td className="py-3.5 px-4 text-slate-400 font-mono">
                    {new Date(member.joined_at).toLocaleDateString()}
                  </td>

                  <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                    {member.last_active || "Recent"}
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => handleRemoveMember(member.id)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                      title="Remove Member"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pending Invitations Section */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Pending Team Invitations ({invitations.length})</h2>
          </div>
          <span className="text-xs text-slate-400">
            Valid for 7 days upon delivery
          </span>
        </div>

        {invitations.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No pending invitations. Click &quot;Invite Member&quot; to onboarding new operators.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60">
            {invitations.map((inv) => (
              <div
                key={inv.id}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/20 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-400">
                    <Mail className="h-4 w-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-white">{inv.email}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Invited as <span className="text-cyan-300 font-medium capitalize">{inv.role}</span> • Expires{" "}
                      {new Date(inv.expires_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    {inv.status}
                  </span>
                  <button
                    onClick={() => handleResendInvitation(inv.id)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                    title="Resend Invitation"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => handleCancelInvitation(inv.id)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                    title="Cancel Invitation"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md p-6 rounded-2xl bg-[#111C2D] border border-cyan-500/30 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <UserPlus className="h-4 w-4 text-cyan-400" />
                Invite Team Member
              </div>
              <button
                onClick={() => setShowInviteModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleInviteSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Analyst Email Address</label>
                <input
                  type="email"
                  placeholder="analyst@organization.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Assigned RBAC Role</label>
                <select
                  value={inviteRole}
                  onChange={(e) =>
                    setInviteRole(e.target.value as "admin" | "analyst" | "viewer")
                  }
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="analyst">Analyst (Investigate & Remediate)</option>
                  <option value="admin">Admin (Manage Assets, Scans, & Rules)</option>
                  <option value="viewer">Viewer (Read-Only SOC Telemetry)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  Owner roles must be granted by existing owners post-invitation.
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={inviting}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  {inviting ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Send className="h-3.5 w-3.5" />
                  )}
                  Send Invitation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
