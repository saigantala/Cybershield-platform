"use client";

import { useState } from "react";
import {
  Users,
  Shield,
  Plus,
  Mail,
  UserCheck,
  Lock,
  AlertCircle,
  MoreVertical,
} from "lucide-react";
import { UserRole } from "@cybershield/shared-types";

interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  status: "active" | "invited";
  lastActive: string;
  mfaEnabled: boolean;
}

const initialMembers: TeamMember[] = [
  {
    id: "mem-01",
    name: "Elena Rostova",
    email: "sec-lead@nexusdefense.internal",
    role: "owner",
    status: "active",
    lastActive: "Now",
    mfaEnabled: true,
  },
  {
    id: "mem-02",
    name: "Marcus Vance",
    email: "marcus.vance@nexusdefense.internal",
    role: "admin",
    status: "active",
    lastActive: "15 mins ago",
    mfaEnabled: true,
  },
  {
    id: "mem-03",
    name: "Aria Thorne",
    email: "aria.thorne@nexusdefense.internal",
    role: "analyst",
    status: "active",
    lastActive: "2 hours ago",
    mfaEnabled: true,
  },
  {
    id: "mem-04",
    name: "David Kim",
    email: "david.kim@nexusdefense.internal",
    role: "viewer",
    status: "active",
    lastActive: "1 day ago",
    mfaEnabled: false,
  },
];

export default function TeamAccessPage() {
  const [members, setMembers] = useState<TeamMember[]>(initialMembers);
  const [isInviting, setIsInviting] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<UserRole>("analyst");

  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail) return;

    const newMember: TeamMember = {
      id: `mem-${Date.now()}`,
      name: inviteEmail.split("@")[0].replace(".", " "),
      email: inviteEmail,
      role: inviteRole,
      status: "invited",
      lastActive: "Invitation Pending",
      mfaEnabled: false,
    };

    setMembers([...members, newMember]);
    setIsInviting(false);
    setInviteEmail("");
  };

  const getRoleBadge = (role: UserRole) => {
    switch (role) {
      case "owner":
        return "text-purple-400 bg-purple-500/10 border-purple-500/30";
      case "admin":
        return "text-cyan-400 bg-cyan-500/10 border-cyan-500/30";
      case "analyst":
        return "text-blue-400 bg-blue-500/10 border-blue-500/30";
      case "viewer":
        return "text-slate-400 bg-slate-500/10 border-slate-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Users className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Team & Role-Based Access Control (RBAC)
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enforce granular tenant roles, multi-factor authentication mandates, and scanning initiation privileges
          </p>
        </div>

        <button
          onClick={() => setIsInviting(true)}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-xs font-semibold text-white hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>Invite Security Analyst</span>
        </button>
      </div>

      {/* RBAC Permission Matrix Card */}
      <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyan-400" />
          Role Permission Privileges Matrix
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3 rounded-lg bg-[#0B1220] border border-purple-500/30 space-y-1.5">
            <span className="font-bold text-purple-400 uppercase text-[11px] block">
              Owner
            </span>
            <p className="text-slate-300 text-[11px]">
              Full tenant jurisdiction: billing, organization deletion, API keys, and all scanner execution.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1220] border border-cyan-500/30 space-y-1.5">
            <span className="font-bold text-cyan-400 uppercase text-[11px] block">
              Admin
            </span>
            <p className="text-slate-300 text-[11px]">
              Scope approval, launching Nmap/OpenVAS scans, inviting members, managing findings and incidents.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1220] border border-blue-500/30 space-y-1.5">
            <span className="font-bold text-blue-400 uppercase text-[11px] block">
              Analyst
            </span>
            <p className="text-slate-300 text-[11px]">
              Triage vulnerabilities, run authorized scans on pre-approved scopes, comment on incidents.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1220] border border-slate-700 space-y-1.5">
            <span className="font-bold text-slate-400 uppercase text-[11px] block">
              Viewer (Read-Only)
            </span>
            <p className="text-slate-400 text-[11px]">
              Audit compliance view only. Strictly blocked from launching scans or modifying finding states.
            </p>
          </div>
        </div>
      </div>

      {/* Members Table */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0B1220]/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-3 px-4">Member Name</th>
                <th className="py-3 px-4">Work Email</th>
                <th className="py-3 px-4">Security Role</th>
                <th className="py-3 px-4">MFA State</th>
                <th className="py-3 px-4">Account Status</th>
                <th className="py-3 px-4">Last Activity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {members.map((member) => (
                <tr key={member.id} className="hover:bg-[#162338]/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2.5">
                      <div className="h-7 w-7 rounded-full bg-blue-600/30 border border-blue-500/40 text-cyan-300 font-bold flex items-center justify-center text-xs">
                        {member.name.charAt(0)}
                      </div>
                      <span className="font-bold text-white">{member.name}</span>
                    </div>
                  </td>

                  <td className="py-3 px-4 font-mono text-slate-300 text-[11px]">
                    {member.email}
                  </td>

                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getRoleBadge(
                        member.role
                      )}`}
                    >
                      {member.role}
                    </span>
                  </td>

                  <td className="py-3 px-4">
                    {member.mfaEnabled ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                        <Lock className="h-3 w-3" /> Enforced
                      </span>
                    ) : (
                      <span className="text-amber-400 text-[11px]">Pending Setup</span>
                    )}
                  </td>

                  <td className="py-3 px-4">
                    <span className="capitalize text-slate-300 font-semibold text-[11px]">
                      {member.status}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                    {member.lastActive}
                  </td>

                  <td className="py-3 px-4 text-right">
                    <button className="text-slate-400 hover:text-white p-1">
                      <MoreVertical className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Invite Member Modal */}
      {isInviting && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-md p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Mail className="h-5 w-5 text-cyan-400" />
                Invite Team Member
              </h3>
              <button
                onClick={() => setIsInviting(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleInvite} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Corporate Email Address
                </label>
                <input
                  type="email"
                  placeholder="analyst@nexusdefense.internal"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  required
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Assign RBAC Security Role
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as UserRole)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 uppercase font-bold"
                >
                  <option value="analyst">Analyst (Triage & Scan)</option>
                  <option value="admin">Admin (Manage Scopes & Team)</option>
                  <option value="viewer">Viewer (Read-Only Compliance)</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/20 text-[11px] text-slate-300">
                An invitation link with Supabase Auth magic token will be dispatched to this address.
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsInviting(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold"
                >
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
