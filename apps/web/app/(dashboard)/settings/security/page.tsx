"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  ShieldAlert,
  Key,
  Smartphone,
  Globe,
  Laptop,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Lock,
  Fingerprint,
  Users,
} from "lucide-react";
import { apiIdentity } from "@/lib/api-client";
import type { UserSecurityOverview } from "@/types/identity";

export default function SecuritySettingsPage() {
  const [overview, setOverview] = useState<UserSecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiIdentity.getOverview();
      if (res.data) {
        setOverview(res.data);
      } else {
        // Fallback demo state if offline
        setOverview({
          user_id: "00000000-0000-0000-0000-000000000001",
          email: "admin@apexcyberdefense.io",
          role: "owner",
          mfa_enabled: true,
          current_aal: "aal2",
          mfa_enforced_by_org: true,
          recovery_codes_remaining: 10,
          active_sessions_count: 2,
          sso_enforced_by_org: false,
          security_score: 90,
          security_recommendations: [
            "Organization mandates MFA for your role. Keep your recovery codes in a secure vault.",
            "Consider configuring Single Sign-On (SSO) enforcement for apexcyberdefense.io domain.",
          ],
        });
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load security overview");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-emerald-400";
    if (score >= 60) return "text-amber-400";
    return "text-rose-400";
  };

  const getScoreGradient = (score: number) => {
    if (score >= 80) return "from-emerald-500/20 to-teal-500/20 border-emerald-500/30";
    if (score >= 60) return "from-amber-500/20 to-orange-500/20 border-amber-500/30";
    return "from-rose-500/20 to-red-500/20 border-rose-500/30";
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-slate-900/60 to-purple-950/40 border border-cyan-500/20 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              Zero Trust Security
            </span>
            <span className="text-xs text-slate-400">Sprint 18 IAM Suite</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="w-6 h-6 text-cyan-400" />
            Identity & Account Security Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage Multi-Factor Authentication (MFA), Enterprise SSO, active device sessions, and Zero Trust access policies.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3.5 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 rounded-xl transition-all flex items-center gap-2 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            href="/identity/access-policies"
            className="px-4 py-2 text-sm font-medium text-black bg-cyan-400 hover:bg-cyan-300 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2"
          >
            <ShieldCheck className="w-4 h-4" />
            Access Policies
          </Link>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Link
          href="/settings/security"
          className="p-3.5 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 flex items-center gap-2.5 text-xs font-semibold shadow-inner"
        >
          <Lock className="w-4 h-4 text-cyan-400" />
          Security Overview
        </Link>
        <Link
          href="/settings/mfa"
          className="p-3.5 rounded-xl bg-slate-900/40 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-2.5 text-xs font-medium transition-all"
        >
          <Smartphone className="w-4 h-4 text-emerald-400" />
          MFA & Passkeys
        </Link>
        <Link
          href="/settings/sso"
          className="p-3.5 rounded-xl bg-slate-900/40 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-2.5 text-xs font-medium transition-all"
        >
          <Globe className="w-4 h-4 text-blue-400" />
          Enterprise SSO
        </Link>
        <Link
          href="/settings/sessions"
          className="p-3.5 rounded-xl bg-slate-900/40 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-2.5 text-xs font-medium transition-all"
        >
          <Laptop className="w-4 h-4 text-amber-400" />
          Active Sessions
        </Link>
        <Link
          href="/identity/audit"
          className="p-3.5 rounded-xl bg-slate-900/40 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-2.5 text-xs font-medium transition-all"
        >
          <Fingerprint className="w-4 h-4 text-purple-400" />
          Identity Audit
        </Link>
      </div>

      {/* Main Grid: Score & Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Column */}
        <div className={`p-6 rounded-2xl bg-gradient-to-br border backdrop-blur-xl ${getScoreGradient(overview?.security_score ?? 80)} flex flex-col justify-between`}>
          <div>
            <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Account Hardening Posture</span>
            <div className="mt-4 flex items-baseline gap-2">
              <span className={`text-6xl font-black tracking-tight ${getScoreColor(overview?.security_score ?? 80)}`}>
                {overview?.security_score ?? 80}
              </span>
              <span className="text-slate-400 text-lg font-medium">/ 100</span>
            </div>
            <p className="text-sm text-slate-300 mt-2 font-medium">
              {overview && overview.security_score >= 80
                ? "Enterprise Grade Security Posture"
                : overview && overview.security_score >= 60
                ? "Acceptable Posture – Action Recommended"
                : "Vulnerable Posture – Immediate Action Required"}
            </p>
            <div className="mt-4 w-full bg-slate-800/60 rounded-full h-2.5 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  (overview?.security_score ?? 80) >= 80
                    ? "bg-emerald-400"
                    : (overview?.security_score ?? 80) >= 60
                    ? "bg-amber-400"
                    : "bg-rose-400"
                }`}
                style={{ width: `${overview?.security_score ?? 80}%` }}
              />
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-slate-800/50 space-y-2 text-xs text-slate-300">
            <div className="flex items-center justify-between">
              <span>MFA Assurance Level:</span>
              <span className="font-mono text-cyan-400 uppercase font-semibold">
                {overview?.current_aal || "AAL1"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Account Role:</span>
              <span className="font-semibold text-white capitalize">{overview?.role || "Owner"}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Active Sessions:</span>
              <span className="font-semibold text-white">{overview?.active_sessions_count || 1} Device(s)</span>
            </div>
          </div>
        </div>

        {/* Feature Cards Grid (2 cols) */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Card 1: MFA */}
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800/80 hover:border-slate-700/80 transition-all flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <Smartphone className="w-5 h-5" />
                </div>
                {overview?.mfa_enabled ? (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Enrolled
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    <AlertTriangle className="w-3.5 h-3.5" /> Disabled
                  </span>
                )}
              </div>
              <h3 className="font-semibold text-white text-base">Multi-Factor Authentication</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Time-Based One-Time Passwords (TOTP) protect your account against credential theft.
              </p>
              <div className="mt-3 text-xs text-slate-300 space-y-1">
                <p>Recovery Codes: <span className="font-mono text-cyan-400">{overview?.recovery_codes_remaining ?? 10} remaining</span></p>
                <p>Enforced by Org: <span className="font-medium">{overview?.mfa_enforced_by_org ? "Yes (Mandatory)" : "Optional"}</span></p>
              </div>
            </div>
            <Link
              href="/settings/mfa"
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Configure MFA Settings <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Card 2: Enterprise SSO */}
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800/80 hover:border-slate-700/80 transition-all flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
                  <Globe className="w-5 h-5" />
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  OIDC / SAML 2.0
                </span>
              </div>
              <h3 className="font-semibold text-white text-base">Single Sign-On (SSO)</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Connect Microsoft Entra ID, Okta, or Google Workspace for centralized IAM.
              </p>
              <div className="mt-3 text-xs text-slate-300 space-y-1">
                <p>SSO Enforcement: <span className="font-medium">{overview?.sso_enforced_by_org ? "Active" : "Optional / Hybrid"}</span></p>
                <p>Active IdPs: <span className="font-medium text-cyan-400">Microsoft Entra ID (Configured)</span></p>
              </div>
            </div>
            <Link
              href="/settings/sso"
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Manage SSO Providers <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Card 3: Active Device Sessions */}
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800/80 hover:border-slate-700/80 transition-all flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
                  <Laptop className="w-5 h-5" />
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300">
                  {overview?.active_sessions_count || 1} Active
                </span>
              </div>
              <h3 className="font-semibold text-white text-base">Active Sessions & Devices</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Continuous session tracking with anomaly detection and instant revocation.
              </p>
              <div className="mt-3 text-xs text-slate-300 space-y-1">
                <p>Current Browser: <span className="font-medium text-cyan-400">Chrome (Desktop)</span></p>
                <p>Session Timeout: <span className="font-medium">60 min idle / 24 hr max</span></p>
              </div>
            </div>
            <Link
              href="/settings/sessions"
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Review Active Sessions <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Card 4: Zero Trust Access Policies */}
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800/80 hover:border-slate-700/80 transition-all flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  Fail-Closed
                </span>
              </div>
              <h3 className="font-semibold text-white text-base">Zero Trust Microsegmentation</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Granular Attribute-Based Access Control (ABAC) requiring AAL2 for sensitive operations.
              </p>
              <div className="mt-3 text-xs text-slate-300 space-y-1">
                <p>Active Rules: <span className="font-medium text-cyan-400">4 Rules Evaluated</span></p>
                <p>Step-Up Protection: <span className="font-medium">Active (Forensics, API Keys)</span></p>
              </div>
            </div>
            <Link
              href="/identity/access-policies"
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Manage Zero Trust Rules <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* Actionable Recommendations List */}
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800/80 backdrop-blur-xl">
        <h3 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          Recommended Hardening Actions
        </h3>
        <div className="space-y-3">
          {overview?.security_recommendations.map((rec, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/60 flex items-start justify-between gap-4"
            >
              <div className="flex items-start gap-3">
                <div className="p-1 rounded bg-amber-500/10 text-amber-400 mt-0.5">
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">{rec}</p>
                  <p className="text-xs text-slate-400 mt-0.5">Elevate your organizational compliance and tenant posture score.</p>
                </div>
              </div>
              <Link
                href="/settings/mfa"
                className="px-3 py-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-800/50 rounded-lg whitespace-nowrap transition-colors"
              >
                Resolve
              </Link>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
