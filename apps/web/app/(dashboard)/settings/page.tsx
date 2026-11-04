"use client";

import { useState } from "react";
import {
  Settings,
  Shield,
  Bell,
  Sliders,
  User,
  CheckCircle2,
  Building2,
  Paintbrush,
  Save,
  Moon,
  Sparkles,
  Lock,
} from "lucide-react";
import { mockOrganizations, mockCurrentUser } from "@/lib/mockData";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"profile" | "org" | "notifications" | "appearance">("profile");

  // Profile Form
  const [fullName, setFullName] = useState(mockCurrentUser.fullName);
  const [email, setEmail] = useState(mockCurrentUser.email);
  const [mfaEnabled, setMfaEnabled] = useState(true);

  // Organization Form
  const [orgName, setOrgName] = useState(mockOrganizations[0].name);
  const [domain, setDomain] = useState(mockOrganizations[0].verifiedDomain || "");
  const [plan, setPlan] = useState(mockOrganizations[0].plan);

  // Notification Preferences
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [pushAlerts, setPushAlerts] = useState(true);
  const [criticalOnly, setCriticalOnly] = useState(false);

  // Appearance Settings
  const [themeMode, setThemeMode] = useState("dark-soc");
  const [glassIntensity, setGlassIntensity] = useState("high");
  const [refreshInterval, setRefreshInterval] = useState("10");

  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    window.setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Settings className="h-6 w-6 text-cyan-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Settings & Platform Configuration
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Manage your personal profile, tenant identity, alert preferences, and SOC console appearance
          </p>
        </div>

        {saved && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-semibold animate-pulse">
            <CheckCircle2 className="h-4 w-4" />
            <span>Settings Saved Successfully</span>
          </div>
        )}
      </div>

      {/* Settings Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs">
        <button
          onClick={() => setActiveTab("profile")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
            activeTab === "profile"
              ? "bg-blue-600 text-white"
              : "text-slate-400 hover:text-white hover:bg-slate-800"
          }`}
        >
          <User className="h-3.5 w-3.5" />
          <span>Profile Settings</span>
        </button>

        <button
          onClick={() => setActiveTab("org")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
            activeTab === "org"
              ? "bg-blue-600 text-white"
              : "text-slate-400 hover:text-white hover:bg-slate-800"
          }`}
        >
          <Building2 className="h-3.5 w-3.5" />
          <span>Organization Settings</span>
        </button>

        <button
          onClick={() => setActiveTab("notifications")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
            activeTab === "notifications"
              ? "bg-blue-600 text-white"
              : "text-slate-400 hover:text-white hover:bg-slate-800"
          }`}
        >
          <Bell className="h-3.5 w-3.5" />
          <span>Notification Preferences</span>
        </button>

        <button
          onClick={() => setActiveTab("appearance")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-semibold transition-colors ${
            activeTab === "appearance"
              ? "bg-blue-600 text-white"
              : "text-slate-400 hover:text-white hover:bg-slate-800"
          }`}
        >
          <Paintbrush className="h-3.5 w-3.5" />
          <span>Appearance Settings</span>
        </button>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Tab 1: Profile Settings */}
        {activeTab === "profile" && (
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <User className="h-4 w-4 text-cyan-400" />
              Security Lead Operator Profile
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Corporate Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>

            <div className="pt-2">
              <label className="flex items-center gap-3 cursor-pointer text-xs">
                <input
                  type="checkbox"
                  checked={mfaEnabled}
                  onChange={(e) => setMfaEnabled(e.target.checked)}
                  className="rounded bg-[#0B1220] border-slate-700 text-blue-600 focus:ring-0 h-4 w-4"
                />
                <div>
                  <span className="text-slate-200 font-semibold block">
                    FIDO2 / Hardware Security Token (MFA) Mandate
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Requires WebAuthn / hardware security key authentication on every sign-in.
                  </span>
                </div>
              </label>
            </div>
          </div>
        )}

        {/* Tab 2: Organization Settings */}
        {activeTab === "org" && (
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Building2 className="h-4 w-4 text-cyan-400" />
              Tenant Workspace Boundaries
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Organization Legal Name
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Apex Domain Validation
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-300 font-semibold block mb-1 text-xs">
                Subscription Tier
              </label>
              <select
                value={plan}
                onChange={(e) => setPlan(e.target.value as any)}
                className="w-full max-w-xs bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 text-xs capitalize"
              >
                <option value="enterprise">Enterprise Tier (Unlimited Scopes)</option>
                <option value="professional">Professional Tier (10 Subnets)</option>
                <option value="standard">Standard Tier (3 Subnets)</option>
              </select>
            </div>
          </div>
        )}

        {/* Tab 3: Notification Preferences */}
        {activeTab === "notifications" && (
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Bell className="h-4 w-4 text-cyan-400" />
              Real-Time Alert Dispatch
            </h3>

            <div className="space-y-3 text-xs">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={emailAlerts}
                  onChange={(e) => setEmailAlerts(e.target.checked)}
                  className="rounded bg-[#0B1220] border-slate-700 text-blue-600 focus:ring-0 h-4 w-4"
                />
                <div>
                  <span className="text-slate-200 font-semibold block">
                    Email Notifications
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Receive instant security notices for Critical/High CVEs and scan completions.
                  </span>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={pushAlerts}
                  onChange={(e) => setPushAlerts(e.target.checked)}
                  className="rounded bg-[#0B1220] border-slate-700 text-blue-600 focus:ring-0 h-4 w-4"
                />
                <div>
                  <span className="text-slate-200 font-semibold block">
                    Mobile Push Notifications
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Dispatch alerts directly to on-call mobile analysts.
                  </span>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={criticalOnly}
                  onChange={(e) => setCriticalOnly(e.target.checked)}
                  className="rounded bg-[#0B1220] border-slate-700 text-blue-600 focus:ring-0 h-4 w-4"
                />
                <div>
                  <span className="text-slate-200 font-semibold block">
                    Mute Low &amp; Medium Vulnerability Alerts
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Only trigger push alarms for CVSS &gt;= 7.0 or CISA KEV hits.
                  </span>
                </div>
              </label>
            </div>
          </div>
        )}

        {/* Tab 4: Appearance Settings */}
        {activeTab === "appearance" && (
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Paintbrush className="h-4 w-4 text-cyan-400" />
              SOC Display & Visual Aesthetics
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Color Theme Palette
                </label>
                <select
                  value={themeMode}
                  onChange={(e) => setThemeMode(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                >
                  <option value="dark-soc">Dark Glassmorphism SOC (Default)</option>
                  <option value="cyber-midnight">Cyber Midnight</option>
                  <option value="high-contrast">High Contrast Threat Command</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Glassmorphism Blur Level
                </label>
                <select
                  value={glassIntensity}
                  onChange={(e) => setGlassIntensity(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400"
                >
                  <option value="high">High Blur (16px backdrop blur)</option>
                  <option value="medium">Medium Blur (8px)</option>
                  <option value="low">Subtle (Solid dark cards)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Telemetry Auto-Refresh (Seconds)
                </label>
                <input
                  type="number"
                  value={refreshInterval}
                  onChange={(e) => setRefreshInterval(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/20 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>
          </div>
        )}

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            type="submit"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold text-xs hover:shadow-lg hover:shadow-blue-500/25 active:scale-95 transition-all"
          >
            <Save className="h-4 w-4" />
            <span>Save Settings</span>
          </button>
        </div>
      </form>
    </div>
  );
}
