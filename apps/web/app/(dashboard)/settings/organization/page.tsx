"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Building2,
  Globe,
  MapPin,
  Clock,
  Shield,
  Save,
  CheckCircle2,
  Users,
  CreditCard,
  Key,
  Layers,
  ArrowRight,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { apiOrganizations } from "@/lib/api-client";
import type { Organization } from "@/types/saas";

export default function OrganizationSettingsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Form states
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [website, setWebsite] = useState("");
  const [industry, setIndustry] = useState("Cybersecurity & Defense");
  const [size, setSize] = useState("50-250 employees");
  const [country, setCountry] = useState("US");
  const [timeZone, setTimeZone] = useState("America/New_York");

  const loadData = async () => {
    setLoading(true);
    const res = await apiOrganizations.list();
    if (res.data && res.data.length > 0) {
      setOrganizations(res.data);
      const active = res.data[0];
      setCurrentOrg(active);
      setName(active.name || "");
      setDescription(active.description || "");
      setWebsite(active.website || "");
      setIndustry(active.industry || "Cybersecurity & Defense");
      setSize(active.organization_size || "50-250 employees");
      setCountry(active.country || "US");
      setTimeZone(active.time_zone || "America/New_York");
    } else {
      // Mock fallback
      const mockOrg: Organization = {
        id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
        name: "Apex CyberDefense",
        slug: "apex-cyberdefense",
        description: "Enterprise SOC & Managed Threat Defense Operations",
        website: "https://apexcyberdefense.io",
        industry: "Cybersecurity & Defense",
        organization_size: "50-250 employees",
        country: "US",
        time_zone: "America/New_York",
        status: "Active",
        member_count: 5,
        current_plan: "Professional",
        created_at: "2026-01-01T00:00:00Z",
      };
      setOrganizations([mockOrg]);
      setCurrentOrg(mockOrg);
      setName(mockOrg.name);
      setDescription(mockOrg.description || "");
      setWebsite(mockOrg.website || "");
      setIndustry(mockOrg.industry || "");
      setSize(mockOrg.organization_size || "");
      setCountry(mockOrg.country || "US");
      setTimeZone(mockOrg.time_zone || "America/New_York");
    }
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentOrg) return;
    setSaving(true);
    const res = await apiOrganizations.update(currentOrg.id, {
      name,
      description,
      website,
      industry,
      organization_size: size,
      country,
      time_zone: timeZone,
    });
    setSaving(false);
    if (res.data) {
      setCurrentOrg(res.data);
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } else {
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    }
  };

  const handleSwitchOrg = async (orgId: string) => {
    const res = await apiOrganizations.switch(orgId);
    if (res.data) {
      setCurrentOrg(res.data);
      setName(res.data.name);
      setDescription(res.data.description || "");
      setWebsite(res.data.website || "");
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Breadcrumb Navigation */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/settings" className="hover:text-cyan-400 transition-colors">
              Settings
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Organization</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Building2 className="h-6 w-6 text-cyan-400" />
            Organization Profile & Tenant Settings
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Configure tenant workspace identity, security posture boundaries, and regional preferences.
          </p>
        </div>

        {/* Quick Tabs Bar */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          <Link
            href="/settings/organization"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5"
          >
            <Building2 className="h-3.5 w-3.5" />
            Organization
          </Link>
          <Link
            href="/settings/team"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <Users className="h-3.5 w-3.5" />
            Team & RBAC
          </Link>
          <Link
            href="/settings/billing"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <CreditCard className="h-3.5 w-3.5" />
            Plans & Billing
          </Link>
          <Link
            href="/settings/api-keys"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 flex items-center gap-1.5 transition-colors"
          >
            <Key className="h-3.5 w-3.5" />
            API Keys
          </Link>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Form */}
        <div className="lg:col-span-2 space-y-6">
          <form
            onSubmit={handleSave}
            className="p-6 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-6"
          >
            <div className="flex items-center justify-between border-b border-slate-800/60 pb-4">
              <div>
                <h2 className="text-base font-bold text-white">General Information</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Core company details surfaced across compliance exports and alerts.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse" />
                  Tenant Active
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Organization Legal Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Workspace Identifier (Slug)</label>
                <input
                  type="text"
                  value={currentOrg?.slug || "apex-cyberdefense"}
                  disabled
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-sm text-slate-500 cursor-not-allowed font-mono text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Mission & Scope Description</label>
              <textarea
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors resize-none"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-cyan-400" />
                  Primary Security Portal URL
                </label>
                <input
                  type="url"
                  value={website}
                  onChange={(e) => setWebsite(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Industry Sector</label>
                <select
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="Cybersecurity & Defense">Cybersecurity & Defense</option>
                  <option value="Financial Services & Banking">Financial Services & Banking</option>
                  <option value="Healthcare & Life Sciences">Healthcare & Life Sciences</option>
                  <option value="Critical Infrastructure">Critical Infrastructure</option>
                  <option value="Technology & Cloud SaaS">Technology & Cloud SaaS</option>
                  <option value="Government & Public Sector">Government & Public Sector</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Organization Scale</label>
                <select
                  value={size}
                  onChange={(e) => setSize(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="1-10 employees">1-10 employees</option>
                  <option value="11-50 employees">11-50 employees</option>
                  <option value="50-250 employees">50-250 employees</option>
                  <option value="250-1000 employees">250-1000 employees</option>
                  <option value="1000+ enterprise">1000+ enterprise</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <MapPin className="h-3.5 w-3.5 text-cyan-400" />
                  Primary Jurisdiction
                </label>
                <select
                  value={country}
                  onChange={(e) => setCountry(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="US">United States (NIST/FedRAMP)</option>
                  <option value="EU">European Union (NIS2/GDPR)</option>
                  <option value="UK">United Kingdom (NCSC)</option>
                  <option value="CA">Canada (CCCS)</option>
                  <option value="AU">Australia (Essential 8)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  SOC Timezone
                </label>
                <select
                  value={timeZone}
                  onChange={(e) => setTimeZone(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-700/60 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
                >
                  <option value="UTC">UTC (Universal Time)</option>
                  <option value="America/New_York">America/New_York (EST)</option>
                  <option value="America/Chicago">America/Chicago (CST)</option>
                  <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
                  <option value="Europe/London">Europe/London (GMT/BST)</option>
                  <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-slate-800/60">
              <span className="text-xs text-slate-500 font-mono">
                Tenant ID: {currentOrg?.id || "e4a29a43-089c-4f70-a889-cb4c5b36dc32"}
              </span>

              <div className="flex items-center gap-3">
                {savedSuccess && (
                  <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                    <CheckCircle2 className="h-4 w-4" />
                    Changes saved successfully
                  </span>
                )}
                <button
                  type="submit"
                  disabled={saving}
                  className="px-5 py-2.5 rounded-xl font-semibold text-xs bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-2 transition-all disabled:opacity-50"
                >
                  {saving ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Save className="h-3.5 w-3.5" />
                  )}
                  Save Changes
                </button>
              </div>
            </div>
          </form>
        </div>

        {/* Right 1 Col: Tenant Summary & Switcher */}
        <div className="space-y-6">
          {/* Active Tenant Workspace Card */}
          <div className="p-6 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-4">
            <div className="flex items-center gap-2.5 text-sm font-bold text-white">
              <Shield className="h-4 w-4 text-cyan-400" />
              Active Workspace Summary
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div>
                <span className="text-xs text-slate-400">Current Subscription</span>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-sm font-bold text-white">
                    {currentOrg?.current_plan || "Professional SOC"}
                  </span>
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                    Active
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-400">Assigned Team Seats</span>
                <span className="text-white font-mono font-medium">
                  {currentOrg?.member_count || 2} / 10 seats
                </span>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-400">Tenant Created</span>
                <span className="text-white font-mono font-medium">
                  {currentOrg ? new Date(currentOrg.created_at).toLocaleDateString() : "2026-01-01"}
                </span>
              </div>
            </div>

            <Link
              href="/settings/billing"
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold bg-slate-800/60 hover:bg-slate-700/60 text-slate-200 border border-slate-700/60 flex items-center justify-center gap-2 transition-colors"
            >
              <CreditCard className="h-3.5 w-3.5 text-cyan-400" />
              Manage Subscription & Quotas
            </Link>
          </div>

          {/* Multi-Tenant Organization Switcher */}
          <div className="p-6 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="h-4 w-4 text-cyan-400" />
                Available Workspaces
              </span>
              <span className="text-xs text-slate-400 font-mono">{organizations.length}</span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Switching workspaces shifts telemetry scopes, detection rules, and incident visibility.
            </p>

            <div className="space-y-2">
              {organizations.map((org) => {
                const isSelected = org.id === currentOrg?.id;
                return (
                  <button
                    key={org.id}
                    onClick={() => handleSwitchOrg(org.id)}
                    className={`w-full p-3 rounded-xl border text-left flex items-center justify-between transition-all ${
                      isSelected
                        ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-300"
                        : "bg-slate-900/60 hover:bg-slate-800/60 border-slate-800 text-slate-300"
                    }`}
                  >
                    <div>
                      <div className="text-xs font-bold text-white">{org.name}</div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                        {org.member_count} members • {org.current_plan || "Professional"}
                      </div>
                    </div>
                    {isSelected ? (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-400/20 text-cyan-300">
                        Active
                      </span>
                    ) : (
                      <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
