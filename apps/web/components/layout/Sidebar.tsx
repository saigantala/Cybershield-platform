"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  Server,
  Network,
  Radar,
  Bug,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Activity,
  Settings,
  ChevronDown,
  Building2,
  Lock,
  ChevronLeft,
  ChevronRight,
  X,
  Globe2,
  BellRing,
  Sliders,
  Radio,
  BookOpen,
  ClipboardCheck,
  Bot,
  BarChart3,
  Users,
  CreditCard,
  Key,
  TrendingUp,
  Award,
  HeartPulse,
  Cpu,
  Workflow,
  Zap,
  PlaySquare,
  BrainCircuit,
  SearchCheck,
  Layers,
  Crosshair,
  FileSearch,
  Fingerprint,
} from "lucide-react";
import { useState, useEffect } from "react";
import { mockOrganizations } from "@/lib/mockData";
import { apiOrganizations } from "@/lib/api-client";
import { cn } from "@/lib/utils";

export const navigationItems = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Live SOC", href: "/soc-monitoring", icon: Activity },
  { name: "AI Threat Hub", href: "/ai-detection", icon: BrainCircuit },
  { name: "AI Investigations", href: "/ai-detection/investigations", icon: SearchCheck },
  { name: "AI Threat Assistant", href: "/ai-threat-investigation", icon: Bot },
  { name: "Predictive Risk", href: "/ai-detection/risk-analysis", icon: ShieldAlert },
  { name: "Detection Rules", href: "/ai-detection/rules", icon: Sliders },
  { name: "ML Models", href: "/ai-detection/models", icon: Cpu },
  { name: "SOAR Hub", href: "/soar", icon: Zap },
  { name: "SOAR Playbooks", href: "/soar/playbooks", icon: Workflow },
  { name: "SOAR Approvals", href: "/soar/approvals", icon: ClipboardCheck },
  { name: "SOAR Executions", href: "/soar/executions", icon: PlaySquare },
  { name: "SOAR Analytics", href: "/soar/analytics", icon: BarChart3 },
  { name: "Executive View", href: "/executive-dashboard", icon: TrendingUp },
  { name: "Traffic Monitor", href: "/network-monitoring", icon: Network },
  { name: "Device Health", href: "/device-health", icon: HeartPulse },
  { name: "Network Anomalies", href: "/network-anomalies", icon: AlertTriangle },
  { name: "Fleet Agents", href: "/monitoring-agents", icon: Cpu },
  { name: "Monitoring Rules", href: "/monitoring-rules", icon: Sliders },
  { name: "AI Assistant", href: "/ai-assistant", icon: Bot },
  { name: "Analytics", href: "/analytics", icon: BarChart3 },
  { name: "Threat Intel", href: "/threat-intelligence", icon: Globe2 },
  { name: "Threat Hunting", href: "/threat-hunting", icon: Crosshair },
  { name: "Digital Forensics", href: "/forensics", icon: FileSearch },
  { name: "Security Events", href: "/security-monitoring", icon: Radio },
  { name: "Alert Center", href: "/alerts", icon: BellRing },
  { name: "Incidents", href: "/incidents", icon: AlertTriangle },
  { name: "Playbooks", href: "/playbooks", icon: BookOpen },
  { name: "Approvals", href: "/response-requests", icon: ClipboardCheck },
  { name: "Assets", href: "/assets", icon: Server },
  { name: "Network Topology", href: "/topology", icon: Network },
  { name: "Scan Center", href: "/scans", icon: Radar },
  { name: "Vulnerabilities", href: "/vulnerabilities", icon: Bug },
  { name: "Risk Assessment", href: "/risk", icon: ShieldCheck },
  { name: "Security Assurance", href: "/security-assurance", icon: ShieldCheck },
  { name: "Compliance", href: "/compliance", icon: Award },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Integrations", href: "/integrations", icon: Layers },
  { name: "Webhooks", href: "/integrations/webhooks", icon: Radio },
  { name: "System Health", href: "/system-health", icon: Activity },
  { name: "Readiness Audit", href: "/admin/production-readiness", icon: ShieldCheck },
  { name: "Release Readiness", href: "/release-readiness", icon: Award },
  { name: "Audit Logs", href: "/audit-logs", icon: Activity },
  { name: "Team & RBAC", href: "/settings/team", icon: Users },
  { name: "Security & MFA", href: "/settings/security", icon: Lock },
  { name: "Identity & Zero Trust", href: "/identity/access-policies", icon: ShieldCheck },
  { name: "Identity Audit", href: "/identity/audit", icon: Fingerprint },
  { name: "Plans & Billing", href: "/settings/billing", icon: CreditCard },
  { name: "API Keys", href: "/settings/api-keys", icon: Key },
  { name: "Platform Admin", href: "/platform-admin", icon: ShieldAlert },
  { name: "Settings", href: "/settings", icon: Settings },
];

interface SidebarProps {
  isCollapsed?: boolean;
  setIsCollapsed?: (collapsed: boolean) => void;
  mobileOpen?: boolean;
  setMobileOpen?: (open: boolean) => void;
}

export function Sidebar({
  isCollapsed = false,
  setIsCollapsed,
  mobileOpen = false,
  setMobileOpen,
}: SidebarProps) {
  const pathname = usePathname();
  const [organizations, setOrganizations] = useState<any[]>(mockOrganizations);
  const [selectedOrg, setSelectedOrg] = useState<any>(mockOrganizations[0]);
  const [showOrgDropdown, setShowOrgDropdown] = useState(false);

  useEffect(() => {
    async function loadUserOrganizations() {
      try {
        const res = await apiOrganizations.list();
        if (res.data && res.data.length > 0) {
          const liveOrgs = res.data.map((o) => ({
            id: o.id,
            name: o.name,
            slug: o.slug || o.name.toLowerCase().replace(/\s+/g, "-"),
            plan: o.current_plan || "enterprise",
            isLive: true,
          }));
          setOrganizations(liveOrgs);
          setSelectedOrg(liveOrgs[0]);
        }
      } catch {
        // Fall back gracefully to mock organizations in preview mode
      }
    }
    loadUserOrganizations();
  }, []);

  const isActiveRoute = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  const sidebarContent = (
    <div className="flex flex-col h-full select-none justify-between">
      <div>
        {/* Brand Header */}
        <div className="p-4 border-b border-[#1E293B]/70 flex items-center justify-between">
          <Link
            href="/"
            onClick={() => setMobileOpen?.(false)}
            className="flex items-center gap-3 group overflow-hidden"
          >
            <div className="h-10 w-10 shrink-0 rounded-xl bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/25 group-hover:scale-105 transition-transform duration-200">
              <ShieldAlert className="h-6 w-6 text-white" />
            </div>
            {!isCollapsed && (
              <div className="transition-opacity duration-200">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-lg text-white tracking-tight">
                    Cyber<span className="text-cyan-400">Shield</span>
                  </span>
                  <span className="text-[10px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                    SOC
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono">v1.2.0-PROD</p>
              </div>
            )}
          </Link>

          {/* Mobile close button */}
          {setMobileOpen && (
            <button
              onClick={() => setMobileOpen(false)}
              className="md:hidden text-slate-400 hover:text-white p-1"
            >
              <X className="h-5 w-5" />
            </button>
          )}

          {/* Desktop collapse toggle */}
          {setIsCollapsed && (
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="hidden md:flex p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#162338] transition-colors"
              title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {isCollapsed ? (
                <ChevronRight className="h-4 w-4" />
              ) : (
                <ChevronLeft className="h-4 w-4" />
              )}
            </button>
          )}
        </div>

        {/* Organization Workspace Selector */}
        {!isCollapsed ? (
          <div className="p-3 border-b border-[#1E293B]/70 relative">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 px-1 mb-1 block">
              Tenant Workspace
            </label>
            <button
              onClick={() => setShowOrgDropdown(!showOrgDropdown)}
              className="w-full flex items-center justify-between p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 hover:border-blue-500/40 text-left transition-colors"
            >
              <div className="flex items-center gap-2.5 overflow-hidden">
                <div className="p-1.5 rounded-md bg-blue-500/10 text-cyan-400 border border-blue-500/20 shrink-0">
                  <Building2 className="h-4 w-4" />
                </div>
                <div className="truncate">
                  <p className="text-xs font-semibold text-slate-200 truncate">
                    {selectedOrg.name}
                  </p>
                  <p className="text-[10px] text-slate-400 font-mono uppercase">
                    {selectedOrg.plan}
                  </p>
                </div>
              </div>
              <ChevronDown className="h-4 w-4 text-slate-400 shrink-0 ml-1" />
            </button>

            {showOrgDropdown && (
              <div className="absolute top-full left-3 right-3 mt-1 py-1 bg-[#111C2D] border border-blue-500/30 rounded-lg shadow-xl z-50 animate-in fade-in-50 duration-150">
                {organizations.map((org) => (
                  <button
                    key={org.id}
                    onClick={() => {
                      setSelectedOrg(org);
                      setShowOrgDropdown(false);
                    }}
                    className={cn(
                      "w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-blue-600/20 transition-colors",
                      selectedOrg.id === org.id
                        ? "text-cyan-400 font-semibold bg-blue-600/10"
                        : "text-slate-300"
                    )}
                  >
                    <span className="truncate">{org.name}</span>
                    <span className="text-[10px] text-slate-400 uppercase font-mono ml-2 shrink-0">
                      {org.plan}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="p-3 border-b border-[#1E293B]/70 flex justify-center">
            <div
              className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-cyan-400"
              title={selectedOrg.name}
            >
              <Building2 className="h-4 w-4" />
            </div>
          </div>
        )}

        {/* Navigation Links */}
        <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-210px)]">
          {!isCollapsed && (
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 px-2 py-1.5">
              Command & Operations
            </div>
          )}

          {navigationItems.map((item) => {
            const isActive = isActiveRoute(item.href);
            const Icon = item.icon;

            return (
              <Link
                key={item.name}
                href={item.href}
                onClick={() => setMobileOpen?.(false)}
                className={cn(
                  "flex items-center gap-3 rounded-lg text-xs font-medium transition-all group relative",
                  isCollapsed ? "justify-center p-2.5" : "px-3 py-2",
                  isActive
                    ? "bg-gradient-to-r from-blue-600/25 to-cyan-500/10 text-cyan-300 border border-blue-500/40 shadow-sm shadow-blue-500/10 font-semibold"
                    : "text-slate-300 hover:text-white hover:bg-[#162338]"
                )}
                title={isCollapsed ? item.name : undefined}
              >
                {isActive && (
                  <div className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r-full bg-cyan-400 shadow-[0_0_8px_#22D3EE]" />
                )}
                <Icon
                  className={cn(
                    "h-4 w-4 shrink-0 transition-colors",
                    isActive
                      ? "text-cyan-400"
                      : "text-slate-400 group-hover:text-blue-400"
                  )}
                />
                {!isCollapsed && <span className="truncate">{item.name}</span>}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Engine Status & Security Boundary Pill */}
      <div className="p-3 border-t border-[#1E293B]/70 bg-[#0B1220]/80">
        {!isCollapsed ? (
          <div className="p-2.5 rounded-lg bg-[#111C2D]/80 border border-blue-500/20 text-xs">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-medium text-slate-300 flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                Scanner Engine
              </span>
              <span className="text-[10px] text-emerald-400 font-mono font-semibold">
                ISOLATED
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
              <Lock className="h-3 w-3 text-cyan-400 shrink-0" />
              <span className="truncate">Active Bound Scopes</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title="Scanner Engine: Isolated">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        className={cn(
          "hidden md:block bg-[#0B1220] border-r border-[#1E293B] h-screen sticky top-0 z-30 transition-all duration-300",
          isCollapsed ? "w-[72px]" : "w-64"
        )}
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer Overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div
            className="fixed inset-0 bg-black/75 backdrop-blur-sm"
            onClick={() => setMobileOpen?.(false)}
          />
          <aside className="relative w-72 max-w-[80vw] bg-[#0B1220] border-r border-[#1E293B] h-full z-10 shadow-2xl">
            {sidebarContent}
          </aside>
        </div>
      )}
    </>
  );
}
