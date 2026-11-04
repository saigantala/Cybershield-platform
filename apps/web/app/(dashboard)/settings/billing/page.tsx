"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  CreditCard,
  ShieldCheck,
  Check,
  Zap,
  TrendingUp,
  Server,
  Users,
  Radar,
  Bot,
  AlertCircle,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  Download,
  Building2,
  Key,
} from "lucide-react";
import { apiSubscriptions } from "@/lib/api-client";
import type {
  OrganizationSubscription,
  SubscriptionPlan,
  SubscriptionUsage,
} from "@/types/saas";

export default function BillingSettingsPage() {
  const [subscription, setSubscription] = useState<OrganizationSubscription | null>(null);
  const [plans, setPlans] = useState<SubscriptionPlan[]>([]);
  const [usage, setUsage] = useState<SubscriptionUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadBillingData = async () => {
    setLoading(true);
    const [subRes, plansRes, usageRes] = await Promise.all([
      apiSubscriptions.getCurrent(),
      apiSubscriptions.getPlans(),
      apiSubscriptions.getUsage(),
    ]);

    if (subRes.data) {
      setSubscription(subRes.data);
    } else {
      setSubscription({
        id: "70000000-0000-0000-0000-000000000001",
        organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
        plan_id: "60000000-0000-0000-0000-000000000002",
        plan_name: "Professional SOC",
        plan_code: "PROFESSIONAL",
        status: "Active",
        billing_provider: "mock",
        current_period_start: "2026-10-01T00:00:00Z",
        current_period_end: "2026-11-01T00:00:00Z",
        cancel_at_period_end: false,
        price: 199.0,
      });
    }

    if (plansRes.data && plansRes.data.length > 0) {
      setPlans(plansRes.data);
    } else {
      setPlans([
        {
          id: "60000000-0000-0000-0000-000000000001",
          plan_name: "Free Starter",
          plan_code: "FREE",
          description: "Essential network discovery and posture assessment for small labs.",
          price: 0.0,
          currency: "USD",
          billing_interval: "monthly",
          max_members: 3,
          max_assets: 25,
          monthly_scan_limit: 10,
          ai_usage_limit: 50,
          feature_flags: {
            threat_intel: false,
            incident_response: false,
            custom_playbooks: false,
            advanced_export: false,
          },
          is_active: true,
        },
        {
          id: "60000000-0000-0000-0000-000000000002",
          plan_name: "Professional SOC",
          plan_code: "PROFESSIONAL",
          description: "Full-featured vulnerability management and threat intel operations.",
          price: 199.0,
          currency: "USD",
          billing_interval: "monthly",
          max_members: 10,
          max_assets: 250,
          monthly_scan_limit: 100,
          ai_usage_limit: 1000,
          feature_flags: {
            threat_intel: true,
            incident_response: true,
            custom_playbooks: true,
            advanced_export: true,
          },
          is_active: true,
        },
        {
          id: "60000000-0000-0000-0000-000000000003",
          plan_name: "Enterprise Defense",
          plan_code: "ENTERPRISE",
          description: "Tailored scale, custom playbooks, dedicated assistance, and unmetered reports.",
          price: 799.0,
          currency: "USD",
          billing_interval: "monthly",
          max_members: 50,
          max_assets: 2000,
          monthly_scan_limit: 1000,
          ai_usage_limit: 10000,
          feature_flags: {
            threat_intel: true,
            incident_response: true,
            custom_playbooks: true,
            advanced_export: true,
          },
          is_active: true,
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
    loadBillingData();
  }, []);

  const handleUpgrade = async (planCode: string) => {
    setCheckoutLoading(planCode);
    setActionError(null);
    const res = await apiSubscriptions.checkout({
      plan_code: planCode,
      billing_interval: "monthly",
    });
    setCheckoutLoading(null);
    if (res.data) {
      setSubscription(res.data.subscription);
      setActionSuccess(`Plan successfully updated to ${planCode}`);
      loadBillingData();
      setTimeout(() => setActionSuccess(null), 4000);
    } else if (res.error) {
      setActionError(res.error);
    }
  };

  const handleCancelAutoRenew = async () => {
    if (!confirm("Are you sure you want to cancel automatic subscription renewal?")) return;
    const res = await apiSubscriptions.cancel();
    if (res.data) {
      setSubscription(res.data);
      setActionSuccess("Subscription will cancel at period end");
      setTimeout(() => setActionSuccess(null), 4000);
    }
  };

  const calcPercent = (used: number, limit: number) => {
    if (!limit || limit === 0) return 0;
    return Math.min(Math.round((used / limit) * 100), 100);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/settings" className="hover:text-cyan-400 transition-colors">
              Settings
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Billing & Subscriptions</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <CreditCard className="h-6 w-6 text-cyan-400" />
            Subscription Tiers & Metered Usage Quotas
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Monitor plan bandwidth, asset thresholds, and flexible SaaS billing tier upgrades.
          </p>
        </div>

        {/* Current Plan Badge */}
        <div className="p-3 rounded-2xl bg-gradient-to-r from-blue-900/30 to-cyan-900/30 border border-cyan-500/30 flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-300">
            <Zap className="h-4 w-4" />
          </div>
          <div>
            <div className="text-xs text-slate-400">Current Plan</div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              {subscription?.plan_name || "Professional SOC"}
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                ${subscription?.price || 199}/mo
              </span>
            </div>
          </div>
        </div>
      </div>

      {actionSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-xs">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{actionSuccess}</span>
        </div>
      )}
      {actionError && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-rose-300 text-xs">
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{actionError}</span>
        </div>
      )}

      {/* Metered Usage Progress Section */}
      <div className="p-6 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Metered Resource Quotas (Current Cycle)</h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Cycle ends:{" "}
            {subscription
              ? new Date(subscription.current_period_end).toLocaleDateString()
              : "Nov 1, 2026"}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Asset Quota */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Server className="h-3.5 w-3.5 text-cyan-400" />
                Monitored Assets
              </span>
              <span className="font-mono text-white font-bold">
                {usage?.assets_used || 12} / {usage?.assets_limit || 250}
              </span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-500"
                style={{
                  width: `${calcPercent(usage?.assets_used || 12, usage?.assets_limit || 250)}%`,
                }}
              />
            </div>
            <div className="text-[11px] text-slate-500 text-right">
              {calcPercent(usage?.assets_used || 12, usage?.assets_limit || 250)}% utilized
            </div>
          </div>

          {/* Member Seats */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Users className="h-3.5 w-3.5 text-blue-400" />
                Analyst Seats
              </span>
              <span className="font-mono text-white font-bold">
                {usage?.members_used || 2} / {usage?.members_limit || 10}
              </span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-indigo-400 transition-all duration-500"
                style={{
                  width: `${calcPercent(usage?.members_used || 2, usage?.members_limit || 10)}%`,
                }}
              />
            </div>
            <div className="text-[11px] text-slate-500 text-right">
              {calcPercent(usage?.members_used || 2, usage?.members_limit || 10)}% utilized
            </div>
          </div>

          {/* Discovery & Vuln Scans */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Radar className="h-3.5 w-3.5 text-emerald-400" />
                Monthly Scans
              </span>
              <span className="font-mono text-white font-bold">
                {usage?.monthly_scans_used || 8} / {usage?.monthly_scans_limit || 100}
              </span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-500"
                style={{
                  width: `${calcPercent(
                    usage?.monthly_scans_used || 8,
                    usage?.monthly_scans_limit || 100
                  )}%`,
                }}
              />
            </div>
            <div className="text-[11px] text-slate-500 text-right">
              {calcPercent(usage?.monthly_scans_used || 8, usage?.monthly_scans_limit || 100)}%
              utilized
            </div>
          </div>

          {/* AI SOC Requests */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Bot className="h-3.5 w-3.5 text-purple-400" />
                AI SOC Consultations
              </span>
              <span className="font-mono text-white font-bold">
                {usage?.ai_requests_used || 14} / {usage?.ai_requests_limit || 1000}
              </span>
            </div>
            <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-purple-500 to-pink-400 transition-all duration-500"
                style={{
                  width: `${calcPercent(
                    usage?.ai_requests_used || 14,
                    usage?.ai_requests_limit || 1000
                  )}%`,
                }}
              />
            </div>
            <div className="text-[11px] text-slate-500 text-right">
              {calcPercent(usage?.ai_requests_used || 14, usage?.ai_requests_limit || 1000)}%
              utilized
            </div>
          </div>
        </div>
      </div>

      {/* Subscription Tier Cards */}
      <div>
        <div className="mb-4">
          <h2 className="text-base font-bold text-white">Choose Your Operational Tier</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent enterprise licensing with unmetered compliance and instant provisioning.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plans.map((plan) => {
            const isCurrent =
              subscription?.plan_code.toUpperCase() === plan.plan_code.toUpperCase();
            const isEnterprise = plan.plan_code === "ENTERPRISE";
            return (
              <div
                key={plan.id}
                className={`relative rounded-2xl p-6 transition-all backdrop-blur-md flex flex-col justify-between ${
                  isCurrent
                    ? "bg-[#162338] border-2 border-cyan-500/60 shadow-xl shadow-cyan-500/10"
                    : isEnterprise
                    ? "bg-[#111C2D]/90 border border-purple-500/40"
                    : "bg-[#111C2D]/80 border border-slate-800/80"
                }`}
              >
                {isCurrent && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-gradient-to-r from-blue-600 to-cyan-500 text-white shadow">
                    Active Plan
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <h3 className="text-base font-bold text-white">{plan.plan_name}</h3>
                    <p className="text-xs text-slate-400 mt-1 min-h-[32px]">
                      {plan.description}
                    </p>
                  </div>

                  <div className="flex items-baseline gap-1">
                    <span className="text-3xl font-black text-white">${plan.price}</span>
                    <span className="text-xs text-slate-400">/ month</span>
                  </div>

                  <div className="pt-3 border-t border-slate-800/80 space-y-2.5 text-xs">
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>Up to {plan.max_assets} Monitored Assets</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>{plan.max_members} Analyst Seats</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>{plan.monthly_scan_limit} Scans / month</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>{plan.ai_usage_limit} AI SOC Consultations</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>
                        {plan.feature_flags.threat_intel
                          ? "Real-time CISA KEV & Threat Intel"
                          : "Basic Threat Indicators"}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Check className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span>
                        {plan.feature_flags.incident_response
                          ? "MITRE ATT&CK Automated Playbooks"
                          : "Manual Incident Triage"}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="pt-6 mt-6 border-t border-slate-800/80">
                  {isCurrent ? (
                    <div className="space-y-2">
                      <button
                        disabled
                        className="w-full py-2.5 rounded-xl text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 cursor-default"
                      >
                        Current Active Plan
                      </button>
                      {!subscription?.cancel_at_period_end && (
                        <button
                          onClick={handleCancelAutoRenew}
                          className="w-full text-center text-[11px] text-slate-500 hover:text-rose-400 transition-colors"
                        >
                          Cancel renewal at period end
                        </button>
                      )}
                    </div>
                  ) : (
                    <button
                      onClick={() => handleUpgrade(plan.plan_code)}
                      disabled={checkoutLoading === plan.plan_code}
                      className="w-full py-2.5 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                    >
                      {checkoutLoading === plan.plan_code ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Zap className="h-3.5 w-3.5 text-cyan-400" />
                      )}
                      Switch to {plan.plan_name}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Invoice History Section */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CreditCard className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Billing History & Invoices</h2>
          </div>
          <span className="text-xs text-slate-400">Payment method: Corporate Card (•• 4242)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">Invoice ID</th>
                <th className="py-3 px-4 font-semibold">Date</th>
                <th className="py-3 px-4 font-semibold">Plan Description</th>
                <th className="py-3 px-4 font-semibold">Amount</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Receipt</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr className="hover:bg-slate-800/20 transition-colors">
                <td className="py-3 px-4 font-mono text-slate-300">INV-2026-10-001</td>
                <td className="py-3 px-4 text-slate-400">Oct 01, 2026</td>
                <td className="py-3 px-4 font-medium text-white">Professional SOC - Monthly</td>
                <td className="py-3 px-4 font-mono font-bold text-white">$199.00 USD</td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Paid
                  </span>
                </td>
                <td className="py-3 px-4 text-right">
                  <button className="p-1 rounded text-slate-400 hover:text-cyan-400 transition-colors">
                    <Download className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
              <tr className="hover:bg-slate-800/20 transition-colors">
                <td className="py-3 px-4 font-mono text-slate-300">INV-2026-09-001</td>
                <td className="py-3 px-4 text-slate-400">Sep 01, 2026</td>
                <td className="py-3 px-4 font-medium text-white">Professional SOC - Monthly</td>
                <td className="py-3 px-4 font-mono font-bold text-white">$199.00 USD</td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Paid
                  </span>
                </td>
                <td className="py-3 px-4 text-right">
                  <button className="p-1 rounded text-slate-400 hover:text-cyan-400 transition-colors">
                    <Download className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
