"use client";

import { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  TrendingUp,
  AlertTriangle,
  Server,
  Layers,
  CheckCircle2,
  Lock,
  ArrowUpRight,
  Info,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import {
  mockPostureMetrics,
  mockRiskTrendData,
  mockComplianceBenchmarks,
  mockAssetRiskRankings,
} from "@/lib/mockData";
import { getSeverityColor } from "@/lib/utils";

export default function RiskAssessmentPage() {
  const [selectedStandard, setSelectedStandard] = useState("all");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Enterprise Risk Assessment & Posture Index
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Algorithmic prioritization, asset exposure scoring, predictive modeling, and compliance benchmarks
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20">
          <ShieldCheck className="h-4 w-4" />
          <span>Overall Score: <strong>86 / 100</strong> (Grade A)</span>
        </div>
      </div>

      {/* Top Row: Overall Security Score Gauge & Risk Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Score Gauge Card */}
        <div className="soc-glass rounded-xl p-6 border border-blue-500/20 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-44 h-44 bg-gradient-to-bl from-emerald-500/10 via-cyan-500/5 to-transparent rounded-bl-full pointer-events-none" />

          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block mb-2">
              Overall Security Score
            </span>

            <div className="flex items-baseline gap-3 my-3">
              <span className="text-5xl font-black text-white font-mono">86</span>
              <span className="text-slate-400 font-mono text-xl">/ 100</span>
              <span className="ml-auto text-xs font-bold px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                Grade A Optimal
              </span>
            </div>

            <div className="w-full bg-[#080D18] h-3 rounded-full overflow-hidden p-0.5 border border-slate-800 mb-4">
              <div
                className="h-full rounded-full bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400"
                style={{ width: "86%" }}
              />
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Calculated using CVSS base severity, asset criticality, network perimeter exposure, and CISA KEV presence.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Formula: Weighted Risk Decay Index</span>
            <span className="text-emerald-400 font-mono font-bold">+4% vs prior month</span>
          </div>
        </div>

        {/* Risk Distribution by Category */}
        <div className="lg:col-span-2 soc-glass rounded-xl p-6 border border-blue-500/20 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Risk Distribution Across Domains
                </h3>
                <p className="text-xs text-slate-400">
                  Surface exposure mapped across enterprise domains
                </p>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                L7 Ingress Monitored
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">Perimeter Infrastructure</span>
                  <span className="font-mono text-cyan-400 font-bold">Low Exposure (18%)</span>
                </div>
                <div className="w-full bg-[#111C2D] h-2 rounded-full overflow-hidden">
                  <div className="bg-cyan-400 h-full" style={{ width: "18%" }} />
                </div>
                <span className="text-[10px] text-slate-400">Strict ingress filtering active on edge gateway.</span>
              </div>

              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">Database & PII Tier</span>
                  <span className="font-mono text-rose-400 font-bold">Elevated Risk (68%)</span>
                </div>
                <div className="w-full bg-[#111C2D] h-2 rounded-full overflow-hidden">
                  <div className="bg-rose-400 h-full" style={{ width: "68%" }} />
                </div>
                <span className="text-[10px] text-slate-400">regreSSHion CVE pending emergency maintenance.</span>
              </div>

              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">IoT & Facilities</span>
                  <span className="font-mono text-amber-400 font-bold">Moderate Risk (44%)</span>
                </div>
                <div className="w-full bg-[#111C2D] h-2 rounded-full overflow-hidden">
                  <div className="bg-amber-400 h-full" style={{ width: "44%" }} />
                </div>
                <span className="text-[10px] text-slate-400">Default camera credentials pending password rotation.</span>
              </div>

              <div className="p-3.5 rounded-lg bg-[#0B1220] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">Corporate Endpoints</span>
                  <span className="font-mono text-emerald-400 font-bold">Secure (22%)</span>
                </div>
                <div className="w-full bg-[#111C2D] h-2 rounded-full overflow-hidden">
                  <div className="bg-emerald-400 h-full" style={{ width: "22%" }} />
                </div>
                <span className="text-[10px] text-slate-400">EDR agent reporting 99.8% compliance.</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Predictive Risk Trend & Compliance Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Predictive Threat Modeling Line Chart (Inspired by Image 2 SentinelX) */}
        <div className="soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Risk Trend & Predictive Threat Modeling
              </h3>
              <p className="text-xs text-slate-400">Actual posture vs AI predicted curve</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              30-Day Trend
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={mockRiskTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} />
                <YAxis domain={[65, 95]} stroke="#64748B" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111C2D",
                    borderColor: "rgba(59, 130, 246, 0.3)",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#F8FAFC",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="riskScore"
                  stroke="#22D3EE"
                  strokeWidth={2.5}
                  name="Actual Posture"
                />
                <Line
                  type="monotone"
                  dataKey="predicted"
                  stroke="#8B5CF6"
                  strokeWidth={2}
                  strokeDasharray="4 4"
                  name="Predicted Target"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Compliance Status Benchmarks (Inspired by Image 5 SecureOps) */}
        <div className="soc-glass rounded-xl p-5 border border-blue-500/20 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Regulatory Framework Alignment
              </h3>
              <p className="text-xs text-slate-400">Automated mapping against standard frameworks</p>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              5 Audited
            </span>
          </div>

          <div className="space-y-3.5">
            {mockComplianceBenchmarks.map((bench) => (
              <div key={bench.standard} className="space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{bench.standard}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-white">{bench.compliance}%</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-bold">
                      {bench.status}
                    </span>
                  </div>
                </div>
                <div className="w-full bg-[#080D18] h-2 rounded-full overflow-hidden border border-slate-800">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-emerald-400"
                    style={{ width: `${bench.compliance}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row: Asset Risk Ranking */}
      <div className="soc-glass rounded-xl overflow-hidden border border-blue-500/20">
        <div className="p-4 bg-[#0B1220]/80 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              Asset Risk Priority Ranking
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            Top Vulnerable Systems Ranked by Exposure
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-3 px-4">Rank & Asset</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Primary Risk Factor</th>
                <th className="py-3 px-4">Risk Severity</th>
                <th className="py-3 px-4 text-right">Calculated Risk Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {mockAssetRiskRankings.map((item, index) => (
                <tr key={item.id} className="hover:bg-[#162338]/50 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2.5">
                      <span className="h-5 w-5 rounded-full bg-slate-800 font-mono text-[10px] font-bold text-cyan-400 flex items-center justify-center shrink-0">
                        #{index + 1}
                      </span>
                      <span className="font-bold text-white">{item.name}</span>
                    </div>
                  </td>

                  <td className="py-3 px-4 font-mono text-cyan-400 text-[11px]">
                    {item.ip}
                  </td>

                  <td className="py-3 px-4 text-slate-300">
                    {item.type}
                  </td>

                  <td className="py-3 px-4 text-slate-200">
                    {item.reason}
                  </td>

                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityColor(
                        item.severity
                      )}`}
                    >
                      {item.severity}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-right font-mono font-bold text-sm text-white">
                    {item.riskScore} <span className="text-slate-400 text-xs font-normal">/ 100</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
