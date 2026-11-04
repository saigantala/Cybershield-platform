"use client";

import { useEffect, useState } from "react";
import {
  Package,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  ArrowUpRight,
} from "lucide-react";
import { apiSecurityAssurance } from "@/lib/api-client";
import type { DependencyPackageItem } from "@/types/security-assurance";
import { SecurityAssuranceNav } from "@/components/security-assurance/SecurityAssuranceNav";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";

export default function DependenciesPage() {
  const [dependencies, setDependencies] = useState<DependencyPackageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [ecosystemFilter, setEcosystemFilter] = useState("all");
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  const loadDependencies = async () => {
    setLoading(true);
    try {
      const res = await apiSecurityAssurance.getDependencies();
      if (res.data) setDependencies(res.data);
    } catch (err) {
      console.error("Failed to load dependencies", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDependencies();
  }, []);

  const filtered = dependencies.filter((dep) => {
    const matchesSearch = dep.package_name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesEco = ecosystemFilter === "all" || dep.ecosystem === ecosystemFilter;
    const matchesVuln = !vulnerableOnly || dep.vulnerable;
    return matchesSearch && matchesEco && matchesVuln;
  });

  const totalDeps = dependencies.length;
  const vulnerableCount = dependencies.filter((d) => d.vulnerable).length;
  const pythonCount = dependencies.filter((d) => d.ecosystem === "python").length;
  const npmCount = dependencies.filter((d) => d.ecosystem === "npm").length;

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <Package className="w-7 h-7 text-amber-400" />
              Software Supply Chain & Dependency Auditing
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Continuous CVE analysis and SBOM audits powered by pip-audit and npm audit integrations.
            </p>
          </div>
          <button
            onClick={loadDependencies}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-amber-400" : ""}`} />
            Re-scan Dependencies
          </button>
        </div>

        {/* Sub-Navigation */}
        <SecurityAssuranceNav />

        {/* Highlight Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
            <span className="text-xs text-slate-400 block mb-1">Total Packages</span>
            <span className="text-2xl font-bold text-white">{totalDeps}</span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
            <span className="text-xs text-slate-400 block mb-1">Vulnerable Packages</span>
            <span className={`text-2xl font-bold ${vulnerableCount > 0 ? "text-amber-400" : "text-emerald-400"}`}>
              {vulnerableCount}
            </span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
            <span className="text-xs text-slate-400 block mb-1">Python Ecosystem (pip)</span>
            <span className="text-2xl font-bold text-cyan-400">{pythonCount}</span>
          </div>
          <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-4">
            <span className="text-xs text-slate-400 block mb-1">JavaScript Ecosystem (npm)</span>
            <span className="text-2xl font-bold text-violet-400">{npmCount}</span>
          </div>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl p-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search package name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <select
              value={ecosystemFilter}
              onChange={(e) => setEcosystemFilter(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-amber-500"
            >
              <option value="all">All Ecosystems</option>
              <option value="python">Python (PyPI)</option>
              <option value="npm">Node.js (npm)</option>
            </select>

            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={vulnerableOnly}
                onChange={(e) => setVulnerableOnly(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-amber-500 focus:ring-0"
              />
              Vulnerable Only
            </label>
          </div>
        </div>

        {/* Dependencies List Table */}
        <div className="bg-slate-900/60 border border-slate-800/80 backdrop-blur-xl rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/40">
                  <th className="py-3 px-4">Package</th>
                  <th className="py-3 px-4">Ecosystem</th>
                  <th className="py-3 px-4">Current Version</th>
                  <th className="py-3 px-4">Status & Severity</th>
                  <th className="py-3 px-4">CVE Identifiers</th>
                  <th className="py-3 px-4">Recommended Upgrade</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filtered.map((dep, idx) => (
                  <tr key={`${dep.package_name}-${idx}`} className="hover:bg-slate-800/20">
                    <td className="py-3 px-4 font-semibold text-slate-200">{dep.package_name}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        dep.ecosystem === "python" ? "bg-cyan-500/10 text-cyan-400" : "bg-violet-500/10 text-violet-400"
                      }`}>
                        {dep.ecosystem}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{dep.current_version}</td>
                    <td className="py-3 px-4">
                      {dep.vulnerable ? (
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          dep.highest_severity === "critical"
                            ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                            : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                        }`}>
                          {dep.highest_severity} ({dep.vulnerabilities_count})
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Clean
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {dep.cve_list && dep.cve_list.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {dep.cve_list.map((cve) => (
                            <span key={cve} className="px-1.5 py-0.5 bg-slate-800 rounded font-mono text-[10px] text-slate-300">
                              {cve}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-emerald-400 font-medium">
                      {dep.fixed_version ? (
                        <span className="flex items-center gap-1">
                          {dep.fixed_version} <ArrowUpRight className="w-3 h-3 text-emerald-400" />
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}
