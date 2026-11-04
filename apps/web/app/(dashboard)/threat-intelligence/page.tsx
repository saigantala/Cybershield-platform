"use client";

import { useState, useEffect, useMemo } from "react";
import {
  Globe2,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  X,
  RotateCcw,
  Clock,
  Layers,
  Copy,
  Check,
  Plus,
  RefreshCw,
  AlertTriangle,
  Radio,
  FileCode,
  Trash2,
  Info,
} from "lucide-react";
import {
  ThreatIndicator,
  ThreatFeed,
  ThreatIntelOverview,
  IndicatorType,
  ThreatCategory,
  SeverityLevel,
} from "@/types/threat-intel";
import { apiThreatIntel } from "@/lib/api-client";
import { getSeverityColor, formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  Info: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function ThreatIntelligencePage() {
  const [overview, setOverview] = useState<ThreatIntelOverview | null>(null);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [selectedType, setSelectedType] = useState<string>("all");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [minConfidence, setMinConfidence] = useState<number>(0);

  // State Modals
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIndicator | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [syncingFeedId, setSyncingFeedId] = useState<string | null>(null);

  // Manual IOC Form State
  const [formType, setFormType] = useState<IndicatorType>("ipv4");
  const [formValue, setFormValue] = useState("");
  const [formCategory, setFormCategory] = useState<ThreatCategory>("c2");
  const [formSeverity, setFormSeverity] = useState<SeverityLevel>("High");
  const [formConfidence, setFormConfidence] = useState(85);
  const [formSource, setFormSource] = useState("Analyst Ingestion");
  const [formDesc, setFormDesc] = useState("");
  const [formRefUrl, setFormRefUrl] = useState("");
  const [formTtl, setFormTtl] = useState(30);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [overviewRes, indicatorsRes, feedsRes] = await Promise.all([
        apiThreatIntel.getOverview(),
        apiThreatIntel.listIndicators({
          page,
          page_size: pageSize,
          search: search || undefined,
          indicator_type: selectedType !== "all" ? selectedType : undefined,
          severity: selectedSeverity !== "all" ? selectedSeverity : undefined,
          threat_category: selectedCategory !== "all" ? selectedCategory : undefined,
          min_confidence: minConfidence > 0 ? minConfidence : undefined,
        }),
        apiThreatIntel.listFeeds(),
      ]);

      if (overviewRes.data) setOverview(overviewRes.data);
      if (indicatorsRes.data) {
        setIndicators(indicatorsRes.data.items || []);
        setTotalCount(indicatorsRes.data.total || 0);
      }
      if (feedsRes.data) setFeeds(feedsRes.data || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load threat intelligence telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [page, selectedType, selectedSeverity, selectedCategory, minConfidence]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchData();
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSyncFeed = async (feedId: string) => {
    setSyncingFeedId(feedId);
    try {
      const res = await apiThreatIntel.syncFeed(feedId);
      if (res.data) {
        await fetchData();
      }
    } catch (e) {
      // keep silent or handle
    } finally {
      setSyncingFeedId(null);
    }
  };

  const handleCreateIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      const res = await apiThreatIntel.createIndicator({
        indicator_type: formType,
        indicator_value: formValue,
        threat_category: formCategory,
        severity: formSeverity,
        confidence: formConfidence,
        source: formSource,
        description: formDesc || undefined,
        reference_url: formRefUrl || undefined,
        expires_in_days: formTtl,
      });

      if (res.error) {
        setFormError(res.error);
      } else {
        setShowAddModal(false);
        setFormValue("");
        setFormDesc("");
        setFormRefUrl("");
        await fetchData();
      }
    } catch (err: any) {
      setFormError(err.message || "Failed to create indicator.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteIndicator = async (id: string) => {
    if (!confirm("Are you sure you want to remove this threat indicator?")) return;
    try {
      await apiThreatIntel.deleteIndicator(id);
      await fetchData();
    } catch (e) {
      // ignore
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Threat Intelligence</h1>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              IOC Hub
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative Indicators of Compromise, automated provider feeds, and observable reputation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchData()}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium shadow-lg shadow-blue-600/20 transition-colors"
          >
            <Plus className="h-4 w-4" />
            Register Indicator
          </button>
        </div>
      </div>

      {/* KPI Overview Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Total IOCs</span>
            <Globe2 className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {overview?.total_indicators ?? totalCount}
          </div>
          <span className="text-[11px] text-slate-400">All managed indicators</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Malicious IPs</span>
            <Radio className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">
            {overview?.malicious_ips ?? 0}
          </div>
          <span className="text-[11px] text-slate-400">IPv4 & IPv6 targets</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Domains</span>
            <Layers className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-indigo-400">
            {overview?.malicious_domains ?? 0}
          </div>
          <span className="text-[11px] text-slate-400">C2 & phishing hosts</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">URLs & Hashes</span>
            <FileCode className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">
            {(overview?.malicious_urls ?? 0) + (overview?.malicious_hashes ?? 0)}
          </div>
          <span className="text-[11px] text-slate-400">Pay-loads & malware</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">High Confidence</span>
            <CheckCircle className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {overview?.high_confidence_count ?? 0}
          </div>
          <span className="text-[11px] text-slate-400">&ge; 90% confidence</span>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs uppercase tracking-wider font-semibold">Feed Syncs</span>
            <RefreshCw className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {feeds.length} Active
          </div>
          <span className="text-[11px] text-slate-400">Automated providers</span>
        </div>
      </div>

      {/* Threat Feeds Status Banner */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/60 backdrop-blur-md">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">External Threat Feed Providers</h3>
          </div>
          <span className="text-xs text-slate-400">Scheduled Caching & Sanitization</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {feeds.map((feed) => (
            <div
              key={feed.id}
              className="p-3 rounded-lg border border-slate-800/80 bg-slate-900/60 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-200 line-clamp-1">
                    {feed.feed_name}
                  </span>
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${
                      feed.is_enabled
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                        : "bg-slate-500/10 text-slate-400 border border-slate-500/20"
                    }`}
                  >
                    {feed.is_enabled ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono mt-1">
                  Interval: every {feed.sync_interval_hours}h
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Last: {feed.last_synced_at ? formatDateTime(feed.last_synced_at) : "Never"}
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between">
                <span className="text-xs font-mono text-cyan-400">
                  {feed.indicator_count} IOCs
                </span>
                <button
                  onClick={() => handleSyncFeed(feed.id)}
                  disabled={syncingFeedId === feed.id || !feed.is_enabled}
                  className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 disabled:opacity-40"
                >
                  <RefreshCw
                    className={`h-3 w-3 ${syncingFeedId === feed.id ? "animate-spin" : ""}`}
                  />
                  Sync
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search IOC observable, IP, domain, hash or description..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 transition-colors"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedType}
              onChange={(e) => {
                setSelectedType(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Types</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="sha256">SHA256</option>
              <option value="md5">MD5</option>
              <option value="sha1">SHA1</option>
            </select>

            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={selectedCategory}
              onChange={(e) => {
                setSelectedCategory(e.target.value);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-900/80 border border-slate-700/80 rounded-lg text-xs text-slate-200 focus:outline-none"
            >
              <option value="all">All Categories</option>
              <option value="c2">C2 (Command & Control)</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="ransomware">Ransomware</option>
              <option value="botnet">Botnet</option>
              <option value="scanner">Recon / Scanner</option>
              <option value="exploit">Exploitation</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium"
            >
              Filter
            </button>

            {(search || selectedType !== "all" || selectedSeverity !== "all" || selectedCategory !== "all") && (
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setSelectedType("all");
                  setSelectedSeverity("all");
                  setSelectedCategory("all");
                  setPage(1);
                }}
                className="p-2 text-slate-400 hover:text-slate-200"
                title="Reset filters"
              >
                <RotateCcw className="h-4 w-4" />
              </button>
            )}
          </div>
        </form>
      </div>

      {/* IOC Table */}
      <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-900/40">
                <th className="py-3 px-4">Observable Indicator</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Threat Category</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Last Seen</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Loading threat intelligence telemetry...
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No threat indicators found matching current filters.
                  </td>
                </tr>
              ) : (
                indicators.map((ioc) => {
                  const badge = SEVERITY_BADGES[ioc.severity] || SEVERITY_BADGES.Medium;
                  return (
                    <tr
                      key={ioc.id}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                      onClick={() => setSelectedIndicator(ioc)}
                    >
                      <td className="py-3 px-4 font-mono font-medium text-slate-200">
                        <div className="flex items-center gap-2 max-w-md">
                          <span className="truncate">{ioc.indicator_value}</span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(ioc.indicator_value, ioc.id);
                            }}
                            className="text-slate-500 hover:text-slate-300 transition-colors"
                            title="Copy observable"
                          >
                            {copiedId === ioc.id ? (
                              <Check className="h-3.5 w-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="h-3.5 w-3.5" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded font-mono text-[10px] uppercase font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {ioc.indicator_type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 capitalize">
                          {ioc.threat_category}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${badge.bg} ${badge.text} ${badge.border}`}
                        >
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                ioc.confidence >= 90
                                  ? "bg-rose-500"
                                  : ioc.confidence >= 75
                                  ? "bg-amber-500"
                                  : "bg-blue-500"
                              }`}
                              style={{ width: `${ioc.confidence}%` }}
                            />
                          </div>
                          <span className="font-mono text-slate-300">{ioc.confidence}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                        {ioc.source}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                        {formatDateTime(ioc.last_seen)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setSelectedIndicator(ioc)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                          >
                            Details
                          </button>
                          <button
                            onClick={() => handleDeleteIndicator(ioc.id)}
                            className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10"
                            title="Delete IOC"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {indicators.length} of {totalCount} indicators
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span>Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={indicators.length < pageSize}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 disabled:opacity-40 hover:bg-slate-800"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* IOC Detail Drawer Modal */}
      {selectedIndicator && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe2 className="h-5 w-5 text-blue-400" />
                <h2 className="text-lg font-bold text-white">Indicator Observable Details</h2>
              </div>
              <button
                onClick={() => setSelectedIndicator(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1">
                  Observable Value
                </div>
                <div className="font-mono text-sm text-cyan-300 break-all select-all">
                  {selectedIndicator.indicator_value}
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Type</span>
                  <span className="font-mono font-bold text-slate-200 uppercase">
                    {selectedIndicator.indicator_type}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Threat Category</span>
                  <span className="font-semibold text-blue-400 capitalize">
                    {selectedIndicator.threat_category}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Severity</span>
                  <span
                    className={`font-bold ${
                      SEVERITY_BADGES[selectedIndicator.severity]?.text || "text-slate-200"
                    }`}
                  >
                    {selectedIndicator.severity}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase">Confidence</span>
                  <span className="font-mono font-bold text-emerald-400">
                    {selectedIndicator.confidence}%
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-slate-400 font-semibold">Feed Source</div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 font-mono">
                  {selectedIndicator.source}
                </div>
              </div>

              {selectedIndicator.description && (
                <div className="space-y-2">
                  <div className="text-slate-400 font-semibold">Threat Context & Analysis</div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300">
                    {selectedIndicator.description}
                  </div>
                </div>
              )}

              {selectedIndicator.reference_url && (
                <div className="space-y-2">
                  <div className="text-slate-400 font-semibold">Authoritative Reference</div>
                  <a
                    href={selectedIndicator.reference_url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1.5 text-blue-400 hover:text-blue-300 break-all"
                  >
                    <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                    <span>{selectedIndicator.reference_url}</span>
                  </a>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 pt-2">
                <div className="text-slate-400">
                  First Seen:{" "}
                  <span className="font-mono text-slate-300">
                    {formatDateTime(selectedIndicator.first_seen)}
                  </span>
                </div>
                <div className="text-slate-400">
                  Last Seen:{" "}
                  <span className="font-mono text-slate-300">
                    {formatDateTime(selectedIndicator.last_seen)}
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedIndicator(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual IOC Registration Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Plus className="h-5 w-5 text-blue-400" />
                <h2 className="text-lg font-bold text-white">Register Threat Indicator</h2>
              </div>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateIndicator} className="p-6 space-y-4 text-xs">
              {formError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  {formError}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Indicator Type</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as IndicatorType)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="ipv4">IPv4 Address</option>
                    <option value="ipv6">IPv6 Address</option>
                    <option value="domain">Domain Name</option>
                    <option value="url">URL</option>
                    <option value="sha256">SHA256 Hash</option>
                    <option value="md5">MD5 Hash</option>
                    <option value="sha1">SHA1 Hash</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Threat Category</label>
                  <select
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value as ThreatCategory)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="c2">Command & Control (C2)</option>
                    <option value="malware">Malware</option>
                    <option value="phishing">Phishing</option>
                    <option value="ransomware">Ransomware</option>
                    <option value="botnet">Botnet</option>
                    <option value="scanner">Recon / Scanner</option>
                    <option value="exploit">Exploitation</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Observable Value</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.99 or evil-c2.darknet.ru"
                  value={formValue}
                  onChange={(e) => setFormValue(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">
                    Confidence ({formConfidence}%)
                  </label>
                  <input
                    type="range"
                    min={1}
                    max={100}
                    value={formConfidence}
                    onChange={(e) => setFormConfidence(Number(e.target.value))}
                    className="w-full mt-2"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">TTL (Days)</label>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={formTtl}
                    onChange={(e) => setFormTtl(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Source / Attribution</label>
                <input
                  type="text"
                  value={formSource}
                  onChange={(e) => setFormSource(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Description / Threat Notes</label>
                <textarea
                  rows={2}
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                  placeholder="Details on campaign, observed tactics, or infrastructure association..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Reference URL</label>
                <input
                  type="url"
                  placeholder="https://..."
                  value={formRefUrl}
                  onChange={(e) => setFormRefUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !formValue}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-40"
                >
                  {submitting ? "Ingesting..." : "Save Indicator"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
