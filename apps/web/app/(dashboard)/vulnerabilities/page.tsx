"use client";

import { useState, useEffect, useMemo } from "react";
import {
  Bug,
  Search,
  Filter,
  Flame,
  ShieldAlert,
  CheckCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  X,
  FileCode,
  AlertOctagon,
  Download,
  Play,
  RotateCcw,
  StopCircle,
  Check,
  Clock,
  Layers,
  Server,
  Activity,
  Shield,
  Info,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  LineChart,
  Line,
} from "recharts";
import {
  VulnerabilityFinding,
  VulnerabilityOverview,
  VulnerabilityScan,
  RemediationHistoryEntry,
  VulnerabilitySeverity,
  VulnerabilityStatus,
} from "@/types/vulnerability";
import { apiVulnerabilities, apiScopes } from "@/lib/api-client";
import { mockFindings } from "@/lib/mockData";
import { getSeverityColor, getStatusBadge, formatDateTime } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#FB7185",
  High: "#F59E0B",
  Medium: "#38BDF8",
  Low: "#34D399",
  Informational: "#94A3B8",
};

export default function VulnerabilitiesPage() {
  const [activeTab, setActiveTab] = useState<"findings" | "scans" | "analytics">("findings");

  // Overview Stats
  const [overview, setOverview] = useState<VulnerabilityOverview>({
    total_findings: 4,
    critical_count: 1,
    high_count: 1,
    medium_count: 1,
    low_count: 1,
    informational_count: 0,
    kev_count: 1,
    resolved_count: 1,
    severity_distribution: { Critical: 1, High: 1, Medium: 1, Low: 1, Informational: 0 },
    top_affected_assets: [],
  });

  // Findings State
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [isLiveBackend, setIsLiveBackend] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [findingHistory, setFindingHistory] = useState<RemediationHistoryEntry[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(8);

  // Remediation Modal State
  const [remediationTarget, setRemediationTarget] = useState<VulnerabilityFinding | null>(null);
  const [remediationStatus, setRemediationStatus] = useState<VulnerabilityStatus>("In Progress");
  const [remediationNotes, setRemediationNotes] = useState("");
  const [remediationError, setRemediationError] = useState("");
  const [submittingRemediation, setSubmittingRemediation] = useState(false);

  // Scan Center State
  const [scans, setScans] = useState<VulnerabilityScan[]>([]);
  const [scopes, setScopes] = useState<any[]>([]);
  const [selectedScopeId, setSelectedScopeId] = useState("");
  const [selectedScanType, setSelectedScanType] = useState<"mock" | "openvas" | "zap_baseline">("mock");
  const [certified, setCertified] = useState(false);
  const [launchingScan, setLaunchingScan] = useState(false);
  const [scanMessage, setScanMessage] = useState<{ text: string; error?: boolean } | null>(null);

  // Load Data
  const fetchData = async () => {
    setLoading(true);
    try {
      // 1. Load Overview
      const ovRes = await apiVulnerabilities.getOverview();
      if (ovRes.data && !ovRes.error) {
        setOverview(ovRes.data);
        setIsLiveBackend(true);
      }

      // 2. Load Findings
      const findRes = await apiVulnerabilities.listFindings();
      if (findRes.data && findRes.data.items && findRes.data.items.length > 0) {
        setFindings(findRes.data.items);
      } else {
        // Fallback to initial mock data mapped to standard types
        const initialMock: VulnerabilityFinding[] = [
          {
            id: "88888888-8888-8888-8888-888888888888",
            organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            asset_id: "11111111-1111-1111-1111-111111111111",
            asset_name: "PROD-EDGE-FIREWALL-01",
            asset_ip: "192.168.10.1",
            title: "Fortinet FortiOS SSL-VPN Out-of-Bounds Write RCE",
            description: "An out-of-bounds write vulnerability in Fortinet FortiOS allows an unauthenticated attacker to execute arbitrary code or commands.",
            cve_id: "CVE-2024-21762",
            cvss_score: 9.8,
            cvss_version: "3.1",
            severity: "Critical",
            prioritization_score: 98.6,
            affected_service: "SSL-VPN Web Portal",
            affected_version: "FortiOS 7.4.2",
            evidence: "GET /remote/login HTTP/1.1 on 192.168.10.1:443 returned vulnerable header token.",
            remediation: "Upgrade FortiOS to version 7.4.3 or disable the web interface.",
            reference_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
            is_kev: true,
            kev_metadata: { cveID: "CVE-2024-21762", dueDate: "2024-02-16", knownRansomwareCampaignUse: "Known" },
            status: "Open",
            first_detected_at: new Date().toISOString(),
            last_detected_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          {
            id: "99999999-9999-9999-9999-999999999999",
            organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            asset_id: "22222222-2222-2222-2222-222222222222",
            asset_name: "DB-POSTGRES-PRIMARY",
            asset_ip: "192.168.10.45",
            title: "OpenSSH Signal Handler Race Condition RCE (regreSSHion)",
            description: "A signal handler race condition was discovered in OpenSSH server (sshd) in glibc-based Linux systems where attackers can execute arbitrary code as root.",
            cve_id: "CVE-2024-6387",
            cvss_score: 8.1,
            cvss_version: "3.1",
            severity: "High",
            prioritization_score: 56.7,
            affected_service: "OpenSSH",
            affected_version: "OpenSSH_8.9p1",
            evidence: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 banner observed on port 22.",
            remediation: "Update OpenSSH to OpenSSH 9.8p1 or set LoginGraceTime to 0 in sshd_config.",
            reference_urls: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
            is_kev: false,
            status: "In Progress",
            first_detected_at: new Date().toISOString(),
            last_detected_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          {
            id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            organization_id: "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            asset_id: "22222222-2222-2222-2222-222222222222",
            asset_name: "DB-POSTGRES-PRIMARY",
            asset_ip: "192.168.10.45",
            title: "SSH Protocol Terrapin Attack (Prefix Truncation)",
            description: "The Terrapin attack exploits vulnerabilities in the SSH transport layer protocol to truncate handshake messages.",
            cve_id: "CVE-2023-48795",
            cvss_score: 5.9,
            cvss_version: "3.1",
            severity: "Medium",
            prioritization_score: 41.3,
            affected_service: "OpenSSH",
            affected_version: "OpenSSH_8.9p1",
            evidence: "Target 192.168.10.45:22 supports chacha20-poly1305 without strict key exchange extension.",
            remediation: "Disable ChaCha20-Poly1305 and CBC-EtM ciphers or apply strict KEX patches.",
            reference_urls: ["https://terrapin-attack.com/"],
            is_kev: false,
            status: "Open",
            first_detected_at: new Date().toISOString(),
            last_detected_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ];
        setFindings(initialMock);
      }

      // 3. Load Scans
      const scansRes = await apiVulnerabilities.listScans();
      if (scansRes.data) {
        setScans(scansRes.data);
      }

      // 4. Load Scopes for Assessment Center
      const scopesRes = await apiScopes.list();
      if (scopesRes.data) {
        setScopes(scopesRes.data);
        const firstApproved = scopesRes.data.find(
          (s: any) => s.authorization_status === "Approved" && !s.is_expired
        );
        if (firstApproved) {
          setSelectedScopeId(firstApproved.id);
        }
      }
    } catch (e) {
      console.warn("Error fetching vulnerability data:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const q = searchTerm.toLowerCase();
      const matchesSearch =
        !q ||
        f.title.toLowerCase().includes(q) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(q)) ||
        (f.asset_name && f.asset_name.toLowerCase().includes(q)) ||
        (f.asset_ip && f.asset_ip.includes(q));

      const matchesSeverity =
        severityFilter === "all" || f.severity.toLowerCase() === severityFilter.toLowerCase();

      const matchesStatus =
        statusFilter === "all" || f.status.toLowerCase() === statusFilter.toLowerCase();

      const matchesKev = !kevOnly || f.is_kev;

      return matchesSearch && matchesSeverity && matchesStatus && matchesKev;
    });
  }, [findings, searchTerm, severityFilter, statusFilter, kevOnly]);

  const totalPages = Math.ceil(filteredFindings.length / pageSize) || 1;
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredFindings.slice(start, start + pageSize);
  }, [filteredFindings, currentPage, pageSize]);

  // Open Details Modal & Load History
  const openFindingDetails = async (finding: VulnerabilityFinding) => {
    setSelectedFinding(finding);
    try {
      const histRes = await apiVulnerabilities.getFindingHistory(finding.id);
      if (histRes.data) {
        setFindingHistory(histRes.data);
      } else {
        setFindingHistory([]);
      }
    } catch (e) {
      setFindingHistory([]);
    }
  };

  // Launch Assessment Scan
  const handleLaunchScan = async () => {
    if (!selectedScopeId) {
      setScanMessage({ text: "Please select an authorized scope.", error: true });
      return;
    }
    if (!certified) {
      setScanMessage({
        text: "You must certify legal authorization before scanning.",
        error: true,
      });
      return;
    }

    setLaunchingScan(true);
    setScanMessage(null);

    try {
      const res = await apiVulnerabilities.createScan({
        scan_scope_id: selectedScopeId,
        scan_type: selectedScanType,
        operator_certified: true,
      });

      if (res.data && !res.error) {
        setScanMessage({
          text: `Assessment launched successfully! Scan Job ID: ${res.data.id.substring(0, 8)}...`,
        });
        await fetchData();
      } else {
        setScanMessage({
          text: res.error || "Failed to launch vulnerability assessment.",
          error: true,
        });
      }
    } catch (err: any) {
      setScanMessage({ text: err.message || "Failed to dispatch scan.", error: true });
    } finally {
      setLaunchingScan(false);
    }
  };

  // Cancel Active Scan
  const handleCancelScan = async (scanId: string) => {
    try {
      await apiVulnerabilities.cancelScan(scanId);
      await fetchData();
    } catch (e) {
      console.error("Cancel failed:", e);
    }
  };

  // Submit Remediation Transition
  const submitRemediation = async () => {
    if (!remediationTarget) return;

    if (
      (remediationStatus === "Accepted Risk" || remediationStatus === "False Positive") &&
      (!remediationNotes || !remediationNotes.trim())
    ) {
      setRemediationError(
        `A detailed justification is required when setting status to '${remediationStatus}'.`
      );
      return;
    }

    setSubmittingRemediation(true);
    setRemediationError("");

    try {
      const res = await apiVulnerabilities.applyRemediation(remediationTarget.id, {
        new_status: remediationStatus,
        notes: remediationNotes,
      });

      if (res.data && !res.error) {
        // Update local findings state
        setFindings((prev) =>
          prev.map((f) => (f.id === remediationTarget.id ? res.data : f))
        );
        if (selectedFinding?.id === remediationTarget.id) {
          setSelectedFinding(res.data);
          const hist = await apiVulnerabilities.getFindingHistory(remediationTarget.id);
          if (hist.data) setFindingHistory(hist.data);
        }
        setRemediationTarget(null);
        setRemediationNotes("");
      } else {
        setRemediationError(res.error || "Remediation update failed.");
      }
    } catch (err: any) {
      setRemediationError(err.message || "Remediation update failed.");
    } finally {
      setSubmittingRemediation(false);
    }
  };

  // Export CSV
  const handleExportCSV = () => {
    const headers = [
      "CVE ID",
      "Title",
      "Severity",
      "CVSS",
      "Priority Score",
      "Asset Name",
      "Asset IP",
      "CISA KEV",
      "Status",
      "Detected Date",
    ];
    const rows = filteredFindings.map((f) => [
      `"${f.cve_id || "N/A"}"`,
      `"${f.title.replace(/"/g, '""')}"`,
      `"${f.severity}"`,
      f.cvss_score,
      f.prioritization_score,
      `"${f.asset_name || "N/A"}"`,
      `"${f.asset_ip || "N/A"}"`,
      f.is_kev ? "YES" : "NO",
      `"${f.status}"`,
      `"${f.first_detected_at}"`,
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cybershield_vulnerabilities_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Severity Distribution Chart Data
  const severityChartData = useMemo(() => {
    const counts = overview.severity_distribution || {};
    return [
      { name: "Critical", value: counts.Critical || 0, color: SEVERITY_COLORS.Critical },
      { name: "High", value: counts.High || 0, color: SEVERITY_COLORS.High },
      { name: "Medium", value: counts.Medium || 0, color: SEVERITY_COLORS.Medium },
      { name: "Low", value: counts.Low || 0, color: SEVERITY_COLORS.Low },
      { name: "Informational", value: counts.Informational || 0, color: SEVERITY_COLORS.Informational },
    ].filter((item) => item.value > 0);
  }, [overview]);

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30">
              <Bug className="h-5 w-5" />
            </div>
            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Vulnerability Assessment & Triage
            </h1>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                isLiveBackend
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                  : "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
              }`}
            >
              {isLiveBackend ? "DB Connected" : "Local Evaluation"}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated NVD CVE intelligence, CVSS v3.1 scoring, CISA KEV catalog weaponization, and remediation lifecycles
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg bg-[#0B1220] border border-blue-500/20 p-1">
            <button
              onClick={() => setActiveTab("findings")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                activeTab === "findings"
                  ? "bg-blue-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Findings
            </button>
            <button
              onClick={() => setActiveTab("scans")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                activeTab === "scans"
                  ? "bg-blue-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Scan Center
            </button>
            <button
              onClick={() => setActiveTab("analytics")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                activeTab === "analytics"
                  ? "bg-blue-600 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Analytics
            </button>
          </div>

          <button
            onClick={fetchData}
            title="Refresh"
            className="p-2 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white hover:border-cyan-400 transition-colors"
          >
            <RotateCcw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Part A: 5 Overview Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div
          onClick={() => { setSeverityFilter("all"); setKevOnly(false); setCurrentPage(1); }}
          className={`soc-glass rounded-xl p-3 border cursor-pointer transition-all ${
            severityFilter === "all" && !kevOnly ? "border-cyan-400 bg-[#162338]" : "border-blue-500/20"
          }`}
        >
          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
            Total Findings
          </span>
          <p className="text-xl font-black text-white font-mono mt-0.5">
            {overview.total_findings}
          </p>
          <span className="text-[10px] text-slate-500 mt-1 block">Active across scope</span>
        </div>

        <div
          onClick={() => { setSeverityFilter("Critical"); setKevOnly(false); setCurrentPage(1); }}
          className={`soc-glass rounded-xl p-3 border cursor-pointer transition-all ${
            severityFilter === "Critical" ? "border-rose-400 bg-[#162338]" : "border-rose-500/20"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider">
              Critical
            </span>
            <AlertOctagon className="h-3.5 w-3.5 text-rose-400" />
          </div>
          <p className="text-xl font-black text-rose-300 font-mono mt-0.5">
            {overview.critical_count}
          </p>
          <span className="text-[10px] text-rose-400/80 mt-1 block">CVSS 9.0 – 10.0</span>
        </div>

        <div
          onClick={() => { setSeverityFilter("High"); setKevOnly(false); setCurrentPage(1); }}
          className={`soc-glass rounded-xl p-3 border cursor-pointer transition-all ${
            severityFilter === "High" ? "border-amber-400 bg-[#162338]" : "border-amber-500/20"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">
              High
            </span>
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
          </div>
          <p className="text-xl font-black text-amber-300 font-mono mt-0.5">
            {overview.high_count}
          </p>
          <span className="text-[10px] text-amber-400/80 mt-1 block">CVSS 7.0 – 8.9</span>
        </div>

        <div
          onClick={() => { setKevOnly(true); setSeverityFilter("all"); setCurrentPage(1); }}
          className={`soc-glass rounded-xl p-3 border cursor-pointer transition-all ${
            kevOnly ? "border-rose-400 bg-rose-950/20 shadow-lg shadow-rose-950/50" : "border-rose-500/30"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1">
              <Flame className="h-3 w-3 text-rose-400 animate-pulse" />
              CISA KEV
            </span>
          </div>
          <p className="text-xl font-black text-rose-400 font-mono mt-0.5">
            {overview.kev_count}
          </p>
          <span className="text-[10px] text-rose-400/80 mt-1 block">Actively weaponized</span>
        </div>

        <div
          onClick={() => { setStatusFilter("Resolved"); setCurrentPage(1); }}
          className={`soc-glass rounded-xl p-3 border cursor-pointer transition-all ${
            statusFilter === "Resolved" ? "border-emerald-400 bg-[#162338]" : "border-emerald-500/20"
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
              Resolved
            </span>
            <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
          </div>
          <p className="text-xl font-black text-emerald-300 font-mono mt-0.5">
            {overview.resolved_count}
          </p>
          <span className="text-[10px] text-emerald-400/80 mt-1 block">Mitigated &amp; closed</span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: FINDINGS INVENTORY */}
      {/* ========================================================================= */}
      {activeTab === "findings" && (
        <div className="space-y-4">
          {/* Table Search & Filter Strip */}
          <div className="flex flex-col md:flex-row items-center justify-between gap-3 bg-[#0B1220] p-3 rounded-xl border border-blue-500/20">
            <div className="relative w-full md:w-80">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search CVE-ID, title, IP or hostname..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-[#111C2D] border border-blue-500/20 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto text-xs">
              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="bg-[#111C2D] border border-blue-500/20 text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-400 text-xs"
              >
                <option value="all">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Informational">Informational</option>
              </select>

              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="bg-[#111C2D] border border-blue-500/20 text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-400 text-xs"
              >
                <option value="all">All Statuses</option>
                <option value="Open">Open</option>
                <option value="Acknowledged">Acknowledged</option>
                <option value="In Progress">In Progress</option>
                <option value="Resolved">Resolved</option>
                <option value="Accepted Risk">Accepted Risk</option>
                <option value="False Positive">False Positive</option>
              </select>

              {/* KEV Filter Pill */}
              <button
                onClick={() => {
                  setKevOnly(!kevOnly);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg border font-semibold flex items-center gap-1.5 transition-colors ${
                  kevOnly
                    ? "bg-rose-500/20 border-rose-500/50 text-rose-300"
                    : "bg-[#111C2D] border-blue-500/20 text-slate-400 hover:text-white"
                }`}
              >
                <Flame className="h-3 w-3 text-rose-400" />
                KEV Only
              </button>

              {/* Export CSV Button */}
              <button
                onClick={handleExportCSV}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white hover:border-cyan-400 transition-colors shrink-0"
              >
                <Download className="h-3.5 w-3.5 text-cyan-400" />
                Export CSV
              </button>
            </div>
          </div>

          {/* Findings Table */}
          <div className="soc-glass rounded-xl border border-blue-500/20 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase bg-[#0B1220]">
                    <th className="py-3 px-3">Severity</th>
                    <th className="py-3 px-3">CVE ID</th>
                    <th className="py-3 px-3">Vulnerability Title</th>
                    <th className="py-3 px-3">Target Asset</th>
                    <th className="py-3 px-3">Affected Service</th>
                    <th className="py-3 px-3">CVSS</th>
                    <th className="py-3 px-3">Threat</th>
                    <th className="py-3 px-3">Status</th>
                    <th className="py-3 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-medium">
                  {paginatedFindings.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-12 text-center text-slate-500">
                        No security findings match the current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedFindings.map((f) => (
                      <tr key={f.id} className="hover:bg-[#162338]/50 transition-colors">
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border inline-block ${getSeverityColor(
                              f.severity
                            )}`}
                          >
                            {f.severity}
                          </span>
                        </td>

                        <td className="py-3 px-3 font-mono font-bold">
                          {f.cve_id ? (
                            <span className="text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20 text-[11px]">
                              {f.cve_id}
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">None</span>
                          )}
                        </td>

                        <td className="py-3 px-3">
                          <div className="flex flex-col">
                            <span
                              onClick={() => openFindingDetails(f)}
                              className="text-white font-semibold hover:text-cyan-400 cursor-pointer truncate max-w-xs"
                            >
                              {f.title}
                            </span>
                            <span className="text-slate-400 text-[11px] truncate max-w-xs">
                              {f.description?.substring(0, 60)}...
                            </span>
                          </div>
                        </td>

                        <td className="py-3 px-3">
                          <div className="flex flex-col">
                            <span className="text-slate-200 font-mono text-[11px]">
                              {f.asset_name || "Unknown Asset"}
                            </span>
                            <span className="text-slate-500 text-[10px] font-mono">
                              {f.asset_ip}
                            </span>
                          </div>
                        </td>

                        <td className="py-3 px-3 text-slate-300 font-mono text-[11px]">
                          {f.affected_service || "TCP Service"}
                        </td>

                        <td className="py-3 px-3 font-mono font-bold text-slate-200">
                          {f.cvss_score ? f.cvss_score.toFixed(1) : "0.0"}
                        </td>

                        <td className="py-3 px-3">
                          {f.is_kev ? (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-bold">
                              <Flame className="h-3 w-3 text-rose-400" />
                              KEV
                            </span>
                          ) : (
                            <span className="text-slate-600 text-[10px] font-mono">—</span>
                          )}
                        </td>

                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              f.status === "Resolved"
                                ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                                : f.status === "In Progress"
                                ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                                : f.status === "Accepted Risk"
                                ? "bg-amber-500/10 text-amber-300 border-amber-500/30"
                                : "bg-slate-800 text-slate-300 border-slate-700"
                            }`}
                          >
                            {f.status}
                          </span>
                        </td>

                        <td className="py-3 px-3 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => {
                                setRemediationTarget(f);
                                setRemediationStatus(f.status);
                                setRemediationNotes("");
                                setRemediationError("");
                              }}
                              className="px-2 py-1 rounded bg-[#111C2D] border border-blue-500/20 text-[11px] text-cyan-300 hover:text-white hover:border-cyan-400 transition-colors"
                            >
                              Triage
                            </button>
                            <button
                              onClick={() => openFindingDetails(f)}
                              className="p-1 rounded bg-[#111C2D] border border-blue-500/20 text-slate-400 hover:text-white transition-colors"
                            >
                              <ExternalLink className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="p-3 bg-[#0B1220]/80 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <div>
                Showing{" "}
                <strong className="text-white">
                  {(currentPage - 1) * pageSize + (paginatedFindings.length > 0 ? 1 : 0)}
                </strong>{" "}
                to{" "}
                <strong className="text-white">
                  {Math.min(currentPage * pageSize, filteredFindings.length)}
                </strong>{" "}
                of <strong className="text-white">{filteredFindings.length}</strong> findings
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(Math.max(currentPage - 1, 1))}
                  disabled={currentPage === 1}
                  className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <span className="font-mono px-2">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(Math.min(currentPage + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="p-1.5 rounded-lg bg-[#111C2D] border border-blue-500/20 text-slate-300 hover:text-white disabled:opacity-40"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: SCAN CENTER (Vulnerability Assessment Orchestrator) */}
      {/* ========================================================================= */}
      {activeTab === "scans" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Assessment Launcher Card */}
            <div className="soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
              <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
                <Play className="h-4 w-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Launch Vulnerability Assessment
                </h3>
              </div>

              <div className="space-y-3 text-xs">
                {/* Scope Selector */}
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Target Network Scope (Approved Only)
                  </label>
                  <select
                    value={selectedScopeId}
                    onChange={(e) => setSelectedScopeId(e.target.value)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 text-white rounded-lg p-2 focus:outline-none focus:border-cyan-400 text-xs"
                  >
                    {scopes.length === 0 ? (
                      <option value="">No registered scopes found</option>
                    ) : (
                      scopes.map((s) => (
                        <option
                          key={s.id}
                          value={s.id}
                          disabled={s.authorization_status !== "Approved" || s.is_expired}
                        >
                          {s.scope_name} ({s.cidr_range}) — {s.authorization_status}
                          {s.is_expired ? " [EXPIRED]" : ""}
                        </option>
                      ))
                    )}
                  </select>
                </div>

                {/* Scan Type / Engine */}
                <div>
                  <label className="text-slate-300 font-semibold block mb-1">
                    Assessment Engine
                  </label>
                  <select
                    value={selectedScanType}
                    onChange={(e) => setSelectedScanType(e.target.value as any)}
                    className="w-full bg-[#0B1220] border border-blue-500/20 text-white rounded-lg p-2 focus:outline-none focus:border-cyan-400 text-xs"
                  >
                    <option value="mock">Diagnostic Mock Scanner (Safe Simulation)</option>
                    <option value="openvas">Greenbone / OpenVAS Community Engine</option>
                    <option value="zap_baseline">OWASP ZAP Passive Baseline Engine</option>
                  </select>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Passive checks and safe vulnerability verification only. Exploits &amp; brute-force are strictly disabled.
                  </p>
                </div>

                {/* Operator Certification Checkbox */}
                <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 space-y-2">
                  <div className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      id="operator_cert"
                      checked={certified}
                      onChange={(e) => setCertified(e.target.checked)}
                      className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-400 focus:ring-0"
                    />
                    <label htmlFor="operator_cert" className="text-[11px] text-slate-300 leading-snug cursor-pointer">
                      I certify under organizational authority that our organization owns or has explicit written authorization to assess targets in this subnet.
                    </label>
                  </div>
                </div>

                {scanMessage && (
                  <div
                    className={`p-2.5 rounded-lg text-xs font-mono border ${
                      scanMessage.error
                        ? "bg-rose-950/30 text-rose-300 border-rose-500/30"
                        : "bg-emerald-950/30 text-emerald-300 border-emerald-500/30"
                    }`}
                  >
                    {scanMessage.text}
                  </div>
                )}

                <button
                  onClick={handleLaunchScan}
                  disabled={launchingScan || !certified}
                  className="w-full py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold hover:shadow-lg hover:shadow-cyan-500/20 active:scale-95 disabled:opacity-40 transition-all flex items-center justify-center gap-2"
                >
                  <Play className="h-4 w-4 fill-white" />
                  {launchingScan ? "Dispatching Assessment..." : "Start Assessment"}
                </button>
              </div>
            </div>

            {/* Assessment History Table */}
            <div className="lg:col-span-2 soc-glass rounded-xl p-5 border border-blue-500/20 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    Recent Vulnerability Scans
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  {scans.length} Recorded Runs
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px] uppercase">
                      <th className="py-2 px-3">Scan Type</th>
                      <th className="py-2 px-3">Engine</th>
                      <th className="py-2 px-3">Status</th>
                      <th className="py-2 px-3">Assets</th>
                      <th className="py-2 px-3">Findings</th>
                      <th className="py-2 px-3">Started At</th>
                      <th className="py-2 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-medium">
                    {scans.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-slate-500">
                          No assessment runs recorded yet.
                        </td>
                      </tr>
                    ) : (
                      scans.map((s) => (
                        <tr key={s.id} className="hover:bg-[#162338]/40">
                          <td className="py-2.5 px-3 font-mono font-bold text-cyan-300">
                            {s.scan_type.toUpperCase()}
                          </td>
                          <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs">
                            {s.scanner_name}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                s.status === "completed"
                                  ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                                  : s.status === "running"
                                  ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30 animate-pulse"
                                  : s.status === "cancelled"
                                  ? "bg-slate-800 text-slate-400 border-slate-700"
                                  : "bg-rose-500/10 text-rose-300 border-rose-500/30"
                              }`}
                            >
                              {s.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300">
                            {s.total_assets}
                          </td>
                          <td className="py-2.5 px-3 font-mono font-bold text-amber-300">
                            {s.total_findings}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                            {s.started_at ? formatDateTime(s.started_at) : "Pending"}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {s.status === "running" && (
                              <button
                                onClick={() => handleCancelScan(s.id)}
                                className="px-2 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 hover:bg-rose-500/30 text-[10px] font-bold"
                              >
                                Cancel
                              </button>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: ANALYTICS & CHARTS */}
      {/* ========================================================================= */}
      {activeTab === "analytics" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart 1: Severity Distribution */}
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2">
              Vulnerability Severity Distribution
            </h3>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0B1220",
                      borderColor: "#1E293B",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-center gap-4 text-xs font-mono mt-2">
              {severityChartData.map((d) => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                  <span className="text-slate-400">{d.name}:</span>
                  <span className="text-white font-bold">{d.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Chart 2: Top Affected Assets */}
          <div className="soc-glass rounded-xl p-5 border border-blue-500/20">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2">
              Top Affected Assets
            </h3>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={
                    overview.top_affected_assets.length > 0
                      ? overview.top_affected_assets
                      : [
                          { asset_id: "mock-1", asset_name: "EDGE-FIREWALL", asset_ip: "10.0.0.1", total: 2, critical: 1, high: 1 },
                          { asset_id: "mock-2", asset_name: "POSTGRES-PRIMARY", asset_ip: "10.0.0.2", total: 2, critical: 0, high: 2 },
                        ]
                  }
                  layout="vertical"
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                  <XAxis type="number" stroke="#64748B" />
                  <YAxis type="category" dataKey="asset_name" stroke="#64748B" width={110} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0B1220",
                      borderColor: "#1E293B",
                      borderRadius: "8px",
                    }}
                  />
                  <Bar dataKey="total" fill="#3B82F6" name="Total Findings" />
                  <Bar dataKey="critical" fill="#FB7185" name="Critical" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 1: FINDING DETAILS DRAWER */}
      {/* ========================================================================= */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto p-6 shadow-2xl space-y-6">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityColor(
                      selectedFinding.severity
                    )}`}
                  >
                    {selectedFinding.severity} (CVSS {selectedFinding.cvss_score})
                  </span>
                  {selectedFinding.cve_id && (
                    <span className="font-mono text-cyan-400 font-bold text-xs bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                      {selectedFinding.cve_id}
                    </span>
                  )}
                  {selectedFinding.is_kev && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-bold">
                      <Flame className="h-3 w-3 text-rose-400" />
                      CISA KEV WEAPONIZED
                    </span>
                  )}
                  <span className="text-[10px] font-mono text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                    Prioritization: {selectedFinding.prioritization_score}/100
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-2">
                  {selectedFinding.title}
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Affected Host: {selectedFinding.asset_name} ({selectedFinding.asset_ip})
                  {selectedFinding.affected_service && ` • Service: ${selectedFinding.affected_service}`}
                </p>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Description */}
            <div className="space-y-1.5 text-xs">
              <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
                Vulnerability Analysis
              </h4>
              <p className="text-slate-300 leading-relaxed bg-[#0B1220] p-3 rounded-lg border border-slate-800">
                {selectedFinding.description}
              </p>
            </div>

            {/* Proof of Concept Evidence */}
            {selectedFinding.evidence && (
              <div className="space-y-1.5 text-xs">
                <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <FileCode className="h-4 w-4 text-cyan-400" />
                  Proof of Concept Evidence
                </h4>
                <pre className="p-3 rounded-lg bg-[#060A12] border border-blue-500/20 font-mono text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.evidence}
                </pre>
              </div>
            )}

            {/* Remediation Guidance */}
            <div className="space-y-1.5 text-xs">
              <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <CheckCircle className="h-4 w-4 text-emerald-400" />
                Remediation Guidance
              </h4>
              <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-200 leading-relaxed">
                <p>{selectedFinding.remediation}</p>
              </div>
            </div>

            {/* Remediation Audit History */}
            <div className="space-y-2 text-xs border-t border-slate-800 pt-4">
              <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <Clock className="h-4 w-4 text-purple-400" />
                Remediation History Audit Trail
              </h4>
              {findingHistory.length === 0 ? (
                <p className="text-slate-500 italic text-[11px]">
                  No status transitions recorded yet.
                </p>
              ) : (
                <div className="space-y-2">
                  {findingHistory.map((h) => (
                    <div
                      key={h.id}
                      className="p-2.5 rounded bg-[#0B1220] border border-slate-800 text-[11px] flex items-start justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-slate-400">{h.previous_status}</span>
                          <span className="text-cyan-400">→</span>
                          <span className="font-bold text-white font-mono">{h.new_status}</span>
                        </div>
                        {h.notes && <p className="text-slate-300 mt-1 italic">"{h.notes}"</p>}
                      </div>
                      <span className="text-slate-500 font-mono text-[10px]">
                        {formatDateTime(h.created_at)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Close Drawer */}
            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 hover:text-white text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: TRIAGE & REMEDIATION WORKFLOW MODAL */}
      {/* ========================================================================= */}
      {remediationTarget && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111C2D] border border-blue-500/40 rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                Vulnerability Triage &amp; Lifecycle
              </h3>
              <button
                onClick={() => setRemediationTarget(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 block">Target Finding:</span>
                <p className="text-white font-bold mt-0.5">{remediationTarget.title}</p>
                <p className="text-[11px] font-mono text-cyan-400">
                  Current Status: {remediationTarget.status}
                </p>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  New Status Transition:
                </label>
                <select
                  value={remediationStatus}
                  onChange={(e) => setRemediationStatus(e.target.value as VulnerabilityStatus)}
                  className="w-full bg-[#0B1220] border border-blue-500/30 text-white rounded-lg p-2 focus:outline-none focus:border-cyan-400 text-xs"
                >
                  <option value="Open">Open (Unacknowledged)</option>
                  <option value="Acknowledged">Acknowledged (In Triage)</option>
                  <option value="In Progress">In Progress (Patching / Remediating)</option>
                  <option value="Resolved">Resolved (Fixed &amp; Verified)</option>
                  <option value="Accepted Risk">Accepted Risk (Formal Justification Required)</option>
                  <option value="False Positive">False Positive (Technical Justification Required)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-semibold block mb-1">
                  Justification / Remediation Notes:
                  {(remediationStatus === "Accepted Risk" || remediationStatus === "False Positive") && (
                    <span className="text-rose-400 ml-1 font-bold">* MANDATORY</span>
                  )}
                </label>
                <textarea
                  rows={3}
                  placeholder={
                    remediationStatus === "Accepted Risk"
                      ? "Specify compensating security controls, risk register ID, and CISO approval reference..."
                      : remediationStatus === "False Positive"
                      ? "Explain why the observed banner or signal does not represent an exploitable flaw..."
                      : "Optional notes regarding patch schedule or remediation ticket..."
                  }
                  value={remediationNotes}
                  onChange={(e) => setRemediationNotes(e.target.value)}
                  className="w-full bg-[#0B1220] border border-blue-500/30 text-white rounded-lg p-2.5 focus:outline-none focus:border-cyan-400 text-xs"
                />
              </div>

              {remediationError && (
                <div className="p-2.5 rounded bg-rose-950/30 border border-rose-500/30 text-rose-300 text-xs">
                  {remediationError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setRemediationTarget(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  onClick={submitRemediation}
                  disabled={submittingRemediation}
                  className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold hover:shadow-lg hover:shadow-cyan-500/20 active:scale-95 disabled:opacity-40"
                >
                  {submittingRemediation ? "Submitting..." : "Apply Transition"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
