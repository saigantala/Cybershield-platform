"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ListCheck,
  Search,
  Filter,
  CheckCircle2,
  AlertCircle,
  Clock,
  ExternalLink,
  Edit3,
  Layers,
  Save,
  X,
  FileText,
  Paperclip,
  Check,
  RefreshCw,
} from "lucide-react";
import { apiCompliance } from "@/lib/api-client";
import type { AssessmentStatus, ComplianceControl } from "@/types/compliance";

export default function ComplianceAssessmentsPage() {
  const searchParams = useSearchParams();
  const initialFramework = searchParams.get("framework") || "all";

  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [selectedFramework, setSelectedFramework] = useState(initialFramework);
  const [selectedStatus, setSelectedStatus] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);

  // Edit Assessment Modal state
  const [editingControl, setEditingControl] = useState<ComplianceControl | null>(null);
  const [newStatus, setNewStatus] = useState<AssessmentStatus>("Not Assessed");
  const [assignedOwner, setAssignedOwner] = useState("");
  const [reviewDate, setReviewDate] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const loadControls = async () => {
    setLoading(true);
    const fwParam = selectedFramework === "all" ? undefined : selectedFramework;
    const res = await apiCompliance.getControls({ framework_code: fwParam });
    if (res.data) {
      setControls(res.data);
    } else {
      // Mock fallback
      setControls([
        {
          id: "81000000-0000-0000-0000-000000000001",
          framework_id: "80000000-0000-0000-0000-000000000001",
          framework_code: "NIST_CSF_2_0",
          control_id: "ID.AM-01",
          title: "Physical Devices and Systems Inventory",
          description: "Physical devices and systems within the organization are inventoried and correlated with network discovery telemetry.",
          domain: "Identify (Asset Management)",
          remediation_guidance: "Deploy automated Nmap discovery scans across authorized subnets.",
          current_status: "Implemented",
          assigned_owner: "Lead Infrastructure Architect",
          review_date: "2026-12-15",
          notes: "Automated network discovery active across all approved subnets.",
          evidence_count: 1,
        },
        {
          id: "81000000-0000-0000-0000-000000000002",
          framework_id: "80000000-0000-0000-0000-000000000001",
          framework_code: "NIST_CSF_2_0",
          control_id: "ID.RA-01",
          title: "Asset Vulnerability Identification",
          description: "Asset vulnerabilities are identified, validated against authoritative CVE and CISA KEV feeds, and documented.",
          domain: "Identify (Risk Assessment)",
          remediation_guidance: "Execute weekly vulnerability scans and correlate findings with the national CISA KEV catalog.",
          current_status: "Partially Implemented",
          assigned_owner: "Senior Vulnerability Analyst",
          review_date: "2026-11-20",
          notes: "Weekly vulnerability scans automated. Secondary air-gapped lab pending.",
          evidence_count: 0,
        },
        {
          id: "81000000-0000-0000-0000-000000000006",
          framework_id: "80000000-0000-0000-0000-000000000002",
          framework_code: "CIS_CONTROLS_V8",
          control_id: "CIS-1.1",
          title: "Enterprise Asset Inventory",
          description: "Establish and maintain a detailed enterprise asset inventory tracking authorized and unauthorized hardware.",
          domain: "Asset Management",
          remediation_guidance: "Run automated network discovery on RFC 1918 subnets.",
          current_status: "Implemented",
          assigned_owner: "Chief Security Architect",
          review_date: "2026-12-01",
          notes: "Continuous inventory active.",
          evidence_count: 1,
        },
        {
          id: "81000000-0000-0000-0000-000000000010",
          framework_id: "80000000-0000-0000-0000-000000000003",
          framework_code: "OWASP_TOP_10_2021",
          control_id: "A01:2021",
          title: "Broken Access Control Defense",
          description: "Enforce strict server-side authorization boundaries, deny access by default, and restrict CORS.",
          domain: "Access Control",
          remediation_guidance: "Enforce PostgreSQL Row Level Security (RLS) across all collections.",
          current_status: "Implemented",
          assigned_owner: "AppSec Lead",
          review_date: "2026-12-30",
          notes: "RLS enabled across all tables.",
          evidence_count: 0,
        },
      ]);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadControls();
  }, [selectedFramework]);

  const openEditModal = (control: ComplianceControl) => {
    setEditingControl(control);
    setNewStatus(control.current_status);
    setAssignedOwner(control.assigned_owner || "");
    setReviewDate(control.review_date || "");
    setNotes(control.notes || "");
    setSaveSuccess(false);
  };

  const handleSaveAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingControl) return;
    setSaving(true);
    const res = await apiCompliance.createAssessment({
      control_id: editingControl.id,
      status: newStatus,
      assigned_owner: assignedOwner || undefined,
      review_date: reviewDate || undefined,
      notes: notes || undefined,
    });
    setSaving(false);
    if (res.data) {
      setSaveSuccess(true);
      setTimeout(() => {
        setEditingControl(null);
        loadControls();
      }, 1200);
    }
  };

  const filteredControls = controls.filter((c) => {
    const matchesSearch =
      c.control_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (c.domain && c.domain.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus =
      selectedStatus === "all" || c.current_status === selectedStatus;

    return matchesSearch && matchesStatus;
  });

  const statusBadge = (status: AssessmentStatus) => {
    switch (status) {
      case "Implemented":
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1 w-fit">
            <CheckCircle2 className="h-3 w-3" /> Implemented
          </span>
        );
      case "Partially Implemented":
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center gap-1 w-fit">
            <Clock className="h-3 w-3" /> Partial
          </span>
        );
      case "Not Applicable":
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-slate-500/10 text-slate-400 border border-slate-500/20 flex items-center gap-1 w-fit">
            N/A
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-1 w-fit">
            <AlertCircle className="h-3 w-3" /> Not Assessed
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/compliance" className="hover:text-cyan-400 transition-colors">
              Compliance
            </Link>
            <span>/</span>
            <span className="text-cyan-400 font-medium">Control Assessments</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <ListCheck className="h-6 w-6 text-cyan-400" />
            Compliance Controls & Assessment Register
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Audit implementation progress, assign control owners, and link supporting digital evidence.
          </p>
        </div>

        <Link
          href="/compliance/evidence"
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-2 transition-colors self-start md:self-auto"
        >
          <Paperclip className="h-4 w-4 text-cyan-400" />
          Evidence Vault
        </Link>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search by Control ID, title or domain..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Framework Filter */}
          <select
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
            className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Frameworks</option>
            <option value="NIST_CSF_2_0">NIST CSF 2.0</option>
            <option value="CIS_CONTROLS_V8">CIS Controls v8</option>
            <option value="OWASP_TOP_10_2021">OWASP Top 10 (2021)</option>
            <option value="ISO_27001_2022">ISO/IEC 27001:2022</option>
          </select>

          {/* Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Statuses</option>
            <option value="Implemented">Implemented</option>
            <option value="Partially Implemented">Partially Implemented</option>
            <option value="Not Assessed">Not Assessed</option>
            <option value="Not Applicable">Not Applicable</option>
          </select>
        </div>

        <div className="text-xs text-slate-400 font-mono self-end md:self-auto">
          Showing {filteredControls.length} Controls
        </div>
      </div>

      {/* Controls Table */}
      <div className="rounded-2xl bg-[#111C2D]/80 border border-slate-800/80 backdrop-blur-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">Control ID</th>
                <th className="py-3 px-4 font-semibold">Framework</th>
                <th className="py-3 px-4 font-semibold">Control Title & Domain</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold">Assigned Owner</th>
                <th className="py-3 px-4 font-semibold">Review Date</th>
                <th className="py-3 px-4 font-semibold">Evidence</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredControls.map((c) => (
                <tr key={c.id} className="hover:bg-slate-800/20 transition-colors">
                  <td className="py-3.5 px-4 font-mono font-bold text-cyan-300">
                    {c.control_id}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">
                    {c.framework_code.replace(/_/g, " ")}
                  </td>
                  <td className="py-3.5 px-4 max-w-sm">
                    <div className="font-semibold text-white">{c.title}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5 truncate">{c.domain}</div>
                  </td>
                  <td className="py-3.5 px-4">{statusBadge(c.current_status)}</td>
                  <td className="py-3.5 px-4 text-slate-300">
                    {c.assigned_owner || <span className="text-slate-600">Unassigned</span>}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">
                    {c.review_date || <span className="text-slate-600">Not set</span>}
                  </td>
                  <td className="py-3.5 px-4">
                    {c.evidence_count > 0 ? (
                      <span className="inline-flex items-center gap-1 font-mono text-cyan-400 font-bold">
                        <Paperclip className="h-3 w-3" /> {c.evidence_count} file(s)
                      </span>
                    ) : (
                      <span className="text-slate-600">None</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => openEditModal(c)}
                      className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors ml-auto"
                    >
                      <Edit3 className="h-3.5 w-3.5 text-cyan-400" />
                      Assess
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Assessment Modal */}
      {editingControl && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg p-6 rounded-2xl bg-[#111C2D] border border-cyan-500/40 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {editingControl.control_id} • {editingControl.framework_code}
                </span>
                <h2 className="text-sm font-bold text-white mt-1">{editingControl.title}</h2>
              </div>
              <button
                onClick={() => setEditingControl(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300">Official Control Description:</div>
              <p className="leading-relaxed">{editingControl.description}</p>
            </div>

            <form onSubmit={handleSaveAssessment} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Assessment Status</label>
                  <select
                    value={newStatus}
                    onChange={(e) => setNewStatus(e.target.value as AssessmentStatus)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Implemented">Implemented</option>
                    <option value="Partially Implemented">Partially Implemented</option>
                    <option value="Not Assessed">Not Assessed</option>
                    <option value="Not Applicable">Not Applicable</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Assigned Control Owner</label>
                  <input
                    type="text"
                    placeholder="e.g. Lead SOC Architect"
                    value={assignedOwner}
                    onChange={(e) => setAssignedOwner(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Scheduled Audit Review Date</label>
                <input
                  type="date"
                  value={reviewDate}
                  onChange={(e) => setReviewDate(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Assessment Notes & Findings</label>
                <textarea
                  rows={3}
                  placeholder="Document telemetry evidence, policy mappings, or residual risk justifications..."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500 resize-none"
                />
              </div>

              {saveSuccess && (
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
                  <Check className="h-4 w-4" /> Assessment saved successfully
                </div>
              )}

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setEditingControl(null)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white shadow-lg shadow-blue-500/20 flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  {saving ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Save className="h-3.5 w-3.5" />
                  )}
                  Save Assessment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
