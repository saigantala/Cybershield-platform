"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  User,
  CheckCircle2,
  ShieldAlert,
  Flame,
  FileText,
  Shield,
  Layers,
  CheckSquare,
  Activity,
  Radio,
  Globe2,
  ExternalLink,
  Plus,
  Trash2,
  Download,
  Copy,
  Check,
  Send,
  MessageSquare,
  Lock,
  ChevronRight,
  BookOpen,
  ClipboardCheck,
  Zap,
  Server,
  RefreshCw,
  X,
  FileCode,
} from "lucide-react";
import {
  Incident,
  IncidentAlert,
  IncidentNote,
  IncidentTimelineEvent,
  IncidentAttackMapping,
  IncidentEvidence,
  IncidentPlaybook,
  ResponseRequest,
  IncidentStatus,
  IncidentSeverity,
  IncidentPriority,
  ResponseActionType,
} from "@/types/incident";
import {
  apiIncidents,
  apiAttack,
  apiEvidence,
  apiPlaybooks,
  apiResponseRequests,
  apiAlerts,
} from "@/lib/api-client";
import { formatDateTime } from "@/lib/utils";

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  Critical: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  High: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Medium: { bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/30" },
  Low: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
};

const STATUS_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  New: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  Acknowledged: { bg: "bg-purple-500/10", text: "text-purple-400", border: "border-purple-500/30" },
  Investigating: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  Containment: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/30" },
  Eradication: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  Recovery: { bg: "bg-cyan-500/10", text: "text-cyan-400", border: "border-cyan-500/30" },
  Resolved: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  Closed: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

export default function IncidentInvestigationWorkspace() {
  const params = useParams();
  const incidentId = params?.incidentId as string;
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<
    "overview" | "alerts" | "assets" | "attack" | "evidence" | "playbooks" | "approvals" | "timeline"
  >("overview");

  const [incident, setIncident] = useState<Incident | null>(null);
  const [alerts, setAlerts] = useState<IncidentAlert[]>([]);
  const [timeline, setTimeline] = useState<IncidentTimelineEvent[]>([]);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [attackMappings, setAttackMappings] = useState<IncidentAttackMapping[]>([]);
  const [evidenceList, setEvidenceList] = useState<IncidentEvidence[]>([]);
  const [playbooks, setPlaybooks] = useState<IncidentPlaybook[]>([]);
  const [responseRequests, setResponseRequests] = useState<ResponseRequest[]>([]);
  const [loading, setLoading] = useState(true);

  // Modals & Action States
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [targetStatus, setTargetStatus] = useState<IncidentStatus>("Investigating");
  const [resolutionSummary, setResolutionSummary] = useState("");

  const [showAssignModal, setShowAssignModal] = useState(false);
  const [targetAssignee, setTargetAssignee] = useState("");

  const [showLinkAlertModal, setShowLinkAlertModal] = useState(false);
  const [availableAlerts, setAvailableAlerts] = useState<any[]>([]);
  const [selectedAlertToLink, setSelectedAlertToLink] = useState("");

  const [showMapTechniqueModal, setShowMapTechniqueModal] = useState(false);
  const [tacticsList, setTacticsList] = useState<any[]>([]);
  const [techniquesList, setTechniquesList] = useState<any[]>([]);
  const [selectedTechniqueId, setSelectedTechniqueId] = useState("T1190");
  const [mapConfidence, setMapConfidence] = useState(85);
  const [mapEvidence, setMapEvidence] = useState("");

  const [showUploadEvidenceModal, setShowUploadEvidenceModal] = useState(false);
  const [evName, setEvName] = useState("");
  const [evFilename, setEvFilename] = useState("");
  const [evType, setEvType] = useState<any>("log");
  const [evMime, setEvMime] = useState("text/plain");
  const [evContent, setEvContent] = useState("");
  const [evDesc, setEvDesc] = useState("");

  const [showAttachPlaybookModal, setShowAttachPlaybookModal] = useState(false);
  const [catalogPlaybooks, setCatalogPlaybooks] = useState<any[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState("");

  const [showCreateRequestModal, setShowCreateRequestModal] = useState(false);
  const [reqAction, setReqAction] = useState<ResponseActionType>("isolate_asset");
  const [reqTarget, setReqTarget] = useState("");
  const [reqJustification, setReqJustification] = useState("");

  const [newNoteText, setNewNoteText] = useState("");
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchIncidentData = async () => {
    setLoading(true);
    try {
      const [
        incRes,
        alertsRes,
        timelineRes,
        notesRes,
        attackRes,
        evidenceRes,
        pbRes,
        reqRes,
      ] = await Promise.all([
        apiIncidents.get(incidentId),
        apiIncidents.listAlerts(incidentId),
        apiIncidents.getTimeline(incidentId),
        apiIncidents.listNotes(incidentId),
        apiAttack.listIncidentMappings(incidentId),
        apiEvidence.list(incidentId),
        apiPlaybooks.listIncidentPlaybooks(incidentId),
        apiResponseRequests.list(incidentId),
      ]);

      if (incRes.data) {
        setIncident(incRes.data);
        setTargetStatus(incRes.data.status);
        setResolutionSummary(incRes.data.resolution_summary || "");
      }
      if (alertsRes.data) setAlerts(alertsRes.data);
      if (timelineRes.data) setTimeline(timelineRes.data);
      if (notesRes.data) setNotes(notesRes.data);
      if (attackRes.data) setAttackMappings(attackRes.data);
      if (evidenceRes.data) setEvidenceList(evidenceRes.data);
      if (pbRes.data) setPlaybooks(pbRes.data);
      if (reqRes.data) setResponseRequests(reqRes.data);
    } catch (e) {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      fetchIncidentData();
    }
  }, [incidentId]);

  const handleUpdateStatus = async () => {
    try {
      await apiIncidents.update(incidentId, {
        status: targetStatus,
        resolution_summary: resolutionSummary || undefined,
      });
      setShowStatusModal(false);
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleAssignIncident = async () => {
    if (!targetAssignee) return;
    try {
      await apiIncidents.assign(incidentId, targetAssignee);
      setShowAssignModal(false);
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleLinkAlert = async () => {
    if (!selectedAlertToLink) return;
    try {
      await apiIncidents.linkAlert(incidentId, selectedAlertToLink);
      setShowLinkAlertModal(false);
      setSelectedAlertToLink("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleUnlinkAlert = async (alertId: string) => {
    if (!confirm("Are you sure you want to unlink this alert from the incident?")) return;
    try {
      await apiIncidents.unlinkAlert(incidentId, alertId);
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const openMapTechniqueModal = async () => {
    setShowMapTechniqueModal(true);
    try {
      const [tacRes, techRes] = await Promise.all([
        apiAttack.getTactics(),
        apiAttack.getTechniques(),
      ]);
      if (tacRes.data) setTacticsList(tacRes.data);
      if (techRes.data) setTechniquesList(techRes.data);
    } catch (e) {
      // ignore
    }
  };

  const handleMapTechnique = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiAttack.mapTechnique(incidentId, {
        technique_id: selectedTechniqueId,
        confidence: mapConfidence,
        evidence: mapEvidence || undefined,
      });
      setShowMapTechniqueModal(false);
      setMapEvidence("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleUnmapTechnique = async (mappingId: string) => {
    try {
      await apiAttack.unmapTechnique(incidentId, mappingId);
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const b64 = evContent ? btoa(evContent) : undefined;
      await apiEvidence.upload(incidentId, {
        evidence_name: evName,
        evidence_type: evType,
        original_filename: evFilename,
        mime_type: evMime,
        file_bytes_base64: b64,
        description: evDesc || undefined,
      });
      setShowUploadEvidenceModal(false);
      setEvName("");
      setEvFilename("");
      setEvContent("");
      setEvDesc("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleDeleteEvidence = async (evidenceId: string) => {
    if (!confirm("Delete this evidence artifact from the secure vault?")) return;
    try {
      await apiEvidence.delete(incidentId, evidenceId);
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const openAttachPlaybookModal = async () => {
    setShowAttachPlaybookModal(true);
    try {
      const res = await apiPlaybooks.list();
      if (res.data) setCatalogPlaybooks(res.data);
    } catch (e) {
      // ignore
    }
  };

  const handleAttachPlaybook = async () => {
    if (!selectedPlaybookId) return;
    try {
      await apiPlaybooks.attachToIncident(incidentId, selectedPlaybookId);
      setShowAttachPlaybookModal(false);
      setSelectedPlaybookId("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleToggleStepStatus = async (
    assignmentId: string,
    stepId: string,
    currentStatus: string
  ) => {
    const nextStatus = currentStatus === "Completed" ? "Pending" : "Completed";
    try {
      await apiPlaybooks.updateStepProgress(incidentId, assignmentId, stepId, {
        status: nextStatus,
      });
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleCreateResponseRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiResponseRequests.create(incidentId, {
        action_type: reqAction,
        target_resource: reqTarget,
        justification: reqJustification,
      });
      setShowCreateRequestModal(false);
      setReqTarget("");
      setReqJustification("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim()) return;
    try {
      await apiIncidents.addNote(incidentId, newNoteText.trim());
      setNewNoteText("");
      fetchIncidentData();
    } catch (e) {
      // ignore
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportReport = async () => {
    try {
      const res = await apiIncidents.exportReport(incidentId, "json");
      if (res.data) {
        const blob = new Blob([JSON.stringify(res.data, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `Incident_${incident?.incident_number || incidentId}_Report.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      // ignore
    }
  };

  if (loading && !incident) {
    return (
      <div className="py-24 text-center text-slate-400">
        <RefreshCw className="h-8 w-8 animate-spin mx-auto text-blue-500 mb-3" />
        Loading Incident Investigation Workspace...
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-8 text-center text-slate-400">
        <AlertTriangle className="h-10 w-10 text-rose-400 mx-auto mb-3" />
        Incident case not found.
        <div className="mt-4">
          <Link href="/incidents" className="text-blue-400 hover:underline">
            &larr; Back to Incident Center
          </Link>
        </div>
      </div>
    );
  }

  const sBadge = SEVERITY_BADGES[incident.severity] || SEVERITY_BADGES.Medium;
  const stBadge = STATUS_BADGES[incident.status] || STATUS_BADGES.New;

  return (
    <div className="space-y-6">
      {/* Navigation & Header */}
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <Link
            href="/incidents"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Incident Center</span>
          </Link>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportReport}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
            >
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              <span>Export Report</span>
            </button>
            <button
              onClick={() => setShowStatusModal(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow shadow-blue-600/25"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Update Status</span>
            </button>
          </div>
        </div>

        {/* Incident Case Banner */}
        <div className="p-5 rounded-2xl border border-slate-800 bg-[#111C2D]/90 backdrop-blur-md space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xl font-black text-cyan-400 tracking-tight">
                {incident.incident_number}
              </span>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-semibold border ${sBadge.bg} ${sBadge.text} ${sBadge.border}`}
              >
                {incident.severity}
              </span>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-semibold border ${stBadge.bg} ${stBadge.text} ${stBadge.border}`}
              >
                {incident.status}
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                Priority: {incident.priority}
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs text-slate-400">
              <div className="flex items-center gap-1.5">
                <User className="h-4 w-4 text-cyan-400" />
                <span>
                  {incident.assigned_to ? "Analyst Assigned" : "Unassigned"}
                </span>
                <button
                  onClick={() => setShowAssignModal(true)}
                  className="text-blue-400 hover:underline ml-1"
                >
                  (Change)
                </button>
              </div>
              <span className="text-slate-600">|</span>
              <div className="font-mono text-slate-400">
                Detected: {formatDateTime(incident.detected_at)}
              </div>
            </div>
          </div>

          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">{incident.title}</h1>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">{incident.description}</p>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center gap-1 border-b border-slate-800 overflow-x-auto pb-1 text-xs">
        {[
          { key: "overview", label: "Overview", icon: FileText },
          { key: "alerts", label: `Alerts (${alerts.length})`, icon: AlertTriangle },
          { key: "assets", label: "Assets & Indicators", icon: Server },
          { key: "attack", label: `MITRE ATT&CK (${attackMappings.length})`, icon: Shield },
          { key: "evidence", label: `Evidence Vault (${evidenceList.length})`, icon: Lock },
          { key: "playbooks", label: `Playbooks (${playbooks.length})`, icon: BookOpen },
          { key: "approvals", label: `Response Approvals (${responseRequests.length})`, icon: ClipboardCheck },
          { key: "timeline", label: `Timeline & Notes (${timeline.length + notes.length})`, icon: Clock },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-semibold transition-colors whitespace-nowrap ${
                isActive
                  ? "bg-blue-600 text-white shadow-md shadow-blue-600/20"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT: 1. OVERVIEW */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              {/* Executive Incident Summary */}
              <div className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-4">
                <div className="flex items-center gap-2 text-white font-bold">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  <h2>Incident Investigation Summary</h2>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block mb-1">
                      What Happened
                    </span>
                    <p className="text-slate-200 leading-relaxed">
                      {incident.description}
                    </p>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block mb-1">
                      When It Happened
                    </span>
                    <div className="space-y-1 font-mono text-slate-300">
                      <div>Detected: {formatDateTime(incident.detected_at)}</div>
                      <div>Acknowledged: {incident.acknowledged_at ? formatDateTime(incident.acknowledged_at) : "Pending"}</div>
                      <div>Investigating Started: {incident.investigation_started_at ? formatDateTime(incident.investigation_started_at) : "Pending"}</div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block mb-1">
                      Affected Infrastructure
                    </span>
                    <div className="space-y-1">
                      {incident.affected_assets && incident.affected_assets.length > 0 ? (
                        incident.affected_assets.map((a, idx) => (
                          <div key={idx} className="font-mono text-cyan-300">
                            &bull; {a}
                          </div>
                        ))
                      ) : (
                        <span className="text-slate-500 italic">No specific asset assigned</span>
                      )}
                    </div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block mb-1">
                      Recommended Next Steps
                    </span>
                    <ul className="list-disc list-inside space-y-1 text-slate-300">
                      <li>Review related correlation alert telemetry.</li>
                      <li>Attach and execute standard response playbook.</li>
                      <li>Submit containment request for approval if required.</li>
                    </ul>
                  </div>
                </div>

                {incident.resolution_summary && (
                  <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs">
                    <span className="font-bold text-emerald-400 block mb-1">Resolution Summary</span>
                    <p className="text-emerald-200">{incident.resolution_summary}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Side Key Metrics */}
            <div className="space-y-4 text-xs">
              <div className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-3">
                <h3 className="font-bold text-white">Case Telemetry</h3>
                <div className="space-y-2 divide-y divide-slate-800/80">
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Incident Type:</span>
                    <span className="text-slate-200 font-medium">{incident.incident_type}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Severity:</span>
                    <span className="text-rose-400 font-bold">{incident.severity}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Priority Tier:</span>
                    <span className="text-amber-400 font-mono font-bold">{incident.priority}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Source:</span>
                    <span className="text-slate-200 font-mono">{incident.source}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Linked Alerts:</span>
                    <span className="text-cyan-400 font-bold">{alerts.length}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">Evidence Vault:</span>
                    <span className="text-purple-400 font-bold">{evidenceList.length} files</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-400">ATT&CK Techniques:</span>
                    <span className="text-indigo-400 font-bold">{attackMappings.length} mapped</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 2. ALERTS & EVENTS */}
      {activeTab === "alerts" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Correlated Security Alerts</h3>
            <button
              onClick={async () => {
                setShowLinkAlertModal(true);
                const res = await apiAlerts.list();
                if (res.data) setAvailableAlerts(res.data.items || []);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" />
              Link Alert
            </button>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase text-slate-400 bg-slate-900/40">
                  <th className="py-3 px-4">Alert Title</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Linked At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      No alerts linked to this incident.
                    </td>
                  </tr>
                ) : (
                  alerts.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4 font-semibold text-slate-200">
                        {a.alert_title}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                          {a.alert_severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {a.alert_status}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {formatDateTime(a.linked_at)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleUnlinkAlert(a.alert_id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 text-xs transition-colors"
                        >
                          Unlink
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 3. ASSETS & INDICATORS */}
      {activeTab === "assets" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 space-y-3">
            <h3 className="font-bold text-white flex items-center gap-2">
              <Server className="h-4 w-4 text-blue-400" />
              Targeted Infrastructure Assets
            </h3>
            {incident.affected_assets && incident.affected_assets.length > 0 ? (
              <div className="space-y-2">
                {incident.affected_assets.map((asset, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <span className="font-mono font-bold text-slate-200 block">{asset}</span>
                      <span className="text-[11px] text-slate-400">Critical Core Subnet Node</span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                      Critical Asset
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-500 italic">No assets assigned yet.</p>
            )}
          </div>

          <div className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 space-y-3">
            <h3 className="font-bold text-white flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-cyan-400" />
              Related Threat Indicators
            </h3>
            <div className="space-y-2">
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-mono text-cyan-300 block">198.51.100.42</span>
                  <span className="text-[11px] text-slate-400">LockBit 3.0 C2 Host (URLhaus)</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  98% Conf.
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-mono text-indigo-300 block">CVE-2024-21762</span>
                  <span className="text-[11px] text-slate-400">Fortinet FortiOS SSL-VPN RCE (CISA KEV)</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  Weaponized
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 4. MITRE ATT&CK */}
      {activeTab === "attack" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">MITRE ATT&CK Matrix Alignment</h3>
              <p className="text-xs text-slate-400">Source: MITRE ATT&CK Enterprise Matrix v15.1</p>
            </div>
            <button
              onClick={openMapTechniqueModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" />
              Map Technique
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attackMappings.length === 0 ? (
              <div className="col-span-full py-12 text-center text-slate-500 text-xs">
                No ATT&CK techniques mapped to this incident yet.
              </div>
            ) : (
              attackMappings.map((m) => (
                <div
                  key={m.id}
                  className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono font-bold text-cyan-400 text-xs">
                        {m.technique_id}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {m.tactic_name}
                      </span>
                    </div>
                    <h4 className="font-bold text-slate-200 text-sm mb-1">{m.technique_name}</h4>
                    {m.evidence && (
                      <p className="text-xs text-slate-400 mt-2 p-2 rounded bg-slate-900/60 border border-slate-800">
                        Evidence: {m.evidence}
                      </p>
                    )}
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                    <span className="text-emerald-400 font-mono">Confidence: {m.confidence}%</span>
                    <div className="flex items-center gap-2">
                      <a
                        href={`https://attack.mitre.org/techniques/${m.technique_id}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-400 hover:text-blue-300"
                        title="Official Reference"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                      <button
                        onClick={() => handleUnmapTechnique(m.id)}
                        className="text-slate-500 hover:text-rose-400"
                        title="Remove Mapping"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: 5. EVIDENCE VAULT */}
      {activeTab === "evidence" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Forensic Evidence Vault</h3>
              <p className="text-xs text-slate-400">
                Secure SHA-256 integrity-verified investigation artifacts (non-executable).
              </p>
            </div>
            <button
              onClick={() => setShowUploadEvidenceModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" />
              Upload Evidence
            </button>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase text-slate-400 bg-slate-900/40">
                  <th className="py-3 px-4">Artifact Name</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">SHA-256 Hash</th>
                  <th className="py-3 px-4">File Size</th>
                  <th className="py-3 px-4">Uploaded At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {evidenceList.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No forensic evidence artifacts stored in vault.
                    </td>
                  </tr>
                ) : (
                  evidenceList.map((e) => (
                    <tr key={e.id} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4">
                        <span className="font-semibold text-slate-200 block">{e.evidence_name}</span>
                        <span className="font-mono text-slate-500 text-[11px]">{e.original_filename}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {e.evidence_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-cyan-300">
                        <div className="flex items-center gap-1.5">
                          <span>{e.sha256_hash.substring(0, 16)}...</span>
                          <button
                            onClick={() => handleCopy(e.sha256_hash, e.id)}
                            className="text-slate-500 hover:text-slate-300"
                            title="Copy full SHA-256"
                          >
                            {copiedHash === e.id ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {Math.round(e.file_size / 1024)} KB
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {formatDateTime(e.uploaded_at)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleDeleteEvidence(e.id)}
                            className="p-1 rounded text-slate-500 hover:text-rose-400"
                            title="Delete Artifact"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT: 6. PLAYBOOKS */}
      {activeTab === "playbooks" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Active Response Playbooks</h3>
              <p className="text-xs text-slate-400">
                Actionable step-by-step SOPs guiding analyst investigation (non-destructive).
              </p>
            </div>
            <button
              onClick={openAttachPlaybookModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" />
              Attach Playbook
            </button>
          </div>

          <div className="space-y-4">
            {playbooks.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs rounded-xl border border-slate-800 bg-[#111C2D]/80">
                No response playbooks attached to this incident.
              </div>
            ) : (
              playbooks.map((pb) => (
                <div
                  key={pb.id}
                  className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4 text-blue-400" />
                      <h4 className="font-bold text-white text-sm">{pb.playbook_name}</h4>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 capitalize">
                        {pb.category}
                      </span>
                    </div>
                    <span
                      className={`px-2.5 py-0.5 rounded text-[11px] font-semibold border ${
                        pb.status === "Completed"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      }`}
                    >
                      {pb.status}
                    </span>
                  </div>

                  <div className="space-y-2 pt-2">
                    {pb.step_progress.map((step) => {
                      const isDone = step.status === "Completed";
                      return (
                        <div
                          key={step.id}
                          className={`p-3 rounded-lg border transition-colors flex items-center justify-between text-xs ${
                            isDone
                              ? "bg-slate-900/40 border-slate-800/60 text-slate-400"
                              : "bg-slate-900/80 border-slate-800 text-slate-200"
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <input
                              type="checkbox"
                              checked={isDone}
                              onChange={() =>
                                handleToggleStepStatus(pb.id, step.step_id, step.status)
                              }
                              className="rounded border-slate-700 text-blue-600 focus:ring-0 cursor-pointer"
                            />
                            <div>
                              <span className={`font-semibold ${isDone ? "line-through text-slate-500" : ""}`}>
                                {step.step_number}. {step.step_title}
                              </span>
                              {step.notes && (
                                <p className="text-[11px] text-cyan-400 mt-0.5 font-mono">
                                  Notes: {step.notes}
                                </p>
                              )}
                            </div>
                          </div>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                              isDone ? "text-emerald-400 bg-emerald-500/10" : "text-amber-400 bg-amber-500/10"
                            }`}
                          >
                            {step.status}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: 7. RESPONSE APPROVALS */}
      {activeTab === "approvals" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Response Action Requests</h3>
              <p className="text-xs text-slate-400">
                Formal approval pipeline for disruptive containment actions (human-in-the-loop).
              </p>
            </div>
            <button
              onClick={() => setShowCreateRequestModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              <Plus className="h-3.5 w-3.5" />
              Request Action
            </button>
          </div>

          <div className="space-y-3">
            {responseRequests.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs rounded-xl border border-slate-800 bg-[#111C2D]/80">
                No response action requests initiated for this incident.
              </div>
            ) : (
              responseRequests.map((req) => (
                <div
                  key={req.id}
                  className="p-4 rounded-xl border border-slate-800 bg-[#111C2D]/80 backdrop-blur-md space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-cyan-400 uppercase">
                      {req.action_type.replace(/_/g, " ")}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        req.status === "Approved"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          : req.status === "Rejected"
                          ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                          : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      }`}
                    >
                      {req.status}
                    </span>
                  </div>
                  <div className="text-slate-300">
                    Target Resource: <span className="font-mono text-white">{req.target_resource}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-slate-400">
                    Justification: {req.justification}
                  </div>
                  {req.approval && (
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                      <span className="font-bold text-slate-400 block mb-0.5">
                        Approval Decision ({req.approval.decision})
                      </span>
                      {req.approval.decision_notes}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT: 8. TIMELINE & NOTES */}
      {activeTab === "timeline" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
          {/* Investigation Notes Thread */}
          <div className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 space-y-4">
            <h3 className="font-bold text-white flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-cyan-400" />
              Investigation Notes Timeline
            </h3>

            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {notes.length === 0 ? (
                <p className="text-slate-500 italic p-3 text-center bg-slate-900/40 rounded-lg">
                  No analyst notes recorded yet.
                </p>
              ) : (
                notes.map((n) => (
                  <div
                    key={n.id}
                    className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-mono text-cyan-400">SOC Analyst</span>
                      <span>{formatDateTime(n.created_at)}</span>
                    </div>
                    <p className="text-slate-200 leading-relaxed">{n.note}</p>
                  </div>
                ))
              )}
            </div>

            <form onSubmit={handleAddNote} className="flex gap-2 pt-2 border-t border-slate-800">
              <input
                type="text"
                placeholder="Log forensic observation or investigative update..."
                value={newNoteText}
                onChange={(e) => setNewNoteText(e.target.value)}
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500"
              />
              <button
                type="submit"
                disabled={!newNoteText.trim()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg flex items-center gap-1.5 disabled:opacity-40 font-semibold"
              >
                <Send className="h-3.5 w-3.5" />
                Post
              </button>
            </form>
          </div>

          {/* Chronological System Timeline */}
          <div className="p-5 rounded-xl border border-slate-800 bg-[#111C2D]/80 space-y-4">
            <h3 className="font-bold text-white flex items-center gap-2">
              <Clock className="h-4 w-4 text-purple-400" />
              Audit Timeline
            </h3>

            <div className="space-y-3 max-h-96 overflow-y-auto pr-1 border-l border-slate-800 ml-2 pl-4">
              {timeline.map((t) => (
                <div key={t.id} className="relative space-y-1">
                  <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-blue-500 border border-slate-900" />
                  <div className="text-[11px] font-mono text-slate-500">
                    {formatDateTime(t.created_at)}
                  </div>
                  <div className="font-semibold text-slate-200">{t.description}</div>
                  <span className="text-[10px] font-mono text-cyan-400 block">
                    event: {t.event_type}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Status Update Modal */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Update Incident Status</h3>
              <button onClick={() => setShowStatusModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Status Workflow</label>
              <select
                value={targetStatus}
                onChange={(e) => setTargetStatus(e.target.value as IncidentStatus)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="New">New</option>
                <option value="Acknowledged">Acknowledged</option>
                <option value="Investigating">Investigating</option>
                <option value="Containment">Containment</option>
                <option value="Eradication">Eradication</option>
                <option value="Recovery">Recovery</option>
                <option value="Resolved">Resolved</option>
                <option value="Closed">Closed</option>
              </select>
            </div>

            {(targetStatus === "Resolved" || targetStatus === "Closed") && (
              <div>
                <label className="block text-slate-400 font-semibold mb-1">
                  Resolution Summary (Mandatory)
                </label>
                <textarea
                  rows={3}
                  required
                  placeholder="Summarize root cause, remediation actions, and outcome..."
                  value={resolutionSummary}
                  onChange={(e) => setResolutionSummary(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowStatusModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleUpdateStatus}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold"
              >
                Save Status
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Assign Analyst Modal */}
      {showAssignModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-sm bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Assign Lead Analyst</h3>
              <button onClick={() => setShowAssignModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Designated Responder</label>
              <select
                value={targetAssignee}
                onChange={(e) => setTargetAssignee(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="">Select Analyst</option>
                <option value="00000000-0000-0000-0000-000000000001">Lead SOC Analyst (Elena Rostova)</option>
                <option value="00000000-0000-0000-0000-000000000002">Security Architect (Marcus Vance)</option>
              </select>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowAssignModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleAssignIncident}
                disabled={!targetAssignee}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
              >
                Assign
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Link Alert Modal */}
      {showLinkAlertModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Link Active Alert</h3>
              <button onClick={() => setShowLinkAlertModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Select Alert</label>
              <select
                value={selectedAlertToLink}
                onChange={(e) => setSelectedAlertToLink(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="">Select Alert from SOC Queue</option>
                {availableAlerts.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.severity}] {a.title}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowLinkAlertModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleLinkAlert}
                disabled={!selectedAlertToLink}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
              >
                Link to Case
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Map Technique Modal */}
      {showMapTechniqueModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Map MITRE ATT&CK Technique</h3>
              <button onClick={() => setShowMapTechniqueModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleMapTechnique} className="space-y-3">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Technique</label>
                <select
                  value={selectedTechniqueId}
                  onChange={(e) => setSelectedTechniqueId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                >
                  {techniquesList.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.id}: {t.name} ({t.tactic_name})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">
                  Confidence ({mapConfidence}%)
                </label>
                <input
                  type="range"
                  min={1}
                  max={100}
                  value={mapConfidence}
                  onChange={(e) => setMapConfidence(Number(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Observable Evidence</label>
                <textarea
                  rows={2}
                  placeholder="Observed packet trace, log line, or forensic artifact..."
                  value={mapEvidence}
                  onChange={(e) => setMapEvidence(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowMapTechniqueModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold"
                >
                  Map to Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Upload Evidence Modal */}
      {showUploadEvidenceModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Upload Forensic Evidence</h3>
              <button onClick={() => setShowUploadEvidenceModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleUploadEvidence} className="space-y-3">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Evidence Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Host Syslog Dump (WAN Router)"
                  value={evName}
                  onChange={(e) => setEvName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Original Filename</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. syslog_dump.log"
                    value={evFilename}
                    onChange={(e) => setEvFilename(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Type</label>
                  <select
                    value={evType}
                    onChange={(e) => setEvType(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                  >
                    <option value="log">Log File</option>
                    <option value="document">Document / PDF</option>
                    <option value="screenshot">Screenshot / Image</option>
                    <option value="network_capture">Network Capture (pcap)</option>
                    <option value="forensic_artifact">Forensic Artifact</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Evidence Payload / Text</label>
                <textarea
                  rows={3}
                  placeholder="Paste log snippet, memory dump headers, or raw text..."
                  value={evContent}
                  onChange={(e) => setEvContent(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowUploadEvidenceModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!evName || !evFilename}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
                >
                  Upload & Verify
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Attach Playbook Modal */}
      {showAttachPlaybookModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Attach Response Playbook</h3>
              <button onClick={() => setShowAttachPlaybookModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Select Playbook</label>
              <select
                value={selectedPlaybookId}
                onChange={(e) => setSelectedPlaybookId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
              >
                <option value="">Select Playbook SOP</option>
                {catalogPlaybooks.map((pb) => (
                  <option key={pb.id} value={pb.id}>
                    {pb.playbook_name} ({pb.steps?.length || 0} steps)
                  </option>
                ))}
              </select>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowAttachPlaybookModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleAttachPlaybook}
                disabled={!selectedPlaybookId}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
              >
                Attach Playbook
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Response Action Request Modal */}
      {showCreateRequestModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111C2D] border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Request Response Action</h3>
              <button onClick={() => setShowCreateRequestModal(false)} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateResponseRequest} className="space-y-3">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Action Type</label>
                <select
                  value={reqAction}
                  onChange={(e) => setReqAction(e.target.value as ResponseActionType)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                >
                  <option value="isolate_asset">Request Asset Isolation</option>
                  <option value="disable_account">Request Account Disablement</option>
                  <option value="block_firewall_rule">Request Firewall Rule Block</option>
                  <option value="remediate_vulnerability">Request Vulnerability Remediation</option>
                  <option value="escalate_incident">Request Executive Escalation</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Target Resource</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 192.168.10.15 or user@domain.com"
                  value={reqTarget}
                  onChange={(e) => setReqTarget(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Justification</label>
                <textarea
                  rows={2}
                  required
                  placeholder="Provide operational necessity and threat context for approving officer..."
                  value={reqJustification}
                  onChange={(e) => setReqJustification(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateRequestModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!reqTarget || !reqJustification}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold disabled:opacity-40"
                >
                  Submit for Approval
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
