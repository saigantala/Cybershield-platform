import { createClient } from "@/lib/supabase/client";
import type {
  ComplianceAssessment,
  ComplianceControl,
  ComplianceEvidence,
  ComplianceFramework,
  ComplianceSummary,
} from "@/types/compliance";
import type {
  MonitoringStatus,
  MonitoringAgent,
  TelemetryFlow,
  DeviceHealth,
  NetworkAnomaly,
  MonitoringRule,
  MonitoringEvent,
  TrafficAnalytics,
  ProtocolBreakdown,
  TopTalker,
} from "@/types/monitoring";
import type {
  ExecutiveDashboardData,
  ReportPreview,
  SecurityPosture,
  SecurityReport,
} from "@/types/reporting";
import type {
  APIKey,
  APIKeyCreated,
  Organization,
  OrganizationInvitation,
  OrganizationMember,
  OrganizationSubscription,
  PlatformOverview,
  SubscriptionPlan,
  SubscriptionUsage,
} from "@/types/saas";
import type {
  SOARWorkflow,
  SOARWorkflowCreatePayload,
  SOARWorkflowUpdatePayload,
  SOARExecution,
  SOARExecutionDetail,
  SOARExecutionRequest,
  SOARExecutionLogItem,
  SOARApproval,
  SOARApprovalDecisionPayload,
  SOARAnalytics,
  NotificationTemplate,
  NotificationTestPayload,
  NotificationDelivery,
} from "@/types/soar";
import type {
  AIDetectionModel,
  AIModelVersion,
  AIDetectionRule,
  AIDetectionRuleCreatePayload,
  AIDetectionResult,
  AIDetectionInvestigation,
  AIFeedbackPayload,
  AIRiskPrediction,
  AIThreatAnalytics,
  AIThreatInvestigationQueryResponse,
} from "@/types/ai-detection";
import type {
  Integration,
  IntegrationCreate,
  IntegrationUpdate,
  IntegrationTestRequest,
  IntegrationTestResponse,
  IntegrationSyncRequest,
  IntegrationSyncResponse,
  IntegrationDeliveryLog,
  IntegrationHealthSummary,
  WebhookEndpoint,
  WebhookEndpointCreate,
  WebhookEndpointUpdate,
  WebhookSecretRotateResponse,
  WebhookDeliveryAttempt,
  WebhookReplayResponse,
} from "@/types/integrations";
import type {
  SystemHealthOverview,
  ProductionReadinessReport,
} from "@/types/system-health";
import type {
  ThreatHuntingCase,
  ThreatHuntingCaseCreate,
  ThreatHuntingCaseUpdate,
  ThreatHuntingFinding,
  ThreatHuntingFindingCreate,
  ThreatHuntingQueryParam,
  ThreatHuntingQueryResult,
  ThreatHuntingQueryResponse,
  ThreatHuntingQuerySave,
  IOCInvestigationResponse,
  ThreatHuntingDashboardStats,
} from "@/types/threat-hunting";
import type {
  ForensicCase,
  ForensicCaseCreate,
  ForensicCaseUpdate,
  ForensicCaseAsset,
  ForensicEvidenceItem,
  ForensicEvidenceItemCreate,
  ForensicCustodyEvent,
  CustodyChainVerificationResponse,
  ForensicAnalysisJob,
  ForensicCaseNote,
  ForensicCaseNoteCreate,
  ForensicReport,
  ForensicReportCreate,
  ForensicTimelineFilter,
  ForensicTimelineResponse,
  ForensicsDashboardStats,
} from "@/types/forensics";
import type {
  UserSecurityOverview,
  MFASetupResponse,
  MFAVerifyRequest,
  MFAVerifyResponse,
  MFARecoveryCodeResponse,
  StepUpAuthResponse,
  SSOProvider,
  SSOProviderCreate,
  DomainVerification,
  SessionMetadata,
  AccessPolicy,
  AccessPolicyCreate,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  OrganizationIdentityPolicy,
  IdentityAuditEvent,
} from "@/types/identity";
import type {
  SecurityAssessment,
  SecurityCheck,
  SecurityTestRun,
  SecurityFinding,
  SecurityFindingNote,
  SecurityRiskAcceptanceRequest,
  DependencyPackageItem,
  ContainerScanResult,
  SecurityConfigurationCheck,
  SecurityScannerConfig,
  SecurityComponentInventory,
  SecurityAssuranceOverview,
  SecurityReportExport,
} from "@/types/security-assurance";
import type { EnterpriseReleaseOverview } from "@/types/release-readiness";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export interface ApiResponse<T> {
  data: T | null;
  error: string | null;
  isOffline?: boolean;
}

export interface BackendHealth {
  isOnline: boolean;
  status: string;
  version?: string;
  redisConnected?: boolean;
}

/**
 * Checks the operational health and connectivity of the FastAPI backend.
 */
export async function getBackendHealth(): Promise<BackendHealth> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`${API_BASE_URL}/health`, {
      method: "GET",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return {
        isOnline: true,
        status: data.status,
        version: data.version,
        redisConnected: data.redis_connected,
      };
    }
    return { isOnline: false, status: "degraded" };
  } catch (err) {
    return { isOnline: false, status: "offline" };
  }
}

/**
 * Core authenticated fetch wrapper forwarding Supabase bearer token to FastAPI backend.
 */
export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${API_BASE_URL}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  // 1. Retrieve current Supabase access token if logged in
  let bearerToken: string | null = null;
  try {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) {
      bearerToken = session.access_token;
    }
  } catch (e) {
    // Continue without token if session check fails
  }

  // 2. Prepare headers
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (bearerToken) {
    headers["Authorization"] = `Bearer ${bearerToken}`;
  }

  // 3. Timeout handler (8 seconds)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const res = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const json = await res.json().catch(() => null);

    if (!res.ok) {
      const detail = json?.detail || json?.error || `Request failed with status ${res.status}`;
      return {
        data: null,
        error: typeof detail === "string" ? detail : JSON.stringify(detail),
      };
    }

    return { data: json as T, error: null };
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return {
        data: null,
        error: "CyberShield Security Gateway request timed out.",
        isOffline: true,
      };
    }
    return {
      data: null,
      error: "FastAPI security backend is currently unreachable.",
      isOffline: true,
    };
  }
}

// Reusable service clients
export const apiAssets = {
  list: (params?: Record<string, any>) => {
    const query = params ? `?${new URLSearchParams(params).toString()}` : "";
    return apiFetch<{ items: any[]; total: number }>(`/assets${query}`);
  },
  get: (id: string) => apiFetch<any>(`/assets/${id}`),
  create: (data: any) => apiFetch<any>("/assets", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: any) =>
    apiFetch<any>(`/assets/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  delete: (id: string) => apiFetch<any>(`/assets/${id}`, { method: "DELETE" }),
};

export const apiScopes = {
  list: () => apiFetch<any[]>("/scopes"),
  create: (data: any) => apiFetch<any>("/scopes", { method: "POST", body: JSON.stringify(data) }),
  get: (id: string) => apiFetch<any>(`/scopes/${id}`),
  approve: (id: string) => apiFetch<any>(`/scopes/${id}/approve`, { method: "POST" }),
};

export const apiScans = {
  list: () => apiFetch<any[]>("/scans"),
  create: (data: any) => apiFetch<any>("/scans", { method: "POST", body: JSON.stringify(data) }),
  get: (id: string) => apiFetch<any>(`/scans/${id}`),
  cancel: (id: string) => apiFetch<any>(`/scans/${id}/cancel`, { method: "POST" }),
  getEvents: (id: string) => apiFetch<any[]>(`/scans/${id}/events`),
};

export const apiVulnerabilities = {
  getOverview: (orgId?: string) => {
    const q = orgId ? `?organization_id=${orgId}` : "";
    return apiFetch<any>(`/vulnerabilities/overview${q}`);
  },
  listFindings: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<{ items: any[]; total: number; page: number; page_size: number }>(
      `/vulnerabilities/findings${query}`
    );
  },
  getFinding: (id: string) => apiFetch<any>(`/vulnerabilities/findings/${id}`),
  updateFinding: (id: string, data: any) =>
    apiFetch<any>(`/vulnerabilities/findings/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  applyRemediation: (id: string, data: { new_status: string; notes?: string }) =>
    apiFetch<any>(`/vulnerabilities/findings/${id}/remediation`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getFindingHistory: (id: string) => apiFetch<any[]>(`/vulnerabilities/findings/${id}/history`),
  listScans: () => apiFetch<any[]>("/vulnerabilities/scans"),
  createScan: (data: {
    scan_scope_id: string;
    scan_type?: string;
    operator_certified: boolean;
    target_asset_ids?: string[];
  }) =>
    apiFetch<any>("/vulnerabilities/scans", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  cancelScan: (id: string) =>
    apiFetch<any>(`/vulnerabilities/scans/${id}/cancel`, { method: "POST" }),
  getCve: (cveId: string) => apiFetch<any>(`/vulnerabilities/cves/${cveId}`),
  getKev: (limit: number = 50) => apiFetch<any>(`/vulnerabilities/kev?limit=${limit}`),
  getAssetVulnerabilities: (assetId: string) =>
    apiFetch<any[]>(`/vulnerabilities/assets/${assetId}`),
};

export const apiThreatIntel = {
  getOverview: (orgId?: string) => {
    const q = orgId ? `?organization_id=${orgId}` : "";
    return apiFetch<any>(`/threat-intelligence/overview${q}`);
  },
  listIndicators: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<{ items: any[]; total: number; page: number; page_size: number }>(
      `/threat-intelligence/indicators${query}`
    );
  },
  getIndicator: (id: string) => apiFetch<any>(`/threat-intelligence/indicators/${id}`),
  createIndicator: (data: any) =>
    apiFetch<any>("/threat-intelligence/indicators", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  deleteIndicator: (id: string) =>
    apiFetch<any>(`/threat-intelligence/indicators/${id}`, { method: "DELETE" }),
  listFeeds: () => apiFetch<any[]>("/threat-intelligence/feeds"),
  syncFeed: (id: string) =>
    apiFetch<any>(`/threat-intelligence/feeds/${id}/sync`, { method: "POST" }),
};

export const apiSecurityEvents = {
  list: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<{ items: any[]; total: number; page: number; page_size: number }>(
      `/security-events${query}`
    );
  },
  get: (id: string) => apiFetch<any>(`/security-events/${id}`),
  ingest: (data: any) =>
    apiFetch<any>("/security-events", {
      method: "POST",
      body: JSON.stringify(data),
    }),
};

export const apiAlerts = {
  list: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<{ items: any[]; total: number; page: number; page_size: number }>(
      `/alerts${query}`
    );
  },
  get: (id: string) => apiFetch<any>(`/alerts/${id}`),
  update: (id: string, data: any) =>
    apiFetch<any>(`/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  assign: (id: string, assignedTo: string) =>
    apiFetch<any>(`/alerts/${id}/assign`, {
      method: "PATCH",
      body: JSON.stringify({ assigned_to: assignedTo }),
    }),
  addNote: (id: string, note: string) =>
    apiFetch<any>(`/alerts/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  linkIncident: (id: string, incidentId: string) =>
    apiFetch<any>(`/alerts/${id}/link-incident`, {
      method: "PATCH",
      body: JSON.stringify({ incident_id: incidentId }),
    }),
};

export const apiDetectionRules = {
  list: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<any[]>(`/detection-rules${query}`);
  },
  get: (id: string) => apiFetch<any>(`/detection-rules/${id}`),
  create: (data: any) =>
    apiFetch<any>("/detection-rules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  update: (id: string, data: any) =>
    apiFetch<any>(`/detection-rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  enable: (id: string) =>
    apiFetch<any>(`/detection-rules/${id}/enable`, { method: "PATCH" }),
  disable: (id: string) =>
    apiFetch<any>(`/detection-rules/${id}/disable`, { method: "PATCH" }),
};

export const apiIncidents = {
  list: (params?: Record<string, any>) => {
    const cleanParams: Record<string, string> = {};
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== "" && v !== "all") {
          cleanParams[k] = String(v);
        }
      });
    }
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<{ items: any[]; total: number; page: number; page_size: number }>(`/incidents${query}`);
  },
  get: (id: string) => apiFetch<any>(`/incidents/${id}`),
  create: (data: any) =>
    apiFetch<any>("/incidents", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  update: (id: string, data: any) =>
    apiFetch<any>(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  assign: (id: string, assignedTo: string) =>
    apiFetch<any>(`/incidents/${id}/assign`, {
      method: "POST",
      body: JSON.stringify({ assigned_to: assignedTo }),
    }),
  listAlerts: (id: string) => apiFetch<any[]>(`/incidents/${id}/alerts`),
  linkAlert: (id: string, alertId: string) =>
    apiFetch<any>(`/incidents/${id}/alerts`, {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
  unlinkAlert: (id: string, alertId: string) =>
    apiFetch<any>(`/incidents/${id}/alerts/${alertId}`, {
      method: "DELETE",
    }),
  getTimeline: (id: string) => apiFetch<any[]>(`/incidents/${id}/timeline`),
  listNotes: (id: string) => apiFetch<any[]>(`/incidents/${id}/notes`),
  addNote: (id: string, note: string) =>
    apiFetch<any>(`/incidents/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  exportReport: (id: string, format: string = "json") =>
    apiFetch<any>(`/incidents/${id}/export?format=${format}`),
};

export const apiAttack = {
  getTactics: () => apiFetch<any[]>("/attack/tactics"),
  getTechniques: (params?: { tactic_id?: string; search?: string }) => {
    const cleanParams: Record<string, string> = {};
    if (params?.tactic_id && params.tactic_id !== "all") cleanParams["tactic_id"] = params.tactic_id;
    if (params?.search) cleanParams["search"] = params.search;
    const query = Object.keys(cleanParams).length > 0 ? `?${new URLSearchParams(cleanParams).toString()}` : "";
    return apiFetch<any[]>(`/attack/techniques${query}`);
  },
  listIncidentMappings: (incidentId: string) =>
    apiFetch<any[]>(`/incidents/${incidentId}/attack-mappings`),
  mapTechnique: (incidentId: string, data: { technique_id: string; confidence: number; evidence?: string }) =>
    apiFetch<any>(`/incidents/${incidentId}/attack-mappings`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  unmapTechnique: (incidentId: string, mappingId: string) =>
    apiFetch<any>(`/incidents/${incidentId}/attack-mappings/${mappingId}`, {
      method: "DELETE",
    }),
};

export const apiEvidence = {
  list: (incidentId: string) => apiFetch<any[]>(`/incidents/${incidentId}/evidence`),
  upload: (incidentId: string, data: any) =>
    apiFetch<any>(`/incidents/${incidentId}/evidence`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  get: (incidentId: string, evidenceId: string) =>
    apiFetch<any>(`/incidents/${incidentId}/evidence/${evidenceId}`),
  delete: (incidentId: string, evidenceId: string) =>
    apiFetch<any>(`/incidents/${incidentId}/evidence/${evidenceId}`, {
      method: "DELETE",
    }),
};

export const apiPlaybooks = {
  list: () => apiFetch<any[]>("/playbooks"),
  get: (id: string) => apiFetch<any>(`/playbooks/${id}`),
  create: (data: any) =>
    apiFetch<any>("/playbooks", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  update: (id: string, data: any) =>
    apiFetch<any>(`/playbooks/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  listIncidentPlaybooks: (incidentId: string) =>
    apiFetch<any[]>(`/incidents/${incidentId}/playbooks`),
  attachToIncident: (incidentId: string, playbookId: string, assignedTo?: string) =>
    apiFetch<any>(`/incidents/${incidentId}/playbooks`, {
      method: "POST",
      body: JSON.stringify({ playbook_id: playbookId, assigned_to: assignedTo }),
    }),
  updateStepProgress: (
    incidentId: string,
    assignmentId: string,
    stepId: string,
    data: { status: string; notes?: string }
  ) =>
    apiFetch<any>(`/incidents/${incidentId}/playbooks/${assignmentId}/steps/${stepId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
};

export const apiResponseRequests = {
  list: (incidentId?: string) => {
    const q = incidentId ? `?incident_id=${incidentId}` : "";
    return apiFetch<any[]>(`/response-requests${q}`);
  },
  create: (incidentId: string, data: { action_type: string; target_resource: string; justification: string }) =>
    apiFetch<any>(`/incidents/${incidentId}/response-requests`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  approve: (requestId: string, decisionNotes: string) =>
    apiFetch<any>(`/response-requests/${requestId}/approve`, {
      method: "POST",
      body: JSON.stringify({ decision_notes: decisionNotes }),
    }),
  reject: (requestId: string, decisionNotes: string) =>
    apiFetch<any>(`/response-requests/${requestId}/reject`, {
      method: "POST",
      body: JSON.stringify({ decision_notes: decisionNotes }),
    }),
};

export const apiAI = {
  chat: (message: string, conversationId?: string) =>
    apiFetch<any>("/ai/chat", {
      method: "POST",
      body: JSON.stringify({ message, conversation_id: conversationId }),
    }),
  listConversations: () => apiFetch<any[]>("/ai/conversations"),
  getConversation: (conversationId: string) =>
    apiFetch<any>(`/ai/conversations/${conversationId}`),
  deleteConversation: (conversationId: string) =>
    apiFetch<any>(`/ai/conversations/${conversationId}`, { method: "DELETE" }),
  postMessage: (conversationId: string, message: string) =>
    apiFetch<any>(`/ai/conversations/${conversationId}/messages`, {
      method: "POST",
      body: JSON.stringify({ message }),
    }),
  analyzeAlert: (alertId: string) =>
    apiFetch<any>(`/ai/analyze-alert/${alertId}`, { method: "POST" }),
  summarizeIncident: (incidentId: string) =>
    apiFetch<any>(`/ai/summarize-incident/${incidentId}`, { method: "POST" }),
  recommendRemediation: (findingId: string) =>
    apiFetch<any>(`/ai/recommend-remediation/${findingId}`, { method: "POST" }),
  listRecommendations: (params?: { type?: string; entityId?: string; status?: string }) => {
    const q = new URLSearchParams();
    if (params?.type) q.append("recommendation_type", params.type);
    if (params?.entityId) q.append("related_entity_id", params.entityId);
    if (params?.status) q.append("status", params.status);
    return apiFetch<any[]>(`/ai/recommendations${q.toString() ? `?${q.toString()}` : ""}`);
  },
  reviewRecommendation: (recommendationId: string, decision: "Approved" | "Rejected", notes: string) =>
    apiFetch<any>(`/ai/recommendations/${recommendationId}/review`, {
      method: "POST",
      body: JSON.stringify({ decision, review_notes: notes }),
    }),
  getUsage: () => apiFetch<any>("/ai/usage"),
};

export const apiAnalytics = {
  getOverview: () => apiFetch<any>("/analytics/overview"),
  getAssets: () => apiFetch<any>("/analytics/assets"),
  getVulnerabilities: () => apiFetch<any>("/analytics/vulnerabilities"),
  getAlerts: () => apiFetch<any>("/analytics/alerts"),
  getIncidents: () => apiFetch<any>("/analytics/incidents"),
  getThreatIntelligence: () => apiFetch<any>("/analytics/threat-intelligence"),
  getPosture: (orgId?: string) =>
    apiFetch<SecurityPosture>(`/analytics/posture${orgId ? `?organization_id=${orgId}` : ""}`),
  getExecutiveSummary: (dateRange?: string, orgId?: string) =>
    apiFetch<ExecutiveDashboardData>(
      `/analytics/executive-summary?date_range=${dateRange || "30d"}${
        orgId ? `&organization_id=${orgId}` : ""
      }`
    ),
  getCompliance: (orgId?: string) =>
    apiFetch<ComplianceSummary>(
      `/analytics/compliance${orgId ? `?organization_id=${orgId}` : ""}`
    ),
};

export const apiOrganizations = {
  list: () => apiFetch<Organization[]>("/organizations"),
  create: (data: Partial<Organization>) =>
    apiFetch<Organization>("/organizations", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  get: (orgId: string) => apiFetch<Organization>(`/organizations/${orgId}`),
  update: (orgId: string, data: Partial<Organization>) =>
    apiFetch<Organization>(`/organizations/${orgId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  switch: (orgId: string) =>
    apiFetch<Organization>(`/organizations/${orgId}/switch`, {
      method: "POST",
    }),
};

export const apiTeam = {
  listMembers: (orgId?: string) =>
    apiFetch<OrganizationMember[]>(`/team/members${orgId ? `?org_id=${orgId}` : ""}`),
  updateMemberRole: (memberId: string, role: string, orgId?: string) =>
    apiFetch<OrganizationMember>(
      `/team/members/${memberId}/role${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "PATCH",
        body: JSON.stringify({ role }),
      }
    ),
  removeMember: (memberId: string, orgId?: string) =>
    apiFetch<{ status: string; message: string }>(
      `/team/members/${memberId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "DELETE",
      }
    ),
  listInvitations: (orgId?: string) =>
    apiFetch<OrganizationInvitation[]>(`/team/invitations${orgId ? `?org_id=${orgId}` : ""}`),
  inviteMember: (data: { email: string; role: string }, orgId?: string) =>
    apiFetch<OrganizationInvitation>(`/team/invitations${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  resendInvitation: (invId: string, orgId?: string) =>
    apiFetch<OrganizationInvitation>(
      `/team/invitations/${invId}/resend${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
      }
    ),
  cancelInvitation: (invId: string, orgId?: string) =>
    apiFetch<{ status: string; message: string }>(
      `/team/invitations/${invId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "DELETE",
      }
    ),
};

export const apiSubscriptions = {
  getPlans: () => apiFetch<SubscriptionPlan[]>("/subscriptions/plans"),
  getCurrent: (orgId?: string) =>
    apiFetch<OrganizationSubscription>(
      `/subscriptions/current${orgId ? `?org_id=${orgId}` : ""}`
    ),
  checkout: (data: { plan_code: string; billing_interval?: string }, orgId?: string) =>
    apiFetch<{ subscription: OrganizationSubscription; checkout_url: string }>(
      `/subscriptions/checkout${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  cancel: (orgId?: string) =>
    apiFetch<OrganizationSubscription>(
      `/subscriptions/cancel${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
      }
    ),
  getUsage: (orgId?: string) =>
    apiFetch<SubscriptionUsage>(`/subscriptions/usage${orgId ? `?org_id=${orgId}` : ""}`),
};

export const apiApiKeys = {
  list: (orgId?: string) =>
    apiFetch<APIKey[]>(`/api-keys${orgId ? `?org_id=${orgId}` : ""}`),
  create: (
    data: { key_name: string; scopes: string[]; expires_in_days?: number },
    orgId?: string
  ) =>
    apiFetch<APIKeyCreated>(`/api-keys${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  revoke: (keyId: string, orgId?: string) =>
    apiFetch<{ status: string; message: string }>(
      `/api-keys/${keyId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "DELETE",
      }
    ),
  rotate: (keyId: string, orgId?: string) =>
    apiFetch<APIKeyCreated>(`/api-keys/${keyId}/rotate${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
    }),
};

export const apiPlatformAdmin = {
  getOverview: () => apiFetch<PlatformOverview>("/platform-admin/overview"),
  listOrganizations: () => apiFetch<Organization[]>("/platform-admin/organizations"),
  listUsers: () => apiFetch<any[]>("/platform-admin/users"),
  suspendOrganization: (orgId: string, reason: string) =>
    apiFetch<Organization>(`/platform-admin/organizations/${orgId}/suspend`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  reactivateOrganization: (orgId: string) =>
    apiFetch<Organization>(`/platform-admin/organizations/${orgId}/reactivate`, {
      method: "POST",
    }),
};

export const apiCompliance = {
  getFrameworks: (orgId?: string) =>
    apiFetch<ComplianceFramework[]>(`/compliance/frameworks${orgId ? `?org_id=${orgId}` : ""}`),
  getControls: (params?: { framework_code?: string; domain?: string; org_id?: string }) => {
    const q = new URLSearchParams();
    if (params?.framework_code) q.append("framework_code", params.framework_code);
    if (params?.domain) q.append("domain", params.domain);
    if (params?.org_id) q.append("org_id", params.org_id);
    return apiFetch<ComplianceControl[]>(`/compliance/controls${q.toString() ? `?${q.toString()}` : ""}`);
  },
  listAssessments: (orgId?: string) =>
    apiFetch<ComplianceAssessment[]>(`/compliance/assessments${orgId ? `?org_id=${orgId}` : ""}`),
  createAssessment: (data: Partial<ComplianceAssessment>, orgId?: string) =>
    apiFetch<ComplianceAssessment>(`/compliance/assessments${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateAssessment: (assessmentId: string, data: Partial<ComplianceAssessment>, orgId?: string) =>
    apiFetch<ComplianceAssessment>(
      `/compliance/assessments/${assessmentId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),
  listEvidence: (params?: { control_id?: string; assessment_id?: string; org_id?: string }) => {
    const q = new URLSearchParams();
    if (params?.control_id) q.append("control_id", params.control_id);
    if (params?.assessment_id) q.append("assessment_id", params.assessment_id);
    if (params?.org_id) q.append("org_id", params.org_id);
    return apiFetch<ComplianceEvidence[]>(`/compliance/evidence${q.toString() ? `?${q.toString()}` : ""}`);
  },
  uploadEvidence: async (formData: FormData, orgId?: string): Promise<ApiResponse<ComplianceEvidence>> => {
    const url = `${API_BASE_URL}/compliance/evidence${orgId ? `?org_id=${orgId}` : ""}`;
    let bearerToken: string | null = null;
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      if (session?.access_token) bearerToken = session.access_token;
    } catch {}

    const headers: Record<string, string> = {};
    if (bearerToken) headers["Authorization"] = `Bearer ${bearerToken}`;

    try {
      const res = await fetch(url, { method: "POST", headers, body: formData });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        return { data: null, error: errJson.detail || `Upload failed: ${res.statusText}` };
      }
      const data = await res.json();
      return { data, error: null };
    } catch (e: any) {
      return { data: null, error: e.message || "Network error", isOffline: true };
    }
  },
  deleteEvidence: (evidenceId: string, orgId?: string) =>
    apiFetch<{ status: string; message: string }>(
      `/compliance/evidence/${evidenceId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "DELETE",
      }
    ),
};

export const apiReports = {
  list: (reportType?: string, orgId?: string) =>
    apiFetch<SecurityReport[]>(
      `/reports${reportType ? `?report_type=${reportType}` : ""}${orgId ? `&org_id=${orgId}` : ""}`
    ),
  preview: (data: any, orgId?: string) =>
    apiFetch<ReportPreview>(`/reports/preview${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  generate: (data: any, orgId?: string) =>
    apiFetch<SecurityReport>(`/reports/generate${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  get: (reportId: string, orgId?: string) =>
    apiFetch<SecurityReport>(`/reports/${reportId}${orgId ? `?org_id=${orgId}` : ""}`),
  getDownloadUrl: (reportId: string, format: string = "pdf", orgId?: string) =>
    `${API_BASE_URL}/reports/${reportId}/download?format=${format}${orgId ? `&org_id=${orgId}` : ""}`,
};

export const apiMonitoring = {
  getStatus: (orgId?: string) =>
    apiFetch<MonitoringStatus>(`/monitoring/status${orgId ? `?org_id=${orgId}` : ""}`),
  listEvents: (limit: number = 50, orgId?: string) =>
    apiFetch<MonitoringEvent[]>(`/monitoring/events?limit=${limit}${orgId ? `&org_id=${orgId}` : ""}`),
  listAgents: (orgId?: string) =>
    apiFetch<MonitoringAgent[]>(`/monitoring/agents${orgId ? `?org_id=${orgId}` : ""}`),
  registerAgent: (data: Partial<MonitoringAgent>, orgId?: string) =>
    apiFetch<MonitoringAgent>(`/monitoring/agents/register${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  ingestTelemetry: (data: any, agentKey?: string) => {
    const headers: Record<string, string> = {};
    if (agentKey) headers["X-Agent-Key"] = agentKey;
    return apiFetch<any>("/monitoring/telemetry", {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    });
  },
  getTelemetry: (timeWindowSeconds: number = 3600, orgId?: string) =>
    apiFetch<TelemetryFlow[]>(
      `/monitoring/telemetry?time_window_seconds=${timeWindowSeconds}${orgId ? `&org_id=${orgId}` : ""}`
    ),
  listDeviceHealth: (orgId?: string) =>
    apiFetch<DeviceHealth[]>(`/monitoring/device-health${orgId ? `?org_id=${orgId}` : ""}`),
  getDeviceHealth: (assetId: string, orgId?: string) =>
    apiFetch<DeviceHealth>(`/monitoring/device-health/${assetId}${orgId ? `?org_id=${orgId}` : ""}`),
  listRules: (orgId?: string) =>
    apiFetch<MonitoringRule[]>(`/monitoring/rules${orgId ? `?org_id=${orgId}` : ""}`),
  createRule: (data: Partial<MonitoringRule>, orgId?: string) =>
    apiFetch<MonitoringRule>(`/monitoring/rules${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateRule: (ruleId: string, data: Partial<MonitoringRule>, orgId?: string) =>
    apiFetch<MonitoringRule>(`/monitoring/rules/${ruleId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
};

export const apiNetwork = {
  getTraffic: (timeWindowSeconds: number = 3600, orgId?: string) =>
    apiFetch<TrafficAnalytics>(
      `/network/traffic?time_window_seconds=${timeWindowSeconds}${orgId ? `&org_id=${orgId}` : ""}`
    ),
  getProtocols: (timeWindowSeconds: number = 3600, orgId?: string) =>
    apiFetch<ProtocolBreakdown[]>(
      `/network/protocols?time_window_seconds=${timeWindowSeconds}${orgId ? `&org_id=${orgId}` : ""}`
    ),
  getTopTalkers: (timeWindowSeconds: number = 3600, orgId?: string) =>
    apiFetch<TopTalker[]>(
      `/network/top-talkers?time_window_seconds=${timeWindowSeconds}${orgId ? `&org_id=${orgId}` : ""}`
    ),
  getAnomalies: (statusFilter?: string, orgId?: string) =>
    apiFetch<NetworkAnomaly[]>(
      `/network/anomalies${statusFilter ? `?status_filter=${statusFilter}` : ""}${
        orgId ? `${statusFilter ? "&" : "?"}org_id=${orgId}` : ""
      }`
    ),
};

export const apiSOAR = {
  listWorkflows: (status?: string, orgId?: string) =>
    apiFetch<SOARWorkflow[]>(
      `/soar/workflows${status ? `?status=${status}` : ""}${orgId ? `${status ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  getWorkflow: (workflowId: string, orgId?: string) =>
    apiFetch<SOARWorkflow>(`/soar/workflows/${workflowId}${orgId ? `?org_id=${orgId}` : ""}`),
  createWorkflow: (data: SOARWorkflowCreatePayload, orgId?: string) =>
    apiFetch<SOARWorkflow>(`/soar/workflows${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateWorkflow: (workflowId: string, data: SOARWorkflowUpdatePayload, orgId?: string) =>
    apiFetch<SOARWorkflow>(`/soar/workflows/${workflowId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  publishWorkflow: (workflowId: string, orgId?: string) =>
    apiFetch<SOARWorkflow>(`/soar/workflows/${workflowId}/publish${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
    }),
  executeWorkflow: (workflowId: string, data: SOARExecutionRequest, orgId?: string) =>
    apiFetch<SOARExecutionDetail>(`/soar/workflows/${workflowId}/execute${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  listExecutions: (status?: string, orgId?: string) =>
    apiFetch<SOARExecution[]>(
      `/soar/executions${status ? `?status=${status}` : ""}${orgId ? `${status ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  getExecution: (executionId: string, orgId?: string) =>
    apiFetch<SOARExecutionDetail>(`/soar/executions/${executionId}${orgId ? `?org_id=${orgId}` : ""}`),
  cancelExecution: (executionId: string, orgId?: string) =>
    apiFetch<SOARExecution>(`/soar/executions/${executionId}/cancel${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
    }),
  getExecutionLogs: (executionId: string, orgId?: string) =>
    apiFetch<SOARExecutionLogItem[]>(`/soar/executions/${executionId}/logs${orgId ? `?org_id=${orgId}` : ""}`),
  listApprovals: (decision?: string, orgId?: string) =>
    apiFetch<SOARApproval[]>(
      `/soar/approvals${decision ? `?decision=${decision}` : ""}${orgId ? `${decision ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  approveAction: (approvalId: string, data: SOARApprovalDecisionPayload, orgId?: string) =>
    apiFetch<SOARApproval>(`/soar/approvals/${approvalId}/approve${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  rejectAction: (approvalId: string, data: SOARApprovalDecisionPayload, orgId?: string) =>
    apiFetch<SOARApproval>(`/soar/approvals/${approvalId}/reject${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getAnalytics: (orgId?: string) =>
    apiFetch<SOARAnalytics>(`/soar/analytics${orgId ? `?org_id=${orgId}` : ""}`),
  listNotifications: (orgId?: string) =>
    apiFetch<NotificationTemplate[]>(`/soar/notifications${orgId ? `?org_id=${orgId}` : ""}`),
  testNotification: (data: NotificationTestPayload, orgId?: string) =>
    apiFetch<NotificationDelivery>(`/soar/notifications/test${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
};

export const apiAIDetection = {
  listResults: (category?: string, severity?: string, orgId?: string) =>
    apiFetch<AIDetectionResult[]>(
      `/ai-detection/results${category ? `?category=${category}` : ""}${
        severity ? `${category ? "&" : "?"}severity=${severity}` : ""
      }${orgId ? `${category || severity ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  getResult: (resultId: string, orgId?: string) =>
    apiFetch<AIDetectionResult>(`/ai-detection/results/${resultId}${orgId ? `?org_id=${orgId}` : ""}`),
  analyzeTelemetry: (data: any, orgId?: string) =>
    apiFetch<AIDetectionResult>(`/ai-detection/analyze${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  listRules: (orgId?: string) =>
    apiFetch<AIDetectionRule[]>(`/ai-detection/rules${orgId ? `?org_id=${orgId}` : ""}`),
  createRule: (data: AIDetectionRuleCreatePayload, orgId?: string) =>
    apiFetch<AIDetectionRule>(`/ai-detection/rules${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateRule: (ruleId: string, data: Partial<AIDetectionRuleCreatePayload>, orgId?: string) =>
    apiFetch<AIDetectionRule>(`/ai-detection/rules/${ruleId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  listInvestigations: (status?: string, orgId?: string) =>
    apiFetch<AIDetectionInvestigation[]>(
      `/ai-detection/investigations${status ? `?status=${status}` : ""}${orgId ? `${status ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  createInvestigation: (data: { detection_id: string; analyst_notes?: string; status?: string }, orgId?: string) =>
    apiFetch<AIDetectionInvestigation>(`/ai-detection/investigations${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateInvestigation: (invId: string, data: any, orgId?: string) =>
    apiFetch<AIDetectionInvestigation>(`/ai-detection/investigations/${invId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  submitFeedback: (data: AIFeedbackPayload, orgId?: string) =>
    apiFetch<any>(`/ai-detection/feedback${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  listModels: (orgId?: string) =>
    apiFetch<AIDetectionModel[]>(`/ai-detection/models${orgId ? `?org_id=${orgId}` : ""}`),
  getModelVersions: (modelId: string, orgId?: string) =>
    apiFetch<AIModelVersion[]>(`/ai-detection/models/${modelId}/versions${orgId ? `?org_id=${orgId}` : ""}`),
  getRiskPredictions: (orgId?: string) =>
    apiFetch<AIRiskPrediction[]>(`/ai-detection/risk-predictions${orgId ? `?org_id=${orgId}` : ""}`),
  getAnalytics: (orgId?: string) =>
    apiFetch<AIThreatAnalytics>(`/ai-detection/analytics${orgId ? `?org_id=${orgId}` : ""}`),
  queryInvestigationAssistant: (data: { query: string; detection_id?: string; asset_id?: string }, orgId?: string) =>
    apiFetch<AIThreatInvestigationQueryResponse>(`/ai-detection/investigation-assistant/chat${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
};

export const apiIntegrations = {
  listIntegrations: (category?: string, orgId?: string) =>
    apiFetch<Integration[]>(
      `/integrations${category ? `?category=${category}` : ""}${orgId ? `${category ? "&" : "?"}org_id=${orgId}` : ""}`
    ),
  getIntegration: (integrationId: string, orgId?: string) =>
    apiFetch<Integration>(`/integrations/${integrationId}${orgId ? `?org_id=${orgId}` : ""}`),
  createIntegration: (data: IntegrationCreate, orgId?: string) =>
    apiFetch<Integration>(`/integrations${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateIntegration: (integrationId: string, data: IntegrationUpdate, orgId?: string) =>
    apiFetch<Integration>(`/integrations/${integrationId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteIntegration: (integrationId: string, orgId?: string) =>
    apiFetch<{ success: boolean; deleted_id: string }>(
      `/integrations/${integrationId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  testConnection: (integrationId: string, data?: IntegrationTestRequest, orgId?: string) =>
    apiFetch<IntegrationTestResponse>(
      `/integrations/${integrationId}/test${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data || {}),
      }
    ),
  syncIntegration: (integrationId: string, data?: IntegrationSyncRequest, orgId?: string) =>
    apiFetch<IntegrationSyncResponse>(
      `/integrations/${integrationId}/sync${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data || {}),
      }
    ),
  listWebhooks: (orgId?: string) =>
    apiFetch<WebhookEndpoint[]>(`/integrations/webhooks${orgId ? `?org_id=${orgId}` : ""}`),
  getWebhook: (webhookId: string, orgId?: string) =>
    apiFetch<WebhookEndpoint>(`/integrations/webhooks/${webhookId}${orgId ? `?org_id=${orgId}` : ""}`),
  createWebhook: (data: WebhookEndpointCreate, orgId?: string) =>
    apiFetch<WebhookEndpoint>(`/integrations/webhooks${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateWebhook: (webhookId: string, data: WebhookEndpointUpdate, orgId?: string) =>
    apiFetch<WebhookEndpoint>(`/integrations/webhooks/${webhookId}${orgId ? `?org_id=${orgId}` : ""}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteWebhook: (webhookId: string, orgId?: string) =>
    apiFetch<{ success: boolean; deleted_id: string }>(
      `/integrations/webhooks/${webhookId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  rotateWebhookSecret: (webhookId: string, orgId?: string) =>
    apiFetch<WebhookSecretRotateResponse>(
      `/integrations/webhooks/${webhookId}/rotate-secret${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  listWebhookDeliveries: (webhookId: string, orgId?: string) =>
    apiFetch<WebhookDeliveryAttempt[]>(
      `/integrations/webhooks/${webhookId}/deliveries${orgId ? `?org_id=${orgId}` : ""}`
    ),
  replayWebhookDelivery: (webhookId: string, deliveryId: string, orgId?: string) =>
    apiFetch<WebhookReplayResponse>(
      `/integrations/webhooks/${webhookId}/deliveries/${deliveryId}/replay${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  listDeliveryLogs: (orgId?: string) =>
    apiFetch<IntegrationDeliveryLog[]>(`/integrations/logs${orgId ? `?org_id=${orgId}` : ""}`),
  getHealthSummary: (orgId?: string) =>
    apiFetch<IntegrationHealthSummary>(`/integrations/health${orgId ? `?org_id=${orgId}` : ""}`),
};

export const apiSystemHealth = {
  getSystemHealth: () =>
    apiFetch<SystemHealthOverview>("/system-health"),
  getProductionReadiness: (orgId?: string) =>
    apiFetch<ProductionReadinessReport>(
      `/system-health/production-readiness${orgId ? `?org_id=${orgId}` : ""}`
    ),
  ping: () =>
    apiFetch<{ status: string; timestamp: string; latency_ms: number }>(
      "/system-health/ping",
      { method: "POST" }
    ),
};

export const apiThreatHunting = {
  getStats: (orgId?: string) =>
    apiFetch<ThreatHuntingDashboardStats>(
      `/threat-hunting/stats${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listCases: (params?: { status?: string; priority?: string; orgId?: string }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append("status", params.status);
    if (params?.priority) q.append("priority", params.priority);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<ThreatHuntingCase[]>(`/threat-hunting/cases${qs ? `?${qs}` : ""}`);
  },
  getCase: (caseId: string, orgId?: string) =>
    apiFetch<ThreatHuntingCase>(
      `/threat-hunting/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createCase: (data: ThreatHuntingCaseCreate, orgId?: string) =>
    apiFetch<ThreatHuntingCase>(
      `/threat-hunting/cases${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  updateCase: (caseId: string, data: ThreatHuntingCaseUpdate, orgId?: string) =>
    apiFetch<ThreatHuntingCase>(
      `/threat-hunting/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "PATCH", body: JSON.stringify(data) }
    ),
  deleteCase: (caseId: string, orgId?: string) =>
    apiFetch<void>(
      `/threat-hunting/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  listFindings: (params?: { caseId?: string; orgId?: string }) => {
    const q = new URLSearchParams();
    if (params?.caseId) q.append("case_id", params.caseId);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<ThreatHuntingFinding[]>(`/threat-hunting/findings${qs ? `?${qs}` : ""}`);
  },
  createFinding: (data: ThreatHuntingFindingCreate, orgId?: string) =>
    apiFetch<ThreatHuntingFinding>(
      `/threat-hunting/findings${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  deleteFinding: (findingId: string, orgId?: string) =>
    apiFetch<void>(
      `/threat-hunting/findings/${findingId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  executeSearch: (params: ThreatHuntingQueryParam, orgId?: string) =>
    apiFetch<ThreatHuntingQueryResult>(
      `/threat-hunting/search${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(params) }
    ),
  listQueries: (orgId?: string) =>
    apiFetch<ThreatHuntingQueryResponse[]>(
      `/threat-hunting/queries${orgId ? `?org_id=${orgId}` : ""}`
    ),
  saveQuery: (data: ThreatHuntingQuerySave, orgId?: string) =>
    apiFetch<ThreatHuntingQueryResponse>(
      `/threat-hunting/queries${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  deleteQuery: (queryId: string, orgId?: string) =>
    apiFetch<void>(
      `/threat-hunting/queries/${queryId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  investigateIOC: (iocValue: string, iocType?: string, orgId?: string) =>
    apiFetch<IOCInvestigationResponse>(
      `/threat-hunting/ioc-investigation${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify({ ioc_value: iocValue, ioc_type: iocType || null }),
      }
    ),
};

export const apiForensics = {
  getStats: (orgId?: string) =>
    apiFetch<ForensicsDashboardStats>(
      `/forensics/stats${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listCases: (params?: { status?: string; priority?: string; orgId?: string }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append("status", params.status);
    if (params?.priority) q.append("priority", params.priority);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<ForensicCase[]>(`/forensics/cases${qs ? `?${qs}` : ""}`);
  },
  getCase: (caseId: string, orgId?: string) =>
    apiFetch<ForensicCase>(
      `/forensics/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createCase: (data: ForensicCaseCreate, orgId?: string) =>
    apiFetch<ForensicCase>(
      `/forensics/cases${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  updateCase: (caseId: string, data: ForensicCaseUpdate, orgId?: string) =>
    apiFetch<ForensicCase>(
      `/forensics/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "PATCH", body: JSON.stringify(data) }
    ),
  deleteCase: (caseId: string, orgId?: string) =>
    apiFetch<void>(
      `/forensics/cases/${caseId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  linkAsset: (caseId: string, assetId: string, roleInCase: string, orgId?: string) =>
    apiFetch<ForensicCaseAsset>(
      `/forensics/cases/${caseId}/assets${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify({ asset_id: assetId, role_in_case: roleInCase }),
      }
    ),
  listEvidence: (params?: { caseId?: string; orgId?: string }) => {
    const q = new URLSearchParams();
    if (params?.caseId) q.append("case_id", params.caseId);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<ForensicEvidenceItem[]>(`/forensics/evidence${qs ? `?${qs}` : ""}`);
  },
  getEvidence: (evidenceId: string, orgId?: string) =>
    apiFetch<ForensicEvidenceItem>(
      `/forensics/evidence/${evidenceId}${orgId ? `?org_id=${orgId}` : ""}`
    ),
  uploadEvidence: (data: ForensicEvidenceItemCreate, orgId?: string) =>
    apiFetch<ForensicEvidenceItem>(
      `/forensics/evidence${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  getCustodyChain: (evidenceId: string, orgId?: string) =>
    apiFetch<ForensicCustodyEvent[]>(
      `/forensics/evidence/${evidenceId}/custody${orgId ? `?org_id=${orgId}` : ""}`
    ),
  verifyChain: (evidenceId: string, orgId?: string) =>
    apiFetch<CustodyChainVerificationResponse>(
      `/forensics/evidence/${evidenceId}/verify-chain${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  appendCustodyRecord: (
    evidenceId: string,
    action: string,
    metadata: any = {},
    orgId?: string
  ) =>
    apiFetch<ForensicCustodyEvent>(
      `/forensics/evidence/${evidenceId}/custody${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ action, metadata }) }
    ),
  runAnalysis: (
    caseId: string,
    evidenceId: string,
    analysisType: string,
    orgId?: string
  ) =>
    apiFetch<ForensicAnalysisJob>(
      `/forensics/cases/${caseId}/analysis?evidence_id=${evidenceId}${orgId ? `&org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ analysis_type: analysisType }) }
    ),
  listAnalysisJobs: (caseId: string, orgId?: string) =>
    apiFetch<ForensicAnalysisJob[]>(
      `/forensics/cases/${caseId}/analysis${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listNotes: (caseId: string, orgId?: string) =>
    apiFetch<ForensicCaseNote[]>(
      `/forensics/cases/${caseId}/notes${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createNote: (caseId: string, data: ForensicCaseNoteCreate, orgId?: string) =>
    apiFetch<ForensicCaseNote>(
      `/forensics/cases/${caseId}/notes${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  deleteNote: (caseId: string, noteId: string, orgId?: string) =>
    apiFetch<void>(
      `/forensics/cases/${caseId}/notes/${noteId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  queryTimeline: (filter: ForensicTimelineFilter, orgId?: string) =>
    apiFetch<ForensicTimelineResponse>(
      `/forensics/timeline${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(filter) }
    ),
  listReports: (caseId: string, orgId?: string) =>
    apiFetch<ForensicReport[]>(
      `/forensics/cases/${caseId}/reports${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createReport: (caseId: string, data: ForensicReportCreate, orgId?: string) =>
    apiFetch<ForensicReport>(
      `/forensics/cases/${caseId}/reports${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  getReport: (reportId: string, orgId?: string) =>
    apiFetch<ForensicReport>(
      `/forensics/reports/${reportId}${orgId ? `?org_id=${orgId}` : ""}`
    ),
};

export const apiIdentity = {
  getOverview: (orgId?: string) =>
    apiFetch<UserSecurityOverview>(
      `/identity/overview${orgId ? `?org_id=${orgId}` : ""}`
    ),
  setupMFA: (orgId?: string) =>
    apiFetch<MFASetupResponse>(
      `/identity/mfa/setup${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  verifyMFA: (data: MFAVerifyRequest, orgId?: string) =>
    apiFetch<MFAVerifyResponse>(
      `/identity/mfa/verify${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  rotateRecoveryCodes: (code: string, orgId?: string) =>
    apiFetch<MFARecoveryCodeResponse>(
      `/identity/mfa/rotate-recovery${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ code }) }
    ),
  disableMFA: (code: string, orgId?: string) =>
    apiFetch<{ success: boolean; message: string }>(
      `/identity/mfa/disable${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ code }) }
    ),
  stepUpAuth: (action: string, code: string, orgId?: string) =>
    apiFetch<StepUpAuthResponse>(
      `/identity/mfa/step-up${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ action, code }) }
    ),
  listSSOProviders: (orgId?: string) =>
    apiFetch<SSOProvider[]>(
      `/identity/sso/providers${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createSSOProvider: (data: SSOProviderCreate, orgId?: string) =>
    apiFetch<SSOProvider>(
      `/identity/sso/providers${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  updateSSOProvider: (providerId: string, data: Partial<SSOProviderCreate>, orgId?: string) =>
    apiFetch<SSOProvider>(
      `/identity/sso/providers/${providerId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "PUT", body: JSON.stringify(data) }
    ),
  deleteSSOProvider: (providerId: string, orgId?: string) =>
    apiFetch<{ success: boolean; message: string }>(
      `/identity/sso/providers/${providerId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  testSSOConnection: (providerId: string, orgId?: string) =>
    apiFetch<{
      success: boolean;
      provider_name: string;
      discovery_status: string;
      message: string;
      details: any;
    }>(
      `/identity/sso/providers/${providerId}/test${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  listDomainVerifications: (orgId?: string) =>
    apiFetch<DomainVerification[]>(
      `/identity/sso/domains${orgId ? `?org_id=${orgId}` : ""}`
    ),
  initiateDomainVerification: (domainName: string, orgId?: string) =>
    apiFetch<DomainVerification>(
      `/identity/sso/domains${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ domain_name: domainName }) }
    ),
  verifyDomain: (domainName: string, orgId?: string) =>
    apiFetch<DomainVerification>(
      `/identity/sso/domains/${domainName}/verify${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  listSessions: (orgId?: string) =>
    apiFetch<SessionMetadata[]>(
      `/identity/sessions${orgId ? `?org_id=${orgId}` : ""}`
    ),
  revokeSession: (sessionId: string, reason?: string, orgId?: string) =>
    apiFetch<{ success: boolean; revoked_session_id: string; message: string }>(
      `/identity/sessions/revoke${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify({ session_id: sessionId, reason }) }
    ),
  revokeAllSessions: (orgId?: string) =>
    apiFetch<{ success: boolean; revoked_count: number; message: string }>(
      `/identity/sessions/revoke-all${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST" }
    ),
  getOrganizationPolicy: (orgId?: string) =>
    apiFetch<OrganizationIdentityPolicy>(
      `/identity/policies/org${orgId ? `?org_id=${orgId}` : ""}`
    ),
  updateOrganizationPolicy: (data: Partial<OrganizationIdentityPolicy>, orgId?: string) =>
    apiFetch<OrganizationIdentityPolicy>(
      `/identity/policies/org${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "PUT", body: JSON.stringify(data) }
    ),
  listAccessPolicies: (orgId?: string) =>
    apiFetch<AccessPolicy[]>(
      `/identity/policies/rules${orgId ? `?org_id=${orgId}` : ""}`
    ),
  createAccessPolicy: (data: AccessPolicyCreate, orgId?: string) =>
    apiFetch<AccessPolicy>(
      `/identity/policies/rules${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  updateAccessPolicy: (policyId: string, data: Partial<AccessPolicyCreate>, orgId?: string) =>
    apiFetch<AccessPolicy>(
      `/identity/policies/rules/${policyId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "PUT", body: JSON.stringify(data) }
    ),
  deleteAccessPolicy: (policyId: string, orgId?: string) =>
    apiFetch<{ success: boolean; message: string }>(
      `/identity/policies/rules/${policyId}${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "DELETE" }
    ),
  evaluateAccess: (data: PolicyEvaluationRequest, orgId?: string) =>
    apiFetch<PolicyEvaluationResponse>(
      `/identity/policies/evaluate${orgId ? `?org_id=${orgId}` : ""}`,
      { method: "POST", body: JSON.stringify(data) }
    ),
  listAuditLog: (params?: { limit?: number; eventType?: string; orgId?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit) q.append("limit", params.limit.toString());
    if (params?.eventType) q.append("event_type", params.eventType);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<IdentityAuditEvent[]>(`/identity/audit${qs ? `?${qs}` : ""}`);
  },
};

export const apiSecurityAssurance = {
  getOverview: (orgId?: string) =>
    apiFetch<SecurityAssuranceOverview>(
      `/security-assurance/overview${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listAssessments: (orgId?: string) =>
    apiFetch<SecurityAssessment[]>(
      `/security-assurance/assessments${orgId ? `?org_id=${orgId}` : ""}`
    ),
  runAssessment: (
    data: {
      assessment_name: string;
      assessment_type: string;
      target_environment?: string;
    },
    orgId?: string
  ) =>
    apiFetch<SecurityAssessment>(
      `/security-assurance/assessments/run${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  getAssessmentChecks: (assessmentId: string, orgId?: string) =>
    apiFetch<SecurityCheck[]>(
      `/security-assurance/assessments/${assessmentId}/checks${orgId ? `?org_id=${orgId}` : ""}`
    ),
  runApiSecuritySuite: (
    data: { target_host?: string; include_fuzzing?: boolean },
    orgId?: string
  ) =>
    apiFetch<SecurityTestRun>(
      `/security-assurance/tests/run-api-suite${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  listTestRuns: (orgId?: string) =>
    apiFetch<SecurityTestRun[]>(
      `/security-assurance/tests/runs${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listFindings: (params?: {
    status?: string;
    severity?: string;
    category?: string;
    orgId?: string;
  }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append("status", params.status);
    if (params?.severity) q.append("severity", params.severity);
    if (params?.category) q.append("category", params.category);
    if (params?.orgId) q.append("org_id", params.orgId);
    const qs = q.toString();
    return apiFetch<SecurityFinding[]>(`/security-assurance/findings${qs ? `?${qs}` : ""}`);
  },
  createFinding: (data: Partial<SecurityFinding>, orgId?: string) =>
    apiFetch<SecurityFinding>(
      `/security-assurance/findings${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  updateFinding: (
    findingId: string,
    data: {
      status?: string;
      severity?: string;
      remediation_recommendation?: string;
      verification_notes?: string;
    },
    orgId?: string
  ) =>
    apiFetch<SecurityFinding>(
      `/security-assurance/findings/${findingId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "PUT",
        body: JSON.stringify(data),
      }
    ),
  addFindingNote: (findingId: string, content: string, orgId?: string) =>
    apiFetch<SecurityFindingNote>(
      `/security-assurance/findings/${findingId}/notes${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify({ content }),
      }
    ),
  acceptRisk: (
    findingId: string,
    data: SecurityRiskAcceptanceRequest,
    orgId?: string
  ) =>
    apiFetch<SecurityFinding>(
      `/security-assurance/findings/${findingId}/accept-risk${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  getDependencies: (orgId?: string) =>
    apiFetch<DependencyPackageItem[]>(
      `/security-assurance/dependencies${orgId ? `?org_id=${orgId}` : ""}`
    ),
  getContainers: (orgId?: string) =>
    apiFetch<ContainerScanResult[]>(
      `/security-assurance/containers${orgId ? `?org_id=${orgId}` : ""}`
    ),
  getConfiguration: (orgId?: string) =>
    apiFetch<SecurityConfigurationCheck[]>(
      `/security-assurance/configuration${orgId ? `?org_id=${orgId}` : ""}`
    ),
  listScannerConfigs: (orgId?: string) =>
    apiFetch<SecurityScannerConfig[]>(
      `/security-assurance/scanners/config${orgId ? `?org_id=${orgId}` : ""}`
    ),
  updateScannerConfig: (
    configId: string,
    data: Partial<SecurityScannerConfig>,
    orgId?: string
  ) =>
    apiFetch<SecurityScannerConfig>(
      `/security-assurance/scanners/config/${configId}${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "PUT",
        body: JSON.stringify(data),
      }
    ),
  exportReport: (
    data: { report_type: string; format: string },
    orgId?: string
  ) =>
    apiFetch<SecurityReportExport>(
      `/security-assurance/reports/export${orgId ? `?org_id=${orgId}` : ""}`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
};

export const apiReleaseReadiness = {
  getOverview: (orgId?: string) =>
    apiFetch<EnterpriseReleaseOverview>(
      `/release-readiness${orgId ? `?org_id=${orgId}` : ""}`
    ),
};








