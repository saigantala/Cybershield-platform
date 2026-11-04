export type IncidentType =
  | "Malware"
  | "Phishing"
  | "Unauthorized Access"
  | "Suspicious Network Activity"
  | "Vulnerability Exploitation"
  | "Data Exposure"
  | "Account Compromise"
  | "IoT Security Incident"
  | "Other";

export type IncidentSeverity = "Critical" | "High" | "Medium" | "Low";
export type IncidentPriority = "P1" | "P2" | "P3" | "P4";
export type IncidentStatus =
  | "New"
  | "Acknowledged"
  | "Investigating"
  | "Containment"
  | "Eradication"
  | "Recovery"
  | "Resolved"
  | "Closed";

export interface Incident {
  id: string;
  organization_id: string;
  incident_number: string;
  title: string;
  description: string;
  incident_type: IncidentType;
  severity: IncidentSeverity;
  status: IncidentStatus;
  priority: IncidentPriority;
  source: string;
  assigned_to?: string | null;
  created_by?: string | null;
  affected_assets?: string[];
  detected_at: string;
  acknowledged_at?: string | null;
  investigation_started_at?: string | null;
  resolved_at?: string | null;
  closed_at?: string | null;
  resolution_summary?: string | null;
  created_at: string;
  updated_at: string;
  linked_alerts_count?: number;
  notes_count?: number;
  evidence_count?: number;
  attack_mappings_count?: number;
}

export interface IncidentAlert {
  id: string;
  incident_id: string;
  alert_id: string;
  linked_by?: string | null;
  linked_at: string;
  alert_title?: string;
  alert_severity?: string;
  alert_status?: string;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author_id?: string | null;
  note: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentTimelineEvent {
  id: string;
  incident_id: string;
  event_type: string;
  description: string;
  actor_id?: string | null;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface AttackTactic {
  id: string;
  name: string;
  description: string;
  reference_url: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic_id: string;
  tactic_name: string;
  description: string;
  platforms: string[];
  reference_url: string;
}

export interface IncidentAttackMapping {
  id: string;
  incident_id: string;
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  confidence: number;
  evidence?: string | null;
  created_by?: string | null;
  created_at: string;
}

export type EvidenceType =
  | "log"
  | "document"
  | "screenshot"
  | "network_capture"
  | "forensic_artifact"
  | "other";

export interface IncidentEvidence {
  id: string;
  incident_id: string;
  organization_id: string;
  evidence_name: string;
  evidence_type: EvidenceType;
  original_filename: string;
  mime_type: string;
  file_size: number;
  sha256_hash: string;
  storage_path: string;
  download_url?: string;
  uploaded_by?: string | null;
  description?: string | null;
  uploaded_at: string;
}

export type PlaybookCategory =
  | "authentication"
  | "malware"
  | "phishing"
  | "vulnerability"
  | "ransomware"
  | "network"
  | "custom";

export interface PlaybookStep {
  id: string;
  step_number: number;
  step_title: string;
  step_description: string;
  is_required: boolean;
}

export interface Playbook {
  id: string;
  organization_id: string;
  playbook_name: string;
  category: PlaybookCategory;
  description: string;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
  steps: PlaybookStep[];
}

export interface StepProgress {
  id: string;
  step_id: string;
  step_number: number;
  step_title: string;
  status: "Pending" | "In Progress" | "Completed" | "Skipped";
  notes?: string | null;
  completed_by?: string | null;
  completed_at?: string | null;
}

export interface IncidentPlaybook {
  id: string;
  incident_id: string;
  playbook_id: string;
  playbook_name: string;
  category: string;
  status: string;
  assigned_to?: string | null;
  started_at: string;
  completed_at?: string | null;
  step_progress: StepProgress[];
}

export type ResponseActionType =
  | "isolate_asset"
  | "disable_account"
  | "block_firewall_rule"
  | "remediate_vulnerability"
  | "escalate_incident";

export interface ResponseApproval {
  id: string;
  request_id: string;
  decision: "Approved" | "Rejected";
  decision_notes: string;
  decided_by?: string | null;
  decided_at: string;
}

export interface ResponseRequest {
  id: string;
  incident_id: string;
  organization_id: string;
  action_type: ResponseActionType;
  target_resource: string;
  justification: string;
  status: "Pending" | "Approved" | "Rejected";
  requested_by?: string | null;
  created_at: string;
  updated_at: string;
  approval?: ResponseApproval | null;
}
