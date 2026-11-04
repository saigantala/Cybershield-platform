export interface SourceReference {
  source_type:
    | "asset"
    | "vulnerability"
    | "cve"
    | "cisa_kev"
    | "threat_indicator"
    | "security_event"
    | "alert"
    | "incident"
    | "mitre_attack"
    | "playbook";
  id: string;
  name: string;
  summary?: string | null;
  severity?: string | null;
  details?: Record<string, any> | null;
}

export interface ChatMessage {
  id?: string;
  role: "user" | "assistant" | "system";
  content: string;
  source_references?: SourceReference[];
  created_at?: string;
}

export interface AIChatResponse {
  conversation_id: string;
  message_id: string;
  response: string;
  source_references: SourceReference[];
  model: string;
  provider: string;
  is_mock: boolean;
  input_tokens: number;
  output_tokens: number;
  created_at: string;
}

export interface AIConversationSummary {
  id: string;
  organization_id: string;
  user_id: string;
  title: string;
  message_count: number;
  created_at: string;
  updated_at: string;
}

export interface AIConversationDetail {
  id: string;
  organization_id: string;
  user_id: string;
  title: string;
  messages: ChatMessage[];
  created_at: string;
  updated_at: string;
}

export interface AlertAnalysisResponse {
  alert_id: string;
  alert_title: string;
  summary: string;
  trigger_cause: string;
  related_assets: string[];
  related_indicators: string[];
  severity_assessment: string;
  false_positive_considerations: string;
  investigation_steps: string[];
  suggested_priority: string;
  supporting_evidence: string[];
  source_references: SourceReference[];
  model: string;
  provider: string;
  is_mock: boolean;
  generated_at: string;
}

export interface IncidentSummaryResponse {
  incident_id: string;
  incident_number: string;
  overview: string;
  timeline_summary: string[];
  affected_assets: string[];
  related_alerts: string[];
  mitre_mappings: string[];
  investigation_progress: string;
  outstanding_questions: string[];
  recommended_next_steps: string[];
  source_references: SourceReference[];
  model: string;
  provider: string;
  is_mock: boolean;
  generated_at: string;
}

export interface RemediationResponse {
  id: string;
  title: string;
  explanation: string;
  related_entity_type: string;
  related_entity_id: string;
  priority: string;
  suggested_steps: string[];
  potential_impact: string;
  verification_steps: string[];
  supporting_references: string[];
  confidence_notes: string;
  status: "Pending Review" | "Approved" | "Rejected" | "Implemented";
  model: string;
  provider: string;
  is_mock: boolean;
  created_at: string;
}

export interface AIUsageSummary {
  organization_id: string;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number;
  provider_breakdown: Record<string, number>;
  recent_logs: Array<{
    id: string;
    endpoint: string;
    model: string;
    total_tokens: number;
    estimated_cost: number;
    created_at: string;
  }>;
}
