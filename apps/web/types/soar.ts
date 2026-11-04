export type WorkflowTriggerType =
  | 'new_critical_alert'
  | 'new_high_vulnerability'
  | 'suspicious_network_activity'
  | 'threat_intel_ioc_match'
  | 'repeated_auth_failures'
  | 'unauthorized_asset_detected'
  | 'manual_investigation';

export type WorkflowStepType =
  | 'trigger'
  | 'condition'
  | 'severity_check'
  | 'asset_lookup'
  | 'threat_intel_lookup'
  | 'vulnerability_lookup'
  | 'create_incident'
  | 'add_incident_note'
  | 'assign_analyst'
  | 'send_notification'
  | 'request_approval'
  | 'generate_report'
  | 'end_workflow';

export type WorkflowCategory =
  | 'incident_response'
  | 'vulnerability_management'
  | 'threat_hunting'
  | 'network_security'
  | 'identity_access'
  | 'custom';

export type WorkflowStatus = 'Draft' | 'Published' | 'Archived';

export type ExecutionStatus =
  | 'Pending'
  | 'Running'
  | 'Waiting_Approval'
  | 'Completed'
  | 'Failed'
  | 'Cancelled';

export type ApprovalDecision =
  | 'Pending'
  | 'Approved'
  | 'Rejected'
  | 'Expired'
  | 'Cancelled'
  | 'Executed'
  | 'Execution_Failed';

export interface SOARStepConfig {
  id?: string;
  step_order: number;
  step_type: WorkflowStepType;
  name: string;
  parameters: Record<string, any>;
  next_step_id?: string;
  on_failure_step_id?: string;
}

export interface SOARWorkflow {
  id: string;
  organization_id: string;
  name: string;
  description?: string;
  category: WorkflowCategory;
  trigger_type: WorkflowTriggerType;
  trigger_conditions: Record<string, any>;
  status: WorkflowStatus;
  is_enabled: boolean;
  version: number;
  steps: SOARStepConfig[];
  created_at: string;
  updated_at: string;
  execution_count?: number;
  success_rate?: number;
}

export interface SOARWorkflowCreatePayload {
  name: string;
  description?: string;
  category?: WorkflowCategory;
  trigger_type: WorkflowTriggerType;
  trigger_conditions?: Record<string, any>;
  steps: SOARStepConfig[];
  is_enabled?: boolean;
}

export interface SOARWorkflowUpdatePayload {
  name?: string;
  description?: string;
  category?: WorkflowCategory;
  trigger_type?: WorkflowTriggerType;
  trigger_conditions?: Record<string, any>;
  steps?: SOARStepConfig[];
  status?: WorkflowStatus;
  is_enabled?: boolean;
}

export interface SOARExecutionRequest {
  trigger_source?: string;
  input_context?: Record<string, any>;
  idempotency_key?: string;
}

export interface SOARExecutionStepItem {
  id: string;
  step_name: string;
  step_type: WorkflowStepType;
  status: string;
  started_at: string;
  completed_at?: string;
  input_payload: Record<string, any>;
  output_payload: Record<string, any>;
  error_message?: string;
}

export interface SOARExecutionLogItem {
  id: string;
  timestamp: string;
  log_level: string;
  message: string;
  payload: Record<string, any>;
}

export interface SOARExecution {
  id: string;
  workflow_id: string;
  workflow_name: string;
  organization_id: string;
  trigger_source: string;
  status: ExecutionStatus;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  context_data: Record<string, any>;
  error_message?: string;
  retry_count: number;
  steps_executed_count: number;
}

export interface SOARExecutionDetail extends SOARExecution {
  steps: SOARExecutionStepItem[];
  logs: SOARExecutionLogItem[];
  approval_required?: Record<string, any>;
}

export interface SOARApproval {
  id: string;
  organization_id: string;
  execution_id: string;
  workflow_name: string;
  action_type: string;
  target_resource: string;
  justification: string;
  requested_by?: string;
  approver_id?: string;
  decision: ApprovalDecision;
  decision_notes?: string;
  decided_at?: string;
  created_at: string;
  expires_at?: string;
  execution_result: Record<string, any>;
}

export interface SOARApprovalDecisionPayload {
  decision: 'Approved' | 'Rejected';
  justification_notes: string;
}

export interface SOARAnalytics {
  total_playbook_executions: number;
  successful_executions: number;
  failed_executions: number;
  pending_approvals: number;
  average_execution_time_ms: number;
  alerts_processed: number;
  incidents_created: number;
  automation_success_rate: number;
  most_frequently_executed: Array<{ playbook_name: string; execution_count: number }>;
  execution_trends: Array<{ date: string; count: number; success_rate: number }>;
}

export interface NotificationTemplate {
  id: string;
  organization_id: string;
  template_name: string;
  channel: 'in_app' | 'email' | 'webhook';
  subject?: string;
  body_template: string;
  is_default: boolean;
  created_at: string;
}

export interface NotificationTestPayload {
  channel: 'in_app' | 'email' | 'webhook';
  recipient: string;
  subject?: string;
  body: string;
}

export interface NotificationDelivery {
  id: string;
  channel: string;
  recipient: string;
  status: string;
  delivered_at?: string;
  error_message?: string;
}
