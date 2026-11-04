from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

WorkflowTriggerType = Literal[
    "new_critical_alert",
    "new_high_vulnerability",
    "suspicious_network_activity",
    "threat_intel_ioc_match",
    "repeated_auth_failures",
    "unauthorized_asset_detected",
    "manual_investigation",
]

WorkflowStepType = Literal[
    "trigger",
    "condition",
    "severity_check",
    "asset_lookup",
    "threat_intel_lookup",
    "vulnerability_lookup",
    "create_incident",
    "add_incident_note",
    "assign_analyst",
    "send_notification",
    "request_approval",
    "generate_report",
    "end_workflow",
]

WorkflowCategory = Literal[
    "incident_response",
    "vulnerability_management",
    "threat_hunting",
    "network_security",
    "identity_access",
    "custom",
]

WorkflowStatus = Literal["Draft", "Published", "Archived"]
ExecutionStatus = Literal["Pending", "Running", "Waiting_Approval", "Completed", "Failed", "Cancelled"]
ApprovalDecision = Literal["Pending", "Approved", "Rejected", "Expired", "Cancelled", "Executed", "Execution_Failed"]

class SOARStepConfig(BaseModel):
    id: Optional[str] = None
    step_order: int
    step_type: WorkflowStepType
    name: str = Field(..., min_length=2, max_length=128)
    parameters: Dict[str, Any] = {}
    next_step_id: Optional[str] = None
    on_failure_step_id: Optional[str] = None

class SOARWorkflowCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = None
    category: WorkflowCategory = "incident_response"
    trigger_type: WorkflowTriggerType
    trigger_conditions: Dict[str, Any] = {}
    steps: List[SOARStepConfig] = []
    is_enabled: bool = True

class SOARWorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[WorkflowCategory] = None
    trigger_type: Optional[WorkflowTriggerType] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    steps: Optional[List[SOARStepConfig]] = None
    status: Optional[WorkflowStatus] = None
    is_enabled: Optional[bool] = None

class SOARWorkflowResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: Optional[str] = None
    category: str
    trigger_type: str
    trigger_conditions: Dict[str, Any] = {}
    status: str
    is_enabled: bool
    version: int
    steps: List[SOARStepConfig] = []
    created_at: str
    updated_at: str
    execution_count: int = 0
    success_rate: float = 100.0

class SOARExecutionRequest(BaseModel):
    trigger_source: str = "manual_investigation"
    input_context: Dict[str, Any] = {}
    idempotency_key: Optional[str] = None

class SOARExecutionStepItem(BaseModel):
    id: str
    step_name: str
    step_type: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    input_payload: Dict[str, Any] = {}
    output_payload: Dict[str, Any] = {}
    error_message: Optional[str] = None

class SOARExecutionLogItem(BaseModel):
    id: str
    timestamp: str
    log_level: str
    message: str
    payload: Dict[str, Any] = {}

class SOARExecutionResponse(BaseModel):
    id: str
    workflow_id: str
    workflow_name: str
    organization_id: str
    trigger_source: str
    status: ExecutionStatus
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    context_data: Dict[str, Any] = {}
    error_message: Optional[str] = None
    retry_count: int = 0
    steps_executed_count: int = 0

class SOARExecutionDetailResponse(SOARExecutionResponse):
    steps: List[SOARExecutionStepItem] = []
    logs: List[SOARExecutionLogItem] = []
    approval_required: Optional[Dict[str, Any]] = None

class SOARApprovalResponse(BaseModel):
    id: str
    organization_id: str
    execution_id: str
    workflow_name: str
    action_type: str
    target_resource: str
    justification: str
    requested_by: Optional[str] = None
    approver_id: Optional[str] = None
    decision: ApprovalDecision
    decision_notes: Optional[str] = None
    decided_at: Optional[str] = None
    created_at: str
    expires_at: Optional[str] = None
    execution_result: Dict[str, Any] = {}

class SOARApprovalDecisionRequest(BaseModel):
    decision: Literal["Approved", "Rejected"]
    justification_notes: str = Field(..., min_length=3, max_length=500)

class SOARAnalyticsResponse(BaseModel):
    total_playbook_executions: int
    successful_executions: int
    failed_executions: int
    pending_approvals: int
    average_execution_time_ms: int
    alerts_processed: int
    incidents_created: int
    automation_success_rate: float
    most_frequently_executed: List[Dict[str, Any]]
    execution_trends: List[Dict[str, Any]]

class NotificationTemplateResponse(BaseModel):
    id: str
    organization_id: str
    template_name: str
    channel: Literal["in_app", "email", "webhook"]
    subject: Optional[str] = None
    body_template: str
    is_default: bool
    created_at: str

class NotificationTestRequest(BaseModel):
    channel: Literal["in_app", "email", "webhook"]
    recipient: str
    subject: Optional[str] = None
    body: str

class NotificationDeliveryResponse(BaseModel):
    id: str
    channel: str
    recipient: str
    status: str
    delivered_at: Optional[str] = None
    error_message: Optional[str] = None
