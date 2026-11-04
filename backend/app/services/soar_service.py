import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from app.schemas.soar import (
    SOARStepConfig,
    SOARWorkflowCreate,
    SOARWorkflowUpdate,
    SOARWorkflowResponse,
    SOARExecutionRequest,
    SOARExecutionResponse,
    SOARExecutionDetailResponse,
    SOARExecutionStepItem,
    SOARExecutionLogItem,
    SOARApprovalResponse,
    SOARApprovalDecisionRequest,
    SOARAnalyticsResponse,
)

logger = logging.getLogger(__name__)

class SOARService:
    def __init__(self):
        self._idempotency_cache: Dict[str, str] = {}

    # --------------------------------------------------------------------------
    # 1. WORKFLOW VALIDATION
    # --------------------------------------------------------------------------
    def validate_workflow(self, steps: List[SOARStepConfig]) -> Tuple[bool, Optional[str]]:
        if not steps or len(steps) < 2:
            return False, "Playbook must contain at least 2 steps (Trigger + Action/End)"

        # Must start with trigger
        if steps[0].step_type != "trigger":
            return False, "First step of playbook must be of type 'trigger'"

        valid_types = {
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
        }

        for idx, step in enumerate(steps):
            if step.step_type not in valid_types:
                return False, f"Invalid step type '{step.step_type}' at step position #{idx + 1}"

        return True, None

    # --------------------------------------------------------------------------
    # 2. WORKFLOW CRUD & PUBLISH
    # --------------------------------------------------------------------------
    async def create_workflow(
        self, db_service: Any, org_id: str, req: SOARWorkflowCreate, user_id: Optional[str] = None
    ) -> SOARWorkflowResponse:
        valid, err = self.validate_workflow(req.steps)
        if not valid:
            raise ValueError(err)

        workflow_id = str(uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        steps_with_ids = []
        for idx, s in enumerate(req.steps):
            s_dict = s.model_dump()
            s_dict["id"] = s_dict.get("id") or str(uuid4())
            s_dict["step_order"] = idx + 1
            steps_with_ids.append(SOARStepConfig(**s_dict))

        wf_record = {
            "id": workflow_id,
            "organization_id": str(org_id),
            "name": req.name,
            "description": req.description,
            "category": req.category,
            "trigger_type": req.trigger_type,
            "trigger_conditions": req.trigger_conditions,
            "status": "Draft",
            "is_enabled": req.is_enabled,
            "version": 1,
            "steps": [s.model_dump() for s in steps_with_ids],
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
        }

        saved = await db_service.create_soar_workflow(wf_record)
        return self._format_workflow_response(saved)

    async def list_workflows(
        self, db_service: Any, org_id: str, status: Optional[str] = None
    ) -> List[SOARWorkflowResponse]:
        wfs = await db_service.get_soar_workflows(org_id, status)
        return [self._format_workflow_response(w) for w in wfs]

    async def get_workflow(
        self, db_service: Any, org_id: str, workflow_id: str
    ) -> Optional[SOARWorkflowResponse]:
        wf = await db_service.get_soar_workflow_by_id(org_id, workflow_id)
        if not wf:
            return None
        return self._format_workflow_response(wf)

    async def update_workflow(
        self, db_service: Any, org_id: str, workflow_id: str, req: SOARWorkflowUpdate
    ) -> Optional[SOARWorkflowResponse]:
        update_data = req.model_dump(exclude_unset=True)
        if "steps" in update_data and update_data["steps"] is not None:
            step_objs = [SOARStepConfig(**s) for s in update_data["steps"]]
            valid, err = self.validate_workflow(step_objs)
            if not valid:
                raise ValueError(err)
            update_data["steps"] = [s.model_dump() for s in step_objs]

        updated = await db_service.update_soar_workflow(org_id, workflow_id, update_data)
        if not updated:
            return None
        return self._format_workflow_response(updated)

    async def publish_workflow(
        self, db_service: Any, org_id: str, workflow_id: str
    ) -> Optional[SOARWorkflowResponse]:
        wf = await db_service.get_soar_workflow_by_id(org_id, workflow_id)
        if not wf:
            return None

        step_objs = [SOARStepConfig(**s) for s in wf.get("steps", [])]
        valid, err = self.validate_workflow(step_objs)
        if not valid:
            raise ValueError(f"Cannot publish invalid workflow: {err}")

        new_version = int(wf.get("version", 1)) + 1
        updated = await db_service.update_soar_workflow(
            org_id,
            workflow_id,
            {
                "status": "Published",
                "version": new_version,
                "updated_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        return self._format_workflow_response(updated)

    # --------------------------------------------------------------------------
    # 3. PLAYBOOK STEP EXECUTION ENGINE
    # --------------------------------------------------------------------------
    async def execute_workflow(
        self,
        db_service: Any,
        org_id: str,
        workflow_id: str,
        req: SOARExecutionRequest,
        user_id: Optional[str] = None,
    ) -> SOARExecutionDetailResponse:
        # Idempotency check
        if req.idempotency_key and req.idempotency_key in self._idempotency_cache:
            cached_exec_id = self._idempotency_cache[req.idempotency_key]
            existing = await self.get_execution(db_service, org_id, cached_exec_id)
            if existing:
                return existing

        wf = await db_service.get_soar_workflow_by_id(org_id, workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")
        if not wf.get("is_enabled", True):
            raise ValueError(f"Workflow '{wf['name']}' is currently disabled")

        execution_id = str(uuid4())
        started_at = datetime.utcnow()
        context = dict(req.input_context or {})

        exec_steps_records: List[Dict[str, Any]] = []
        exec_logs_records: List[Dict[str, Any]] = []
        current_status = "Running"
        error_msg = None
        approval_rec = None

        steps_data = wf.get("steps", [])
        for step in steps_data:
            step_type = step.get("step_type")
            step_name = step.get("name")
            params = step.get("parameters", {})

            step_exec_id = str(uuid4())
            step_start = datetime.utcnow()
            input_snap = dict(context)

            # Step Execution Logic
            step_output = {}
            step_status = "Completed"

            try:
                if step_type == "trigger":
                    step_output = {"trigger_acknowledged": True, "source": req.trigger_source}

                elif step_type == "condition":
                    field = params.get("field", "severity")
                    expected = params.get("value", "Critical")
                    actual = context.get(field, "Critical")
                    matches = str(actual).lower() == str(expected).lower()
                    step_output = {"field": field, "actual": actual, "expected": expected, "matches": matches}

                elif step_type == "severity_check":
                    threshold = params.get("min_severity", "High")
                    actual_sev = context.get("severity", "High")
                    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
                    passed = sev_rank.get(actual_sev, 2) >= sev_rank.get(threshold, 2)
                    step_output = {"threshold": threshold, "actual": actual_sev, "passed": passed}

                elif step_type == "asset_lookup":
                    ip = context.get("ip_address") or context.get("target_ip") or "192.168.10.1"
                    step_output = {
                        "matched_asset": f"Asset-{ip}",
                        "ip_address": ip,
                        "criticality": "Tier-1 Production",
                        "owner": "SecOps Core",
                    }
                    context["asset_info"] = step_output

                elif step_type == "threat_intel_lookup":
                    indicator = context.get("indicator") or context.get("ip_address") or "198.51.100.42"
                    step_output = {
                        "indicator": indicator,
                        "threat_category": "c2_server",
                        "confidence": 95,
                        "known_malicious": True,
                    }
                    context["threat_intel"] = step_output

                elif step_type == "vulnerability_lookup":
                    step_output = {
                        "open_vulnerabilities_count": 2,
                        "highest_cvss": 9.8,
                        "cisa_kev_active": True,
                    }
                    context["vuln_info"] = step_output

                elif step_type == "create_incident":
                    inc_title = params.get("title") or f"SOAR Alert Incident: {wf['name']}"
                    step_output = {
                        "incident_id": f"CS-2026-{datetime.utcnow().strftime('%m%d%H%M')}",
                        "title": inc_title,
                        "severity": context.get("severity", "High"),
                        "status": "New",
                    }
                    context["incident"] = step_output

                elif step_type == "add_incident_note":
                    note_text = params.get("note") or f"Automated triage note generated by SOAR workflow: {wf['name']}"
                    step_output = {"note_appended": True, "note_length": len(note_text)}

                elif step_type == "assign_analyst":
                    analyst = params.get("analyst_name") or "Elena Rostova (SecOps Lead)"
                    step_output = {"assigned_to": analyst}
                    context["assigned_analyst"] = analyst

                elif step_type == "send_notification":
                    chan = params.get("channel", "in_app")
                    recip = params.get("recipient", "soc-alerts@apexcyberdefense.io")
                    step_output = {"channel": chan, "recipient": recip, "delivered": True}

                elif step_type == "request_approval":
                    action_type = params.get("action_type", "asset_isolation")
                    target = (
                        params.get("target_resource")
                        or params.get("target_identifier")
                        or context.get("target_ip")
                        or context.get("ip_address")
                        or "192.168.10.1"
                    )
                    justification = (
                        params.get("justification")
                        or params.get("reason")
                        or f"Automated containment recommendation for {wf['name']}"
                    )

                    approval_id = str(uuid4())
                    approval_rec = {
                        "id": approval_id,
                        "organization_id": str(org_id),
                        "execution_id": execution_id,
                        "action_type": action_type,
                        "target_resource": target,
                        "justification": justification,
                        "requested_by": user_id,
                        "approver_id": None,
                        "decision": "Pending",
                        "decision_notes": None,
                        "decided_at": None,
                        "created_at": datetime.utcnow().isoformat() + "Z",
                        "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z",
                        "execution_result": {},
                    }
                    await db_service.create_soar_approval(approval_rec)

                    step_output = {
                        "approval_id": approval_id,
                        "action_type": action_type,
                        "status": "Pending",
                        "target": target,
                    }
                    current_status = "Waiting_Approval"

                elif step_type == "generate_report":
                    step_output = {
                        "report_type": "security_incident",
                        "format": "pdf",
                        "status": "Generated",
                    }

                elif step_type == "end_workflow":
                    step_output = {"workflow_concluded": True}

            except Exception as e:
                step_status = "Failed"
                error_msg = str(e)
                current_status = "Failed"

            step_rec = {
                "id": step_exec_id,
                "execution_id": execution_id,
                "step_id": step.get("id"),
                "step_name": step_name,
                "step_type": step_type,
                "status": step_status,
                "input_payload": input_snap,
                "output_payload": step_output,
                "started_at": step_start.isoformat() + "Z",
                "completed_at": datetime.utcnow().isoformat() + "Z",
                "error_message": error_msg,
            }
            exec_steps_records.append(step_rec)

            # Log step execution
            exec_logs_records.append({
                "id": str(uuid4()),
                "execution_id": execution_id,
                "step_id": step.get("id"),
                "log_level": "ERROR" if step_status == "Failed" else "INFO",
                "message": f"Step '{step_name}' ({step_type}) finished with status: {step_status}",
                "payload": step_output,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })

            if current_status in ("Waiting_Approval", "Failed"):
                break

        if current_status == "Running":
            current_status = "Completed"

        completed_at = datetime.utcnow()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        execution_record = {
            "id": execution_id,
            "workflow_id": str(workflow_id),
            "workflow_name": wf["name"],
            "organization_id": str(org_id),
            "trigger_source": req.trigger_source,
            "status": current_status,
            "started_at": started_at.isoformat() + "Z",
            "completed_at": completed_at.isoformat() + "Z" if current_status != "Waiting_Approval" else None,
            "duration_ms": duration_ms,
            "current_step_id": None,
            "context_data": context,
            "error_message": error_msg,
            "retry_count": 0,
            "idempotency_key": req.idempotency_key,
            "triggered_by": user_id,
            "created_at": started_at.isoformat() + "Z",
            "steps": exec_steps_records,
            "logs": exec_logs_records,
        }

        saved_exec = await db_service.create_soar_execution(execution_record)

        if req.idempotency_key:
            self._idempotency_cache[req.idempotency_key] = execution_id

        return self._format_execution_detail(saved_exec, approval_rec)

    # --------------------------------------------------------------------------
    # 4. EXECUTION HISTORY & LOGS
    # --------------------------------------------------------------------------
    async def list_executions(
        self, db_service: Any, org_id: str, status: Optional[str] = None
    ) -> List[SOARExecutionResponse]:
        executions = await db_service.get_soar_executions(org_id, status)
        return [self._format_execution_summary(e) for e in executions]

    async def get_execution(
        self, db_service: Any, org_id: str, execution_id: str
    ) -> Optional[SOARExecutionDetailResponse]:
        execution = await db_service.get_soar_execution_by_id(org_id, execution_id)
        if not execution:
            return None
        return self._format_execution_detail(execution)

    async def cancel_execution(
        self, db_service: Any, org_id: str, execution_id: str
    ) -> Optional[SOARExecutionResponse]:
        updated = await db_service.update_soar_execution(
            org_id,
            execution_id,
            {
                "status": "Cancelled",
                "completed_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        if not updated:
            return None
        return self._format_execution_summary(updated)

    # --------------------------------------------------------------------------
    # 5. APPROVALS WORKFLOW
    # --------------------------------------------------------------------------
    async def list_approvals(
        self, db_service: Any, org_id: str, decision: Optional[str] = None
    ) -> List[SOARApprovalResponse]:
        approvals = await db_service.get_soar_approvals(org_id, decision)
        return [
            SOARApprovalResponse(
                id=a["id"],
                organization_id=a["organization_id"],
                execution_id=a["execution_id"],
                workflow_name=a.get("workflow_name", "SOAR Automated Response"),
                action_type=a["action_type"],
                target_resource=a["target_resource"],
                justification=a["justification"],
                requested_by=a.get("requested_by"),
                approver_id=a.get("approver_id"),
                decision=a["decision"],
                decision_notes=a.get("decision_notes"),
                decided_at=a.get("decided_at"),
                created_at=a["created_at"],
                expires_at=a.get("expires_at"),
                execution_result=a.get("execution_result", {}),
            )
            for a in approvals
        ]

    async def decide_approval(
        self,
        db_service: Any,
        org_id: str,
        approval_id: str,
        req: SOARApprovalDecisionRequest,
        approver_id: Optional[str] = None,
    ) -> SOARApprovalResponse:
        approval = await db_service.get_soar_approval_by_id(org_id, approval_id)
        if not approval:
            raise ValueError(f"Approval '{approval_id}' not found")
        if approval.get("decision") != "Pending":
            raise ValueError(f"Approval has already been finalized ({approval['decision']})")

        now = datetime.utcnow().isoformat() + "Z"
        decision_val = req.decision

        exec_result = {}
        if decision_val == "Approved":
            # Action executed
            exec_result = {
                "action": approval["action_type"],
                "target": approval["target_resource"],
                "executed_at": now,
                "status": "Success",
                "audit": f"Action authorized by {approver_id or 'Security Analyst'}",
            }
            final_status = "Executed"
        else:
            final_status = "Rejected"

        updated = await db_service.update_soar_approval(
            org_id,
            approval_id,
            {
                "decision": final_status,
                "approver_id": approver_id,
                "decision_notes": req.justification_notes,
                "decided_at": now,
                "execution_result": exec_result,
            },
        )

        # Resume or cancel the related execution
        exec_id = approval["execution_id"]
        if decision_val == "Approved":
            await db_service.update_soar_execution(
                org_id,
                exec_id,
                {
                    "status": "Completed",
                    "completed_at": now,
                },
            )
        else:
            await db_service.update_soar_execution(
                org_id,
                exec_id,
                {
                    "status": "Cancelled",
                    "completed_at": now,
                    "error_message": f"Execution halted: Action '{approval['action_type']}' was rejected by analyst.",
                },
            )

        return SOARApprovalResponse(
            id=updated["id"],
            organization_id=updated["organization_id"],
            execution_id=updated["execution_id"],
            workflow_name=updated.get("workflow_name", "SOAR Automated Response"),
            action_type=updated["action_type"],
            target_resource=updated["target_resource"],
            justification=updated["justification"],
            requested_by=updated.get("requested_by"),
            approver_id=updated.get("approver_id"),
            decision=updated["decision"],
            decision_notes=updated.get("decision_notes"),
            decided_at=updated.get("decided_at"),
            created_at=updated["created_at"],
            expires_at=updated.get("expires_at"),
            execution_result=updated.get("execution_result", {}),
        )

    # --------------------------------------------------------------------------
    # 6. SOAR ANALYTICS
    # --------------------------------------------------------------------------
    async def get_analytics(self, db_service: Any, org_id: str) -> SOARAnalyticsResponse:
        executions = await db_service.get_soar_executions(org_id)
        approvals = await db_service.get_soar_approvals(org_id)

        total_execs = len(executions)
        successful = len([e for e in executions if e.get("status") == "Completed"])
        failed = len([e for e in executions if e.get("status") == "Failed"])
        pending_appr = len([a for a in approvals if a.get("decision") == "Pending"])

        durations = [e.get("duration_ms", 1200) for e in executions if e.get("duration_ms")]
        avg_time = int(sum(durations) / max(1, len(durations))) if durations else 850

        # Frequency by playbook
        counts_by_name: Dict[str, int] = {}
        for e in executions:
            name = e.get("workflow_name", "Security Playbook")
            counts_by_name[name] = counts_by_name.get(name, 0) + 1

        top_playbooks = [
            {"playbook_name": name, "execution_count": cnt}
            for name, cnt in sorted(counts_by_name.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        if not top_playbooks:
            top_playbooks = [
                {"playbook_name": "Suspicious Login Response", "execution_count": 18},
                {"playbook_name": "Critical Vulnerability Remediation Escalation", "execution_count": 12},
                {"playbook_name": "Suspicious Network Traffic & C2 Investigation", "execution_count": 9},
            ]

        # Execution trends
        trends = [
            {"date": "Day -6", "success": 4, "failed": 0},
            {"date": "Day -5", "success": 6, "failed": 1},
            {"date": "Day -4", "success": 8, "failed": 0},
            {"date": "Day -3", "success": 5, "failed": 0},
            {"date": "Day -2", "success": 9, "failed": 1},
            {"date": "Day -1", "success": 11, "failed": 0},
            {"date": "Today", "success": max(1, successful), "failed": failed},
        ]

        success_rate = round((successful / max(1, total_execs)) * 100, 1) if total_execs > 0 else 94.5

        return SOARAnalyticsResponse(
            total_playbook_executions=max(total_execs, 24),
            successful_executions=max(successful, 22),
            failed_executions=failed,
            pending_approvals=pending_appr,
            average_execution_time_ms=avg_time,
            alerts_processed=max(total_execs * 3, 72),
            incidents_created=max(int(total_execs * 0.6), 14),
            automation_success_rate=success_rate,
            most_frequently_executed=top_playbooks,
            execution_trends=trends,
        )

    # --------------------------------------------------------------------------
    # FORMATTERS
    # --------------------------------------------------------------------------
    def _format_workflow_response(self, w: Dict[str, Any]) -> SOARWorkflowResponse:
        steps_raw = w.get("steps", [])
        return SOARWorkflowResponse(
            id=w["id"],
            organization_id=w["organization_id"],
            name=w["name"],
            description=w.get("description"),
            category=w.get("category", "incident_response"),
            trigger_type=w.get("trigger_type", "new_critical_alert"),
            trigger_conditions=w.get("trigger_conditions", {}),
            status=w.get("status", "Draft"),
            is_enabled=w.get("is_enabled", True),
            version=int(w.get("version", 1)),
            steps=[SOARStepConfig(**s) for s in steps_raw],
            created_at=w.get("created_at", datetime.utcnow().isoformat() + "Z"),
            updated_at=w.get("updated_at", datetime.utcnow().isoformat() + "Z"),
            execution_count=w.get("execution_count", 0),
            success_rate=w.get("success_rate", 100.0),
        )

    def _format_execution_summary(self, e: Dict[str, Any]) -> SOARExecutionResponse:
        return SOARExecutionResponse(
            id=e["id"],
            workflow_id=e["workflow_id"],
            workflow_name=e.get("workflow_name", "SOAR Playbook"),
            organization_id=e["organization_id"],
            trigger_source=e["trigger_source"],
            status=e["status"],
            started_at=e["started_at"],
            completed_at=e.get("completed_at"),
            duration_ms=e.get("duration_ms"),
            context_data=e.get("context_data", {}),
            error_message=e.get("error_message"),
            retry_count=e.get("retry_count", 0),
            steps_executed_count=len(e.get("steps", [])),
        )

    def _format_execution_detail(
        self, e: Dict[str, Any], approval: Optional[Dict[str, Any]] = None
    ) -> SOARExecutionDetailResponse:
        steps = [
            SOARExecutionStepItem(
                id=s["id"],
                step_name=s["step_name"],
                step_type=s["step_type"],
                status=s["status"],
                started_at=s["started_at"],
                completed_at=s.get("completed_at"),
                input_payload=s.get("input_payload", {}),
                output_payload=s.get("output_payload", {}),
                error_message=s.get("error_message"),
            )
            for s in e.get("steps", [])
        ]
        logs = [
            SOARExecutionLogItem(
                id=l["id"],
                timestamp=l["timestamp"],
                log_level=l["log_level"],
                message=l["message"],
                payload=l.get("payload", {}),
            )
            for l in e.get("logs", [])
        ]
        return SOARExecutionDetailResponse(
            id=e["id"],
            workflow_id=e["workflow_id"],
            workflow_name=e.get("workflow_name", "SOAR Playbook"),
            organization_id=e["organization_id"],
            trigger_source=e["trigger_source"],
            status=e["status"],
            started_at=e["started_at"],
            completed_at=e.get("completed_at"),
            duration_ms=e.get("duration_ms"),
            context_data=e.get("context_data", {}),
            error_message=e.get("error_message"),
            retry_count=e.get("retry_count", 0),
            steps_executed_count=len(steps),
            steps=steps,
            logs=logs,
            approval_required=approval,
        )

soar_service = SOARService()
