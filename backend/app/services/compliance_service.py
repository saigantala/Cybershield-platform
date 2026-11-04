from datetime import datetime
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from app.schemas.compliance import (
    ComplianceAssessmentCreate,
    ComplianceAssessmentUpdate,
    ComplianceEvidenceCreate,
)
from app.services.supabase_service import SupabaseService


class ComplianceService:
    @staticmethod
    async def get_frameworks(
        db_service: SupabaseService, org_id: str
    ) -> List[Dict[str, Any]]:
        """Returns compliance frameworks with tenant completion metrics."""
        frameworks = await db_service.get_compliance_frameworks()
        assessments = await db_service.get_compliance_assessments(org_id)
        controls = await db_service.get_compliance_controls()

        result = []
        for fw in frameworks:
            fw_controls = [c for c in controls if str(c["framework_id"]) == str(fw["id"])]
            total = len(fw_controls)

            fw_assessments = [
                a for a in assessments if str(a.get("framework_id")) == str(fw["id"])
            ]

            implemented = sum(
                1 for a in fw_assessments if a.get("status") == "Implemented"
            )
            partial = sum(
                1 for a in fw_assessments if a.get("status") == "Partially Implemented"
            )
            not_applicable = sum(
                1 for a in fw_assessments if a.get("status") == "Not Applicable"
            )
            not_assessed = total - (implemented + partial + not_applicable)
            if not_assessed < 0:
                not_assessed = 0

            # Calculation: (Implemented + 0.5 * Partial) / applicable_controls
            applicable = total - not_applicable
            completion = (
                round(((implemented + 0.5 * partial) / applicable) * 100, 1)
                if applicable > 0
                else 0.0
            )

            fw_copy = dict(fw)
            fw_copy["total_controls"] = total
            fw_copy["implemented_controls"] = implemented
            fw_copy["partially_implemented"] = partial
            fw_copy["not_assessed"] = not_assessed
            fw_copy["completion_percentage"] = min(completion, 100.0)
            result.append(fw_copy)

        return result

    @staticmethod
    async def get_controls(
        db_service: SupabaseService,
        org_id: str,
        framework_code: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Queries controls enriched with current tenant assessment status and evidence counts."""
        return await db_service.get_compliance_controls_with_status(
            org_id=org_id,
            framework_code=framework_code,
            domain=domain,
        )

    @staticmethod
    async def create_assessment(
        db_service: SupabaseService,
        org_id: str,
        payload: ComplianceAssessmentCreate,
    ) -> Dict[str, Any]:
        """Creates or upserts an assessment for a specific control."""
        return await db_service.upsert_compliance_assessment(
            org_id=org_id,
            control_id=str(payload.control_id),
            status=payload.status,
            assigned_owner=payload.assigned_owner,
            review_date=str(payload.review_date) if payload.review_date else None,
            notes=payload.notes,
            remediation_notes=payload.remediation_notes,
        )

    @staticmethod
    async def update_assessment(
        db_service: SupabaseService,
        org_id: str,
        assessment_id: str,
        payload: ComplianceAssessmentUpdate,
    ) -> Optional[Dict[str, Any]]:
        """Updates assessment status, assigned owner, or remediation progress."""
        return await db_service.update_compliance_assessment(
            org_id=org_id,
            assessment_id=assessment_id,
            data=payload.model_dump(exclude_unset=True),
        )

    @staticmethod
    async def upload_evidence(
        db_service: SupabaseService,
        org_id: str,
        user_id: Optional[str],
        file_name: str,
        file_bytes: bytes,
        mime_type: str,
        control_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates evidence, calculates SHA-256 hash, and stores metadata."""
        # Security validation: Disallow executable file types
        disallowed_exts = [".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".dll", ".so"]
        if any(file_name.lower().endswith(ext) for ext in disallowed_exts):
            raise ValueError(f"Executable file types are strictly prohibited in the Evidence Vault: {file_name}")

        if len(file_bytes) > 26214400:  # 25MB limit
            raise ValueError("File size exceeds maximum allowable evidence limit (25MB)")

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        storage_path = f"evidence/{org_id}/{uuid4().hex[:12]}_{file_name}"

        record = {
            "id": str(uuid4()),
            "organization_id": org_id,
            "control_id": control_id,
            "assessment_id": assessment_id,
            "file_name": file_name,
            "file_size": len(file_bytes),
            "mime_type": mime_type,
            "sha256_hash": sha256,
            "storage_path": storage_path,
            "description": description or f"Compliance evidence for control {control_id or 'General'}",
            "uploaded_by": user_id,
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
        }
        return await db_service.create_compliance_evidence(record)

    @staticmethod
    async def get_compliance_summary(
        db_service: SupabaseService, org_id: str
    ) -> Dict[str, Any]:
        """Calculates tenant-wide aggregated compliance metrics."""
        frameworks = await ComplianceService.get_frameworks(db_service, org_id)

        tot_controls = sum(fw["total_controls"] for fw in frameworks)
        tot_impl = sum(fw["implemented_controls"] for fw in frameworks)
        tot_partial = sum(fw["partially_implemented"] for fw in frameworks)
        tot_not_assessed = sum(fw["not_assessed"] for fw in frameworks)

        overall_score = (
            round(((tot_impl + 0.5 * tot_partial) / tot_controls) * 100, 1)
            if tot_controls > 0
            else 0.0
        )

        assessments = await db_service.get_compliance_assessments(org_id)
        now_str = datetime.utcnow().strftime("%Y-%m-%d")
        overdue = sum(
            1
            for a in assessments
            if a.get("review_date")
            and a.get("review_date") < now_str
            and a.get("status") != "Implemented"
        )

        recent = sorted(assessments, key=lambda x: x.get("updated_at", ""), reverse=True)[:5]

        return {
            "organization_id": org_id,
            "overall_compliance_score": min(overall_score, 100.0),
            "total_controls": tot_controls,
            "implemented_count": tot_impl,
            "partially_implemented_count": tot_partial,
            "not_assessed_count": tot_not_assessed,
            "not_applicable_count": 0,
            "framework_breakdown": frameworks,
            "overdue_assessments_count": overdue,
            "recent_activity": recent,
        }


compliance_service = ComplianceService()
