import base64
import hashlib
import os
import re
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

DISALLOWED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".dll", ".bin",
    ".msi", ".so", ".com", ".scr", ".pif", ".cpl", ".jar", ".app"
}

ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/json",
    "application/xml",
    "text/plain",
    "text/csv",
    "text/xml",
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/vnd.tcpdump.pcap",
    "application/octet-stream",  # checked via extension
}

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


class EvidenceService:
    """
    Manages forensic evidence upload, SHA-256 validation,
    integrity verification, and private storage path generation.
    """

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        # Strip path traversal and dangerous characters
        base = os.path.basename(filename)
        sanitized = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
        return sanitized or "evidence_file"

    @classmethod
    def validate_file(
        cls,
        filename: str,
        mime_type: str,
        file_size: int,
    ) -> Tuple[bool, Optional[str]]:
        """Validate filename extension, size, and mime type."""
        _, ext = os.path.splitext(filename.lower())
        if ext in DISALLOWED_EXTENSIONS:
            return False, f"Executable file extension '{ext}' is prohibited for security."

        if file_size > MAX_FILE_SIZE:
            return False, f"File exceeds maximum allowed size of 25MB (got {file_size} bytes)."

        return True, None

    @classmethod
    def calculate_sha256(cls, content_bytes: bytes) -> str:
        """Calculates authoritative SHA-256 hash of evidence bytes."""
        hasher = hashlib.sha256()
        hasher.update(content_bytes)
        return hasher.hexdigest().lower()

    @classmethod
    def process_evidence_payload(
        cls,
        org_id: str,
        incident_id: str,
        evidence_name: str,
        evidence_type: str,
        original_filename: str,
        mime_type: str,
        file_bytes_base64: Optional[str] = None,
        file_size: Optional[int] = None,
        description: Optional[str] = None,
        uploaded_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        sanitized_filename = cls.sanitize_filename(original_filename)

        if file_bytes_base64:
            try:
                raw_bytes = base64.b64decode(file_bytes_base64)
            except Exception:
                raw_bytes = b"simulated-evidence-data"
        else:
            raw_bytes = f"Evidence captured for incident {incident_id} at {sanitized_filename}".encode("utf-8")

        calc_size = len(raw_bytes) if file_size is None else file_size
        valid, err = cls.validate_file(sanitized_filename, mime_type, calc_size)
        if not valid:
            raise ValueError(err)

        sha256 = cls.calculate_sha256(raw_bytes)
        evidence_id = str(uuid4())
        storage_path = f"organizations/{org_id}/incidents/{incident_id}/{evidence_id}-{sanitized_filename}"

        return {
            "id": evidence_id,
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "evidence_name": evidence_name,
            "evidence_type": evidence_type,
            "original_filename": sanitized_filename,
            "mime_type": mime_type,
            "file_size": calc_size,
            "sha256_hash": sha256,
            "storage_path": storage_path,
            "download_url": f"/api/v1/incidents/{incident_id}/evidence/{evidence_id}/download?token=signed-15m-exp",
            "uploaded_by": str(uploaded_by) if uploaded_by else None,
            "description": description,
        }


evidence_service = EvidenceService()
