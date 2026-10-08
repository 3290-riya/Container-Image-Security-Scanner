"""Web application models for the Container Image Security Scanner web UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class UploadType(str, Enum):
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    IMAGE_ARCHIVE = "image_archive"
    PROJECT_ZIP = "project_zip"
    UNKNOWN = "unknown"


@dataclass
class ScanRequest:
    """Represents a scan request submitted via the web UI."""
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    upload_type: UploadType = UploadType.UNKNOWN
    original_filename: str = ""
    severities: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    fail_on: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    report_format: str = "all"  # json | html | all
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanProgress:
    """Tracks real-time scan progress."""
    upload_validated: bool = False
    target_prepared: bool = False
    trivy_running: bool = False
    parsing_complete: bool = False
    scoring_complete: bool = False
    report_generated: bool = False
    current_step: str = "Starting..."
    error_message: str = ""


@dataclass
class WebScanResult:
    """Wraps ScanResult for the web UI layer."""
    scan_id: str
    status: ScanStatus
    request: ScanRequest
    progress: ScanProgress = field(default_factory=ScanProgress)
    scan_result: Optional[Any] = None  # container_scanner.models.ScanResult
    error_message: str = ""
    json_report_path: str = ""
    html_report_path: str = ""
    vuln_report_path: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0

    def to_api_dict(self) -> Dict[str, Any]:
        result = self.scan_result
        summary = {}
        score_info = {}
        gate_info = {}
        vuln_list = []
        misconfig_list = []
        df_list = []
        remediation_list = []

        if result:
            summary = result.summary.to_dict()
            if result.security_score:
                score_info = result.security_score.to_dict()
            gate_info = {
                "passed": result.gate_passed,
                "fail_on": result.gate_fail_on,
            }
            vuln_list = [v.to_dict() for v in result.vulnerabilities]
            misconfig_list = [m.to_dict() for m in result.misconfigurations]
            df_list = [d.to_dict() for d in result.dockerfile_findings]
            remediation_list = [r.to_dict() for r in result.remediation_items]

        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "upload_type": self.request.upload_type.value,
            "original_filename": self.request.original_filename,
            "created_at": self.request.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "summary": summary,
            "security_score": score_info,
            "gate": gate_info,
            "vulnerabilities": vuln_list,
            "misconfigurations": misconfig_list,
            "dockerfile_findings": df_list,
            "remediation_items": remediation_list,
            "reports": {
                "html_available": bool(self.html_report_path),
                "json_available": bool(self.json_report_path),
            },
        }
