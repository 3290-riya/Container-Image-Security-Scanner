"""
Tests for the web UI layer of the Container Image Security Scanner.

Uses FastAPI TestClient (synchronous wrapper around httpx).
All scanner logic is mocked – these are unit tests for the web layer,
not integration tests for Trivy.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── try to import FastAPI / httpx; skip the whole module if unavailable ──────
pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("httpx", reason="httpx not installed (required by TestClient)")

from fastapi.testclient import TestClient

from web.app import create_app
from web.models import (
    ScanProgress,
    ScanRequest,
    ScanStatus,
    UploadType,
    WebScanResult,
)
from web.upload import (
    UploadError,
    detect_upload_type,
    sanitize_filename,
    save_upload_to_temp,
    _safe_extract_zip,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    """A TestClient with a fresh FastAPI app."""
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _make_web_result(
    status: ScanStatus = ScanStatus.COMPLETE,
    scan_id: str = "test-scan-id-1234",
) -> WebScanResult:
    """Build a minimal WebScanResult for mocking."""
    from datetime import datetime
    req = ScanRequest(
        scan_id=scan_id,
        original_filename="nginx.tar",
        severities=["CRITICAL", "HIGH"],
        fail_on=["CRITICAL"],
        report_format="all",
    )
    result = WebScanResult(
        scan_id=scan_id,
        status=status,
        request=req,
        progress=ScanProgress(
            upload_validated=True,
            target_prepared=True,
            trivy_running=False,
            parsing_complete=True,
            scoring_complete=True,
            report_generated=True,
            current_step="Scan complete.",
        ),
        started_at=datetime(2024, 1, 1, 12, 0, 0),
        finished_at=datetime(2024, 1, 1, 12, 0, 5),
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        with patch("web.routes.check_trivy_available", return_value=True):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_json_trivy_available(self, client):
        with patch("web.routes.check_trivy_available", return_value=True):
            data = client.get("/health").json()
        assert data["trivy"] == "available"
        assert data["status"] == "healthy"

    def test_health_json_trivy_unavailable(self, client):
        with patch("web.routes.check_trivy_available", return_value=False):
            data = client.get("/health").json()
        assert "unavailable" in data["trivy"]
        assert data["status"] == "degraded"


# ─────────────────────────────────────────────────────────────────────────────
# Home page
# ─────────────────────────────────────────────────────────────────────────────

class TestHomePage:
    def test_home_returns_200(self, client):
        with patch("web.routes.list_scans", return_value=[]):
            resp = client.get("/")
        assert resp.status_code == 200

    def test_home_contains_title(self, client):
        with patch("web.routes.list_scans", return_value=[]):
            resp = client.get("/")
        assert b"Container" in resp.content

    def test_home_contains_form(self, client):
        with patch("web.routes.list_scans", return_value=[]):
            resp = client.get("/")
        assert b"scanForm" in resp.content or b"action=\"/scan\"" in resp.content


# ─────────────────────────────────────────────────────────────────────────────
# POST /scan
# ─────────────────────────────────────────────────────────────────────────────

class TestStartScan:
    def _post_scan(self, client, filename: str, content: bytes, extra_fields: dict = None):
        fields = {
            "severities": "CRITICAL,HIGH",
            "fail_on": "CRITICAL",
            "report_format": "all",
        }
        if extra_fields:
            fields.update(extra_fields)
        return client.post(
            "/scan",
            files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
            data=fields,
        )

    def test_valid_dockerfile_redirects(self, client):
        fake_result = _make_web_result(ScanStatus.PENDING)
        with patch("web.routes.submit_scan", return_value=fake_result):
            # Disable redirect following so we capture the 303 directly
            resp = client.post(
                "/scan",
                files={"file": ("Dockerfile", io.BytesIO(b"FROM ubuntu:22.04\n"), "application/octet-stream")},
                data={"severities": "CRITICAL,HIGH", "fail_on": "CRITICAL", "report_format": "all"},
                follow_redirects=False,
            )
        # Should be a redirect (303 See Other) to /scan/{scan_id}
        assert resp.status_code in (303, 302)
        assert "/scan/" in resp.headers.get("location", "")

    def test_empty_file_returns_error(self, client):
        resp = self._post_scan(client, "Dockerfile", b"")
        # Should render error page (status 4xx)
        assert resp.status_code >= 400

    def test_upload_error_shows_error_page(self, client):
        with patch("web.routes.submit_scan", side_effect=UploadError("Bad upload")):
            resp = self._post_scan(client, "Dockerfile", b"FROM ubuntu\n")
        assert resp.status_code in (200, 400)
        assert b"Upload" in resp.content or b"upload" in resp.content or b"Error" in resp.content

    def test_scan_limit_shows_429(self, client):
        with patch("web.routes.submit_scan", side_effect=RuntimeError("Too many concurrent scans")):
            resp = self._post_scan(client, "Dockerfile", b"FROM ubuntu\n")
        assert resp.status_code in (200, 429)


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id} — status / results routing
# ─────────────────────────────────────────────────────────────────────────────

class TestScanPage:
    def test_unknown_scan_returns_404(self, client):
        with patch("web.routes.get_scan", return_value=None):
            resp = client.get("/scan/nonexistent-id")
        assert resp.status_code == 404

    def test_pending_scan_shows_progress(self, client):
        wr = _make_web_result(ScanStatus.PENDING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}")
        assert resp.status_code == 200
        # scanning page
        assert b"scanning" in resp.content.lower() or b"progress" in resp.content.lower() or b"Scan" in resp.content

    def test_running_scan_shows_progress(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}")
        assert resp.status_code == 200

    def test_failed_scan_shows_error(self, client):
        wr = _make_web_result(ScanStatus.FAILED)
        wr.error_message = "Trivy not found"
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}")
        assert resp.status_code in (200, 400)

    def test_complete_scan_shows_results(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        wr.scan_result = _make_mock_scan_result()
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}")
        assert resp.status_code == 200


def _make_mock_scan_result():
    """Build a minimal ScanResult-like mock for the template context."""
    from datetime import datetime
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from container_scanner.models import (
        ScanResult, Severity, SecurityScore, VulnerabilitySummary,
    )
    r = ScanResult(image="nginx:latest", scan_time=datetime.utcnow(), gate_fail_on=["CRITICAL"])
    r.gate_passed = True
    r.trivy_version = "0.75.0"
    r.image_name = "nginx:latest"
    r.vulnerabilities = []
    r.misconfigurations = []
    r.dockerfile_findings = []
    r.remediation_items = []
    r.summary = VulnerabilitySummary(total=0, critical=0, high=0, medium=0, low=0)
    r.security_score = SecurityScore(score=95, risk_level="LOW", deductions=[])
    return r


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/status — JSON polling
# ─────────────────────────────────────────────────────────────────────────────

class TestScanStatus:
    def test_status_not_found_returns_404(self, client):
        with patch("web.routes.get_scan", return_value=None):
            resp = client.get("/scan/bad-id/status")
        assert resp.status_code == 404

    def test_status_returns_json(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "current_step" in data
        assert "progress" in data

    def test_status_complete(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/status")
        data = resp.json()
        assert data["status"] == "complete"

    def test_status_progress_fields(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/status")
        data = resp.json()
        progress = data["progress"]
        assert "upload_validated" in progress
        assert "trivy_running" in progress
        assert "report_generated" in progress


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/json
# ─────────────────────────────────────────────────────────────────────────────

class TestScanJson:
    def test_json_not_complete_returns_409(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/json")
        assert resp.status_code == 409

    def test_json_complete_returns_200(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        wr.scan_result = _make_mock_scan_result()
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/json")
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "status" in data

    def test_json_not_found_returns_404(self, client):
        with patch("web.routes.get_scan", return_value=None):
            resp = client.get("/scan/x/json")
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# File download endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestDownloads:
    def test_report_not_found_when_no_path(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        wr.html_report_path = ""  # no report generated
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/report")
        # 404 because path is empty / file doesn't exist
        assert resp.status_code == 404

    def test_json_report_not_complete_returns_409(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/report.json")
        assert resp.status_code == 409

    def test_vuln_report_not_complete_returns_409(self, client):
        wr = _make_web_result(ScanStatus.RUNNING)
        with patch("web.routes.get_scan", return_value=wr):
            resp = client.get(f"/scan/{wr.scan_id}/vulnerabilities.json")
        assert resp.status_code == 409

    def test_html_report_served_when_exists(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            f.write("<html><body>Test Report</body></html>")
            tmp_path = f.name
        wr.html_report_path = tmp_path
        try:
            with patch("web.routes.get_scan", return_value=wr):
                resp = client.get(f"/scan/{wr.scan_id}/report")
            assert resp.status_code == 200
            assert b"Test Report" in resp.content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_json_report_served_when_exists(self, client):
        wr = _make_web_result(ScanStatus.COMPLETE)
        payload = {"scan_id": wr.scan_id, "vulnerabilities": []}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(payload, f)
            tmp_path = f.name
        wr.json_report_path = tmp_path
        try:
            with patch("web.routes.get_scan", return_value=wr):
                resp = client.get(f"/scan/{wr.scan_id}/report.json")
            assert resp.status_code == 200
        finally:
            Path(tmp_path).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Upload utilities (unit tests — no HTTP)
# ─────────────────────────────────────────────────────────────────────────────

class TestSanitizeFilename:
    def test_normal_filename(self):
        assert sanitize_filename("nginx.tar") == "nginx.tar"

    def test_strips_directory(self):
        result = sanitize_filename("/etc/passwd")
        assert "/" not in result
        assert result == "passwd"

    def test_strips_path_traversal(self):
        result = sanitize_filename("../../etc/passwd")
        assert ".." not in result

    def test_replaces_spaces(self):
        result = sanitize_filename("my file.tar")
        assert " " not in result

    def test_empty_becomes_upload(self):
        result = sanitize_filename("...")
        assert result == "upload"

    def test_truncates_long_name(self):
        long_name = "a" * 200 + ".tar"
        result = sanitize_filename(long_name)
        assert len(result) <= 128


class TestDetectUploadType:
    def test_tar_is_archive(self):
        assert detect_upload_type("image.tar") == UploadType.IMAGE_ARCHIVE

    def test_zip_is_project(self):
        assert detect_upload_type("project.zip") == UploadType.PROJECT_ZIP

    def test_yml_is_compose(self):
        assert detect_upload_type("docker-compose.yml") == UploadType.COMPOSE

    def test_yaml_is_compose(self):
        assert detect_upload_type("config.yaml") == UploadType.COMPOSE

    def test_dockerfile_lowercase(self):
        assert detect_upload_type("Dockerfile") == UploadType.DOCKERFILE

    def test_dockerfile_extension(self):
        assert detect_upload_type("app.dockerfile") == UploadType.DOCKERFILE

    def test_unknown_extension(self):
        assert detect_upload_type("data.xyz") == UploadType.UNKNOWN


class TestSaveUploadToTemp:
    def test_saves_dockerfile_bytes(self):
        content = b"FROM ubuntu:22.04\nRUN apt-get update\n"
        path, utype = save_upload_to_temp(content, "Dockerfile")
        assert path.exists()
        assert path.read_bytes() == content
        assert utype == UploadType.DOCKERFILE
        # Cleanup
        import shutil
        shutil.rmtree(path.parent, ignore_errors=True)

    def test_empty_raises_upload_error(self):
        with pytest.raises(UploadError, match="empty"):
            save_upload_to_temp(b"", "Dockerfile")

    def test_oversized_raises_upload_error(self):
        from web.upload import MAX_UPLOAD_BYTES
        big = b"x" * (MAX_UPLOAD_BYTES + 1)
        with pytest.raises(UploadError, match="large"):
            save_upload_to_temp(big, "image.tar")

    def test_unknown_extension_raises(self):
        with pytest.raises(UploadError, match="Unsupported"):
            save_upload_to_temp(b"data", "file.exe")

    def test_temp_file_has_random_name(self):
        content = b"FROM ubuntu\n"
        p1, _ = save_upload_to_temp(content, "Dockerfile")
        p2, _ = save_upload_to_temp(content, "Dockerfile")
        assert p1.name != p2.name
        import shutil
        shutil.rmtree(p1.parent, ignore_errors=True)
        shutil.rmtree(p2.parent, ignore_errors=True)


class TestSafeExtractZip:
    def _make_zip(self, members: dict) -> Path:
        """Create a temp ZIP with the given {name: content} members."""
        tmp = Path(tempfile.mktemp(suffix=".zip"))
        with zipfile.ZipFile(tmp, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return tmp

    def test_normal_zip_extracted(self):
        zpath = self._make_zip({"Dockerfile": "FROM ubuntu\n", "README.md": "# test"})
        dest = Path(tempfile.mkdtemp())
        _safe_extract_zip(zpath, dest)
        assert (dest / "Dockerfile").exists()
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        zpath.unlink(missing_ok=True)

    def test_zip_slip_raises_error(self):
        """A member with ../../ path should be rejected."""
        zpath = self._make_zip({"../../evil.txt": "pwned"})
        dest = Path(tempfile.mkdtemp())
        with pytest.raises(UploadError, match="unsafe path"):
            _safe_extract_zip(zpath, dest)
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        zpath.unlink(missing_ok=True)

    def test_bad_zip_raises_error(self):
        tmp = Path(tempfile.mktemp(suffix=".zip"))
        tmp.write_bytes(b"this is not a zip")
        dest = Path(tempfile.mkdtemp())
        with pytest.raises(UploadError, match="Invalid ZIP"):
            _safe_extract_zip(tmp, dest)
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        tmp.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# WebScanResult model
# ─────────────────────────────────────────────────────────────────────────────

class TestWebScanResult:
    def test_duration_zero_when_no_times(self):
        wr = _make_web_result()
        wr.started_at = None
        wr.finished_at = None
        assert wr.duration_seconds == 0.0

    def test_duration_calculated(self):
        from datetime import datetime
        wr = _make_web_result()
        # started/finished already set by fixture helper
        assert wr.duration_seconds == pytest.approx(5.0, abs=1.0)

    def test_to_api_dict_keys(self):
        wr = _make_web_result()
        wr.scan_result = _make_mock_scan_result()
        d = wr.to_api_dict()
        assert "scan_id" in d
        assert "status" in d
        assert "summary" in d
        assert "vulnerabilities" in d
        assert "misconfigurations" in d
        assert "dockerfile_findings" in d
        assert "remediation_items" in d
        assert "gate" in d

    def test_to_api_dict_no_result(self):
        wr = _make_web_result()
        wr.scan_result = None
        d = wr.to_api_dict()
        # Should not raise; summary/vulns should be empty
        assert d["vulnerabilities"] == []
        assert d["summary"] == {}

    def test_scan_status_enum_values(self):
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETE.value == "complete"
        assert ScanStatus.FAILED.value == "failed"

    def test_upload_type_enum_values(self):
        assert UploadType.DOCKERFILE.value == "dockerfile"
        assert UploadType.IMAGE_ARCHIVE.value == "image_archive"
        assert UploadType.PROJECT_ZIP.value == "project_zip"
        assert UploadType.COMPOSE.value == "compose"


# ─────────────────────────────────────────────────────────────────────────────
# Static files
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticFiles:
    def test_css_served(self, client):
        resp = client.get("/static/css/style.css")
        assert resp.status_code == 200
        assert b"body" in resp.content

    def test_js_served(self, client):
        resp = client.get("/static/js/app.js")
        assert resp.status_code == 200
        assert b"function" in resp.content or b"=>" in resp.content or b"var " in resp.content
