"""Tests for report generation (JSON and HTML)."""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.models import (
    DockerfileFinding,
    Misconfiguration,
    RemediationItem,
    ScanResult,
    SecurityScore,
    Severity,
    Vulnerability,
    VulnerabilitySummary,
)
from container_scanner.reports.json_report import write_json_report
from container_scanner.reports.html_report import write_html_report


def make_scan_result() -> ScanResult:
    vuln = Vulnerability(
        vuln_id="CVE-2023-1234",
        package_name="openssl",
        installed_version="1.1.1n",
        fixed_version="1.1.1t",
        severity=Severity.HIGH,
        title="OpenSSL vulnerability",
        description="A test vulnerability.",
        target="test:latest",
    )
    mc = Misconfiguration(
        config_id="DS002",
        title="Running as root",
        severity=Severity.HIGH,
        description="Container runs as root.",
        risk="High risk",
        recommendation="Add USER instruction.",
        target="test:latest",
    )
    df = DockerfileFinding(
        rule_id="DF-008",
        title="Missing USER",
        severity=Severity.HIGH,
        description="No USER instruction.",
        recommendation="Add USER.",
        line_number=None,
    )
    remed = RemediationItem(
        finding_id="CVE-2023-1234",
        package_or_target="openssl",
        severity=Severity.HIGH,
        what_is_wrong="CVE-2023-1234 affects openssl.",
        why_it_matters="High severity.",
        how_to_fix="Upgrade openssl.",
    )
    return ScanResult(
        image="test:latest",
        scan_time=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        vulnerabilities=[vuln],
        misconfigurations=[mc],
        dockerfile_findings=[df],
        summary=VulnerabilitySummary(total=1, high=1),
        security_score=SecurityScore(score=65, risk_level="HIGH"),
        remediation_items=[remed],
        trivy_version="0.48.0",
        scan_duration_seconds=12.5,
        gate_passed=False,
        gate_fail_on=["CRITICAL", "HIGH"],
    )


class TestJSONReport:
    def test_writes_scan_json(self, tmp_path):
        result = make_scan_result()
        path = write_json_report(result, str(tmp_path))
        assert path.exists()
        assert path.name == "scan.json"

    def test_writes_vulnerabilities_json(self, tmp_path):
        result = make_scan_result()
        write_json_report(result, str(tmp_path))
        vuln_path = tmp_path / "vulnerabilities.json"
        assert vuln_path.exists()

    def test_scan_json_is_valid(self, tmp_path):
        result = make_scan_result()
        path = write_json_report(result, str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert data["image"] == "test:latest"
        assert data["summary"]["total"] == 1

    def test_vulnerabilities_json_structure(self, tmp_path):
        result = make_scan_result()
        write_json_report(result, str(tmp_path))
        with open(tmp_path / "vulnerabilities.json") as f:
            data = json.load(f)
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["vuln_id"] == "CVE-2023-1234"

    def test_creates_output_dir_if_missing(self, tmp_path):
        nested_dir = str(tmp_path / "nested" / "output")
        result = make_scan_result()
        write_json_report(result, nested_dir)
        assert (Path(nested_dir) / "scan.json").exists()


class TestHTMLReport:
    def test_writes_html_file(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        assert path.exists()
        assert path.name == "report.html"

    def test_html_contains_image_name(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "test:latest" in content

    def test_html_contains_vulnerability_id(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "CVE-2023-1234" in content

    def test_html_contains_security_score(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "65" in content

    def test_html_contains_risk_level(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "HIGH" in content

    def test_html_gate_failed_shown(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "FAILED" in content

    def test_html_no_script_tags(self, tmp_path):
        result = make_scan_result()
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "<script" not in content.lower()

    def test_html_escapes_special_chars(self, tmp_path):
        result = make_scan_result()
        result.image = "<script>alert('xss')</script>"
        path = write_html_report(result, str(tmp_path))
        content = path.read_text()
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_creates_output_dir_if_missing(self, tmp_path):
        nested = str(tmp_path / "a" / "b" / "c")
        result = make_scan_result()
        write_html_report(result, nested)
        assert (Path(nested) / "report.html").exists()

    def test_empty_scan_renders_without_error(self, tmp_path):
        result = ScanResult(
            image="empty:latest",
            scan_time=datetime.now(timezone.utc),
        )
        from container_scanner.security.scoring import calculate_score
        result.security_score = calculate_score([], [], [])
        result.summary = VulnerabilitySummary()
        path = write_html_report(result, str(tmp_path))
        assert path.exists()
        content = path.read_text()
        assert "empty:latest" in content
