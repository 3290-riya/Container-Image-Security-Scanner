"""Tests for the main scan runner (run_scan orchestrator)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.runner import run_scan, _build_summary
from container_scanner.models import (
    ScanResult,
    Severity,
    Vulnerability,
    VulnerabilitySummary,
)

# ── Trivy JSON fixtures ──────────────────────────────────────────────────────

CLEAN_TRIVY_JSON = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "alpine:3.18",
    "Results": [],
})

VULN_TRIVY_JSON = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "nginx:latest",
    "Results": [
        {
            "Target": "nginx:latest (debian 12)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1n",
                    "FixedVersion": "1.1.1t",
                    "Severity": "HIGH",
                    "Title": "OpenSSL HIGH",
                    "Description": "High severity OpenSSL issue.",
                    "References": [],
                },
                {
                    "VulnerabilityID": "CVE-2023-0002",
                    "PkgName": "libssl",
                    "InstalledVersion": "1.1.1n",
                    "FixedVersion": "",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL CRITICAL",
                    "Description": "Critical OpenSSL issue.",
                    "References": [],
                },
            ],
        }
    ],
})


def _make_trivy_version_json():
    return json.dumps({"Version": "0.48.0"})


class TestRunScanCleanImage:
    """Tests where Trivy returns no vulnerabilities."""

    def test_clean_image_returns_0(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = CLEAN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            code = run_scan(
                image="alpine:3.18",
                output_dir=str(tmp_path),
                fmt="json",
                fail_on=[],
            )
        assert code == 0

    def test_clean_image_writes_reports(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = CLEAN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            run_scan(image="alpine:3.18", output_dir=str(tmp_path), fmt="json", fail_on=[])

        assert (tmp_path / "scan.json").exists()
        assert (tmp_path / "vulnerabilities.json").exists()

    def test_clean_image_score_100(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = CLEAN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            run_scan(image="alpine:3.18", output_dir=str(tmp_path), fmt="json", fail_on=[])

        with open(tmp_path / "scan.json") as f:
            data = json.load(f)
        assert data["security_score"]["score"] == 100
        assert data["security_score"]["risk_level"] == "LOW"


class TestRunScanVulnerableImage:
    """Tests where Trivy returns vulnerabilities."""

    def test_gate_fails_on_critical(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = VULN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            code = run_scan(
                image="nginx:latest",
                output_dir=str(tmp_path),
                fmt="json",
                fail_on=["CRITICAL"],
            )
        assert code == 1

    def test_gate_passes_when_only_high_and_fail_on_critical(self, tmp_path):
        high_only_json = json.dumps({
            "Results": [{
                "Target": "test",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-H",
                    "PkgName": "pkg",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                    "Severity": "HIGH",
                    "Title": "High vuln",
                    "Description": "",
                }]
            }]
        })
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = high_only_json
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            code = run_scan(
                image="test:latest",
                output_dir=str(tmp_path),
                fmt="json",
                fail_on=["CRITICAL"],
            )
        assert code == 0

    def test_vuln_count_in_report(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = VULN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            run_scan(image="nginx:latest", output_dir=str(tmp_path), fmt="json", fail_on=[])

        with open(tmp_path / "scan.json") as f:
            data = json.load(f)
        assert data["summary"]["total"] == 2
        assert data["summary"]["high"] == 1
        assert data["summary"]["critical"] == 1


class TestRunScanDockerfileOnly:
    """Tests for Dockerfile-only scan (no image)."""

    def test_dockerfile_only_returns_0_if_gate_passes(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:22.04\nUSER nobody\nHEALTHCHECK CMD echo ok\n")
        code = run_scan(
            dockerfile=str(df),
            output_dir=str(tmp_path),
            fmt="json",
            fail_on=[],
        )
        assert code == 0

    def test_dockerfile_missing_returns_2(self, tmp_path):
        code = run_scan(
            dockerfile="/nonexistent/Dockerfile",
            output_dir=str(tmp_path),
            fmt="json",
        )
        assert code == 2


class TestRunScanErrors:
    """Tests for error handling."""

    def test_trivy_error_returns_2(self, tmp_path):
        from container_scanner.scanner.trivy import TrivyError
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.side_effect = TrivyError("Trivy not found")
            mock_trivy_cls.return_value = mock_trivy

            code = run_scan(image="nginx:latest", output_dir=str(tmp_path), fmt="json")
        assert code == 2

    def test_invalid_config_returns_2(self, tmp_path):
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("scanner: [invalid: yaml\n")
        code = run_scan(
            image="nginx:latest",
            config_path=str(config_file),
            output_dir=str(tmp_path),
        )
        assert code == 2

    def test_html_report_generated(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = CLEAN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            run_scan(image="alpine:3.18", output_dir=str(tmp_path), fmt="html", fail_on=[])

        assert (tmp_path / "report.html").exists()
        content = (tmp_path / "report.html").read_text()
        assert "alpine:3.18" in content

    def test_both_formats_generated(self, tmp_path):
        with patch("container_scanner.runner.check_docker_available", return_value=False), \
             patch("container_scanner.runner.TrivyRunner") as mock_trivy_cls:
            mock_trivy = MagicMock()
            mock_trivy.version.return_value = "0.48.0"
            mock_trivy.scan_image.return_value = CLEAN_TRIVY_JSON
            mock_trivy.scan_config.return_value = CLEAN_TRIVY_JSON
            mock_trivy_cls.return_value = mock_trivy

            run_scan(image="alpine:3.18", output_dir=str(tmp_path), fmt="all", fail_on=[])

        assert (tmp_path / "scan.json").exists()
        assert (tmp_path / "report.html").exists()


class TestBuildSummary:
    def test_counts_all_severities(self):
        result = ScanResult(
            image="test",
            scan_time=datetime.now(timezone.utc),
            vulnerabilities=[
                Vulnerability("CVE-1", "p", "1", "2", Severity.CRITICAL, "t", ""),
                Vulnerability("CVE-2", "p", "1", "2", Severity.HIGH, "t", ""),
                Vulnerability("CVE-3", "p", "1", "2", Severity.MEDIUM, "t", ""),
                Vulnerability("CVE-4", "p", "1", "2", Severity.LOW, "t", ""),
                Vulnerability("CVE-5", "p", "1", "2", Severity.UNKNOWN, "t", ""),
            ],
        )
        s = _build_summary(result)
        assert s.total == 5
        assert s.critical == 1
        assert s.high == 1
        assert s.medium == 1
        assert s.low == 1
        assert s.unknown == 1

    def test_empty_vulnerabilities(self):
        result = ScanResult(image="test", scan_time=datetime.now(timezone.utc))
        s = _build_summary(result)
        assert s.total == 0
