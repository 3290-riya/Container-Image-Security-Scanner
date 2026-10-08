"""Tests for TrivyRunner subprocess integration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.scanner.trivy import TrivyRunner, TrivyError
from container_scanner.config import load_config


def make_runner(trivy_path: str = "trivy") -> TrivyRunner:
    cfg = load_config(None)
    # Override trivy_path via the internal attribute to avoid writing a tmp config
    runner = TrivyRunner(cfg)
    runner._trivy_path = trivy_path
    return runner


def mock_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


CLEAN_JSON = json.dumps({"SchemaVersion": 2, "Results": []})
VERSION_JSON = json.dumps({"Version": "0.48.0", "Commit": "abc123"})


class TestTrivyRunnerVersion:
    def test_returns_version_from_json(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=VERSION_JSON)
            assert runner.version() == "0.48.0"

    def test_version_fallback_on_plain_text(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout="Version: 0.48.0\nCommit: abc")
            result = runner.version()
            assert "Version" in result or "0.48.0" in result

    def test_version_command_includes_trivy_path(self):
        runner = make_runner(trivy_path="/custom/trivy")
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/custom/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=VERSION_JSON)
            runner.version()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "/custom/trivy"
            assert "version" in cmd

    def test_version_returns_unknown_on_empty_output(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout="")
            assert runner.version() == "unknown"


class TestTrivyRunnerScanImage:
    def test_scan_image_returns_stdout(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            result = runner.scan_image("nginx:latest")
            assert result == CLEAN_JSON

    def test_scan_image_command_structure(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_image("nginx:latest", severities=["HIGH", "CRITICAL"])
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "trivy"
            assert "image" in cmd
            assert "--format" in cmd
            assert "json" in cmd
            assert "--severity" in cmd
            sev_idx = cmd.index("--severity")
            assert "HIGH" in cmd[sev_idx + 1]
            assert "CRITICAL" in cmd[sev_idx + 1]
            assert "nginx:latest" in cmd

    def test_scan_image_uses_shell_false(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_image("nginx:latest")
            assert mock_run.call_args[1]["shell"] is False

    def test_scan_image_raises_on_trivy_not_found(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value=None):
            with pytest.raises(TrivyError, match="not found"):
                runner.scan_image("nginx:latest")

    def test_scan_image_raises_on_timeout(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("trivy", 300)):
            with pytest.raises(TrivyError, match="timed out"):
                runner.scan_image("nginx:latest")

    def test_scan_image_raises_on_bad_exit_code(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(returncode=2, stderr="fatal error")
            with pytest.raises(TrivyError, match="exit.*code.*2|code.*2"):
                runner.scan_image("nginx:latest")

    def test_scan_image_exit_code_1_is_acceptable(self):
        """Exit code 1 is valid: some Trivy versions use it for 'vulns found'."""
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(returncode=1, stdout=CLEAN_JSON)
            result = runner.scan_image("nginx:latest")
            assert result == CLEAN_JSON

    def test_scan_image_raises_on_file_not_found(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run",
                   side_effect=FileNotFoundError("not found")):
            with pytest.raises(TrivyError, match="not found"):
                runner.scan_image("nginx:latest")

    def test_scan_image_raises_on_os_error(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run",
                   side_effect=OSError("permission denied")):
            with pytest.raises(TrivyError, match="Failed to execute"):
                runner.scan_image("nginx:latest")


class TestTrivyRunnerScanConfig:
    def test_scan_config_includes_misconfig_scanner(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_config("nginx:latest")
            cmd = mock_run.call_args[0][0]
            assert "--scanners" in cmd
            idx = cmd.index("--scanners")
            assert cmd[idx + 1] == "misconfig"

    def test_scan_config_uses_shell_false(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_config("nginx:latest")
            assert mock_run.call_args[1]["shell"] is False


class TestTrivyRunnerScanFilesystem:
    def test_scan_filesystem_uses_fs_subcommand(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_filesystem("/app")
            cmd = mock_run.call_args[0][0]
            assert "fs" in cmd
            assert "/app" in cmd

    def test_scan_filesystem_uses_shell_false(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_filesystem("/app")
            assert mock_run.call_args[1]["shell"] is False


class TestTrivyRunnerSeverityFiltering:
    def test_custom_severities_used_in_command(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_image("nginx:latest", severities=["CRITICAL"])
            cmd = mock_run.call_args[0][0]
            sev_idx = cmd.index("--severity")
            assert cmd[sev_idx + 1] == "CRITICAL"

    def test_multiple_severities_joined_with_comma(self):
        runner = make_runner()
        with patch("container_scanner.scanner.trivy.shutil.which", return_value="/usr/bin/trivy"), \
             patch("container_scanner.scanner.trivy.subprocess.run") as mock_run:
            mock_run.return_value = mock_proc(stdout=CLEAN_JSON)
            runner.scan_image("nginx:latest", severities=["CRITICAL", "HIGH", "MEDIUM"])
            cmd = mock_run.call_args[0][0]
            sev_idx = cmd.index("--severity")
            sev_val = cmd[sev_idx + 1]
            assert "CRITICAL" in sev_val
            assert "HIGH" in sev_val
            assert "MEDIUM" in sev_val
            # Must be comma-separated, not space-separated
            assert "," in sev_val
