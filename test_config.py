"""Tests for configuration loading and validation."""

import pytest
import yaml
import os
import tempfile

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.config import (
    ConfigError,
    ScannerConfig,
    load_config,
    _deep_merge,
)


class TestDefaultConfig:
    def test_load_defaults_when_no_file(self):
        cfg = load_config(None)
        assert "CRITICAL" in cfg.severities
        assert "HIGH" in cfg.severities
        assert cfg.gate_enabled is True
        assert "CRITICAL" in cfg.gate_fail_on
        assert cfg.output_directory == "reports"

    def test_trivy_path_default(self):
        cfg = load_config(None)
        assert cfg.trivy_path == "trivy"

    def test_timeout_default(self):
        cfg = load_config(None)
        assert cfg.timeout == 300


class TestConfigValidation:
    def _write_yaml(self, tmp_path, content: str) -> str:
        p = tmp_path / "config.yaml"
        p.write_text(content)
        return str(p)

    def test_valid_full_config(self, tmp_path):
        path = self._write_yaml(tmp_path, """
scanner:
  severity: [CRITICAL, HIGH]
  timeout: 120
  trivy_path: trivy
security_gate:
  enabled: false
  fail_on: [CRITICAL]
reports:
  formats: [json]
output:
  directory: out
""")
        cfg = load_config(path)
        assert cfg.severities == ["CRITICAL", "HIGH"]
        assert cfg.timeout == 120
        assert cfg.gate_enabled is False
        assert cfg.output_directory == "out"

    def test_missing_scanner_section_uses_defaults(self, tmp_path):
        # The config loader deep-merges with DEFAULT_CONFIG, so missing sections
        # are filled from defaults rather than raising an error.
        path = self._write_yaml(tmp_path, """
security_gate:
  enabled: false
  fail_on: []
reports:
  formats: [json]
output:
  directory: my_reports
""")
        # Should load successfully, using defaults for the scanner section
        cfg = load_config(path)
        assert "CRITICAL" in cfg.severities  # from defaults
        assert cfg.gate_enabled is False       # from user config
        assert cfg.output_directory == "my_reports"  # from user config

    def test_invalid_severity_raises(self, tmp_path):
        path = self._write_yaml(tmp_path, """
scanner:
  severity: [CRITICAL, BOGUS]
security_gate:
  enabled: true
  fail_on: []
reports:
  formats: [json]
output:
  directory: reports
""")
        with pytest.raises(ConfigError, match="BOGUS"):
            load_config(path)

    def test_invalid_fail_on_raises(self, tmp_path):
        path = self._write_yaml(tmp_path, """
scanner:
  severity: [CRITICAL]
security_gate:
  enabled: true
  fail_on: [EXTREME]
reports:
  formats: [json]
output:
  directory: reports
""")
        with pytest.raises(ConfigError, match="EXTREME"):
            load_config(path)

    def test_invalid_report_format_raises(self, tmp_path):
        path = self._write_yaml(tmp_path, """
scanner:
  severity: [HIGH]
security_gate:
  enabled: true
  fail_on: []
reports:
  formats: [pdf]
output:
  directory: reports
""")
        with pytest.raises(ConfigError, match="pdf"):
            load_config(path)

    def test_nonexistent_file_raises(self):
        with pytest.raises(ConfigError, match="not found"):
            load_config("/nonexistent/path/config.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        path = self._write_yaml(tmp_path, "scanner: [this: is: invalid: yaml\n")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(path)

    def test_empty_severity_list_raises(self, tmp_path):
        path = self._write_yaml(tmp_path, """
scanner:
  severity: []
security_gate:
  enabled: true
  fail_on: []
reports:
  formats: [json]
output:
  directory: reports
""")
        with pytest.raises(ConfigError, match="non-empty"):
            load_config(path)


class TestDeepMerge:
    def test_override_leaf(self):
        base = {"a": {"b": 1, "c": 2}}
        override = {"a": {"b": 99}}
        result = _deep_merge(base, override)
        assert result["a"]["b"] == 99
        assert result["a"]["c"] == 2

    def test_new_key(self):
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_non_dict_override_replaces(self):
        base = {"a": {"nested": 1}}
        override = {"a": "flat"}
        result = _deep_merge(base, override)
        assert result["a"] == "flat"
