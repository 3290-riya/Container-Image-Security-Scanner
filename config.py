"""Configuration loader and validator for the container image security scanner."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml

DEFAULT_CONFIG = {
    "scanner": {
        "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "timeout": 300,
        "trivy_path": "trivy",
    },
    "security_gate": {
        "enabled": True,
        "fail_on": ["CRITICAL", "HIGH"],
    },
    "reports": {
        "formats": ["json", "html"],
    },
    "output": {
        "directory": "reports",
    },
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


class ConfigError(Exception):
    """Raised for configuration validation failures."""


class ScannerConfig:
    """Holds validated scanner configuration."""

    def __init__(self, data: dict):
        self._data = data
        self._validate()

    # ------------------------------------------------------------------ #
    # Accessors                                                            #
    # ------------------------------------------------------------------ #

    @property
    def severities(self) -> List[str]:
        return self._data["scanner"]["severity"]

    @property
    def timeout(self) -> int:
        return int(self._data["scanner"].get("timeout", 300))

    @property
    def trivy_path(self) -> str:
        return self._data["scanner"].get("trivy_path", "trivy")

    @property
    def gate_enabled(self) -> bool:
        return bool(self._data["security_gate"].get("enabled", True))

    @property
    def gate_fail_on(self) -> List[str]:
        return self._data["security_gate"].get("fail_on", ["CRITICAL", "HIGH"])

    @property
    def report_formats(self) -> List[str]:
        return self._data["reports"].get("formats", ["json", "html"])

    @property
    def output_directory(self) -> str:
        return self._data["output"].get("directory", "reports")

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def _validate(self) -> None:
        data = self._data

        if "scanner" not in data or not isinstance(data["scanner"], dict):
            raise ConfigError("'scanner' section is required and must be a mapping.")

        sev = data["scanner"].get("severity")
        if not isinstance(sev, list) or not sev:
            raise ConfigError("'scanner.severity' must be a non-empty list.")
        for s in sev:
            if s.upper() not in VALID_SEVERITIES:
                raise ConfigError(f"Unknown severity '{s}'. Valid: {VALID_SEVERITIES}")

        if "security_gate" not in data or not isinstance(data["security_gate"], dict):
            raise ConfigError("'security_gate' section is required and must be a mapping.")

        fail_on = data["security_gate"].get("fail_on", [])
        if not isinstance(fail_on, list):
            raise ConfigError("'security_gate.fail_on' must be a list.")
        for s in fail_on:
            if s.upper() not in VALID_SEVERITIES:
                raise ConfigError(f"Unknown severity in fail_on: '{s}'.")

        if "reports" not in data or not isinstance(data["reports"], dict):
            raise ConfigError("'reports' section is required and must be a mapping.")

        fmts = data["reports"].get("formats", [])
        if not isinstance(fmts, list):
            raise ConfigError("'reports.formats' must be a list.")
        for fmt in fmts:
            if fmt not in ("json", "html"):
                raise ConfigError(f"Unknown report format '{fmt}'. Valid: json, html.")

        if "output" not in data or not isinstance(data["output"], dict):
            raise ConfigError("'output' section is required and must be a mapping.")


def load_config(path: Optional[str] = None) -> ScannerConfig:
    """Load configuration from YAML file, falling back to defaults."""
    if path is None:
        # Try the default location relative to the working directory
        default_path = Path("config.yaml")
        if default_path.exists():
            path = str(default_path)

    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Configuration file not found: {path}")
        with open(config_path, encoding="utf-8") as fh:
            try:
                user_data = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                raise ConfigError(f"Invalid YAML in configuration file: {exc}") from exc

        if not isinstance(user_data, dict):
            raise ConfigError("Configuration file must contain a YAML mapping.")

        # Deep-merge with defaults (user values take precedence)
        merged = _deep_merge(DEFAULT_CONFIG, user_data)
        return ScannerConfig(merged)

    return ScannerConfig(DEFAULT_CONFIG.copy())


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
