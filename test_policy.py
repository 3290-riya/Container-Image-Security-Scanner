"""Tests for security gate / policy evaluation."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.models import Severity, Vulnerability, Misconfiguration, DockerfileFinding
from container_scanner.security.policy import evaluate_gate, validate_fail_on


def make_vuln(severity: Severity) -> Vulnerability:
    return Vulnerability(
        vuln_id="CVE-0001",
        package_name="pkg",
        installed_version="1.0",
        fixed_version="1.1",
        severity=severity,
        title="test",
        description="",
    )


def make_misconfig(severity: Severity) -> Misconfiguration:
    return Misconfiguration(
        config_id="MC-001",
        title="test",
        severity=severity,
        description="",
        risk="",
        recommendation="",
        target="test",
    )


def make_df(severity: Severity) -> DockerfileFinding:
    return DockerfileFinding(
        rule_id="DF-001",
        title="test",
        severity=severity,
        description="",
        recommendation="",
    )


class TestGateEvaluation:
    def test_no_fail_on_always_passes(self):
        passed, violations = evaluate_gate([], [make_vuln(Severity.CRITICAL)], [], [])
        assert passed is True
        assert violations == []

    def test_empty_findings_always_passes(self):
        passed, violations = evaluate_gate(["CRITICAL", "HIGH"], [], [], [])
        assert passed is True
        assert violations == []

    def test_critical_triggers_gate(self):
        passed, violations = evaluate_gate(
            ["CRITICAL"],
            [make_vuln(Severity.CRITICAL)],
            [],
            [],
        )
        assert passed is False
        assert len(violations) == 1
        assert violations[0].severity == "CRITICAL"

    def test_high_triggers_gate(self):
        passed, violations = evaluate_gate(
            ["HIGH"],
            [make_vuln(Severity.HIGH)],
            [],
            [],
        )
        assert passed is False

    def test_medium_does_not_trigger_high_gate(self):
        passed, violations = evaluate_gate(
            ["HIGH"],
            [make_vuln(Severity.MEDIUM)],
            [],
            [],
        )
        assert passed is True

    def test_misconfig_triggers_gate(self):
        passed, violations = evaluate_gate(
            ["HIGH"],
            [],
            [make_misconfig(Severity.HIGH)],
            [],
        )
        assert passed is False

    def test_dockerfile_triggers_gate(self):
        passed, violations = evaluate_gate(
            ["HIGH"],
            [],
            [],
            [make_df(Severity.HIGH)],
        )
        assert passed is False

    def test_low_finding_with_critical_gate_passes(self):
        passed, violations = evaluate_gate(
            ["CRITICAL"],
            [make_vuln(Severity.LOW)],
            [],
            [],
        )
        assert passed is True

    def test_violation_count_is_correct(self):
        vulns = [make_vuln(Severity.HIGH), make_vuln(Severity.HIGH), make_vuln(Severity.HIGH)]
        passed, violations = evaluate_gate(["HIGH"], vulns, [], [])
        assert passed is False
        high_violation = next(v for v in violations if v.severity == "HIGH")
        assert high_violation.count == 3

    def test_multiple_fail_on_severities(self):
        passed, violations = evaluate_gate(
            ["CRITICAL", "HIGH"],
            [make_vuln(Severity.HIGH)],
            [],
            [],
        )
        assert passed is False


class TestValidateFailOn:
    def test_valid_severities_no_error(self):
        validate_fail_on(["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="EXTREME"):
            validate_fail_on(["EXTREME"])

    def test_empty_list_no_error(self):
        validate_fail_on([])
