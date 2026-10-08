"""Tests for the security scoring engine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.models import Severity
from container_scanner.security.scoring import calculate_score, _risk_level
from container_scanner.models import Vulnerability, Misconfiguration, DockerfileFinding, CVSS


def make_vuln(vuln_id: str, severity: Severity, package: str = "pkg") -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        package_name=package,
        installed_version="1.0",
        fixed_version="1.1",
        severity=severity,
        title="Test vulnerability",
        description="",
    )


def make_misconfig(config_id: str, severity: Severity) -> Misconfiguration:
    return Misconfiguration(
        config_id=config_id,
        title="Test misconfig",
        severity=severity,
        description="",
        risk="",
        recommendation="",
        target="test",
    )


def make_df_finding(rule_id: str, severity: Severity) -> DockerfileFinding:
    return DockerfileFinding(
        rule_id=rule_id,
        title="Test dockerfile finding",
        severity=severity,
        description="",
        recommendation="",
    )


class TestScoring:
    def test_perfect_score_no_findings(self):
        score = calculate_score([], [], [])
        assert score.score == 100
        assert score.risk_level == "LOW"

    def test_critical_vuln_deducts_20(self):
        vulns = [make_vuln("CVE-0001", Severity.CRITICAL)]
        score = calculate_score(vulns, [], [])
        assert score.score == 80

    def test_high_vuln_deducts_10(self):
        vulns = [make_vuln("CVE-0002", Severity.HIGH)]
        score = calculate_score(vulns, [], [])
        assert score.score == 90

    def test_medium_vuln_deducts_3(self):
        vulns = [make_vuln("CVE-0003", Severity.MEDIUM)]
        score = calculate_score(vulns, [], [])
        assert score.score == 97

    def test_low_vuln_deducts_1(self):
        vulns = [make_vuln("CVE-0004", Severity.LOW)]
        score = calculate_score(vulns, [], [])
        assert score.score == 99

    def test_score_never_below_zero(self):
        # 10 critical vulns = -200 points; should clamp to 0
        vulns = [make_vuln(f"CVE-{i:04d}", Severity.CRITICAL) for i in range(10)]
        score = calculate_score(vulns, [], [])
        assert score.score == 0

    def test_critical_misconfig_deducts_10(self):
        mc = [make_misconfig("MC-001", Severity.CRITICAL)]
        score = calculate_score([], mc, [])
        assert score.score == 90

    def test_high_misconfig_deducts_5(self):
        mc = [make_misconfig("MC-002", Severity.HIGH)]
        score = calculate_score([], mc, [])
        assert score.score == 95

    def test_dockerfile_high_deducts_5(self):
        df = [make_df_finding("DF-001", Severity.HIGH)]
        score = calculate_score([], [], df)
        assert score.score == 95

    def test_combined_deductions(self):
        vulns = [make_vuln("CVE-0001", Severity.CRITICAL)]  # -20
        mc = [make_misconfig("MC-001", Severity.HIGH)]        # -5
        df = [make_df_finding("DF-001", Severity.MEDIUM)]     # -2
        score = calculate_score(vulns, mc, df)
        assert score.score == 73

    def test_deductions_list_populated(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH)]
        score = calculate_score(vulns, [], [])
        assert len(score.deductions) == 1
        assert score.deductions[0]["type"] == "vulnerability"
        assert score.deductions[0]["points"] == 10


class TestRiskLevel:
    def test_100_is_low(self):
        assert _risk_level(100) == "LOW"

    def test_90_is_low(self):
        assert _risk_level(90) == "LOW"

    def test_89_is_moderate(self):
        assert _risk_level(89) == "MODERATE"

    def test_75_is_moderate(self):
        assert _risk_level(75) == "MODERATE"

    def test_74_is_high(self):
        assert _risk_level(74) == "HIGH"

    def test_50_is_high(self):
        assert _risk_level(50) == "HIGH"

    def test_49_is_critical(self):
        assert _risk_level(49) == "CRITICAL"

    def test_0_is_critical(self):
        assert _risk_level(0) == "CRITICAL"
