"""Tests for the remediation engine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.models import Severity, Vulnerability, Misconfiguration, DockerfileFinding
from container_scanner.security.remediation import generate_remediation


def make_vuln(vuln_id: str, severity: Severity, has_fix: bool = True) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        package_name="test-pkg",
        installed_version="1.0",
        fixed_version="1.1" if has_fix else "No fix available",
        severity=severity,
        title="Test vulnerability",
        description="A test vulnerability.",
        target="test:latest",
    )


def make_misconfig(config_id: str, severity: Severity) -> Misconfiguration:
    return Misconfiguration(
        config_id=config_id,
        title="Running as root",
        severity=severity,
        description="Container runs as root.",
        risk="High risk",
        recommendation="Add USER instruction.",
        target="test:latest",
    )


def make_df(rule_id: str, severity: Severity, line_number: int = None) -> DockerfileFinding:
    return DockerfileFinding(
        rule_id=rule_id,
        title="Missing USER",
        severity=severity,
        description="No USER instruction found.",
        recommendation="Add USER instruction.",
        line_number=line_number,
    )


class TestRemediationGeneration:
    def test_empty_findings_empty_items(self):
        items = generate_remediation([], [], [])
        assert items == []

    def test_vulnerability_item_generated(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH)]
        items = generate_remediation(vulns, [], [])
        assert len(items) == 1
        assert items[0].finding_id == "CVE-0001"
        assert items[0].severity == Severity.HIGH

    def test_vuln_with_fix_mentions_upgrade(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH, has_fix=True)]
        items = generate_remediation(vulns, [], [])
        assert "Upgrade" in items[0].how_to_fix or "upgrade" in items[0].how_to_fix.lower()

    def test_vuln_without_fix_mentions_no_fix(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH, has_fix=False)]
        items = generate_remediation(vulns, [], [])
        assert "No upstream fix" in items[0].how_to_fix or "no fix" in items[0].how_to_fix.lower() or "No fix" in items[0].how_to_fix

    def test_misconfig_item_generated(self):
        mc = [make_misconfig("DS002", Severity.HIGH)]
        items = generate_remediation([], mc, [])
        assert len(items) == 1
        assert items[0].finding_id == "DS002"

    def test_dockerfile_item_generated(self):
        df = [make_df("DF-008", Severity.HIGH)]
        items = generate_remediation([], [], df)
        assert len(items) == 1
        assert items[0].finding_id == "DF-008"

    def test_items_sorted_by_priority(self):
        # LOW vuln + CRITICAL vuln: CRITICAL should come first
        items = generate_remediation(
            [
                make_vuln("CVE-LOW", Severity.LOW),
                make_vuln("CVE-CRIT", Severity.CRITICAL),
            ],
            [],
            [],
        )
        assert items[0].finding_id == "CVE-CRIT"
        assert items[-1].finding_id == "CVE-LOW"

    def test_all_items_have_required_fields(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH)]
        mc = [make_misconfig("DS001", Severity.MEDIUM)]
        df = [make_df("DF-001", Severity.LOW)]
        items = generate_remediation(vulns, mc, df)
        for item in items:
            assert item.finding_id
            assert item.what_is_wrong
            assert item.why_it_matters
            assert item.how_to_fix
            assert isinstance(item.priority, int)

    def test_to_dict_serializable(self):
        vulns = [make_vuln("CVE-0001", Severity.HIGH)]
        items = generate_remediation(vulns, [], [])
        d = items[0].to_dict()
        assert d["finding_id"] == "CVE-0001"
        assert d["severity"] == "HIGH"
