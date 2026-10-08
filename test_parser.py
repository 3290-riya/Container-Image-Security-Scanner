"""Tests for Trivy JSON parsing."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.scanner.parser import parse_trivy_image_json, TrivyParseError
from container_scanner.models import Severity


SAMPLE_TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:latest",
    "Results": [
        {
            "Target": "nginx:latest (debian 11.6)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "libc-bin",
                    "InstalledVersion": "2.31-13+deb11u5",
                    "FixedVersion": "2.31-13+deb11u6",
                    "Severity": "HIGH",
                    "Title": "glibc: buffer overflow",
                    "Description": "A buffer overflow exists in glibc.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"],
                    "CVSS": {
                        "nvd": {
                            "V3Score": 7.5,
                            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        }
                    },
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1n-0+deb11u4",
                    "FixedVersion": "",
                    "Severity": "CRITICAL",
                    "Title": "openssl: remote code execution",
                    "Description": "RCE via crafted TLS handshake.",
                    "References": [],
                },
            ],
        },
        {
            "Target": "Python (python-pkg)",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "requests",
                    "InstalledVersion": "2.26.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "requests: SSRF vulnerability",
                    "Description": "Server-side request forgery in requests.",
                    "References": [],
                }
            ],
        },
        {
            "Target": "nginx:latest",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Severity": "HIGH",
                    "Description": "Running containers as root can be dangerous.",
                    "Resolution": "Add USER instruction to set a non-root user.",
                    "Type": "Dockerfile Security Check",
                }
            ],
        },
    ],
}


class TestTrivyParser:
    def test_parses_vulnerabilities(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        vulns, _ = parse_trivy_image_json(raw)
        assert len(vulns) == 3

    def test_parses_misconfigurations(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        _, misconfigs = parse_trivy_image_json(raw)
        assert len(misconfigs) == 1
        assert misconfigs[0].config_id == "DS002"

    def test_vulnerability_fields(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        vulns, _ = parse_trivy_image_json(raw)
        high_vuln = next(v for v in vulns if v.vuln_id == "CVE-2023-1234")
        assert high_vuln.severity == Severity.HIGH
        assert high_vuln.package_name == "libc-bin"
        assert high_vuln.installed_version == "2.31-13+deb11u5"
        assert high_vuln.fixed_version == "2.31-13+deb11u6"
        assert high_vuln.cvss is not None
        assert high_vuln.cvss.score == 7.5

    def test_critical_vulnerability(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        vulns, _ = parse_trivy_image_json(raw)
        crit = next(v for v in vulns if v.vuln_id == "CVE-2023-5678")
        assert crit.severity == Severity.CRITICAL
        assert crit.fixed_version == "No fix available"

    def test_medium_python_vuln(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        vulns, _ = parse_trivy_image_json(raw)
        med = next(v for v in vulns if v.vuln_id == "CVE-2023-9999")
        assert med.severity == Severity.MEDIUM
        assert med.package_name == "requests"
        assert med.target == "Python (python-pkg)"

    def test_unknown_severity_defaults(self):
        data = {
            "Results": [{
                "Target": "test",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-XXX",
                    "PkgName": "pkg",
                    "InstalledVersion": "1.0",
                    "Severity": "GARBAGE",
                    "Title": "test",
                    "Description": "",
                }]
            }]
        }
        vulns, _ = parse_trivy_image_json(json.dumps(data))
        assert vulns[0].severity == Severity.UNKNOWN

    def test_empty_results(self):
        data = {"Results": []}
        vulns, misconfigs = parse_trivy_image_json(json.dumps(data))
        assert vulns == []
        assert misconfigs == []

    def test_no_results_key(self):
        data = {"SchemaVersion": 2}
        vulns, misconfigs = parse_trivy_image_json(json.dumps(data))
        assert vulns == []
        assert misconfigs == []

    def test_invalid_json_raises(self):
        with pytest.raises(TrivyParseError, match="Invalid JSON"):
            parse_trivy_image_json("not-json{")

    def test_non_dict_root_raises(self):
        with pytest.raises(TrivyParseError):
            parse_trivy_image_json(json.dumps([1, 2, 3]))

    def test_results_not_list_raises(self):
        with pytest.raises(TrivyParseError, match="list"):
            parse_trivy_image_json(json.dumps({"Results": "bad"}))

    def test_missing_vuln_id_skipped(self):
        data = {
            "Results": [{
                "Target": "test",
                "Vulnerabilities": [{"PkgName": "pkg", "Severity": "HIGH"}]
            }]
        }
        vulns, _ = parse_trivy_image_json(json.dumps(data))
        assert vulns == []

    def test_references_list(self):
        raw = json.dumps(SAMPLE_TRIVY_JSON)
        vulns, _ = parse_trivy_image_json(raw)
        high = next(v for v in vulns if v.vuln_id == "CVE-2023-1234")
        assert isinstance(high.references, list)
        assert len(high.references) == 1

    def test_null_vulnerabilities_key(self):
        data = {
            "Results": [{
                "Target": "test",
                "Vulnerabilities": None
            }]
        }
        vulns, _ = parse_trivy_image_json(json.dumps(data))
        assert vulns == []
