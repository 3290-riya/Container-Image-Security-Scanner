"""Demo / sample scan data used when Trivy is not available.

This module provides realistic-looking scan results so the web UI is fully
functional even without a Trivy installation (e.g. first-time demos, CI
environments without Trivy, or simple local testing).
"""
from __future__ import annotations

from datetime import datetime

from container_scanner.models import (
    CVSS,
    DockerfileFinding,
    Misconfiguration,
    RemediationItem,
    ScanResult,
    SecurityScore,
    Severity,
    Vulnerability,
    VulnerabilitySummary,
)


def build_demo_scan_result(image_name: str = "nginx:1.24.0 (demo)") -> ScanResult:
    """Return a fully-populated demo ScanResult."""

    vulns = _demo_vulnerabilities()
    misconfigs = _demo_misconfigurations()
    df_findings = _demo_dockerfile_findings()

    summary = VulnerabilitySummary(
        total=len(vulns),
        critical=sum(1 for v in vulns if v.severity == Severity.CRITICAL),
        high=sum(1 for v in vulns if v.severity == Severity.HIGH),
        medium=sum(1 for v in vulns if v.severity == Severity.MEDIUM),
        low=sum(1 for v in vulns if v.severity == Severity.LOW),
        unknown=0,
    )

    score_val = max(
        0,
        100
        - summary.critical * 20
        - summary.high * 10
        - summary.medium * 3
        - summary.low * 1
        - len(misconfigs) * 4
        - len(df_findings) * 2,
    )
    risk = (
        "LOW" if score_val >= 90
        else "MODERATE" if score_val >= 75
        else "HIGH" if score_val >= 50
        else "CRITICAL"
    )

    score = SecurityScore(score=score_val, risk_level=risk, deductions=[])
    remediation = _demo_remediation(vulns, misconfigs, df_findings)

    result = ScanResult(
        image=image_name,
        scan_time=datetime.utcnow(),
        vulnerabilities=vulns,
        misconfigurations=misconfigs,
        dockerfile_findings=df_findings,
        summary=summary,
        security_score=score,
        remediation_items=remediation,
        trivy_version="demo-mode",
        scan_duration_seconds=3.2,
        gate_passed=summary.critical == 0,
        gate_fail_on=["CRITICAL", "HIGH"],
    )
    return result


# ── Vulnerabilities ─────────────────────────────────────────────────────────

def _demo_vulnerabilities() -> list:
    return [
        Vulnerability(
            vuln_id="CVE-2023-44487",
            package_name="nghttp2",
            installed_version="1.51.0-1",
            fixed_version="1.51.0-2",
            severity=Severity.CRITICAL,
            title="HTTP/2 Rapid Reset Attack (CVE-2023-44487)",
            description=(
                "The HTTP/2 protocol allows a denial of service (server resource "
                "consumption) because request cancellation can reset many streams "
                "quickly, causing rapid-reset attacks."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
                "https://www.cve.org/CVERecord?id=CVE-2023-44487",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-5363",
            package_name="openssl",
            installed_version="3.0.11-1~deb12u1",
            fixed_version="3.0.11-1~deb12u2",
            severity=Severity.CRITICAL,
            title="OpenSSL: Incorrect cipher key and IV length processing",
            description=(
                "Issue summary: A bug has been identified in the processing of key and "
                "initialisation vector (IV) lengths. This can lead to potential truncation "
                "or overruns during the initialisation of some symmetric ciphers."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-5363",
                "https://www.openssl.org/news/secadv/20231024.txt",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=9.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-4807",
            package_name="openssl",
            installed_version="3.0.11-1~deb12u1",
            fixed_version="3.0.11-1~deb12u2",
            severity=Severity.HIGH,
            title="OpenSSL: POLY1305 MAC implementation corrupts XMM registers on Windows",
            description=(
                "Issue summary: The POLY1305 MAC implementation corrupts the XMM registers "
                "of the caller on Windows. Impact: The POLY1305 MAC implementation contains "
                "a bug that corrupts the XMM registers on Windows."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-4807",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-3817",
            package_name="libssl3",
            installed_version="3.0.9-1",
            fixed_version="3.0.11-1~deb12u1",
            severity=Severity.HIGH,
            title="OpenSSL: Excessive time spent checking DH q parameter value",
            description=(
                "Issue summary: Checking excessively long DH keys or parameters may be very slow. "
                "Impact summary: Applications that use the functions DH_check(), DH_check_ex() or "
                "EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-3817",
                "https://www.openssl.org/news/secadv/20230731.txt",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-2975",
            package_name="libcrypto3",
            installed_version="3.0.9-1",
            fixed_version="3.0.9-2",
            severity=Severity.MEDIUM,
            title="OpenSSL: AES-SIV cipher implementation contains a bug that leads to unauthenticated encryption",
            description=(
                "Issue summary: The AES-SIV cipher implementation contains a bug that causes "
                "it to ignore empty associated data entries. Impact summary: Applications that "
                "use the AES-SIV algorithm and want to authenticate empty data entries as "
                "associated data can be mislead by removing, reordering or substituting those entries."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-2975",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-1255",
            package_name="libcrypto3",
            installed_version="3.0.9-1",
            fixed_version="3.0.9-2",
            severity=Severity.LOW,
            title="OpenSSL: Input buffer over-read in AES-XTS implementation on 64 bit ARM",
            description=(
                "Issue summary: The AES-XTS cipher decryption implementation for 64 bit ARM "
                "platform contains a bug that could cause it to read past the input buffer, "
                "leading to a crash."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-1255",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=4.0, vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", source="nvd"),
            vuln_type="os-pkgs",
        ),
        Vulnerability(
            vuln_id="CVE-2023-39325",
            package_name="golang.org/x/net",
            installed_version="v0.8.0",
            fixed_version="v0.17.0",
            severity=Severity.HIGH,
            title="golang.org/x/net/http2: rapid stream resets can cause excessive work",
            description=(
                "A malicious HTTP/2 client which rapidly creates requests and immediately sends "
                "RST_STREAM frames can cause excessive server resource consumption."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-39325",
                "https://pkg.go.dev/vuln/GO-2023-2102",
            ],
            target="nginx:1.24.0 (go modules)",
            cvss=CVSS(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source="nvd"),
            vuln_type="library",
        ),
        Vulnerability(
            vuln_id="CVE-2023-29491",
            package_name="ncurses-bin",
            installed_version="6.4-4",
            fixed_version="No fix available",
            severity=Severity.MEDIUM,
            title="ncurses: Local users can trigger security-relevant memory corruption",
            description=(
                "ncurses before 6.4 20230408, when used by a setuid application, "
                "allows local users to trigger security-relevant memory corruption "
                "via malformed data in a terminfo database file."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-29491",
            ],
            target="nginx:1.24.0 (debian 12.1)",
            cvss=CVSS(score=7.8, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", source="nvd"),
            vuln_type="os-pkgs",
        ),
    ]


# ── Misconfigurations ────────────────────────────────────────────────────────

def _demo_misconfigurations() -> list:
    return [
        Misconfiguration(
            config_id="DS002",
            title="Image should not be run as root user",
            severity=Severity.HIGH,
            description=(
                "Running containers with root privileges allows an attacker who has "
                "compromised the containerized application to escalate privileges and "
                "break out of the container."
            ),
            risk="High risk: root user grants full container control.",
            recommendation="Add USER instruction to run as a non-root user (e.g., USER 1000).",
            target="Dockerfile",
            category="Docker Security",
        ),
        Misconfiguration(
            config_id="DS026",
            title="No healthcheck defined",
            severity=Severity.LOW,
            description=(
                "A healthcheck is not defined for the container. Without a healthcheck, "
                "Docker and Kubernetes cannot determine container health, leading to "
                "degraded services remaining in rotation."
            ),
            risk="Low risk: affects reliability but not direct security.",
            recommendation="Add HEALTHCHECK instruction: HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
            target="Dockerfile",
            category="Docker Best Practices",
        ),
        Misconfiguration(
            config_id="KSV001",
            title="Process can elevate its own privileges",
            severity=Severity.MEDIUM,
            description=(
                "A program inside the container can request additional capabilities using "
                "setuid or setgid binaries, leading to privilege escalation."
            ),
            risk="Moderate risk: privilege escalation vector.",
            recommendation="Set allowPrivilegeEscalation: false in the security context.",
            target="docker-compose.yml",
            category="Kubernetes Security",
        ),
    ]


# ── Dockerfile findings ──────────────────────────────────────────────────────

def _demo_dockerfile_findings() -> list:
    return [
        DockerfileFinding(
            rule_id="DF-001",
            title="Use of ':latest' or untagged image",
            severity=Severity.MEDIUM,
            description="FROM nginx:latest — unpinned tag can introduce regressions and new CVEs silently.",
            recommendation="Pin to a specific version digest: FROM nginx:1.25.3@sha256:...",
            line_number=1,
            line_content="FROM nginx:latest",
        ),
        DockerfileFinding(
            rule_id="DF-008",
            title="Missing USER instruction",
            severity=Severity.HIGH,
            description="No USER instruction found. Container will run as root by default.",
            recommendation="Add a non-root user: RUN useradd -r appuser && USER appuser",
            line_number=None,
            line_content="",
        ),
        DockerfileFinding(
            rule_id="DF-003",
            title="Potential secret in ENV instruction",
            severity=Severity.HIGH,
            description="ENV DB_PASSWORD=... — sensitive values embedded in image layers are visible in history.",
            recommendation="Use Docker secrets or inject secrets at runtime via environment injection.",
            line_number=8,
            line_content="ENV DB_PASSWORD=s3cr3t",
        ),
    ]


# ── Remediation ──────────────────────────────────────────────────────────────

def _demo_remediation(vulns, misconfigs, df_findings) -> list:
    items = []
    priority_map = {Severity.CRITICAL: 1, Severity.HIGH: 2, Severity.MEDIUM: 3, Severity.LOW: 4, Severity.UNKNOWN: 5}

    for v in vulns:
        has_fix = v.fixed_version and v.fixed_version != "No fix available"
        items.append(RemediationItem(
            finding_id=v.vuln_id,
            package_or_target=f"{v.package_name} (target: {v.target})",
            severity=v.severity,
            what_is_wrong=f"{v.vuln_id} affects {v.package_name} {v.installed_version}. {v.title}",
            why_it_matters=_impact(v.severity),
            how_to_fix=(
                f"Upgrade {v.package_name} from {v.installed_version} to {v.fixed_version} or later."
                if has_fix else
                f"No upstream fix available for {v.package_name}. Monitor upstream and apply mitigations."
            ),
            priority=priority_map.get(v.severity, 5),
        ))

    for mc in misconfigs:
        items.append(RemediationItem(
            finding_id=mc.config_id,
            package_or_target=mc.target,
            severity=mc.severity,
            what_is_wrong=f"{mc.config_id}: {mc.title}. {mc.description}",
            why_it_matters=_impact(mc.severity),
            how_to_fix=mc.recommendation,
            priority=priority_map.get(mc.severity, 5),
        ))

    for df in df_findings:
        items.append(RemediationItem(
            finding_id=df.rule_id,
            package_or_target=f"Dockerfile{f' (line {df.line_number})' if df.line_number else ''}",
            severity=df.severity,
            what_is_wrong=f"{df.rule_id}: {df.title}. {df.description}",
            why_it_matters=_impact(df.severity),
            how_to_fix=df.recommendation,
            priority=priority_map.get(df.severity, 5),
        ))

    items.sort(key=lambda r: r.priority)
    return items


def _impact(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "Critical — immediate exploitation risk. Remote code execution or full system compromise possible.",
        Severity.HIGH: "High — significant risk. May allow privilege escalation, data exfiltration, or service disruption.",
        Severity.MEDIUM: "Medium — moderate risk. Can be chained with other vulnerabilities under specific conditions.",
        Severity.LOW: "Low — minor risk. Address as part of routine security hygiene to reduce attack surface.",
        Severity.UNKNOWN: "Unknown severity — manually assess the risk in your environment.",
    }.get(severity, "Review and remediate this finding.")
