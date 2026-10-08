"""Main scan runner – orchestrates all scanning phases."""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

from container_scanner.config import ConfigError, load_config
from container_scanner.models import Severity, ScanResult, VulnerabilitySummary
from container_scanner.scanner.trivy import TrivyError, TrivyRunner
from container_scanner.scanner.parser import TrivyParseError, parse_trivy_image_json
from container_scanner.scanner.dockerfile import DockerfileAnalyzer
from container_scanner.scanner.docker import (
    check_docker_available,
    image_exists_locally,
    pull_image,
    DockerError,
)
from container_scanner.security.scoring import calculate_score
from container_scanner.security.remediation import generate_remediation
from container_scanner.security.policy import evaluate_gate
from container_scanner.reports.json_report import write_json_report
from container_scanner.reports.html_report import write_html_report


def run_scan(
    image: Optional[str] = None,
    dockerfile: Optional[str] = None,
    severities: Optional[List[str]] = None,
    fail_on: Optional[List[str]] = None,
    config_path: Optional[str] = None,
    fmt: str = "all",
    output_dir: Optional[str] = None,
    verbose: bool = False,
) -> int:
    """Orchestrate a full scan. Returns exit code (0, 1, or 2)."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        return 2

    # CLI overrides take precedence over config
    active_severities = severities or config.severities
    active_fail_on = fail_on if fail_on is not None else (config.gate_fail_on if config.gate_enabled else [])
    active_output_dir = output_dir or config.output_directory

    start_time = time.monotonic()
    scan_time = datetime.now(timezone.utc)

    result = ScanResult(
        image=image or "(dockerfile only)",
        scan_time=scan_time,
        gate_fail_on=active_fail_on,
    )

    # ------------------------------------------------------------------ #
    # Phase 1 – Image scanning via Trivy                                   #
    # ------------------------------------------------------------------ #
    if image:
        if verbose:
            print(f"[INFO] Scanning image: {image}")

        # Check Docker availability and ensure image is present
        docker_available = check_docker_available()
        if docker_available and not image_exists_locally(image):
            if verbose:
                print(f"[INFO] Image not found locally, pulling: {image}")
            try:
                pull_image(image, timeout=config.timeout)
            except DockerError as exc:
                print(f"[WARN] Could not pull image (Trivy may still scan from registry): {exc}", file=sys.stderr)
        elif not docker_available and verbose:
            print("[INFO] Docker daemon not available; Trivy will attempt to pull the image directly.")

        trivy = TrivyRunner(config)

        # Get Trivy version
        try:
            result.trivy_version = trivy.version()
            if verbose:
                print(f"[INFO] Trivy version: {result.trivy_version}")
        except TrivyError:
            result.trivy_version = "unknown"

        # Vulnerability scan
        try:
            raw_json = trivy.scan_image(image, severities=active_severities)
            vulns, misconfigs_from_vuln_scan = parse_trivy_image_json(raw_json)
            result.vulnerabilities.extend(vulns)
            result.misconfigurations.extend(misconfigs_from_vuln_scan)
            if verbose:
                print(f"[INFO] Found {len(vulns)} vulnerabilities.")
        except TrivyError as exc:
            print(f"[ERROR] Trivy scan failed: {exc}", file=sys.stderr)
            return 2
        except TrivyParseError as exc:
            print(f"[ERROR] Failed to parse Trivy output: {exc}", file=sys.stderr)
            return 2

        # Misconfiguration scan (separate Trivy pass)
        try:
            raw_config_json = trivy.scan_config(image, severities=active_severities)
            _, misconfigs = parse_trivy_image_json(raw_config_json)
            # Avoid duplicates (some versions combine results)
            existing_ids = {m.config_id for m in result.misconfigurations}
            for mc in misconfigs:
                if mc.config_id not in existing_ids:
                    result.misconfigurations.append(mc)
                    existing_ids.add(mc.config_id)
            if verbose:
                print(f"[INFO] Found {len(result.misconfigurations)} misconfigurations.")
        except (TrivyError, TrivyParseError) as exc:
            # Misconfiguration scan is best-effort; don't abort
            if verbose:
                print(f"[WARN] Misconfiguration scan failed (non-fatal): {exc}", file=sys.stderr)

    # ------------------------------------------------------------------ #
    # Phase 2 – Dockerfile analysis                                        #
    # ------------------------------------------------------------------ #
    if dockerfile:
        if verbose:
            print(f"[INFO] Analysing Dockerfile: {dockerfile}")
        analyzer = DockerfileAnalyzer()
        try:
            df_findings = analyzer.analyse(dockerfile)
            result.dockerfile_findings.extend(df_findings)
            if verbose:
                print(f"[INFO] Found {len(df_findings)} Dockerfile issues.")
        except FileNotFoundError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"[ERROR] Cannot read Dockerfile: {exc}", file=sys.stderr)
            return 2

    # ------------------------------------------------------------------ #
    # Phase 3 – Summary, scoring, remediation                              #
    # ------------------------------------------------------------------ #
    result.summary = _build_summary(result)
    result.security_score = calculate_score(
        result.vulnerabilities,
        result.misconfigurations,
        result.dockerfile_findings,
    )
    result.remediation_items = generate_remediation(
        result.vulnerabilities,
        result.misconfigurations,
        result.dockerfile_findings,
    )
    result.scan_duration_seconds = time.monotonic() - start_time

    # ------------------------------------------------------------------ #
    # Phase 4 – Security gate evaluation                                   #
    # ------------------------------------------------------------------ #
    gate_passed, violations = evaluate_gate(
        active_fail_on,
        result.vulnerabilities,
        result.misconfigurations,
        result.dockerfile_findings,
    )
    result.gate_passed = gate_passed

    # ------------------------------------------------------------------ #
    # Phase 5 – Console output                                             #
    # ------------------------------------------------------------------ #
    _print_summary(result, violations, verbose)

    # ------------------------------------------------------------------ #
    # Phase 6 – Report generation                                          #
    # ------------------------------------------------------------------ #
    try:
        if fmt in ("json", "all"):
            json_path = write_json_report(result, active_output_dir)
            print(f"[REPORT] JSON report: {json_path}")
        if fmt in ("html", "all"):
            html_path = write_html_report(result, active_output_dir)
            print(f"[REPORT] HTML report: {html_path}")
    except OSError as exc:
        print(f"[ERROR] Failed to write reports: {exc}", file=sys.stderr)
        return 2

    # ------------------------------------------------------------------ #
    # Exit code                                                            #
    # ------------------------------------------------------------------ #
    if not gate_passed:
        print("\n[GATE] Security gate FAILED.", file=sys.stderr)
        return 1

    print("\n[GATE] Security gate PASSED.")
    return 0


def _build_summary(result: ScanResult) -> VulnerabilitySummary:
    s = VulnerabilitySummary()
    for v in result.vulnerabilities:
        s.total += 1
        if v.severity == Severity.CRITICAL:
            s.critical += 1
        elif v.severity == Severity.HIGH:
            s.high += 1
        elif v.severity == Severity.MEDIUM:
            s.medium += 1
        elif v.severity == Severity.LOW:
            s.low += 1
        else:
            s.unknown += 1
    return s


def _print_summary(result: ScanResult, violations: list, verbose: bool) -> None:
    s = result.summary
    score = result.security_score
    sep = "=" * 60

    score_str = f"{score.score}/100  [Risk: {score.risk_level}]" if score else "N/A"

    print(f"\n{sep}")
    print(f"  Container Image Security Scanner")
    print(f"{sep}")
    print(f"  Image          : {result.image}")
    print(f"  Scan Time      : {result.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Duration       : {result.scan_duration_seconds:.1f}s")
    print(f"{sep}")
    print(f"  Security Score : {score_str}")
    print(f"{sep}")
    print(f"  Vulnerabilities: {s.total} total")
    print(f"    CRITICAL : {s.critical}")
    print(f"    HIGH     : {s.high}")
    print(f"    MEDIUM   : {s.medium}")
    print(f"    LOW      : {s.low}")
    print(f"    UNKNOWN  : {s.unknown}")
    print(f"  Misconfigs     : {len(result.misconfigurations)}")
    print(f"  Dockerfile     : {len(result.dockerfile_findings)} findings")
    print(f"{sep}")

    if violations:
        print(f"  Security Gate  : FAILED")
        for v in violations:
            print(f"    [FAIL] {v}")
    else:
        print(f"  Security Gate  : PASSED")

    print(f"{sep}\n")

    if verbose and result.vulnerabilities:
        print("  Top findings:")
        for vuln in sorted(result.vulnerabilities, key=lambda v: v.severity, reverse=True)[:10]:
            print(f"    [{vuln.severity.value:<8}] {vuln.vuln_id} - {vuln.package_name} {vuln.installed_version} -> {vuln.fixed_version}")
        print()
