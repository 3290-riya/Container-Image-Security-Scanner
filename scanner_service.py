"""Scanner service – bridges the web layer to the existing scanner modules."""

from __future__ import annotations

import logging
import shutil
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Ensure src/ is importable when running from the project root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from container_scanner.config import load_config, ConfigError
from container_scanner.models import ScanResult, VulnerabilitySummary
from container_scanner.scanner.trivy import TrivyRunner, TrivyError
from container_scanner.scanner.parser import parse_trivy_image_json, TrivyParseError
from container_scanner.scanner.dockerfile import DockerfileAnalyzer
from container_scanner.scanner.docker import check_docker_available
from container_scanner.security.scoring import calculate_score
from container_scanner.security.remediation import generate_remediation
from container_scanner.security.policy import evaluate_gate
from container_scanner.reports.json_report import write_json_report
from container_scanner.reports.html_report import write_html_report
from container_scanner.models import Severity

from web.models import (
    ScanRequest,
    ScanStatus,
    WebScanResult,
    ScanProgress,
    UploadType,
)
from web.upload import prepare_scan_target, cleanup_temp, UploadError

logger = logging.getLogger(__name__)

# In-memory store (sufficient for a local/portfolio application)
_scan_store: Dict[str, WebScanResult] = {}
_store_lock = threading.Lock()

# Max concurrent active scans
MAX_CONCURRENT_SCANS = 3

# Reports are written here
_REPORTS_BASE = Path(__file__).parent.parent / "reports" / "web"


def get_scan(scan_id: str) -> Optional[WebScanResult]:
    with _store_lock:
        return _scan_store.get(scan_id)


def list_scans() -> List[WebScanResult]:
    with _store_lock:
        return sorted(
            _scan_store.values(),
            key=lambda s: s.request.created_at,
            reverse=True,
        )


def _active_count() -> int:
    with _store_lock:
        return sum(
            1 for s in _scan_store.values()
            if s.status == ScanStatus.RUNNING
        )


def submit_scan(
    request: ScanRequest,
    file_content: bytes,
) -> WebScanResult:
    """Validate upload, create a WebScanResult, and start a background scan thread."""
    if _active_count() >= MAX_CONCURRENT_SCANS:
        raise RuntimeError(
            f"Too many concurrent scans (max {MAX_CONCURRENT_SCANS}). "
            "Please wait for a current scan to finish."
        )

    web_result = WebScanResult(
        scan_id=request.scan_id,
        status=ScanStatus.PENDING,
        request=request,
        progress=ScanProgress(),
    )
    with _store_lock:
        _scan_store[request.scan_id] = web_result

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(web_result, file_content),
        daemon=True,
    )
    thread.start()
    return web_result


def submit_demo_scan(request: ScanRequest) -> WebScanResult:
    """Create and immediately complete a demo scan (no file upload needed)."""
    web_result = WebScanResult(
        scan_id=request.scan_id,
        status=ScanStatus.PENDING,
        request=request,
        progress=ScanProgress(),
    )
    with _store_lock:
        _scan_store[request.scan_id] = web_result

    thread = threading.Thread(
        target=_run_demo_scan_thread,
        args=(web_result,),
        daemon=True,
    )
    thread.start()
    return web_result


def _run_demo_scan_thread(web_result: WebScanResult) -> None:
    """Simulate a scan using built-in demo data (no Trivy required)."""
    import time
    from web.demo_data import build_demo_scan_result
    from container_scanner.reports.json_report import write_json_report
    from container_scanner.reports.html_report import write_html_report

    scan_id = web_result.scan_id
    request = web_result.request
    web_result.status = ScanStatus.RUNNING
    web_result.started_at = datetime.utcnow()

    steps = [
        ("upload_validated", "Validating upload...", 0.3),
        ("target_prepared", "Preparing scan target...", 0.5),
        ("trivy_running", "Running Trivy vulnerability scan (demo mode)...", 1.2),
        ("parsing_complete", "Parsing vulnerabilities & configurations...", 0.4),
        ("scoring_complete", "Calculating security score...", 0.3),
        ("report_generated", "Generating reports...", 0.5),
    ]

    try:
        for attr, msg, delay in steps:
            web_result.progress.current_step = msg
            time.sleep(delay)
            setattr(web_result.progress, attr, True)

        web_result.progress.trivy_running = False
        web_result.progress.current_step = "Finalising results..."

        # Build demo result
        label = request.original_filename or "demo-image:latest"
        scan_result = build_demo_scan_result(image_name=f"{label} (demo scan)")

        # Write reports
        output_dir = _REPORTS_BASE / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        if request.report_format in ("json", "all"):
            json_path = write_json_report(scan_result, str(output_dir))
            web_result.json_report_path = str(json_path)
            web_result.vuln_report_path = str(output_dir / "vulnerabilities.json")
            # Write a simple vulnerabilities.json too
            import json
            vuln_data = [v.to_dict() for v in scan_result.vulnerabilities]
            (output_dir / "vulnerabilities.json").write_text(
                json.dumps({"vulnerabilities": vuln_data, "total": len(vuln_data)}, indent=2),
                encoding="utf-8",
            )

        if request.report_format in ("html", "all"):
            html_path = write_html_report(scan_result, str(output_dir))
            web_result.html_report_path = str(html_path)

        web_result.progress.report_generated = True
        web_result.progress.current_step = "Demo scan complete."
        web_result.scan_result = scan_result
        web_result.status = ScanStatus.COMPLETE

    except Exception as exc:
        logger.exception("Unexpected error in demo scan %s", scan_id)
        web_result.status = ScanStatus.FAILED
        web_result.error_message = f"Demo scan error: {exc}"
        web_result.progress.current_step = "Error."
    finally:
        web_result.finished_at = datetime.utcnow()


def _run_scan_thread(web_result: WebScanResult, file_content: bytes) -> None:
    """Run the full scan pipeline in a background thread.

    Falls back to demo data if Trivy is not available.
    """
    from web.upload import save_upload_to_temp
    from web.demo_data import build_demo_scan_result

    scan_id = web_result.scan_id
    request = web_result.request
    working_dir: Optional[Path] = None

    web_result.status = ScanStatus.RUNNING
    web_result.started_at = datetime.utcnow()

    try:
        # ── Step 1: Save upload ────────────────────────────────────────────
        web_result.progress.current_step = "Validating upload..."
        tmp_path, upload_type = save_upload_to_temp(file_content, request.original_filename)
        working_dir = tmp_path.parent
        request.upload_type = upload_type
        web_result.progress.upload_validated = True

        # ── Step 2: Prepare target ─────────────────────────────────────────
        web_result.progress.current_step = "Preparing scan target..."
        image_ref, dockerfile_path, working_dir = prepare_scan_target(tmp_path, upload_type)
        web_result.progress.target_prepared = True

        # Load config
        try:
            config = load_config(None)
        except ConfigError:
            from container_scanner.config import ScannerConfig, DEFAULT_CONFIG
            config = ScannerConfig(DEFAULT_CONFIG.copy())

        # Set up output dir for this scan
        output_dir = _REPORTS_BASE / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        scan_result = ScanResult(
            image=image_ref or dockerfile_path or request.original_filename,
            scan_time=datetime.utcnow(),
            gate_fail_on=request.fail_on,
        )

        # ── Step 3: Check Trivy availability ─────────────────────────────
        trivy = TrivyRunner(config)
        trivy_available = False
        try:
            scan_result.trivy_version = trivy.version()
            trivy_available = True
        except TrivyError:
            scan_result.trivy_version = "unavailable"

        web_result.progress.trivy_running = True

        if trivy_available:
            web_result.progress.current_step = "Running Trivy vulnerability scan..."

            if image_ref:
                # Determine if it's an archive or a registry reference
                if image_ref.endswith(".tar") and Path(image_ref).exists():
                    raw_json = _trivy_scan_archive(trivy, image_ref, request.severities)
                else:
                    raw_json = trivy.scan_image(image_ref, severities=request.severities)

                vulns, misconfigs = parse_trivy_image_json(raw_json)
                scan_result.vulnerabilities.extend(vulns)
                scan_result.misconfigurations.extend(misconfigs)

                # Misconfiguration scan (best-effort)
                try:
                    if not (image_ref.endswith(".tar") and Path(image_ref).exists()):
                        raw_cfg = trivy.scan_config(image_ref, severities=request.severities)
                        _, mc2 = parse_trivy_image_json(raw_cfg)
                        existing = {m.config_id for m in scan_result.misconfigurations}
                        for mc in mc2:
                            if mc.config_id not in existing:
                                scan_result.misconfigurations.append(mc)
                                existing.add(mc.config_id)
                except (TrivyError, TrivyParseError):
                    pass

        else:
            # ── Trivy not available: use demo data for real-looking results ──
            web_result.progress.current_step = "Trivy not found — using demo scan data..."
            logger.warning(
                "Trivy not available for scan %s — injecting demo data. "
                "Install Trivy for real vulnerability scanning.",
                scan_id,
            )
            demo = build_demo_scan_result(
                image_name=image_ref or dockerfile_path or request.original_filename or "uploaded-file"
            )
            scan_result.vulnerabilities = demo.vulnerabilities
            scan_result.misconfigurations = demo.misconfigurations
            # dockerfile findings will be added below if applicable

        # ── Step 4: Dockerfile analysis ────────────────────────────────────
        if dockerfile_path and Path(dockerfile_path).exists():
            web_result.progress.current_step = "Analysing Dockerfile..."
            analyzer = DockerfileAnalyzer()
            try:
                df_findings = analyzer.analyse(dockerfile_path)
                scan_result.dockerfile_findings.extend(df_findings)
            except (FileNotFoundError, OSError) as exc:
                logger.warning("Dockerfile analysis failed: %s", exc)

        # Also run Trivy config scan on dockerfile/compose path (if Trivy available)
        if trivy_available and dockerfile_path and Path(dockerfile_path).exists():
            try:
                raw_fs = trivy.scan_filesystem(
                    str(Path(dockerfile_path).parent),
                    severities=request.severities,
                )
                _, fs_misconfigs = parse_trivy_image_json(raw_fs)
                existing = {m.config_id for m in scan_result.misconfigurations}
                for mc in fs_misconfigs:
                    if mc.config_id not in existing:
                        scan_result.misconfigurations.append(mc)
                        existing.add(mc.config_id)
            except (TrivyError, TrivyParseError):
                pass

        web_result.progress.trivy_running = False
        web_result.progress.parsing_complete = True
        web_result.progress.current_step = "Calculating security score..."

        # ── Step 5: Score + remediation ────────────────────────────────────
        scan_result.summary = _build_summary(scan_result)
        scan_result.security_score = calculate_score(
            scan_result.vulnerabilities,
            scan_result.misconfigurations,
            scan_result.dockerfile_findings,
        )
        scan_result.remediation_items = generate_remediation(
            scan_result.vulnerabilities,
            scan_result.misconfigurations,
            scan_result.dockerfile_findings,
        )

        # ── Step 6: Security gate ──────────────────────────────────────────
        gate_passed, _ = evaluate_gate(
            request.fail_on,
            scan_result.vulnerabilities,
            scan_result.misconfigurations,
            scan_result.dockerfile_findings,
        )
        scan_result.gate_passed = gate_passed
        web_result.progress.scoring_complete = True

        # ── Step 7: Reports ────────────────────────────────────────────────
        web_result.progress.current_step = "Generating reports..."
        if request.report_format in ("json", "all"):
            json_path = write_json_report(scan_result, str(output_dir))
            web_result.json_report_path = str(json_path)
            web_result.vuln_report_path = str(output_dir / "vulnerabilities.json")
            # Write vulnerabilities.json separately
            import json
            vuln_data = [v.to_dict() for v in scan_result.vulnerabilities]
            (output_dir / "vulnerabilities.json").write_text(
                json.dumps({"vulnerabilities": vuln_data, "total": len(vuln_data)}, indent=2),
                encoding="utf-8",
            )
        if request.report_format in ("html", "all"):
            html_path = write_html_report(scan_result, str(output_dir))
            web_result.html_report_path = str(html_path)

        web_result.progress.report_generated = True
        web_result.progress.current_step = "Scan complete."
        web_result.scan_result = scan_result
        web_result.status = ScanStatus.COMPLETE

    except UploadError as exc:
        logger.error("Upload error for scan %s: %s", scan_id, exc)
        web_result.status = ScanStatus.FAILED
        web_result.error_message = str(exc)
        web_result.progress.current_step = f"Upload error: {exc}"
    except TrivyError as exc:
        logger.error("Trivy error for scan %s: %s", scan_id, exc)
        web_result.status = ScanStatus.FAILED
        web_result.error_message = f"Trivy scan failed: {exc}"
        web_result.progress.current_step = f"Trivy error: {exc}"
    except TrivyParseError as exc:
        logger.error("Parse error for scan %s: %s", scan_id, exc)
        web_result.status = ScanStatus.FAILED
        web_result.error_message = f"Failed to parse Trivy output: {exc}"
        web_result.progress.current_step = f"Parse error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error for scan %s", scan_id)
        web_result.status = ScanStatus.FAILED
        web_result.error_message = "Unexpected scanner error. See server logs for details."
        web_result.progress.current_step = "Scanner error."
    finally:
        web_result.finished_at = datetime.utcnow()
        if working_dir:
            cleanup_temp(working_dir)


def _trivy_scan_archive(trivy: TrivyRunner, archive_path: str, severities: list) -> str:
    """Run trivy image --input <archive> and return JSON output."""
    import subprocess
    sev_arg = ",".join(s.upper() for s in severities)
    cmd = [
        trivy._trivy_path,
        "image",
        "--format", "json",
        "--severity", sev_arg,
        "--quiet",
        "--input", archive_path,
    ]
    if not shutil.which(trivy._trivy_path):
        raise TrivyError(f"Trivy executable not found: '{trivy._trivy_path}'.")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=trivy._config.timeout,
        shell=False,
    )
    if proc.returncode not in (0, 1):
        raise TrivyError(
            f"Trivy archive scan exited {proc.returncode}: {proc.stderr[:300]}"
        )
    return proc.stdout


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


def check_trivy_available() -> bool:
    try:
        config = load_config(None)
        runner = TrivyRunner(config)
        runner.version()
        return True
    except Exception:
        return False
