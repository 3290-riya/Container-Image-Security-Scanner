"""FastAPI route definitions for the Container Image Security Scanner web UI."""

from __future__ import annotations

import logging
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from web.models import ScanRequest, ScanStatus, UploadType
from web.scanner_service import (
    check_trivy_available,
    get_scan,
    list_scans,
    submit_scan,
    submit_demo_scan,
)
from web.upload import UploadError

logger = logging.getLogger(__name__)

router = APIRouter()

# Templates location
_TEMPLATES_DIR = Path(__file__).parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ─────────────────────────────────────────────────────────────────────────────
# Helper: render error page
# ─────────────────────────────────────────────────────────────────────────────

def _error_page(request: Request, title: str, message: str, status_code: int = 400) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        {"error_title": title, "error_message": message},
        status_code=status_code,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    recent_scans = list_scans()[:10]
    trivy_ok = check_trivy_available()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"recent_scans": recent_scans, "trivy_available": trivy_ok},
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /health
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    trivy_ok = check_trivy_available()
    return JSONResponse({
        "status": "healthy" if trivy_ok else "degraded",
        "scanner": "available",
        "trivy": "available" if trivy_ok else "unavailable (demo mode active)",
        "demo_mode": not trivy_ok,
    })


# ─────────────────────────────────────────────────────────────────────────────
# POST /scan  – submit a new scan
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan")
async def start_scan(
    request: Request,
    file: UploadFile = File(...),
    severities: str = Form(default="CRITICAL,HIGH,MEDIUM,LOW"),
    fail_on: str = Form(default="CRITICAL,HIGH"),
    report_format: str = Form(default="all"),
):
    # Read the upload
    try:
        content = await file.read()
    except Exception as exc:
        return _error_page(request, "Upload Error", f"Failed to read uploaded file: {exc}")

    # Validate synchronously before spawning background thread
    if not content:
        return _error_page(request, "Upload Error", "Uploaded file is empty.")

    original_filename = file.filename or "upload"

    # Parse form values
    sev_list = [s.strip().upper() for s in severities.split(",") if s.strip()]
    fail_list = [s.strip().upper() for s in fail_on.split(",") if s.strip()]
    valid_sevs = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    sev_list = [s for s in sev_list if s in valid_sevs] or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    fail_list = [s for s in fail_list if s in valid_sevs] or ["CRITICAL", "HIGH"]
    if report_format not in ("json", "html", "all"):
        report_format = "all"

    scan_req = ScanRequest(
        original_filename=original_filename,
        severities=sev_list,
        fail_on=fail_list,
        report_format=report_format,
    )

    try:
        web_result = submit_scan(scan_req, content)
    except UploadError as exc:
        return _error_page(request, "Upload Validation Failed", str(exc))
    except RuntimeError as exc:
        return _error_page(request, "Scan Limit Reached", str(exc), status_code=429)
    except Exception as exc:
        logger.exception("Unexpected error submitting scan")
        return _error_page(
            request, "Internal Error",
            "An unexpected error occurred. See server logs for details.",
            status_code=500,
        )

    # Redirect to polling page
    return RedirectResponse(url=f"/scan/{web_result.scan_id}", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# POST /scan/demo  – submit a demo scan (no file required)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/demo")
async def start_demo_scan(
    request: Request,
    label: str = Form(default="nginx:1.24.0"),
):
    """Start a demo scan with pre-built sample data (Trivy not required)."""
    scan_req = ScanRequest(
        original_filename=label or "nginx:1.24.0",
        severities=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        fail_on=["CRITICAL", "HIGH"],
        report_format="all",
        upload_type=UploadType.IMAGE_ARCHIVE,
    )
    try:
        web_result = submit_demo_scan(scan_req)
    except Exception as exc:
        logger.exception("Error starting demo scan")
        return _error_page(request, "Demo Scan Error", str(exc), status_code=500)

    return RedirectResponse(url=f"/scan/{web_result.scan_id}", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}  – status / results page
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        return _error_page(request, "Scan Not Found", f"Scan ID '{scan_id}' not found.", 404)

    if web_result.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        return templates.TemplateResponse(
            request,
            "scanning.html",
            {"scan": web_result},
        )

    if web_result.status == ScanStatus.FAILED:
        return _error_page(
            request,
            "Scan Failed",
            web_result.error_message or "The scan failed for an unknown reason.",
        )

    # Complete – show results dashboard
    result = web_result.scan_result
    score = result.security_score if result else None
    summary = result.summary if result else None

    # Build severity-grouped vulnerabilities
    crit_vulns = [v for v in result.vulnerabilities if v.severity.value == "CRITICAL"] if result else []
    high_vulns = [v for v in result.vulnerabilities if v.severity.value == "HIGH"] if result else []
    med_vulns = [v for v in result.vulnerabilities if v.severity.value == "MEDIUM"] if result else []
    low_vulns = [v for v in result.vulnerabilities if v.severity.value == "LOW"] if result else []

    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "scan": web_result,
            "result": result,
            "score": score,
            "summary": summary,
            "crit_vulns": crit_vulns,
            "high_vulns": high_vulns,
            "med_vulns": med_vulns,
            "low_vulns": low_vulns,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/status  – JSON status poll
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return JSONResponse({
        "scan_id": scan_id,
        "status": web_result.status.value,
        "current_step": web_result.progress.current_step,
        "progress": {
            "upload_validated": web_result.progress.upload_validated,
            "target_prepared": web_result.progress.target_prepared,
            "trivy_running": web_result.progress.trivy_running,
            "parsing_complete": web_result.progress.parsing_complete,
            "scoring_complete": web_result.progress.scoring_complete,
            "report_generated": web_result.progress.report_generated,
        },
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/json  – JSON API result
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/json")
async def scan_json(scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    if web_result.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=409, detail="Scan not yet complete.")
    return JSONResponse(web_result.to_api_dict())


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/report  – download HTML report
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/report")
async def download_html_report(scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if web_result.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=409, detail="Scan not yet complete.")
    if not web_result.html_report_path:
        raise HTTPException(status_code=404, detail="HTML report not found.")
    path = Path(web_result.html_report_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="HTML report not found.")
    return FileResponse(
        path=str(path),
        media_type="text/html",
        filename=f"scan-report-{scan_id[:8]}.html",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/report.json  – download scan.json
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/report.json")
async def download_json_report(scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if web_result.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=409, detail="Scan not yet complete.")
    if not web_result.json_report_path:
        raise HTTPException(status_code=404, detail="JSON report not found.")
    path = Path(web_result.json_report_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="JSON report not found.")
    return FileResponse(
        path=str(path),
        media_type="application/json",
        filename=f"scan-{scan_id[:8]}.json",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /scan/{scan_id}/vulnerabilities.json
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/vulnerabilities.json")
async def download_vuln_report(scan_id: str):
    web_result = get_scan(scan_id)
    if web_result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if web_result.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=409, detail="Scan not yet complete.")
    if not web_result.vuln_report_path:
        raise HTTPException(status_code=404, detail="Vulnerability report not found.")
    path = Path(web_result.vuln_report_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Vulnerability report not found.")
    return FileResponse(
        path=str(path),
        media_type="application/json",
        filename=f"vulnerabilities-{scan_id[:8]}.json",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/history  – JSON scan history
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/history")
async def scan_history():
    """Return a JSON list of all scans (summary only, no full vulnerability details)."""
    scans = list_scans()
    items = []
    for s in scans:
        result = s.scan_result
        summary = {}
        score_info = {}
        if result:
            summary = result.summary.to_dict()
            if result.security_score:
                score_info = result.security_score.to_dict()
        items.append({
            "scan_id": s.scan_id,
            "status": s.status.value,
            "filename": s.request.original_filename,
            "upload_type": s.request.upload_type.value,
            "created_at": s.request.created_at.isoformat(),
            "duration_seconds": s.duration_seconds,
            "summary": summary,
            "security_score": score_info,
            "gate_passed": result.gate_passed if result else None,
            "reports": {
                "html": f"/scan/{s.scan_id}/report" if s.html_report_path else None,
                "json": f"/scan/{s.scan_id}/report.json" if s.json_report_path else None,
            },
        })
    return JSONResponse({"scans": items, "total": len(items)})


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/demo/data  – demo JSON result (for API exploration)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/demo/data")
async def demo_data():
    """Return a demo ScanResult as JSON (for API exploration, no scan needed)."""
    from web.demo_data import build_demo_scan_result
    result = build_demo_scan_result()
    return JSONResponse({
        "note": "This is demo/sample data. Run a real scan to get actual vulnerability data.",
        "scan": result.to_dict(),
    })
