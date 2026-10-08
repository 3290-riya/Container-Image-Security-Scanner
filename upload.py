"""Secure file upload handler and scan orchestration service."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from web.models import UploadType

logger = logging.getLogger(__name__)

# Upload security limits
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 512 MB
ALLOWED_EXTENSIONS = {".tar", ".zip", ".yml", ".yaml", "dockerfile", ".dockerfile", ".txt"}
MAX_ZIP_MEMBERS = 1000
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024  # 256 MB

# Map lowercase filenames / extensions to upload types
_EXT_TYPE_MAP = {
    ".tar": UploadType.IMAGE_ARCHIVE,
    ".zip": UploadType.PROJECT_ZIP,
    ".yml": UploadType.COMPOSE,
    ".yaml": UploadType.COMPOSE,
}

_NAME_TYPE_MAP = {
    "dockerfile": UploadType.DOCKERFILE,
}


class UploadError(Exception):
    """Raised for invalid / unsafe uploads."""


def detect_upload_type(filename: str) -> UploadType:
    """Infer the upload type from the (sanitized) filename."""
    name = Path(filename).name.lower()
    ext = Path(filename).suffix.lower()
    if name in _NAME_TYPE_MAP:
        return _NAME_TYPE_MAP[name]
    if name.endswith(".dockerfile"):
        return UploadType.DOCKERFILE
    if ext in _EXT_TYPE_MAP:
        return _EXT_TYPE_MAP[ext]
    return UploadType.UNKNOWN


def sanitize_filename(filename: str) -> str:
    """Return a safe filename, stripping directory components and dangerous chars."""
    # Take only the final path component
    name = Path(filename).name
    # Replace any character that is not alphanumeric, dot, hyphen, or underscore
    import re
    safe = re.sub(r"[^\w.\-]", "_", name)
    # Collapse leading dots (hidden files)
    safe = safe.lstrip(".")
    # Truncate to a reasonable length
    if len(safe) > 128:
        safe = safe[:128]
    return safe or "upload"


def save_upload_to_temp(
    content: bytes,
    original_filename: str,
) -> Tuple[Path, UploadType]:
    """
    Save uploaded bytes to a secure temporary directory.

    Returns (temp_file_path, upload_type).
    Raises UploadError for invalid inputs.
    """
    if len(content) == 0:
        raise UploadError("Uploaded file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise UploadError(
            f"File too large: {len(content):,} bytes. "
            f"Maximum allowed: {MAX_UPLOAD_BYTES // (1024*1024)} MB."
        )

    safe_name = sanitize_filename(original_filename)
    upload_type = detect_upload_type(safe_name)

    if upload_type == UploadType.UNKNOWN:
        ext = Path(safe_name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS and safe_name.lower() not in ("dockerfile",):
            raise UploadError(
                f"Unsupported file type '{ext or safe_name}'. "
                f"Allowed: Dockerfile, .tar, .zip, .yml, .yaml"
            )

    # Create a fresh isolated temp directory for this upload
    tmp_dir = Path(tempfile.mkdtemp(prefix="ciss_upload_"))
    # Use a random hex token as filename to prevent any path-based attacks
    token = uuid.uuid4().hex
    ext = Path(safe_name).suffix.lower() or ""
    tmp_path = tmp_dir / f"{token}{ext}"

    try:
        tmp_path.write_bytes(content)
    except OSError as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise UploadError(f"Failed to save uploaded file: {exc}") from exc

    return tmp_path, upload_type


def prepare_scan_target(
    tmp_path: Path,
    upload_type: UploadType,
) -> Tuple[Optional[str], Optional[str], Path]:
    """
    Prepare the scan target from the uploaded file.

    Returns (image_ref, dockerfile_path, working_dir).
      - image_ref: path to image archive (for Trivy image --input) or None
      - dockerfile_path: path to Dockerfile for analysis, or None
      - working_dir: temp dir owning the artefacts (caller must clean up)
    """
    working_dir = tmp_path.parent

    if upload_type == UploadType.IMAGE_ARCHIVE:
        # Pass the .tar directly to Trivy via --input
        return str(tmp_path), None, working_dir

    if upload_type == UploadType.DOCKERFILE:
        return None, str(tmp_path), working_dir

    if upload_type == UploadType.COMPOSE:
        # Trivy can scan a directory or a config file for misconfigs
        return None, str(tmp_path), working_dir

    if upload_type == UploadType.PROJECT_ZIP:
        extract_dir = working_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        _safe_extract_zip(tmp_path, extract_dir)

        # Find a Dockerfile inside the ZIP (first match wins)
        dockerfile_path: Optional[str] = None
        for candidate in extract_dir.rglob("Dockerfile"):
            dockerfile_path = str(candidate)
            break

        return None, dockerfile_path, working_dir

    raise UploadError(f"Cannot prepare scan target for upload type: {upload_type}")


def _safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    """
    Extract a ZIP archive safely, preventing ZIP slip (path traversal).
    Raises UploadError on suspicious entries.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise UploadError(
                    f"ZIP contains too many files ({len(members)}). "
                    f"Maximum: {MAX_ZIP_MEMBERS}."
                )

            total_size = sum(m.file_size for m in members)
            if total_size > MAX_EXTRACTED_BYTES:
                raise UploadError(
                    f"ZIP extracted size too large ({total_size:,} bytes). "
                    f"Maximum: {MAX_EXTRACTED_BYTES // (1024*1024)} MB."
                )

            dest_resolved = dest_dir.resolve()
            for member in members:
                # Prevent ZIP slip: resolve the target path and verify it stays inside dest_dir
                member_path = (dest_dir / member.filename).resolve()
                try:
                    member_path.relative_to(dest_resolved)
                except ValueError:
                    raise UploadError(
                        f"ZIP contains unsafe path: '{member.filename}'. "
                        "Extraction refused."
                    )
                zf.extract(member, dest_dir)
    except zipfile.BadZipFile as exc:
        raise UploadError(f"Invalid ZIP file: {exc}") from exc
    except UploadError:
        raise
    except Exception as exc:
        raise UploadError(f"Failed to extract ZIP: {exc}") from exc


def cleanup_temp(working_dir: Path) -> None:
    """Safely remove the temporary working directory."""
    try:
        shutil.rmtree(working_dir, ignore_errors=True)
    except Exception as exc:
        logger.warning("Failed to clean up temp dir %s: %s", working_dir, exc)
