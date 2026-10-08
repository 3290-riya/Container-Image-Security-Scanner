"""FastAPI application factory for the Container Image Security Scanner web UI."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# Ensure src/ is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

_STATIC_DIR = Path(__file__).parent.parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(
        title="Container Image Security Scanner",
        description="Web dashboard for scanning Docker images and Dockerfiles for vulnerabilities.",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # Mount static files
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Register routes
    from web.routes import router
    app.include_router(router)

    return app


app = create_app()
