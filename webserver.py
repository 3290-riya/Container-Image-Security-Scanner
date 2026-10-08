#!/usr/bin/env python3
"""Web application entry-point for the Container Image Security Scanner.

Usage:
    python webserver.py
    python webserver.py --host 0.0.0.0 --port 8000
    python webserver.py --reload   (development mode)
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure src/ and project root are importable
sys.path.insert(0, str(Path(__file__).parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Container Image Security Scanner - Web Dashboard"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  Container Image Security Scanner - Web Dashboard")
    print(f"{'='*60}")
    print(f"  URL: http://{args.host}:{args.port}")
    print(f"  API: http://{args.host}:{args.port}/api/docs")
    print(f"  Press CTRL+C to stop")
    print(f"{'='*60}\n")

    uvicorn.run(
        "web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level="info",
    )


if __name__ == "__main__":
    main()
