"""CLI entry point for the Container Image Security Scanner."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from container_scanner import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Container Image Security Scanner - "
            "scan Docker images and Dockerfiles for vulnerabilities and misconfigurations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0   Scan completed and security gate passed (or gate disabled)
  1   Security gate FAILED (findings exceed policy threshold)
  2   Scanner / configuration / runtime error

Examples:
  scanner --image nginx:latest
  scanner --image nginx:latest --format json
  scanner --image nginx:latest --format html
  scanner --image nginx:latest --severity HIGH,CRITICAL
  scanner --image nginx:latest --fail-on HIGH
  scanner --dockerfile Dockerfile
  scanner --image nginx:latest --output reports/
""",
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    target_group = parser.add_argument_group("Scan targets")
    target_group.add_argument(
        "--image",
        metavar="IMAGE",
        help="Docker image to scan (e.g. nginx:latest)",
    )
    target_group.add_argument(
        "--dockerfile",
        metavar="PATH",
        help="Path to a Dockerfile to analyse",
    )

    scan_group = parser.add_argument_group("Scan options")
    scan_group.add_argument(
        "--severity",
        metavar="SEVERITIES",
        default=None,
        help="Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW (default: all)",
    )
    scan_group.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        default=None,
        help="Comma-separated severities that trigger a gate failure (exit code 1)",
    )
    scan_group.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to config.yaml (default: ./config.yaml if present)",
    )

    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "--format",
        choices=["json", "html", "all"],
        default="all",
        help="Report format: json | html | all (default: all)",
    )
    output_group.add_argument(
        "--output",
        metavar="DIR",
        default=None,
        help="Output directory for reports (default: from config or ./reports)",
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    return parser


def parse_severity_list(raw: Optional[str]) -> Optional[List[str]]:
    """Parse a comma-separated severity string into a list.

    Returns None if raw is None.
    Returns [] if raw is an empty string.
    """
    if raw is None:
        return None
    parts = [s.strip().upper() for s in raw.split(",") if s.strip()]
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    for part in parts:
        if part not in valid:
            raise ValueError(f"Invalid severity '{part}'. Valid: {', '.join(sorted(valid))}")
    return parts


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns exit code."""
    # Deferred import to allow the CLI module to be imported without heavy deps.
    from container_scanner.runner import run_scan

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.image and not args.dockerfile:
        parser.print_help()
        return 2

    try:
        severity_list = parse_severity_list(args.severity)
        fail_on_list = parse_severity_list(args.fail_on) if args.fail_on else None
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    return run_scan(
        image=args.image,
        dockerfile=args.dockerfile,
        severities=severity_list,
        fail_on=fail_on_list,
        config_path=args.config,
        fmt=args.format,
        output_dir=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())
