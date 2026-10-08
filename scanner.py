#!/usr/bin/env python3
"""Entry-point wrapper for the Container Image Security Scanner.

Usage:
    python scanner.py --image nginx:latest
    python scanner.py --dockerfile Dockerfile
    python scanner.py --help
"""

import sys
import os

# Ensure src/ is on the Python path when running directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from container_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
