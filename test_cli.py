"""Tests for the CLI argument parsing."""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.cli import build_parser, parse_severity_list, main


class TestBuildParser:
    def test_help_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_version_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--version"])

    def test_image_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "nginx:latest"])
        assert args.image == "nginx:latest"

    def test_dockerfile_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--dockerfile", "Dockerfile"])
        assert args.dockerfile == "Dockerfile"

    def test_severity_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x", "--severity", "HIGH,CRITICAL"])
        assert args.severity == "HIGH,CRITICAL"

    def test_fail_on_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x", "--fail-on", "CRITICAL"])
        assert args.fail_on == "CRITICAL"

    def test_format_default(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x"])
        assert args.format == "all"

    def test_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x", "--format", "json"])
        assert args.format == "json"

    def test_output_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x", "--output", "/tmp/reports"])
        assert args.output == "/tmp/reports"

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--image", "x", "--verbose"])
        assert args.verbose is True


class TestParseSeverityList:
    def test_single_severity(self):
        result = parse_severity_list("HIGH")
        assert result == ["HIGH"]

    def test_multiple_severities(self):
        result = parse_severity_list("HIGH,CRITICAL")
        assert set(result) == {"HIGH", "CRITICAL"}

    def test_lowercase_normalized(self):
        result = parse_severity_list("critical,high")
        assert "CRITICAL" in result
        assert "HIGH" in result

    def test_none_returns_none(self):
        assert parse_severity_list(None) is None

    def test_empty_string_returns_empty(self):
        result = parse_severity_list("")
        assert result == []

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="EXTREME"):
            parse_severity_list("EXTREME")


class TestMainEntryPoint:
    def test_no_args_returns_2(self):
        result = main([])
        assert result == 2

    def test_help_exits_0(self):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_invalid_severity_returns_2(self):
        result = main(["--image", "nginx:latest", "--severity", "EXTREME"])
        assert result == 2

    def test_image_scan_calls_run_scan(self):
        with patch("container_scanner.runner.run_scan") as mock_run:
            mock_run.return_value = 0
            result = main(["--image", "nginx:latest"])
            assert result == 0
            mock_run.assert_called_once()

    def test_run_scan_kwargs_passed(self):
        with patch("container_scanner.runner.run_scan") as mock_run:
            mock_run.return_value = 0
            main(["--image", "nginx:latest", "--severity", "HIGH", "--fail-on", "CRITICAL", "--format", "json"])
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["image"] == "nginx:latest"
            assert call_kwargs["severities"] == ["HIGH"]
            assert call_kwargs["fail_on"] == ["CRITICAL"]
            assert call_kwargs["fmt"] == "json"
