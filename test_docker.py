"""Tests for docker.py – Docker availability and image management helpers."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.scanner.docker import (
    check_docker_available,
    image_exists_locally,
    pull_image,
    get_image_digest,
    DockerError,
)


class TestCheckDockerAvailable:
    def test_returns_false_when_docker_not_on_path(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value=None):
            assert check_docker_available() is False

    def test_returns_true_when_docker_info_succeeds(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert check_docker_available() is True

    def test_returns_false_when_docker_info_fails(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert check_docker_available() is False

    def test_returns_false_on_timeout(self):
        import subprocess
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("docker", 10)):
            assert check_docker_available() is False

    def test_returns_false_on_os_error(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run",
                   side_effect=OSError("permission denied")):
            assert check_docker_available() is False


class TestImageExistsLocally:
    def test_returns_true_when_image_found(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert image_exists_locally("nginx:latest") is True

    def test_returns_false_when_image_not_found(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert image_exists_locally("nonexistent:latest") is False

    def test_returns_false_when_docker_unavailable(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value=None):
            assert image_exists_locally("nginx:latest") is False

    def test_uses_shell_false(self):
        """Verify subprocess.run is called with shell=False."""
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            image_exists_locally("nginx:latest")
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get("shell") is False


class TestPullImage:
    def test_pull_succeeds(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            pull_image("nginx:latest")  # Should not raise

    def test_pull_fails_raises_docker_error(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="not found")
            with pytest.raises(DockerError, match="docker pull failed"):
                pull_image("nonexistent:image")

    def test_pull_no_docker_raises(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value=None):
            with pytest.raises(DockerError, match="Docker CLI not found"):
                pull_image("nginx:latest")

    def test_pull_timeout_raises(self):
        import subprocess
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("docker", 300)):
            with pytest.raises(DockerError, match="timed out"):
                pull_image("nginx:latest")

    def test_pull_uses_shell_false(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            pull_image("nginx:latest")
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get("shell") is False


class TestGetImageDigest:
    def test_returns_digest(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="nginx@sha256:abc123\n"
            )
            digest = get_image_digest("nginx:latest")
            assert digest == "nginx@sha256:abc123"

    def test_returns_none_when_no_value(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="<no value>\n")
            assert get_image_digest("nginx:latest") is None

    def test_returns_none_when_docker_unavailable(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value=None):
            assert get_image_digest("nginx:latest") is None

    def test_returns_none_on_error(self):
        with patch("container_scanner.scanner.docker.shutil.which", return_value="/usr/bin/docker"), \
             patch("container_scanner.scanner.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert get_image_digest("nginx:latest") is None
