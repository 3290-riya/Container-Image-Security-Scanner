"""Tests for Dockerfile security analyser."""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from container_scanner.scanner.dockerfile import DockerfileAnalyzer
from container_scanner.models import Severity


def write_dockerfile(tmp_path, content: str) -> str:
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    return str(p)


class TestDockerfileAnalyzer:
    def setup_method(self):
        self.analyzer = DockerfileAnalyzer()

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            self.analyzer.analyse("/nonexistent/Dockerfile")

    def test_clean_dockerfile_minimal_findings(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3
RUN useradd -r appuser
USER appuser
HEALTHCHECK --interval=30s CMD echo healthy
CMD ["python3", "app.py"]
""")
        findings = self.analyzer.analyse(path)
        rule_ids = [f.rule_id for f in findings]
        assert "DF-001" not in rule_ids  # tagged, not latest
        assert "DF-002" not in rule_ids  # USER is not root
        assert "DF-008" not in rule_ids  # has USER
        assert "DF-009" not in rule_ids  # has HEALTHCHECK

    def test_detects_latest_tag(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM nginx:latest
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-001" for f in findings)

    def test_detects_untagged_image(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-001" for f in findings)

    def test_detects_root_user(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
USER root
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-002" for f in findings)

    def test_detects_secret_in_env(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
ENV API_KEY=supersecret
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-003" for f in findings)

    def test_detects_secret_in_arg(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
ARG SECRET_TOKEN
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-004" for f in findings)

    def test_detects_dangerous_command(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN curl https://example.com/install.sh | bash
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-005" for f in findings)

    def test_detects_missing_user(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN apt-get update
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-008" for f in findings)

    def test_detects_missing_healthcheck(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN apt-get update
USER nobody
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-009" for f in findings)

    def test_missing_user_is_high_severity(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN apt-get update
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        user_finding = next(f for f in findings if f.rule_id == "DF-008")
        assert user_finding.severity == Severity.HIGH

    def test_findings_have_recommendations(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM nginx:latest
""")
        findings = self.analyzer.analyse(path)
        for f in findings:
            assert f.recommendation, f"Finding {f.rule_id} has no recommendation"

    def test_sudo_detected(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
RUN sudo apt-get install python3
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-006" for f in findings)

    def test_add_remote_url_detected(self, tmp_path):
        path = write_dockerfile(tmp_path, """FROM ubuntu:22.04
ADD https://example.com/file.tar.gz /app/
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        assert any(f.rule_id == "DF-007" for f in findings)

    def test_comments_ignored(self, tmp_path):
        path = write_dockerfile(tmp_path, """# This is a comment with ENV API_KEY=test
FROM ubuntu:22.04
USER nobody
HEALTHCHECK CMD echo ok
""")
        findings = self.analyzer.analyse(path)
        # The comment should not trigger DF-003
        env_findings = [f for f in findings if f.rule_id == "DF-003"]
        assert len(env_findings) == 0
