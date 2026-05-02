"""Tests for Dockerfile security scanner."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from depfence.scanners.dockerfile_scanner import DockerfileScanner


@pytest.fixture
def scanner():
    return DockerfileScanner()


def _write_dockerfile(tmpdir: Path, content: str, name: str = "Dockerfile") -> Path:
    f = tmpdir / name
    f.write_text(content)
    return f


class TestUnpinnedBaseImage:
    @pytest.mark.asyncio
    async def test_no_tag(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM ubuntu\nRUN echo hi\n")
            findings = await scanner.scan_project(Path(d))
            titles = [f.title for f in findings]
            assert any("Unpinned base image" in t for t in titles)

    @pytest.mark.asyncio
    async def test_latest_tag(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM node:latest\nRUN npm install\n")
            findings = await scanner.scan_project(Path(d))
            titles = [f.title for f in findings]
            assert any(":latest tag" in t for t in titles)
            assert any("Unpinned" in t for t in titles)

    @pytest.mark.asyncio
    async def test_pinned_version_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM python:3.12-slim\nRUN pip install flask\n")
            findings = await scanner.scan_project(Path(d))
            titles = [f.title for f in findings]
            assert not any("Unpinned" in t for t in titles)

    @pytest.mark.asyncio
    async def test_digest_pinned_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM python@sha256:abcdef1234567890\nRUN echo\n")
            findings = await scanner.scan_project(Path(d))
            assert not any("Unpinned" in f.title for f in findings)


class TestRootUser:
    @pytest.mark.asyncio
    async def test_no_user_directive(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM node:18\nRUN npm install\nCMD ['node', 'app.js']\n")
            findings = await scanner.scan_project(Path(d))
            assert any("root" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_user_directive_present(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM node:18\nRUN npm install\nUSER node\nCMD ['node', 'app.js']\n")
            findings = await scanner.scan_project(Path(d))
            assert not any("root" in f.title.lower() for f in findings)


class TestSecrets:
    @pytest.mark.asyncio
    async def test_password_in_env(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM alpine:3.18\nENV DB_PASSWORD=hunter2\nRUN echo\n")
            findings = await scanner.scan_project(Path(d))
            assert any("Secret" in f.title or "credential" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_aws_key_in_arg(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM alpine:3.18\nARG AWS_SECRET_ACCESS_KEY=abc123\nRUN echo\n")
            findings = await scanner.scan_project(Path(d))
            assert any("credential" in f.title.lower() or "Secret" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_safe_env_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM alpine:3.18\nENV APP_PORT=8080\nUSER app\nRUN echo\n")
            findings = await scanner.scan_project(Path(d))
            assert not any("Secret" in f.title for f in findings)


class TestPipeToShell:
    @pytest.mark.asyncio
    async def test_curl_pipe_bash(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/install.sh | bash\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("Pipe-to-shell" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_wget_pipe_sh(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM ubuntu:22.04\nRUN wget -qO- https://example.com/setup | sh\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("Pipe-to-shell" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_safe_download_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM ubuntu:22.04\nRUN curl -o /tmp/setup.sh https://example.com/setup.sh && chmod +x /tmp/setup.sh\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert not any("Pipe-to-shell" in f.title for f in findings)


class TestEOLImages:
    @pytest.mark.asyncio
    async def test_python2(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM python:2.7\nRUN pip install flask\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("EOL" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_node12(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM node:12-alpine\nRUN npm install\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("EOL" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_debian_jessie(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM debian:jessie\nRUN apt-get update\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("EOL" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_modern_image_no_eol(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM node:20-alpine\nRUN npm install\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert not any("EOL" in f.title for f in findings)


class TestHealthcheck:
    @pytest.mark.asyncio
    async def test_missing_healthcheck(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            content = "FROM node:20\n" + "RUN echo line\n" * 12 + "USER app\n"
            _write_dockerfile(Path(d), content)
            findings = await scanner.scan_project(Path(d))
            assert any("HEALTHCHECK" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_healthcheck_present(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            content = "FROM node:20\n" + "RUN echo line\n" * 12 + "HEALTHCHECK CMD curl -f http://localhost/\nUSER app\n"
            _write_dockerfile(Path(d), content)
            findings = await scanner.scan_project(Path(d))
            assert not any("HEALTHCHECK" in f.title for f in findings)


class TestAptKey:
    @pytest.mark.asyncio
    async def test_apt_key_add(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            _write_dockerfile(Path(d), "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/key.gpg | apt-key add -\nUSER app\n")
            findings = await scanner.scan_project(Path(d))
            assert any("apt-key" in f.title for f in findings)


class TestMultiStage:
    @pytest.mark.asyncio
    async def test_multistage_no_false_positive(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            content = "FROM node:20 AS builder\nRUN npm install\nFROM node:20-alpine\nCOPY --from=builder /app /app\nUSER node\nHEALTHCHECK CMD curl -f http://localhost/\n"
            _write_dockerfile(Path(d), content)
            findings = await scanner.scan_project(Path(d))
            assert not any("root" in f.title.lower() for f in findings)


class TestFileDiscovery:
    @pytest.mark.asyncio
    async def test_finds_named_dockerfiles(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Dockerfile").write_text("FROM alpine:3.18\nUSER app\n")
            (p / "Dockerfile.dev").write_text("FROM ubuntu\nUSER app\n")
            findings = await scanner.scan_project(p)
            assert any("Unpinned" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_scan_returns_empty_for_packages(self, scanner):
        result = await scanner.scan([])
        assert result == []


class TestSecureDockerfile:
    @pytest.mark.asyncio
    async def test_fully_secure_no_findings(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            content = (
                "FROM python:3.12-slim\n"
                "WORKDIR /app\n"
                "COPY requirements.txt .\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n"
                "COPY . .\n"
                "USER appuser\n"
                "HEALTHCHECK CMD python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:8000/health\")'\n"
                "CMD [\"python\", \"main.py\"]\n"
            )
            _write_dockerfile(Path(d), content)
            findings = await scanner.scan_project(Path(d))
            assert len(findings) == 0
