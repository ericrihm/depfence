"""CI/CD configuration generator — auto-generates CI workflows for depfence.

Generates ready-to-use configurations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Bitbucket Pipelines
"""

from __future__ import annotations

from pathlib import Path


def generate_github_actions(
    fail_on: str = "high",
    scan_docker: bool = True,
    scan_workflows: bool = True,
    compliance_report: bool = False,
) -> str:
    """Generate a GitHub Actions workflow for depfence scanning."""
    steps = []
    steps.append("      - uses: actions/checkout@v4")
    steps.append("      - uses: actions/setup-python@v5")
    steps.append("        with:")
    steps.append("          python-version: '3.12'")
    steps.append("      - run: pip install depfence")

    steps.append(f"      - name: Security Scan")
    steps.append(f"        run: depfence scan --fail-on {fail_on} --format sarif -o results.sarif")

    if scan_docker:
        steps.append("      - name: Dockerfile Scan")
        steps.append("        run: depfence scan-docker --format json")
        steps.append("        continue-on-error: true")

    if scan_workflows:
        steps.append("      - name: Workflow Scan")
        steps.append("        run: depfence scan-workflows --format json")
        steps.append("        continue-on-error: true")

    if compliance_report:
        steps.append("      - name: Compliance Report")
        steps.append("        run: depfence compliance --format markdown -o compliance-report.md")
        steps.append("      - uses: actions/upload-artifact@v4")
        steps.append("        with:")
        steps.append("          name: compliance-report")
        steps.append("          path: compliance-report.md")

    steps.append("      - name: Upload SARIF")
    steps.append("        if: always()")
    steps.append("        uses: github/codeql-action/upload-sarif@v3")
    steps.append("        with:")
    steps.append("          sarif_file: results.sarif")

    workflow = f"""name: depfence Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

permissions:
  security-events: write
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
{chr(10).join(steps)}
"""
    return workflow


def generate_gitlab_ci(fail_on: str = "high") -> str:
    """Generate a GitLab CI configuration for depfence."""
    return f"""depfence-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install depfence
  script:
    - depfence scan --fail-on {fail_on} --format json -o gl-dependency-scanning-report.json
    - depfence scan-docker
    - depfence compliance --format markdown -o compliance-report.md
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - compliance-report.md
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


def generate_pre_commit_hook() -> str:
    """Generate a pre-commit hook configuration."""
    return """repos:
  - repo: local
    hooks:
      - id: depfence-scan
        name: depfence security scan
        entry: depfence scan --fail-on high --no-fetch
        language: python
        additional_dependencies: ['depfence']
        pass_filenames: false
        stages: [commit]
      - id: depfence-secrets
        name: depfence secrets check
        entry: python -c "import asyncio; from depfence.scanners.secrets_scanner import SecretsScanner; from pathlib import Path; s=SecretsScanner(); f=asyncio.run(s.scan_project(Path('.'))); exit(1 if f else 0)"
        language: python
        additional_dependencies: ['depfence']
        pass_filenames: false
        stages: [commit]
"""


def generate_bitbucket_pipelines(fail_on: str = "high") -> str:
    """Generate Bitbucket Pipelines configuration."""
    return f"""pipelines:
  default:
    - step:
        name: depfence Security Scan
        image: python:3.12-slim
        script:
          - pip install depfence
          - depfence scan --fail-on {fail_on}
          - depfence scan-docker
          - depfence compliance --format json -o compliance.json
        artifacts:
          - compliance.json
  pull-requests:
    '**':
      - step:
          name: PR Security Gate
          image: python:3.12-slim
          script:
            - pip install depfence
            - depfence scan --fail-on {fail_on}
"""


def write_ci_config(project_dir: Path, ci_type: str, **kwargs) -> Path:
    """Write CI configuration to the correct path."""
    generators = {
        "github": (generate_github_actions, ".github/workflows/depfence.yml"),
        "gitlab": (generate_gitlab_ci, ".gitlab-ci-depfence.yml"),
        "pre-commit": (generate_pre_commit_hook, ".pre-commit-config.yaml"),
        "bitbucket": (generate_bitbucket_pipelines, "bitbucket-pipelines.yml"),
    }

    if ci_type not in generators:
        raise ValueError(f"Unknown CI type: {ci_type}. Choose from: {list(generators.keys())}")

    generator, path = generators[ci_type]
    content = generator(**kwargs)
    output_path = project_dir / path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    return output_path
