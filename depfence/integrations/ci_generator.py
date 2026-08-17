"""CI/CD configuration generator — auto-generates CI workflows for depfence.

Generates ready-to-use configurations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Bitbucket Pipelines
"""

from __future__ import annotations

from pathlib import Path

from depfence import __version__

_CHECKOUT_SHA = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"  # v7
_SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"  # v6
_UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"  # v4
_DOWNLOAD_ARTIFACT_SHA = "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53"  # v6
_UPLOAD_SARIF_SHA = "ff0a06e83cb2de871e5a09832bc6a81e7276941f"  # v3


def generate_github_actions(
    fail_on: str = "high",
    scan_docker: bool = True,
    scan_workflows: bool = True,
    compliance_report: bool = False,
) -> str:
    """Generate a GitHub Actions workflow for depfence scanning."""
    if fail_on not in {"critical", "high", "medium", "low", "any", "none"}:
        raise ValueError(f"Unsupported failure threshold: {fail_on}")
    steps = []
    steps.append(f"      - uses: actions/checkout@{_CHECKOUT_SHA} # v7")
    steps.append(f"      - uses: actions/setup-python@{_SETUP_PYTHON_SHA} # v6")
    steps.append("        with:")
    steps.append("          python-version: '3.12'")
    steps.append(f'      - run: pip install "depfence=={__version__}"')

    steps.append("      - name: Security Scan")
    steps.append("        id: scan")
    steps.append("        run: |")
    steps.append("          set +e")
    steps.append(
        f"          depfence scan . --fail-on {fail_on} --format sarif -o results.sarif"
    )
    steps.append("          status=$?")
    steps.append('          echo "exit-code=$status" >> "$GITHUB_OUTPUT"')
    steps.append("          exit 0")

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
        steps.append(f"      - uses: actions/upload-artifact@{_UPLOAD_ARTIFACT_SHA} # v4")
        steps.append("        with:")
        steps.append("          name: compliance-report")
        steps.append("          path: compliance-report.md")

    steps.append("      - name: Retain SARIF")
    steps.append("        if: always()")
    steps.append(f"        uses: actions/upload-artifact@{_UPLOAD_ARTIFACT_SHA} # v4")
    steps.append("        with:")
    steps.append("          name: depfence-sarif")
    steps.append("          path: results.sarif")
    steps.append("          if-no-files-found: error")
    steps.append("      - name: Enforce scan result")
    steps.append("        if: always()")
    steps.append("        env:")
    steps.append("          SCAN_EXIT_CODE: ${{ steps.scan.outputs.exit-code }}")
    steps.append('        run: test "${SCAN_EXIT_CODE:-2}" -eq 0')

    workflow = f"""name: depfence Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
{chr(10).join(steps)}

  upload-sarif:
    if: ${{{{ always() && github.event_name != 'pull_request' }}}}
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/download-artifact@{_DOWNLOAD_ARTIFACT_SHA} # v6
        with:
          name: depfence-sarif
      - uses: github/codeql-action/upload-sarif@{_UPLOAD_SARIF_SHA} # v3
        with:
          sarif_file: results.sarif
          category: depfence
"""
    return workflow


def generate_gitlab_ci(fail_on: str = "high") -> str:
    """Generate a GitLab CI configuration for depfence."""
    return f"""depfence-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install depfence=={__version__}
  script:
    - depfence scan --fail-on {fail_on} --format json -o depfence-results.json
    - depfence scan-docker
    - depfence compliance --format markdown -o compliance-report.md
  artifacts:
    paths:
      - depfence-results.json
      - compliance-report.md
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""


def generate_pre_commit_hook() -> str:
    """Generate a pre-commit hook configuration."""
    return f"""repos:
  - repo: local
    hooks:
      - id: depfence-scan
        name: depfence security scan
        entry: depfence scan --fail-on high --no-fetch
        language: python
        additional_dependencies: ['depfence=={__version__}']
        pass_filenames: false
        stages: [commit]
      - id: depfence-secrets
        name: depfence secrets check
        entry: python -c "import asyncio; from depfence.scanners.secrets_scanner import SecretsScanner; from pathlib import Path; s=SecretsScanner(); f=asyncio.run(s.scan_project(Path('.'))); exit(1 if f else 0)"
        language: python
        additional_dependencies: ['depfence=={__version__}']
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
          - pip install depfence=={__version__}
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
          - pip install depfence=={__version__}
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
