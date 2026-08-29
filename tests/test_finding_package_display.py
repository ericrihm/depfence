"""Findings whose package is a plain string must not crash report rendering.

Package-shaped findings carry a PackageMeta; artifact findings set `package`
to a string like "artifact:docs/evil.ttf" (artifact_analysis.py, and
visual_text_deception_scanner.py). Reporters that reach for `.name` therefore
crash on exactly the findings depfence advertises detecting.

inline_suppress.py already guards this with hasattr; these tests pin the
behaviour everywhere else.
"""

from __future__ import annotations

from depfence.core.models import Finding, FindingType, ScanResult, Severity


def _artifact_finding() -> Finding:
    return Finding(
        finding_type=FindingType.VISUAL_TEXT_DECEPTION,
        severity=Severity.HIGH,
        package="artifact:docs/evil.ttf",
        title="Degenerate glyph-to-codepoint mapping",
        detail="The font maps many codepoints onto one glyph.",
        confidence=0.92,
    )


def _result() -> ScanResult:
    return ScanResult(target=".", ecosystem="python", findings=[_artifact_finding()])


def test_package_display_handles_a_string_package() -> None:
    from depfence.core.models import package_display_name

    assert package_display_name("artifact:docs/evil.ttf") == "artifact:docs/evil.ttf"


def test_package_display_handles_a_package_object() -> None:
    from depfence.core.models import PackageId, package_display_name

    assert package_display_name(PackageId(ecosystem="pypi", name="requests")) == "requests"


def test_package_ecosystem_handles_a_string_package() -> None:
    from depfence.core.models import package_ecosystem

    assert package_ecosystem("artifact:docs/evil.ttf") == ""


def test_html_report_renders_an_artifact_finding() -> None:
    """depfence scan . --format html crashed on any flagged font/PDF/DOCX."""
    from depfence.core.html_report import generate_html_report

    html = generate_html_report(_result(), project_name="t")

    assert "evil.ttf" in html


def test_html_report_still_renders_a_package_finding() -> None:
    from depfence.core.html_report import generate_html_report
    from depfence.core.models import PackageId

    finding = Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=Severity.HIGH,
        package=PackageId(ecosystem="pypi", name="requests", version="2.0.0"),
        title="CVE-0000",
        detail="x",
        confidence=0.9,
    )
    result = ScanResult(target=".", ecosystem="pypi", findings=[finding])

    html = generate_html_report(result, project_name="t")

    assert "requests" in html
