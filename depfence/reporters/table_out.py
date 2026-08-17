"""Rich table reporter for terminal output."""

from __future__ import annotations

import io
import os
import sys
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from depfence.core.models import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class TableReporter:
    name = "table"
    format = "table"

    def render(self, result: ScanResult, *, max_rows: int | None = None) -> str:
        try:
            term_width = os.get_terminal_size().columns
        except OSError:
            term_width = 120
        width = max(80, min(term_width, 200))

        color = sys.stdout.isatty()
        buffer = io.StringIO()
        console = Console(record=True, width=width, file=buffer, force_terminal=color)

        console.print()
        console.print(f"[bold]depfence scan: {result.target}[/bold]")
        console.print(
            f"Packages scanned: {result.packages_scanned} | "
            f"Findings: {len(result.findings)} | "
            f"Critical: {result.critical_count} | "
            f"High: {result.high_count}"
        )
        console.print()

        if result.errors or result.scanner_errors:
            error_count = len(set(result.errors)) + len(result.scanner_errors)
            console.print(
                f"[bold magenta]INDETERMINATE: {error_count} scan stage error(s); "
                "absence of findings is not a pass.[/bold magenta]"
            )
            for error in result.errors[:5]:
                console.print(Text(f"  - {error}", style="magenta"))
            for scanner, error in list(sorted(result.scanner_errors.items()))[:5]:
                console.print(Text(f"  - {scanner}: {error}", style="magenta"))
            console.print()

        if not result.findings:
            if not result.errors and not result.scanner_errors:
                console.print("[green]No issues found in the evaluated corpus.[/green]")
            return str(console.export_text())

        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=22)
        table.add_column("Package", width=28)
        table.add_column("Title", min_width=30)
        table.add_column("Fix", width=12)

        sorted_findings = sorted(
            result.findings,
            key=lambda f: list(Severity).index(f.severity),
        )

        display = sorted_findings if max_rows is None else sorted_findings[:max_rows]
        remaining = len(sorted_findings) - len(display)

        for f in display:
            sev_text = Text(f.severity.value.upper())
            sev_text.stylize(_SEVERITY_COLORS.get(f.severity, ""))
            # Wrap finding-derived cells in Text() so Rich renders them literally.
            # Titles/packages can contain '[' (e.g. a bracketed file path), which Rich
            # would otherwise parse as console markup and raise MarkupError.
            table.add_row(
                sev_text,
                Text(f.finding_type.value),
                Text(str(f.package)),
                Text(f.title),
                Text(f.fix_version or ""),
            )

        if remaining > 0:
            tail = Counter(f.severity.value for f in sorted_findings[len(display):])
            summary = ", ".join(f"{v} {k}" for k, v in tail.items())
            table.add_row(
                Text(""),
                Text(""),
                Text(""),
                Text(f"... {remaining} more findings ({summary})", style="dim"),
                Text(""),
            )

        console.print(table)

        if result.has_blockers:
            console.print()
            console.print("[bold red]BLOCKED: Critical issues or malicious packages detected.[/bold red]")

        if color:
            return buffer.getvalue()
        return str(console.export_text())
