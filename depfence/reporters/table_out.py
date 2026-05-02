"""Rich table reporter for terminal output."""

from __future__ import annotations

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

    def render(self, result: ScanResult) -> str:
        console = Console(record=True, width=120)

        console.print()
        console.print(f"[bold]depfence scan: {result.target}[/bold]")
        console.print(
            f"Packages scanned: {result.packages_scanned} | "
            f"Findings: {len(result.findings)} | "
            f"Critical: {result.critical_count} | "
            f"High: {result.high_count}"
        )
        console.print()

        if not result.findings:
            console.print("[green]No issues found.[/green]")
            return console.export_text()

        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=18)
        table.add_column("Package", width=25)
        table.add_column("Title", min_width=30)
        table.add_column("Fix", width=12)

        sorted_findings = sorted(
            result.findings,
            key=lambda f: list(Severity).index(f.severity),
        )

        for f in sorted_findings:
            sev_text = Text(f.severity.value.upper())
            sev_text.stylize(_SEVERITY_COLORS.get(f.severity, ""))
            table.add_row(
                sev_text,
                f.finding_type.value,
                str(f.package),
                f.title,
                f.fix_version or "",
            )

        console.print(table)

        if result.has_blockers:
            console.print()
            console.print("[bold red]BLOCKED: Critical issues or malicious packages detected.[/bold red]")

        return console.export_text()
