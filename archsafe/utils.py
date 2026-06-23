"""Rich terminal display utilities for ArchSafe."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from archsafe.models import (
    AURCheckResult,
    FindingSeverity,
    RiskLevel,
    UpdateCheckResult,
)

console = Console()

_RISK_COLORS = {
    RiskLevel.SAFE: "green",
    RiskLevel.LOW: "yellow",
    RiskLevel.MEDIUM: "dark_orange",
    RiskLevel.HIGH: "red",
}

_RISK_EMOJIS = {
    RiskLevel.SAFE: "✅",
    RiskLevel.LOW: "⚠️",
    RiskLevel.MEDIUM: "⚠️",
    RiskLevel.HIGH: "❌",
}

_RISK_LABELS = {
    RiskLevel.SAFE: "SAFE",
    RiskLevel.LOW: "RISK IS INVOLVED!",
    RiskLevel.MEDIUM: "RISK IS INVOLVED!",
    RiskLevel.HIGH: "RISK IS INVOLVED!!",
}

_SEVERITY_COLORS = {
    FindingSeverity.LOW: "dim",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.HIGH: "dark_orange",
    FindingSeverity.CRITICAL: "bold red",
}


def _risk_bar(score: int) -> str:
    """Create a simple text-based risk bar."""
    filled = score // 5  # 0-20 blocks
    return "█" * filled + "░" * (20 - filled)


def display_update_result(result: UpdateCheckResult) -> None:
    """Display the update check result with Rich formatting."""
    color = _RISK_COLORS[result.risk_level]
    emoji = _RISK_EMOJIS[result.risk_level]
    label = _RISK_LABELS[result.risk_level]

    # Header
    header = Text(f"{emoji} {label}", style=f"bold {color}")
    console.print()
    console.print(Panel(header, border_style=color, padding=(0, 2)))

    # Risk score
    bar = _risk_bar(result.risk_score)
    console.print(f"\n  Risk Score: [{color}]{result.risk_score}/100[/{color}]")
    console.print(f"  [{color}]{bar}[/{color}]")

    # System info summary
    si = result.system_info
    console.print(f"\n  Kernel: [cyan]{si.kernel_version}[/cyan]")
    console.print(f"  DE: [cyan]{si.desktop_environment}[/cyan]")
    console.print(f"  Packages: [cyan]{len(si.installed_packages)}[/cyan] installed")

    # Affected packages
    if result.affected_packages:
        console.print(f"\n  [bold]Affected Packages:[/bold]")
        for pkg in result.affected_packages:
            version = si.installed_packages.get(pkg, "")
            console.print(f"  [red]✗[/red] {pkg} [dim]{version}[/dim]")

    # Flagged news
    flagged = [item for item in result.news_items if item.matched_keywords]
    if flagged:
        console.print(f"\n  [bold]Flagged News:[/bold]")
        for item in flagged:
            date_str = item.published.strftime("%Y-%m-%d")
            console.print(f"  [yellow]●[/yellow] {item.title} [dim]({date_str})[/dim]")
            console.print(f"    Keywords: [yellow]{', '.join(item.matched_keywords)}[/yellow]")
            console.print(f"    [dim]{item.link}[/dim]")

    # AI explanation
    if result.ai_explanation:
        console.print()
        console.print(Panel(
            result.ai_explanation,
            title="[bold]AI Analysis[/bold]",
            border_style="blue",
            padding=(1, 2),
        ))

    console.print()


def display_aur_result(result: AURCheckResult) -> None:
    """Display the AUR analysis result with Rich formatting."""
    color = _RISK_COLORS[result.risk_level]
    emoji = _RISK_EMOJIS[result.risk_level]
    label = _RISK_LABELS[result.risk_level]
    pkg = result.package_info

    # Header
    header = Text(f"{emoji} {label}", style=f"bold {color}")
    console.print()
    console.print(Panel(header, border_style=color, padding=(0, 2)))

    # Risk score
    bar = _risk_bar(result.risk_score)
    console.print(f"\n  Risk Score: [{color}]{result.risk_score}/100[/{color}]")
    console.print(f"  [{color}]{bar}[/{color}]")

    # Package info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Field", style="bold")
    info_table.add_column("Value")
    info_table.add_row("Package", f"{pkg.name} {pkg.version}")
    info_table.add_row("Description", pkg.description or "N/A")
    info_table.add_row("Maintainer", pkg.maintainer or "[red]ORPHANED[/red]")
    info_table.add_row("Votes", str(pkg.num_votes))
    info_table.add_row("Popularity", f"{pkg.popularity:.2f}")
    info_table.add_row(
        "Age",
        f"{(result.package_info.last_modified - result.package_info.first_submitted).days} days",
    )
    if pkg.out_of_date:
        info_table.add_row("Out of Date", f"[red]Yes[/red] (since {pkg.out_of_date.strftime('%Y-%m-%d')})")
    if pkg.url:
        info_table.add_row("Upstream", pkg.url)

    console.print()
    console.print(info_table)

    # Findings table
    if result.findings:
        console.print(f"\n  [bold]Findings:[/bold]")
        findings_table = Table(box=None, padding=(0, 1))
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Description")
        findings_table.add_column("Line", width=6, justify="right")

        for f in sorted(result.findings, key=lambda x: list(FindingSeverity).index(x.severity), reverse=True):
            sev_color = _SEVERITY_COLORS[f.severity]
            findings_table.add_row(
                Text(f.severity.value, style=sev_color),
                f.description,
                str(f.line_number) if f.line_number else "-",
            )

        console.print(findings_table)
    else:
        console.print("\n  [green]No suspicious patterns detected.[/green]")

    # Source URLs
    if result.pkgbuild_analysis.source_urls:
        console.print(f"\n  [bold]Sources:[/bold]")
        for url in result.pkgbuild_analysis.source_urls:
            console.print(f"  [dim]→ {url}[/dim]")

    # AI explanation
    if result.ai_explanation:
        console.print()
        console.print(Panel(
            result.ai_explanation,
            title="[bold]AI Analysis[/bold]",
            border_style="blue",
            padding=(1, 2),
        ))

    console.print()


def print_header() -> None:
    """Print the ArchSafe header banner."""
    banner = Text("🛡️  ArchSafe", style="bold cyan")
    subtitle = Text("Arch Linux Safety Analyzer", style="dim")
    console.print()
    console.print(Panel(
        Text.assemble(banner, "\n", subtitle),
        border_style="cyan",
        padding=(0, 2),
    ))


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"\n  [bold red]Error:[/bold red] {message}\n")
