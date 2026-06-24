"""ArchSafe CLI entry point."""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from archsafe import ai_explainer, aur_checker, config_manager, pkgbuild_analyzer, risk_engine, update_checker
from archsafe.utils import console, display_aur_result, display_update_result, print_error, print_header

# ---------------------------------------------------------------------------
# Root app
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="archsafe",
    help="🛡️ ArchSafe — Arch Linux Safety Analyzer",
    add_completion=False,
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# config sub-app
# ---------------------------------------------------------------------------

config_app = typer.Typer(
    name="config",
    help="Manage API keys and provider settings.",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


@config_app.command("set-key")
def config_set_key(
    api_key: str = typer.Argument(..., help="The API key to store."),
    provider: str = typer.Option(
        None,
        "--provider", "-p",
        help=f"LLM provider. Choices: {', '.join(config_manager.SUPPORTED_PROVIDERS)}. "
             "Defaults to the currently active provider.",
    ),
) -> None:
    """Store an API key for the given provider."""
    try:
        resolved = provider or config_manager.get_provider()
        config_manager.set_api_key(api_key, resolved)
        masked = config_manager.mask_key(api_key)
        console.print(
            f"\n  [green]✓[/green] Stored [bold]{resolved}[/bold] key: [dim]{masked}[/dim]\n"
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)


@config_app.command("get-key")
def config_get_key(
    provider: str = typer.Option(
        None,
        "--provider", "-p",
        help="Provider to query. Defaults to the active provider.",
    ),
) -> None:
    """Show the stored API key for a provider (masked)."""
    resolved = provider or config_manager.get_provider()
    key = config_manager.get_active_api_key(resolved)
    if key:
        console.print(f"\n  [bold]{resolved}[/bold] key: [dim]{config_manager.mask_key(key)}[/dim]\n")
    else:
        console.print(f"\n  [yellow]No API key set for provider '{resolved}'.[/yellow]\n")


@config_app.command("set-provider")
def config_set_provider(
    provider: str = typer.Argument(
        ...,
        help=f"Provider to activate. Choices: {', '.join(config_manager.SUPPORTED_PROVIDERS)}",
    ),
) -> None:
    """Set the active LLM provider."""
    try:
        config_manager.set_provider(provider)
        console.print(f"\n  [green]✓[/green] Active provider set to [bold]{provider}[/bold]\n")
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)


@config_app.command("show")
def config_show() -> None:
    """Display the current configuration (keys are masked)."""
    summary = config_manager.config_summary()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Config file", f"[dim]{summary['config_file']}[/dim]")
    table.add_row("Active provider", f"[cyan]{summary['provider']}[/cyan]")
    console.print()
    for p in config_manager.SUPPORTED_PROVIDERS:
        key_val = summary.get(f"{p}_api_key", "not set")
        model_val = summary.get(f"{p}_model", "")
        style = "green" if "not set" not in key_val else "dim"
        table.add_row(f"{p} api_key", f"[{style}]{key_val}[/{style}]")
        table.add_row(f"{p} model", f"[dim]{model_val}[/dim]")

    console.print(table)
    console.print()


@config_app.command("clear")
def config_clear(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Delete all stored configuration (API keys, provider settings)."""
    if not yes:
        confirmed = typer.confirm("  This will delete all stored keys and settings. Continue?")
        if not confirmed:
            console.print("  [dim]Aborted.[/dim]")
            raise typer.Exit(0)
    config_manager.clear_config()
    console.print("\n  [green]✓[/green] Configuration cleared.\n")


# ---------------------------------------------------------------------------
# update command
# ---------------------------------------------------------------------------

@app.command()
def update(
    days: int = typer.Option(14, "--days", "-d", help="Number of days of news to check."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI explanation."),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="One-shot API key override (takes priority over env vars and stored config).",
        envvar=None,
    ),
) -> None:
    """Check if it's safe to update your Arch Linux system."""
    print_header()

    # Step 1: Fetch news
    with console.status("[bold cyan]Fetching Arch Linux news...[/bold cyan]"):
        try:
            news_items = update_checker.fetch_news(days=days)
        except Exception as e:
            print_error(f"Failed to fetch Arch Linux news: {e}")
            raise typer.Exit(1)

    console.print(f"  [dim]Fetched {len(news_items)} news item(s) from the last {days} days.[/dim]")

    # Step 2: Gather system info
    with console.status("[bold cyan]Gathering system information...[/bold cyan]"):
        system_info = update_checker.get_system_info()

    console.print(f"  [dim]Found {len(system_info.installed_packages)} installed packages.[/dim]")

    # Step 3: Calculate risk
    with console.status("[bold cyan]Analyzing risk...[/bold cyan]"):
        result = risk_engine.calculate_update_risk(news_items, system_info)

    # Step 4: AI explanation (optional)
    if not no_ai:
        with console.status("[bold blue]Generating AI analysis...[/bold blue]"):
            result.ai_explanation = ai_explainer.explain_update(result, api_key=api_key)

    # Step 5: Display results
    display_update_result(result)


# ---------------------------------------------------------------------------
# aur command
# ---------------------------------------------------------------------------

@app.command()
def aur(
    package_name: str = typer.Argument(..., help="Name of the AUR package to analyze."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI explanation."),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="One-shot API key override (takes priority over env vars and stored config).",
        envvar=None,
    ),
) -> None:
    """Analyze the safety of an AUR package."""
    print_header()

    # Step 1: Fetch package info
    with console.status(f"[bold cyan]Fetching AUR info for '{package_name}'...[/bold cyan]"):
        try:
            package_info = aur_checker.fetch_package_info(package_name)
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)
        except Exception as e:
            print_error(f"Failed to fetch AUR package info: {e}")
            raise typer.Exit(1)

    console.print(f"  [dim]Found: {package_info.name} {package_info.version}[/dim]")

    # Step 2: Fetch and analyze PKGBUILD
    with console.status("[bold cyan]Downloading and analyzing PKGBUILD...[/bold cyan]"):
        try:
            pkgbuild_content = aur_checker.fetch_pkgbuild(package_name)
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1)
        except Exception as e:
            print_error(f"Failed to fetch PKGBUILD: {e}")
            raise typer.Exit(1)

        pkgbuild_analysis = pkgbuild_analyzer.analyze(pkgbuild_content)

    console.print(f"  [dim]PKGBUILD analyzed: {len(pkgbuild_analysis.findings)} finding(s).[/dim]")

    # Step 2b: Fetch and analyze .install script (if referenced)
    if pkgbuild_analysis.has_install_script and pkgbuild_analysis.install_script_name:
        script_name = pkgbuild_analysis.install_script_name
        with console.status(f"[bold cyan]Downloading and analyzing {script_name}...[/bold cyan]"):
            try:
                install_content = aur_checker.fetch_install_script(
                    package_name, script_name
                )
            except Exception as e:
                install_content = None
                console.print(
                    f"  [yellow]⚠ Could not fetch {script_name}: {e}[/yellow]"
                )

            if install_content is not None:
                install_analysis = pkgbuild_analyzer.analyze_install_script(
                    install_content, script_name
                )
                pkgbuild_analysis.install_script_analysis = install_analysis
                console.print(
                    f"  [dim]{script_name} analyzed: "
                    f"{len(install_analysis.findings)} finding(s).[/dim]"
                )

    # Step 3: Calculate risk
    with console.status("[bold cyan]Calculating risk score...[/bold cyan]"):
        result = risk_engine.calculate_aur_risk(package_info, pkgbuild_analysis)

    # Step 4: AI explanation (optional)
    if not no_ai:
        with console.status("[bold blue]Generating AI analysis...[/bold blue]"):
            result.ai_explanation = ai_explainer.explain_aur(result, api_key=api_key)

    # Step 5: Display results
    display_aur_result(result)


if __name__ == "__main__":
    app()
