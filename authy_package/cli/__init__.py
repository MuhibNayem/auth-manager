"""Authy CLI (CONTRACTS.md §9).

Importing this package has NO global side effects: logging is configured
lazily in :func:`main` (``logging.basicConfig`` is itself a no-op once a
handler exists). The click group and command registration are the only
module-level work.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.panel import Panel

from authy_package import __version__

console = Console()

from .commands.audit import audit_cmd
from .commands.config import config_cmd
from .commands.deploy import deploy_cmd
from .commands.dev import dev_cmd
from .commands.doctor import doctor_cmd
from .commands.init import init_cmd
from .commands.logs import logs_cmd
from .commands.migrate import migrate_cmd
from .commands.users import users_cmd
from .commands.webhooks import webhooks_cmd
from .tui.dashboard import run_dashboard


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def cli(ctx, version):
    """Authy CLI — authentication infrastructure tooling.

    All commands report honestly: real checks, real database access, and
    explicit "not configured" guidance instead of fabricated output.
    """
    if version:
        console.print(f"[bold blue]Authy CLI[/bold blue] v{__version__}")
        return

    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            "[bold blue]Authy CLI[/bold blue]\n\n"
            "Quick Start:\n"
            "  [green]authy init[/green]       Initialize a new project\n"
            "  [green]authy dev[/green]        Start development server (127.0.0.1)\n"
            "  [green]authy doctor[/green]     Run health checks\n"
            "  [green]authy migrate[/green]    Run database migrations\n"
            "  [green]authy deploy[/green]     Docker build / IaC artifact generation\n\n"
            "Use [bold]authy <command> --help[/bold] for full usage.",
            title="Welcome",
            border_style="blue",
        ))


@click.command(name="dashboard")
def dashboard_cmd():
    """Render a one-shot dashboard snapshot (real db metrics or 'not connected')."""
    asyncio.run(run_dashboard())


cli.add_command(init_cmd, name="init")
cli.add_command(dev_cmd, name="dev")
cli.add_command(migrate_cmd, name="migrate")
cli.add_command(deploy_cmd, name="deploy")
cli.add_command(users_cmd, name="users")
cli.add_command(logs_cmd, name="logs")
cli.add_command(doctor_cmd, name="doctor")
cli.add_command(config_cmd, name="config")
cli.add_command(webhooks_cmd, name="webhooks")
cli.add_command(audit_cmd, name="audit")
cli.add_command(dashboard_cmd, name="dashboard")


def main() -> None:
    """Entry point for the CLI (configures logging lazily)."""
    # basicConfig is a guard: it does nothing when handlers already exist,
    # and it never runs at import time (§9 no import side effects).
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
