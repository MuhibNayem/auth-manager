"""
Authy CLI - Enterprise Grade Command Line Interface
FAANG-level production quality with async operations, rich TUI, and multi-cloud deployment.
"""
__version__ = "2.0.0"
__author__ = "Authy Team"

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.logging import RichHandler
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)

console = Console()

# Import commands
from .commands.init import init_cmd
from .commands.dev import dev_cmd
from .commands.migrate import migrate_cmd
from .commands.deploy import deploy_cmd
from .commands.users import users_cmd
from .commands.logs import logs_cmd
from .commands.doctor import doctor_cmd
from .commands.config import config_cmd
from .commands.webhooks import webhooks_cmd
from .commands.audit import audit_cmd


@click.group(invoke_without_command=True)
@click.option('--version', '-v', is_flag=True, help='Show version')
@click.pass_context
def cli(ctx, version):
    """
    🛡️  Authy CLI - Enterprise Authentication Platform
    
    Production-grade CLI for managing authentication infrastructure.
    Supports multi-cloud deployments, real-time monitoring, and zero-trust security.
    """
    if version:
        console.print(f"[bold blue]Authy CLI[/bold blue] v{__version__}")
        return
    
    if ctx.invoked_subcommand is None:
        # Show help with nice formatting
        console.print(Panel.fit(
            "[bold blue]🛡️  Authy CLI - Enterprise Authentication Platform[/bold blue]\n\n"
            "Quick Start:\n"
            "  [green]authy init[/green]              Initialize new project\n"
            "  [green]authy dev[/green]              Start development server\n"
            "  [green]authy doctor[/green]           Run health checks\n"
            "  [green]authy deploy[/green]           Deploy to production\n\n"
            "Use [bold]authy <command> --help[/bold] for detailed usage.",
            title="Welcome",
            border_style="blue"
        ))


# Register commands
cli.add_command(init_cmd, name='init')
cli.add_command(dev_cmd, name='dev')
cli.add_command(migrate_cmd, name='migrate')
cli.add_command(deploy_cmd, name='deploy')
cli.add_command(users_cmd, name='users')
cli.add_command(logs_cmd, name='logs')
cli.add_command(doctor_cmd, name='doctor')
cli.add_command(config_cmd, name='config')
cli.add_command(webhooks_cmd, name='webhooks')
cli.add_command(audit_cmd, name='audit')


def main():
    """Entry point for the CLI."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        console.print("[dim]Run 'authy doctor' to diagnose issues[/dim]")
        sys.exit(1)


if __name__ == '__main__':
    main()
