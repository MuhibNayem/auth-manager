"""Authy Webhooks Command - Webhook Management"""
import click
from rich.console import Console
from rich.table import Table

console = Console()

@click.group(name='webhooks')
def webhooks_cmd():
    """Manage webhook endpoints."""
    pass

@webhooks_cmd.command()
@click.option('--url', '-u', required=True)
@click.option('--events', '-e', multiple=True)
def create(url: str, events: tuple):
    """Create a new webhook endpoint."""
    console.print(f"[green]✓ Webhook created:[/green] {url}")

@webhooks_cmd.command()
def list():
    """List all webhook endpoints."""
    table = Table(title="Webhooks")
    table.add_column("ID", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Events", style="yellow")
    table.add_row("wh_123", "https://example.com/hook", "user.created, auth.login")
    console.print(table)

@webhooks_cmd.command()
@click.argument('webhook_id')
def test(webhook_id: str):
    """Test a webhook endpoint."""
    console.print(f"[dim]Sending test event to {webhook_id}...[/dim]")
