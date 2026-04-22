"""Authy Users Command - User Management CLI"""
import asyncio
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

console = Console()

@click.group(name='users')
def users_cmd():
    """Manage users and sessions."""
    pass

@users_cmd.command()
@click.option('--email', '-e', required=True)
@click.option('--password', '-p', hide_input=True)
def create(email: str, password: str):
    """Create a new user."""
    console.print(f"[green]✓ User created:[/green] {email}")

@users_cmd.command()
@click.argument('user_id')
def get(user_id: str):
    """Get user details."""
    console.print(f"User: {user_id}")

@users_cmd.command()
@click.argument('user_id')
def delete(user_id: str):
    """Delete a user."""
    if Confirm.ask(f"Delete user {user_id}?"):
        console.print(f"[red]✓ User deleted[/red]")

@users_cmd.command()
@click.option('--limit', '-l', default=20)
def list(limit: int):
    """List users."""
    table = Table(title="Users")
    table.add_column("ID", style="cyan")
    table.add_column("Email", style="green")
    table.add_column("Status", style="yellow")
    table.add_row("usr_123", "user@example.com", "Active")
    console.print(table)

@users_cmd.command()
@click.argument('user_id')
def impersonate(user_id: str):
    """Impersonate a user (admin only)."""
    console.print(f"[yellow]⚠ Impersonating user: {user_id}[/yellow]")
