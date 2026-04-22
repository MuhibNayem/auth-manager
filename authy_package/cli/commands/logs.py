"""Authy Logs Command - Real-time Log Streaming"""
import asyncio
import click
from rich.console import Console
from rich.live import Live
from rich.table import Table
from datetime import datetime

console = Console()

@click.command(name='logs')
@click.option('--follow', '-f', is_flag=True, help='Follow logs in real-time')
@click.option('--level', '-l', type=click.Choice(['debug', 'info', 'warn', 'error']))
@click.option('--service', '-s', help='Filter by service')
@click.option('--since', help='Start time (e.g., 5m, 1h)')
def logs_cmd(follow: bool, level: str, service: str, since: str):
    """Stream and filter application logs."""
    if follow:
        asyncio.run(_follow_logs(level, service))
    else:
        _show_logs(level, service, since)

async def _follow_logs(level: str, service: str):
    """Follow logs in real-time."""
    table = Table(title=f"Live Logs - {service or 'All'}")
    table.add_column("Time", style="dim")
    table.add_column("Level", style="bold")
    table.add_column("Service", style="cyan")
    table.add_column("Message")
    
    with Live(table, refresh_per_second=4, console=console):
        while True:
            await asyncio.sleep(1)

def _show_logs(level: str, service: str, since: str):
    """Show historical logs."""
    console.print("[dim]Showing recent logs...[/dim]")
