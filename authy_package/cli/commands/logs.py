"""``authy logs`` — audit-log tail with honest polling (CONTRACTS.md §9).

The package's real event stream is the hash-chained audit log (§4), so this
command reads it via ``search_audit_events``:

- One-shot mode prints the most recent events.
- ``--follow`` HONESTLY polls the audit log every ``--interval`` seconds and
  prints events newer than the highest sequence already shown. It is a poll,
  not a socket stream — the help text says so. ``--iterations`` bounds the
  poll count (0 = until Ctrl+C) which also keeps it testable.
"""

from __future__ import annotations

import asyncio

import click
from rich.console import Console

from ..utils import db_guidance, get_connected_db

console = Console()


def _fmt(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _render(rows) -> None:
    """Print rows oldest-first, one line each."""
    for row in rows:
        console.print(
            f"[dim]{_fmt(row.get('timestamp'))}[/dim] "
            f"[cyan]{_fmt(row.get('event_type'))}[/cyan] "
            f"actor={_fmt(row.get('actor')) or '-'} "
            f"target={_fmt(row.get('target')) or '-'} "
            f"[dim]seq={_fmt(row.get('sequence'))}[/dim]"
        )


@click.command(name="logs")
@click.option("--follow", "-f", is_flag=True, help="Poll for new audit events")
@click.option("--interval", default=2.0, show_default=True, help="Poll interval seconds (--follow)")
@click.option("--iterations", default=0, show_default=True,
              help="Poll cycles to run; 0 = until Ctrl+C (--follow)")
@click.option("--limit", "-l", default=20, show_default=True, help="Events to show per page")
@click.option("--event-type", "-t", "event_types", multiple=True, help="Filter by event type")
def logs_cmd(follow: bool, interval: float, iterations: int, limit: int, event_types):
    """Show recent audit events, or poll for new ones with --follow."""
    exit_code = asyncio.run(_logs(follow, interval, iterations, limit, event_types))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _logs(follow: bool, interval: float, iterations: int, limit: int,
                event_types) -> int:
    if interval <= 0:
        console.print("[red]✗ --interval must be positive[/red]")
        return 2

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    types = list(event_types) if event_types else None

    try:
        rows, _total = await db.search_audit_events(
            event_types=types, limit=limit, offset=0
        )
    except Exception as exc:
        console.print(f"[red]✗ audit query failed: {exc}[/red]")
        return 1

    if not follow:
        if rows:
            console.print(f"[blue]Last {len(rows)} audit event(s) (newest last):[/blue]")
            _render(list(reversed(rows)))
        else:
            console.print("[yellow]No audit events recorded yet[/yellow]")
        return 0

    # Follow mode: honest polling of the audit tail.
    console.print(
        f"[blue]Polling audit log every {interval}s "
        f"({'until Ctrl+C' if iterations <= 0 else f'{iterations} cycles'}); "
        "this is a poll, not a live stream.[/blue]"
    )
    seen_sequence = max((int(r.get("sequence", 0)) for r in rows), default=0)
    cycles = 0
    try:
        while True:
            await asyncio.sleep(interval)
            cycles += 1
            try:
                fresh, _t = await db.search_audit_events(
                    event_types=types, limit=limit, offset=0
                )
            except Exception as exc:
                console.print(f"[red]✗ poll failed: {exc}[/red]")
                return 1
            new_rows = [
                r for r in fresh if int(r.get("sequence", 0)) > seen_sequence
            ]
            if new_rows:
                new_rows.sort(key=lambda r: int(r.get("sequence", 0)))
                _render(new_rows)
                seen_sequence = max(
                    int(r.get("sequence", 0)) for r in new_rows
                )
            if iterations > 0 and cycles >= iterations:
                break
    except asyncio.CancelledError:
        raise
    return 0
