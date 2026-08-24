"""``tessera audit`` — audit-log search/export via the §4 db contract (§9).

``search`` renders matching events from ``search_audit_events``; ``export``
writes them as JSON or CSV to a file (or stdout). No fabricated events are
ever shown; an unreachable database yields configuration guidance.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..utils import db_guidance, get_connected_db

console = Console()

#: Columns included in table/CSV output (all real record fields).
_EXPORT_FIELDS = [
    "id",
    "sequence",
    "timestamp",
    "event_type",
    "actor",
    "target",
    "ip_address",
    "details",
    "checksum",
]


def _fmt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 user-supplied date; raise ValueError with help text."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise click.BadParameter(
            f"cannot parse {value!r}; use ISO-8601 like 2025-01-15T10:30:00+00:00"
        ) from exc


async def _search(db, event_types, actor, target, start, end, limit, offset):
    """Run the search and return ``(rows, total)``."""
    return await db.search_audit_events(
        event_types=list(event_types) if event_types else None,
        actor=actor,
        target=target,
        start=start,
        end=end,
        limit=limit,
        offset=offset,
    )


@click.group(name="audit")
def audit_cmd():
    """Search and export the audit log (hash-chained, db-backed)."""


@audit_cmd.command("search")
@click.option("--event-type", "-t", "event_types", multiple=True, help="Filter by event type (repeatable)")
@click.option("--actor", default=None, help="Filter by actor")
@click.option("--target", default=None, help="Filter by target")
@click.option("--start", default=None, help="Start time (ISO-8601)")
@click.option("--end", default=None, help="End time (ISO-8601)")
@click.option("--limit", "-l", default=50, show_default=True)
@click.option("--offset", "-o", default=0, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON instead of a table")
def search(event_types, actor, target, start, end, limit, offset, as_json):
    """Search audit events."""
    exit_code = asyncio.run(
        _search_cmd(event_types, actor, target, start, end, limit, offset, as_json)
    )
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _search_cmd(event_types, actor, target, start, end, limit, offset, as_json) -> int:
    try:
        start_dt, end_dt = _parse_dt(start), _parse_dt(end)
    except click.BadParameter as exc:
        console.print(f"[red]✗ {exc.format_message()}[/red]")
        return 2

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        rows, total = await _search(db, event_types, actor, target, start_dt, end_dt, limit, offset)
    except Exception as exc:
        console.print(f"[red]✗ audit search failed: {exc}[/red]")
        return 1

    if as_json:
        click.echo(json.dumps({"total": total, "events": rows}, indent=2, default=str))
        return 0

    table = Table(title=f"Audit Events ({len(rows)} shown, {total} total)")
    table.add_column("Timestamp (UTC)", style="dim")
    table.add_column("Event", style="cyan")
    table.add_column("Actor")
    table.add_column("Target")
    table.add_column("Details", overflow="fold")

    for row in rows:
        table.add_row(
            _fmt(row.get("timestamp")),
            _fmt(row.get("event_type")),
            _fmt(row.get("actor")),
            _fmt(row.get("target")),
            _fmt(row.get("details")),
        )
    console.print(table)
    return 0


@audit_cmd.command("export")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "csv"]), default="json", show_default=True)
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--event-type", "-t", "event_types", multiple=True)
@click.option("--actor", default=None)
@click.option("--start", default=None, help="Start time (ISO-8601)")
@click.option("--end", default=None, help="End time (ISO-8601)")
@click.option("--limit", "-l", default=1000, show_default=True)
def export(fmt, output, event_types, actor, start, end, limit):
    """Export audit events to JSON or CSV."""
    exit_code = asyncio.run(_export_cmd(fmt, output, event_types, actor, start, end, limit))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _export_cmd(fmt, output, event_types, actor, start, end, limit) -> int:
    try:
        start_dt, end_dt = _parse_dt(start), _parse_dt(end)
    except click.BadParameter as exc:
        console.print(f"[red]✗ {exc.format_message()}[/red]")
        return 2

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        rows, total = await _search(db, event_types, actor, None, start_dt, end_dt, limit, 0)
    except Exception as exc:
        console.print(f"[red]✗ audit export failed: {exc}[/red]")
        return 1

    if fmt == "json":
        payload = json.dumps(
            {"total": total, "exported": len(rows), "events": rows},
            indent=2,
            default=str,
        )
    else:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _fmt(row.get(field)) for field in _EXPORT_FIELDS})
        payload = buffer.getvalue()

    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(payload)
        console.print(f"[green]✓ Exported {len(rows)} event(s) to {output}[/green]")
    else:
        click.echo(payload)
    return 0
