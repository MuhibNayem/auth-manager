"""Tessera TUI dashboard — single honest snapshot render (CONTRACTS.md §9).

Renders REAL database metrics when a database is reachable; otherwise every
panel explicitly says "not connected". The dashboard is a single snapshot —
the footer never advertises keybindings that do nothing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

_NOT_CONNECTED = "[red]not connected[/red]"


def create_dashboard() -> Layout:
    """Create the main dashboard layout."""
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(Layout(name="left"), Layout(name="right"))
    layout["left"].split(Layout(name="stats"), Layout(name="recent-activity"))
    layout["right"].split(Layout(name="system-health"), Layout(name="active-sessions"))
    return layout


def make_header() -> Panel:
    """Header with the real current UTC time."""
    text = Text.from_markup("[bold blue]Tessera Dashboard[/bold blue]")
    text.append(
        f"  •  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        style="dim",
    )
    return Panel(text, border_style="blue")


def make_stats_panel(db: Optional[Any]) -> Panel:
    """Statistics panel: real db counts, or an explicit not-connected note."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    if db is None:
        table.add_row("Database", _NOT_CONNECTED)
        table.add_row("Hint", "set TESSERA_DB_TYPE / TESSERA_DB_URL")
        return Panel(table, title="Statistics", border_style="red")

    table.add_row("Total Users", str(db._stats.get("users", 0)))
    table.add_row("Active Users", str(db._stats.get("active_users", 0)))
    table.add_row("Audit Events", str(db._stats.get("audit_events", 0)))
    table.add_row("Webhook Endpoints", str(db._stats.get("webhooks", 0)))
    return Panel(table, title="Statistics", border_style="green")


def make_health_panel(db: Optional[Any]) -> Panel:
    """System health panel from the real health_check result."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Service", style="cyan")
    table.add_column("Status")

    if db is None:
        table.add_row("Database", _NOT_CONNECTED)
    elif db._healthy:
        table.add_row("Database", "[green]● healthy[/green]")
    else:
        table.add_row("Database", "[red]● unhealthy[/red]")
    return Panel(table, title="System Health", border_style="blue")


def make_activity_panel(db: Optional[Any]) -> Panel:
    """Recent audit activity — real events or a not-connected note."""
    if db is None or not db._recent_events:
        body = (
            _NOT_CONNECTED if db is None
            else "[dim]No audit events recorded yet[/dim]"
        )
        return Panel(body, title="Recent Activity")

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Event", style="cyan")
    table.add_column("Actor")
    for event in db._recent_events:
        table.add_row(
            str(event.get("event_type", "")),
            str(event.get("actor", "")),
        )
    return Panel(table, title="Recent Activity")


def make_footer() -> Panel:
    """Footer — honest about the dashboard being a single snapshot."""
    return Panel(
        "[dim]Single snapshot — re-run 'tessera dashboard' to refresh.[/dim]",
        border_style="dim",
    )


class _Snapshot:
    """Container for fetched metrics so render helpers stay synchronous."""

    def __init__(self) -> None:
        self.healthy = False
        self.stats = {"users": 0, "active_users": 0, "audit_events": 0, "webhooks": 0}
        self.recent_events: list = []


async def fetch_snapshot() -> Optional[_Snapshot]:
    """Fetch real metrics; ``None`` when no database is reachable."""
    from tessera.cli.utils import get_connected_db

    db = await get_connected_db()
    if db is None:
        return None

    snap = _Snapshot()
    try:
        snap.healthy = await db.health_check()
        snap.stats["users"] = await db.count_users()
        snap.stats["active_users"] = await db.count_users(active_only=True)
        rows, total = await db.search_audit_events(limit=5, offset=0)
        snap.stats["audit_events"] = total
        snap.recent_events = rows
        snap.stats["webhooks"] = len(await db.list_webhook_endpoints())
    except Exception:
        snap.healthy = False
    return snap


async def run_dashboard() -> None:
    """Render one honest dashboard snapshot."""
    snap = await fetch_snapshot()

    class _View:
        """Adapter so panel builders read attributes uniformly."""

        def __init__(self, snapshot: Optional[_Snapshot]) -> None:
            self._healthy = bool(snapshot and snapshot.healthy)
            self._stats = snapshot.stats if snapshot else {"users": 0, "active_users": 0, "audit_events": 0, "webhooks": 0}
            self._recent_events = snapshot.recent_events if snapshot else []

    db_view = _View(snap) if snap is not None else None

    layout = create_dashboard()
    layout["header"].update(make_header())
    layout["footer"].update(make_footer())
    layout["stats"].update(make_stats_panel(db_view))
    layout["system-health"].update(make_health_panel(db_view))
    layout["recent-activity"].update(make_activity_panel(db_view))
    layout["active-sessions"].update(
        Panel(
            "[dim]Session listing requires an app-scoped query; "
            "see 'tessera users' and the sessions API.[/dim]",
            title="Sessions",
        )
    )
    console.print(layout)
