"""``authy webhooks`` — endpoint management against the §4 db contract (§9).

- ``list`` reads ``db.list_webhook_endpoints()``; secrets are masked to the
  last four characters (§7).
- ``create`` validates the URL (§7: https required in production, no
  loopback/private/link-local/metadata destinations) and stores the endpoint
  with a fresh ``secrets.token_hex(32)`` signing secret. The secret is shown
  ONCE at creation; afterwards only the masked form is available.
- ``test`` attempts a real delivery through ``WebhookManager`` when it is
  importable; otherwise it says so clearly. No fabricated delivery results.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.table import Table

from ..utils import db_guidance, get_connected_db, load_auth_config, mask_value

console = Console()


def _validate_endpoint_url(url: str, env: str) -> Optional[str]:
    """Validate a webhook URL per §7; returns an error string or None."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "URL scheme must be http or https"
    if parsed.scheme == "http" and env == "production":
        return "webhook URLs must use https in production"
    if not parsed.hostname:
        return "URL has no hostname"

    hostname = parsed.hostname
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return f"cannot resolve hostname {hostname!r}: {exc}"

    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or str(addr) in {"169.254.169.254", "fd00:ec2::254"}
        ):
            return f"hostname resolves to a disallowed address ({addr})"
    return None


@click.group(name="webhooks")
def webhooks_cmd():
    """Manage webhook endpoints (db-backed)."""


@webhooks_cmd.command("list")
def list_endpoints():
    """List registered webhook endpoints (secrets masked)."""
    exit_code = asyncio.run(_list_endpoints())
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _list_endpoints() -> int:
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        endpoints = await db.list_webhook_endpoints()
    except Exception as exc:
        console.print(f"[red]✗ list_webhook_endpoints failed: {exc}[/red]")
        return 1

    if not endpoints:
        console.print("[yellow]No webhook endpoints registered[/yellow]")
        return 0

    table = Table(title=f"Webhook Endpoints ({len(endpoints)})")
    table.add_column("ID", style="cyan")
    table.add_column("URL")
    table.add_column("Events")
    table.add_column("Secret")
    table.add_column("Active")

    for endpoint in endpoints:
        events = endpoint.get("events") or []
        events_label = ", ".join(str(e) for e in events) if events else "(all)"
        table.add_row(
            str(endpoint.get("id", "")),
            str(endpoint.get("url", "")),
            events_label,
            mask_value(endpoint.get("secret", "")),
            "yes" if endpoint.get("is_active", True) else "no",
        )
    console.print(table)
    return 0


@webhooks_cmd.command("create")
@click.option("--url", "-u", required=True, help="Endpoint URL")
@click.option("--events", "-e", multiple=True,
              help="Event type(s) to subscribe; empty subscribes to ALL events")
def create(url: str, events):
    """Register a webhook endpoint (shows the signing secret ONCE)."""
    exit_code = asyncio.run(_create(url, list(events)))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _create(url: str, events: List[str]) -> int:
    try:
        config = load_auth_config()
        env = config.env
    except Exception:
        env = "development"

    error = _validate_endpoint_url(url, env)
    if error:
        console.print(f"[red]✗ Invalid webhook URL: {error}[/red]")
        return 2

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    secret = secrets.token_hex(32)  # §0.3; needed verbatim for HMAC signing (§7)
    record = {
        "url": url,
        "secret": secret,
        "events": events,  # [] means subscribe-all (§7, documented)
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {"created_by": "authy-cli"},
    }
    try:
        stored = await db.save_webhook_endpoint(record)
    except Exception as exc:
        console.print(f"[red]✗ save_webhook_endpoint failed: {exc}[/red]")
        return 1

    console.print(f"[green]✓ Webhook endpoint created[/green] id={stored.get('id')}")
    console.print(f"  URL: {url}")
    console.print("  Events: " + (", ".join(events) if events else "(all events)"))
    console.print(
        f"[yellow]⚠ Signing secret (shown ONCE, store it securely):[/yellow] {secret}"
    )
    console.print("[dim]List views will only ever show the masked form.[/dim]")
    return 0


@webhooks_cmd.command("test")
@click.argument("endpoint_id")
@click.option("--event-type", default="user.created", show_default=True,
              help="Event type for the test delivery")
def test(endpoint_id: str, event_type: str):
    """Attempt a real test delivery to an endpoint via WebhookManager."""
    exit_code = asyncio.run(_test(endpoint_id, event_type))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _test(endpoint_id: str, event_type: str) -> int:
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        endpoint = await db.get_webhook_endpoint(endpoint_id)
    except Exception as exc:
        console.print(f"[red]✗ get_webhook_endpoint failed: {exc}[/red]")
        return 1
    if endpoint is None:
        console.print(f"[yellow]Endpoint {endpoint_id} not found[/yellow]")
        return 1

    try:
        from authy_package.webhooks.webhook_manager import (
            WebhookEventType,
            WebhookManager,
        )
    except ImportError:
        console.print(
            "[red]✗ WebhookManager is not importable in this installation; "
            "cannot perform a test delivery.[/red]"
        )
        return 1

    try:
        import httpx

        from authy_package.cache import InMemoryCache

        config = load_auth_config()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            manager = WebhookManager(config, db, InMemoryCache(), client)
            try:
                wh_event_type = WebhookEventType(event_type)
            except ValueError:
                console.print(
                    f"[red]✗ Unknown event type {event_type!r}; valid types: "
                    f"{[e.value for e in WebhookEventType]}[/red]"
                )
                return 2
            await manager.dispatch_event(
                wh_event_type, {"test": True, "endpoint_id": endpoint_id}
            )
            # Attempt immediate processing of the queued delivery.
            await manager._process_pending_events()
    except Exception as exc:
        console.print(f"[red]✗ Test delivery failed: {exc}[/red]")
        return 1

    deliveries = await db.get_webhook_deliveries(endpoint_id, limit=3)
    if not deliveries:
        console.print(
            "[yellow]Delivery was queued but no delivery attempt was recorded "
            "yet (check webhook worker configuration).[/yellow]"
        )
        return 0

    latest = deliveries[0]
    success = latest.get("success")
    status_code = latest.get("status_code", latest.get("response_status"))
    if success:
        console.print(
            f"[green]✓ Test delivery succeeded[/green] (status={status_code})"
        )
        return 0
    console.print(
        f"[red]✗ Test delivery failed[/red] "
        f"(status={status_code}, error={latest.get('error') or latest.get('reason') or 'unknown'})"
    )
    return 1
