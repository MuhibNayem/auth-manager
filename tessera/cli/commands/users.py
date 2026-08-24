"""``tessera users`` — user management against the §4 db contract (§9).

Every subcommand talks to the configured database via ``list_users``,
``get_user_by_id``, ``get_user_by_identifier`` and ``delete_user``. When no
database is reachable the commands print configuration guidance instead of
fabricating data. Password hashes are never displayed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..utils import db_guidance, get_connected_db

console = Console()

#: User fields that must never be printed.
_HIDDEN_FIELDS = ("hashed_password", "mfa_secret")


def _sanitize(user: dict) -> dict:
    """Strip secret fields from a user record for display."""
    return {k: v for k, v in user.items() if k not in _HIDDEN_FIELDS}


def _fmt(value) -> str:
    """Render a record value safely for the table."""
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


@click.group(name="users")
def users_cmd():
    """Manage users (list/get/delete via the configured database)."""


@users_cmd.command("list")
@click.option("--limit", "-l", default=20, show_default=True, help="Max rows")
@click.option("--offset", "-o", default=0, show_default=True, help="Row offset")
@click.option("--search", "-s", default=None, help="Substring search (name/email/username)")
def list_users(limit: int, offset: int, search: Optional[str]):
    """List users from the database."""
    exit_code = asyncio.run(_list_users(limit, offset, search))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _list_users(limit: int, offset: int, search: Optional[str]) -> int:
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        rows, total = await db.list_users(limit=limit, offset=offset, search=search)
    except Exception as exc:
        console.print(f"[red]✗ list_users failed: {exc}[/red]")
        return 1

    table = Table(title=f"Users ({len(rows)} shown, {total} total)")
    table.add_column("ID", style="cyan")
    table.add_column("Username")
    table.add_column("Email")
    table.add_column("Role")
    table.add_column("Active")
    table.add_column("Created (UTC)", style="dim")

    for user in rows:
        table.add_row(
            _fmt(user.get("id")),
            _fmt(user.get("username")),
            _fmt(user.get("email")),
            _fmt(user.get("role")),
            "yes" if user.get("is_active") else "no",
            _fmt(user.get("created_at")),
        )
    console.print(table)
    return 0


@users_cmd.command("get")
@click.argument("user_id", required=False)
@click.option("--email", "-e", default=None, help="Look up by email")
@click.option("--username", "-u", default=None, help="Look up by username")
@click.option("--phone", default=None, help="Look up by phone")
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON")
def get_user(user_id: Optional[str], email: Optional[str], username: Optional[str],
             phone: Optional[str], as_json: bool):
    """Get one user by id or identifier."""
    exit_code = asyncio.run(_get_user(user_id, email, username, phone, as_json))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _get_user(user_id: Optional[str], email: Optional[str], username: Optional[str],
                    phone: Optional[str], as_json: bool) -> int:
    if not any([user_id, email, username, phone]):
        console.print("[red]✗ Provide a USER_ID or one of --email/--username/--phone[/red]")
        return 2

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    try:
        if user_id:
            user = await db.get_user_by_id(user_id)
        else:
            user = await db.get_user_by_identifier(
                username=username, email=email, phone=phone
            )
    except Exception as exc:
        console.print(f"[red]✗ user lookup failed: {exc}[/red]")
        return 1

    if user is None:
        console.print("[yellow]User not found[/yellow]")
        return 1

    if as_json:
        click.echo(json.dumps(_sanitize(user), indent=2, default=str))
        return 0

    table = Table(title="User", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for key, value in _sanitize(user).items():
        table.add_row(key, _fmt(value))
    console.print(table)
    return 0


@users_cmd.command("delete")
@click.argument("user_id")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt")
def delete_user(user_id: str, yes: bool):
    """Delete a user (with confirmation)."""
    exit_code = asyncio.run(_delete_user(user_id, yes))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _delete_user(user_id: str, yes: bool) -> int:
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    user = await db.get_user_by_id(user_id)
    if user is None:
        console.print(f"[yellow]User {user_id} not found[/yellow]")
        return 1

    label = user.get("email") or user.get("username") or user_id
    if not yes:
        if not click.confirm(f"Really delete user '{label}' ({user_id})?"):
            console.print("[yellow]Aborted[/yellow]")
            return 1

    try:
        deleted = await db.delete_user(user_id)
    except Exception as exc:
        console.print(f"[red]✗ delete failed: {exc}[/red]")
        return 1

    if deleted:
        console.print(f"[green]✓ Deleted user {user_id}[/green]")
        return 0
    console.print(f"[red]✗ User {user_id} could not be deleted[/red]")
    return 1
