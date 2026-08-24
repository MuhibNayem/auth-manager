"""``tessera migrate`` — real migrations against the §4 db contract (§9).

- Migration modules are discovered in ``./tessera_migrations/`` (sorted by
  filename; each module exposes ``async def upgrade(db)`` and
  ``async def downgrade(db)``).
- Applied versions are tracked in the db settings kv under the key
  ``schema_migrations`` as a list of ``{"version", "applied_at"}`` records.
- ``run``/``rollback``/``status`` report truthfully: a failed migration
  stops execution and exits non-zero; nothing is ever reported as applied
  unless its ``upgrade`` actually completed.
"""

from __future__ import annotations

import asyncio
import importlib.util
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

import click
from rich.console import Console
from rich.table import Table

from ..utils import db_guidance, get_connected_db

console = Console()

MIGRATIONS_DIR_NAME = "tessera_migrations"
SETTINGS_KEY = "schema_migrations"


def _utcnow_iso() -> str:
    """Timezone-aware UTC timestamp (§0.5)."""
    return datetime.now(timezone.utc).isoformat()


def migrations_dir(base: Optional[Path] = None) -> Path:
    """Directory holding migration modules."""
    return (base or Path.cwd()) / MIGRATIONS_DIR_NAME


def discover_migrations(base: Optional[Path] = None) -> List[Path]:
    """Sorted list of migration module files (version = file stem)."""
    directory = migrations_dir(base)
    if not directory.exists():
        return []
    files = [
        path
        for path in directory.glob("*.py")
        if not path.name.startswith("__")
    ]
    return sorted(files, key=lambda p: p.name)


def load_migration_module(path: Path) -> Any:
    """Load one migration module from ``path`` (unique module name)."""
    spec = importlib.util.spec_from_file_location(
        f"tessera_migration_{path.stem}", path
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load migration module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def get_applied(db) -> List[dict]:
    """Read the applied-migration ledger from db settings kv."""
    value = await db.get_setting(SETTINGS_KEY)
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict) and entry.get("version")]


async def run_migrations(
    db,
    base: Optional[Path] = None,
    target: Optional[str] = None,
    dry_run: bool = False,
) -> Tuple[List[str], Optional[str]]:
    """Apply pending migrations in order.

    Returns ``(applied_versions, failed_version)``; ``failed_version`` is
    ``None`` when everything applied (or there was nothing to apply).
    """
    applied = {entry["version"] for entry in await get_applied(db)}
    pending = [
        path for path in discover_migrations(base) if path.stem not in applied
    ]
    if target is not None:
        pending = [path for path in pending if path.stem <= target]

    done: List[str] = []
    ledger = await get_applied(db)
    for path in pending:
        if dry_run:
            done.append(path.stem)
            continue
        try:
            module = load_migration_module(path)
            await module.upgrade(db)
        except Exception:
            if done or ledger:
                await db.set_setting(SETTINGS_KEY, ledger)
            return done, path.stem
        ledger.append({"version": path.stem, "applied_at": _utcnow_iso()})
        await db.set_setting(SETTINGS_KEY, ledger)
        done.append(path.stem)
    return done, None


async def rollback_migrations(
    db, steps: int = 1, base: Optional[Path] = None
) -> Tuple[List[str], Optional[str]]:
    """Roll back the last ``steps`` applied migrations.

    Returns ``(rolled_back_versions, failed_version)``.
    """
    ledger = await get_applied(db)
    if not ledger:
        return [], None

    to_rollback = ledger[-steps:]
    rolled_back: List[str] = []
    for entry in reversed(to_rollback):
        version = entry["version"]
        path = migrations_dir(base) / f"{version}.py"
        try:
            if not path.exists():
                raise FileNotFoundError(f"migration file not found: {path}")
            module = load_migration_module(path)
            await module.downgrade(db)
        except Exception:
            await db.set_setting(SETTINGS_KEY, ledger)
            return rolled_back, version
        ledger = [e for e in ledger if e["version"] != version]
        await db.set_setting(SETTINGS_KEY, ledger)
        rolled_back.append(version)
    return rolled_back, None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group(name="migrate")
def migrate_cmd():
    """Manage database migrations (./tessera_migrations/, db-tracked)."""


@migrate_cmd.command()
@click.option("--name", "-n", required=True, help="Migration name")
def create(name: str):
    """Create a new migration module in ./tessera_migrations/."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "migration"
    directory = migrations_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{timestamp}_{safe_name}.py"

    path.write_text(
        f'''"""Migration: {name} (created {datetime.now(timezone.utc).isoformat()})."""


async def upgrade(db):
    """Apply the migration via the AbstractDatabase contract (§4)."""
    # Example (settings kv, users, audit — use real db contract methods):
    # await db.set_setting("feature_flag_x", True)
    pass


async def downgrade(db):
    """Revert the migration."""
    # await db.set_setting("feature_flag_x", None)
    pass
''',
        encoding="utf-8",
    )
    console.print(f"[green]✓ Created migration:[/green] {path}")


@migrate_cmd.command()
@click.option("--target", "-t", default=None, help="Apply up to this version (inclusive)")
@click.option("--dry-run", is_flag=True, help="List pending migrations without applying")
def run(target: Optional[str], dry_run: bool):
    """Run pending migrations against the configured database."""
    exit_code = asyncio.run(_run(target, dry_run))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _run(target: Optional[str], dry_run: bool) -> int:
    if not migrations_dir().exists():
        console.print(
            f"[red]✗ No {MIGRATIONS_DIR_NAME}/ directory found in "
            f"{Path.cwd()} (run 'tessera migrate create -n NAME' first)[/red]"
        )
        return 1

    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    applied, failed = await run_migrations(db, target=target, dry_run=dry_run)
    if dry_run:
        if applied:
            console.print("[blue]Pending migrations (dry run):[/blue]")
            for version in applied:
                console.print(f"  - {version}")
        else:
            console.print("[green]No pending migrations[/green]")
        return 0

    for version in applied:
        console.print(f"[green]✓ Applied:[/green] {version}")
    if failed is not None:
        console.print(f"[red]✗ Failed migration: {failed} — stopped.[/red]")
        console.print("[yellow]Earlier migrations in this run were committed.[/yellow]")
        return 1
    if not applied:
        console.print("[green]No pending migrations[/green]")
    return 0


@migrate_cmd.command()
@click.option("--steps", "-s", default=1, show_default=True, help="Migrations to roll back")
def rollback(steps: int):
    """Roll back previously applied migrations."""
    exit_code = asyncio.run(_rollback(steps))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _rollback(steps: int) -> int:
    if steps <= 0:
        console.print("[red]✗ --steps must be positive[/red]")
        return 1
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    rolled_back, failed = await rollback_migrations(db, steps=steps)
    for version in rolled_back:
        console.print(f"[green]✓ Rolled back:[/green] {version}")
    if failed is not None:
        console.print(f"[red]✗ Failed to roll back: {failed} — stopped.[/red]")
        return 1
    if not rolled_back:
        console.print("[yellow]No migrations to roll back[/yellow]")
    return 0


@migrate_cmd.command()
def status():
    """Show migration status (applied vs pending, from the db ledger)."""
    exit_code = asyncio.run(_status())
    if exit_code:
        raise click.exceptions.Exit(exit_code)


async def _status() -> int:
    db = await get_connected_db()
    if db is None:
        console.print(f"[red]✗ {db_guidance()}[/red]")
        return 1

    applied = {entry["version"]: entry.get("applied_at", "") for entry in await get_applied(db)}
    files = discover_migrations()

    table = Table(title="Migration Status")
    table.add_column("Migration", style="cyan")
    table.add_column("Status")
    table.add_column("Applied At (UTC)", style="dim")

    known = set(applied)
    for path in files:
        if path.stem in applied:
            table.add_row(path.stem, "[green]applied[/green]", applied[path.stem])
        else:
            table.add_row(path.stem, "[yellow]pending[/yellow]", "")
        known.discard(path.stem)
    for version in sorted(known):
        table.add_row(version, "[red]applied (file missing)[/red]", applied[version])

    if not files and not applied:
        console.print(
            f"[yellow]No migrations found ({MIGRATIONS_DIR_NAME}/ missing or empty)[/yellow]"
        )
        return 0
    console.print(table)
    return 0
