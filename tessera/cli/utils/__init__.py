"""Shared CLI utilities (config persistence, db access, rendering helpers).

Config files are written with ``0600`` permissions (§0.8); the ``~/.tessera``
directory is created ``0700``. Database access goes through the §4 factory
``get_database`` — every helper here returns honest "not configured" results
instead of fake data when the backend is unreachable.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

#: Default location of the CLI-managed configuration file.
DEFAULT_CONFIG_PATH = Path.home() / ".tessera" / "config.json"

#: Keys whose values are masked in any printed output.
_SECRET_KEY_MARKERS = ("secret", "token", "password", "key", "credential")


def async_command(func: Callable) -> Callable:
    """Decorator to run async Click commands via ``asyncio.run``."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(func(*args, **kwargs))

    return wrapper


# ---------------------------------------------------------------------------
# config file handling (0600)
# ---------------------------------------------------------------------------

def _resolve_config_path(config_path: Optional[str]) -> Path:
    """Resolve an explicit path, ``TESSERA_CONFIG_FILE`` or the default."""
    if config_path:
        return Path(config_path)
    override = os.getenv("TESSERA_CONFIG_FILE")
    if override:
        return Path(override)
    return DEFAULT_CONFIG_PATH


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load CLI configuration JSON; empty dict when absent/unreadable."""
    path = _resolve_config_path(config_path)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(config: Dict[str, Any], config_path: Optional[str] = None) -> Path:
    """Persist configuration JSON with ``0600`` permissions.

    The parent directory is created ``0700`` when we own it. Returns the
    path written.
    """
    path = _resolve_config_path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent == Path.home() / ".tessera":
        os.chmod(path.parent, stat.S_IRWXU)  # 0700

    payload = json.dumps(config, indent=2, sort_keys=True, default=str) + "\n"
    # O_NOFOLLOW avoids symlink swaps; 0600 at creation.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(str(path), flags, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except Exception:
        raise
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # enforce even if file existed
    return path


def is_secret_key(key: str) -> bool:
    """True when a config key looks secret and should be masked in output."""
    lowered = key.lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def mask_value(value: Any) -> str:
    """Mask all but the last four characters of a value for display."""
    text = str(value)
    if len(text) <= 4:
        return "*" * max(len(text), 4)
    return f"{'*' * 8}…{text[-4:]}"


# ---------------------------------------------------------------------------
# database access (honest, never faked)
# ---------------------------------------------------------------------------

def load_auth_config():
    """Build ``AuthConfig`` from the environment (.env honored when present)."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    from tessera.config import AuthConfig

    return AuthConfig.from_env()


#: Process-wide registry of connected memory databases. The in-memory backend
#: has no persistence by design; reusing one instance per process lets CLI
#: commands (and tests) see each other's writes within a single process.
_memory_dbs: Dict[str, Any] = {}


async def get_connected_db(config: Optional[Any] = None):
    """Create and connect the configured database, or ``None``.

    Never raises: callers render "not configured" guidance on ``None``.
    """
    from tessera.db import get_database

    if config is None:
        try:
            config = load_auth_config()
        except Exception:
            return None

    db_config = getattr(config, "database", None)
    db_type = getattr(db_config, "db_type", None)
    if db_type != "memory" and not getattr(db_config, "connection_string", ""):
        return None  # not configured: nothing to connect to (§9 honesty)
    try:
        if db_type == "memory":
            db = _memory_dbs.get("memory")
            if db is None:
                db = get_database(config)
                await db.connect()
                _memory_dbs["memory"] = db
            return db
        db = get_database(config)
        await db.connect()
        return db
    except Exception:
        return None


def db_guidance() -> str:
    """Guidance text printed when no database is reachable."""
    return (
        "Database not configured or unreachable.\n"
        "Set TESSERA_DB_TYPE (sql|mongodb|dynamodb|memory) and TESSERA_DB_URL, "
        "e.g. for local development:\n"
        "  TESSERA_DB_TYPE=memory  (no persistence, single process)\n"
        "  TESSERA_DB_TYPE=sql TESSERA_DB_URL=sqlite+aiosqlite:///./tessera.db\n"
        "Run 'tessera doctor' for full diagnostics."
    )


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------

def create_table(title: str, columns: list) -> Table:
    """Create a formatted table."""
    table = Table(title=title, show_header=True, header_style="bold blue")
    for col in columns:
        table.add_column(col)
    return table


def confirm_action(message: str, default: bool = False) -> bool:
    """Prompt for confirmation."""
    return Confirm.ask(message, default=default)


def prompt_input(message: str, password: bool = False, default: Optional[str] = None) -> str:
    """Prompt for user input."""
    return Prompt.ask(message, password=password, default=default)


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"[red]✗[/red] {message}")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")
