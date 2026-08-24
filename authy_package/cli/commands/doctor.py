"""``authy doctor`` — honest health checks and diagnostics (CONTRACTS.md §9).

Checks performed (no fake results, ever):
- Python version support
- Core package import + per-extra optional dependency probes
- ``AuthConfig.from_env().validate()``
- Database ``health_check()`` when configured (else "not configured")
- Cache ``health_check()`` when enabled (else "not configured")

Exit code is 1 when any check fails, 0 otherwise.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List, Tuple

import click
from rich.console import Console
from rich.table import Table

console = Console()

#: Optional extras probed by doctor: label -> importable module names.
OPTIONAL_EXTRAS = [
    ("fastapi", ["fastapi"]),
    ("flask", ["flask"]),
    ("django", ["django"]),
    ("postgresql/sql", ["sqlalchemy", "aiosqlite"]),
    ("mongodb", ["motor"]),
    ("dynamodb", ["boto3"]),
    ("redis cache", ["redis"]),
    ("httpx", ["httpx"]),
    ("aiohttp", ["aiohttp"]),
    ("sms (twilio)", ["twilio"]),
    ("captcha (httpx)", ["httpx"]),
    ("oidc (authlib)", ["authlib"]),
    ("webauthn (fido2)", ["fido2"]),
    ("python-dotenv", ["dotenv"]),
]

MIN_PYTHON = (3, 9)


def _probe_modules(names: List[str]) -> Tuple[bool, str]:
    """Import-probe modules; report the first missing one."""
    import importlib

    for name in names:
        try:
            importlib.import_module(name)
        except ImportError:
            return False, f"missing '{name}'"
        except Exception as exc:  # broken install
            return False, f"'{name}' failed to import: {exc}"
    return True, "present"


async def _check_database(config) -> Tuple[bool, str]:
    """Connect + health_check the configured database."""
    from authy_package.db import get_database

    db_type = config.database.db_type
    if db_type == "memory":
        detail = "memory backend (in-process only, no persistence)"
    elif not config.database.connection_string:
        return False, f"db_type '{db_type}' but AUTHY_DB_URL is not set"
    else:
        detail = f"db_type '{db_type}'"

    try:
        db = get_database(config)
        await db.connect()
        try:
            healthy = await asyncio.wait_for(db.health_check(), timeout=5.0)
        finally:
            try:
                await db.close()
            except Exception:
                pass
    except Exception as exc:
        return False, f"{detail} — connect failed: {exc}"
    if not healthy:
        return False, f"{detail} — health_check() returned False"
    return True, f"{detail} — healthy"


async def _check_cache(config) -> Tuple[bool, str]:
    """health_check the configured Redis cache."""
    if not config.cache.enabled:
        return True, "cache disabled (not configured)"
    try:
        from authy_package.cache import RedisCache

        cache = RedisCache(config.cache.redis_url)
        try:
            healthy = await asyncio.wait_for(cache.health_check(), timeout=5.0)
        finally:
            try:
                await cache.close()
            except Exception:
                pass
    except ImportError:
        return False, "cache enabled but 'redis' package is not installed"
    except asyncio.TimeoutError:
        return False, f"redis unreachable at {config.cache.redis_url} (timeout)"
    except Exception as exc:
        return False, f"redis check failed: {exc}"
    if not healthy:
        return False, f"redis at {config.cache.redis_url} failed health_check()"
    return True, f"redis reachable at {config.cache.redis_url}"


async def collect_checks() -> Tuple[List[Tuple[str, bool, str]], int]:
    """Run all diagnostics; returns ``(rows, failure_count)``."""
    rows: List[Tuple[str, bool, str]] = []

    # 1. Python version
    py_ok = sys.version_info >= MIN_PYTHON
    rows.append((
        "Python version",
        py_ok,
        f"{sys.version.split()[0]} (requires >= {'.'.join(map(str, MIN_PYTHON))})",
    ))

    # 2. Core import
    try:
        import authy_package

        rows.append(("Core import", True, f"authy_package {authy_package.__version__}"))
    except Exception as exc:
        rows.append(("Core import", False, f"import failed: {exc}"))
        return rows, sum(1 for _, ok, _ in rows if not ok)

    # 3. Optional extras — reported present/missing; a missing OPTIONAL extra
    #    is information, not a failure.
    for extra_label, modules in OPTIONAL_EXTRAS:
        present, detail = _probe_modules(modules)
        rows.append((
            f"Extra: {extra_label}",
            True,
            detail if present else f"missing (optional) — {detail}",
        ))

    # 4. Config validation
    try:
        from authy_package.cli.utils import load_auth_config

        config = load_auth_config()
        config.validate()
        rows.append(("Config validation", True, f"AuthConfig valid (env={config.env})"))
        config_ok = True
    except Exception as exc:
        rows.append(("Config validation", False, str(exc)))
        config_ok = False

    # 5/6. Database + cache (only meaningful when config itself is usable)
    if config_ok:
        try:
            from authy_package.cli.utils import load_auth_config as _lc

            cfg = _lc()
            db_ok, db_detail = await _check_database(cfg)
            rows.append(("Database health", db_ok, db_detail))
        except Exception as exc:
            rows.append(("Database health", False, str(exc)))
        try:
            cache_ok, cache_detail = await _check_cache(cfg)
            rows.append(("Cache health", cache_ok, cache_detail))
        except Exception as exc:
            rows.append(("Cache health", False, str(exc)))
    else:
        rows.append(("Database health", False, "skipped: config invalid"))
        rows.append(("Cache health", False, "skipped: config invalid"))

    failures = sum(1 for _, ok, _ in rows if not ok)
    return rows, failures


@click.command(name="doctor")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def doctor_cmd(verbose: bool):
    """Run comprehensive health checks and diagnostics."""
    rows, failures = asyncio.run(collect_checks())

    table = Table(title="Authy Health Check", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim", overflow="fold")

    for name, ok, detail in rows:
        status = "[green]✓ PASS[/green]" if ok else "[red]✗ FAIL[/red]"
        table.add_row(name, status, detail)

    console.print(table)
    if failures:
        console.print(f"\n[red]✗ {failures} check(s) failed[/red]")
        sys.exit(1)
    console.print("\n[green]✓ All checks passed[/green]")
