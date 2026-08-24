"""``tessera config`` — CLI configuration persisted as JSON (§9).

Storage: ``~/.tessera/config.json`` (override with ``--file`` or
``TESSERA_CONFIG_FILE``). Files are written ``0600`` (§0.8); values whose key
looks secret are masked in ``show`` output but returned verbatim by ``get``.
"""

from __future__ import annotations

import json
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..utils import (
    _resolve_config_path,
    is_secret_key,
    load_config,
    mask_value,
    save_config,
)

console = Console()


@click.group(name="config")
def config_cmd():
    """Manage the local Tessera CLI configuration (~/.tessera/config.json, 0600)."""


@config_cmd.command("show")
@click.option("--file", "-F", "config_file", default=None, help="Config file path")
@click.option("--reveal", is_flag=True, help="Show secret values unmasked (careful)")
def show(config_file: Optional[str], reveal: bool):
    """Show the current configuration (secret values masked by default)."""
    config = load_config(config_file)
    path = _resolve_config_path(config_file)
    if not config:
        console.print(f"[yellow]No configuration found at {path}[/yellow]")
        console.print("[dim]Use 'tessera config set KEY VALUE' to create it.[/dim]")
        return

    table = Table(title=f"Configuration ({path})")
    table.add_column("Key", style="cyan")
    table.add_column("Value")

    for key in sorted(config):
        value = config[key]
        if is_secret_key(key) and not reveal:
            rendered = mask_value(value)
        else:
            rendered = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
        table.add_row(key, rendered)
    console.print(table)


@config_cmd.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--file", "-F", "config_file", default=None, help="Config file path")
@click.option("--json-value", is_flag=True, help="Parse VALUE as JSON (numbers, bools, objects)")
def set_value(key: str, value: str, config_file: Optional[str], json_value: bool):
    """Set a configuration value (persisted 0600)."""
    if not key.strip():
        console.print("[red]✗ KEY must not be empty[/red]")
        raise click.exceptions.Exit(2)

    if json_value:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            console.print(f"[red]✗ VALUE is not valid JSON: {exc}[/red]")
            raise click.exceptions.Exit(2)
    else:
        parsed = value

    config = load_config(config_file)
    config[key] = parsed
    path = save_config(config, config_file)
    console.print(f"[green]✓ Set {key}[/green] [dim]({path}, mode 0600)[/dim]")


@config_cmd.command("get")
@click.argument("key")
@click.option("--file", "-F", "config_file", default=None, help="Config file path")
def get_value(key: str, config_file: Optional[str]):
    """Get a configuration value (verbatim, machine-readable)."""
    config = load_config(config_file)
    if key not in config:
        console.print(f"[yellow]Key {key!r} not set[/yellow]")
        raise click.exceptions.Exit(1)
    value = config[key]
    click.echo(json.dumps(value) if isinstance(value, (dict, list)) else str(value))
