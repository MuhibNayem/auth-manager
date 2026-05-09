"""
CLI Utility Functions - Enterprise Grade
"""
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Callable
from functools import wraps

import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


def async_command(func: Callable) -> Callable:
    """Decorator to run async commands in Click."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper


async def fetch_with_progress(url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Fetch data with progress indicator."""
    async with aiohttp.ClientSession() as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Fetching...", total=None)
            try:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    return await response.json()
            except Exception as e:
                console.print(f"[red]Error fetching {url}: {e}[/red]")
                raise


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or environment."""
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                return json.load(f)
    
    # Try default locations
    default_paths = [
        Path.cwd() / 'authy.config.json',
        Path.home() / '.authy' / 'config.json',
        Path('/etc/authy/config.json')
    ]
    
    for path in default_paths:
        if path.exists():
            with open(path) as f:
                return json.load(f)
    
    # Fall back to environment variables
    return {
        'api_key': os.getenv('AUTHY_API_KEY'),
        'api_secret': os.getenv('AUTHY_API_SECRET'),
        'region': os.getenv('AUTHY_REGION', 'us-east-1'),
        'environment': os.getenv('AUTHY_ENV', 'development')
    }


def save_config(config: Dict[str, Any], config_path: Optional[str] = None) -> None:
    """Save configuration to file."""
    if not config_path:
        config_dir = Path.home() / '.authy'
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / 'config.json'
    else:
        config_path = Path(config_path)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    console.print(f"[green]✓[/green] Configuration saved to [bold]{config_path}[/bold]")


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
