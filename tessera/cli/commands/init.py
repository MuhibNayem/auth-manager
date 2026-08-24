"""``tessera init`` — project scaffolding with REAL templates (CONTRACTS.md §9).

Generated artifacts use only real import paths (``tessera.frameworks``
adapters and their §10 parity API: ``require_auth`` / ``require_role`` /
``rate_limit`` / ``optional_auth``). The generated ``.env`` receives a fresh
``TESSERA_JWT_SECRET`` from ``secrets.token_urlsafe(48)`` — never a
placeholder — and no hardcoded passwords are written anywhere.

An ``tessera_migrations/`` directory with one sample migration is included so
``tessera migrate`` works out of the box.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.prompt import Confirm, Prompt

from ..utils import print_success

console = Console()

ALL_FEATURES = ["mfa", "social", "webhooks", "audit", "organizations", "saml", "oidc"]

DB_URL_TEMPLATES = {
    "postgresql": "postgresql+asyncpg://USER:PASSWORD@localhost:5432/tessera",
    "mysql": "mysql+aiomysql://USER:PASSWORD@localhost:3306/tessera",
    "sqlite": "sqlite+aiosqlite:///./tessera.db",
    "mongodb": "mongodb://localhost:27017",
    "dynamodb": "",
}

DB_TYPE_MAP = {
    "postgresql": "sql",
    "mysql": "sql",
    "sqlite": "sql",
    "mongodb": "mongodb",
    "dynamodb": "dynamodb",
}


@click.command(name="init")
@click.option("--name", "-n", help="Project name (default: current directory name)")
@click.option("--framework", "-f", type=click.Choice(["fastapi", "flask", "django", "none"]),
              help="Web framework")
@click.option("--database", "-d",
              type=click.Choice(["postgresql", "mysql", "sqlite", "mongodb", "dynamodb"]),
              help="Database type")
@click.option("--features", multiple=True, type=click.Choice(ALL_FEATURES),
              help="Enable features (repeatable)")
@click.option("--force", is_flag=True, help="Continue even if the directory is not empty")
@click.option("--yes", "-y", is_flag=True, help="Non-interactive: accept defaults, skip prompts")
def init_cmd(name: Optional[str], framework: Optional[str], database: Optional[str],
             features: tuple, force: bool, yes: bool):
    """Initialize a new Tessera project (honest, runnable scaffolding)."""
    project_dir = Path.cwd() / name if name else Path.cwd()
    project_name = name or Path.cwd().name

    if project_dir.exists() and any(project_dir.iterdir()) and not force and not yes:
        if not Confirm.ask(f"Directory {project_dir} is not empty. Continue?"):
            console.print("[yellow]Aborted[/yellow]")
            return

    project_dir.mkdir(parents=True, exist_ok=True)

    if not framework:
        framework = _detect_framework(project_dir)
        if framework is None:
            framework = "fastapi" if yes else Prompt.ask(
                "Select web framework",
                choices=["fastapi", "flask", "django", "none"],
                default="fastapi",
            )
    if not database:
        database = "sqlite" if yes else Prompt.ask(
            "Select database",
            choices=list(DB_URL_TEMPLATES),
            default="sqlite",
        )
    if not features and not yes:
        features = tuple(
            f for f in ALL_FEATURES if Confirm.ask(f"  Enable {f}?", default=False)
        )

    _scaffold(project_dir, project_name, framework, database, list(features))
    print_success(f"Project '{project_name}' initialized.")
    console.print("\nNext steps:")
    console.print(f"  1. [bold]cd {project_dir.name}[/bold]" if name else "  1. stay in this directory")
    console.print("  2. review [bold].env[/bold] (a real TESSERA_JWT_SECRET was generated)")
    console.print("  3. [bold]pip install -r requirements.txt[/bold]")
    console.print("  4. [bold]tessera migrate run[/bold] then [bold]tessera dev[/bold]")


def _detect_framework(project_dir: Path) -> Optional[str]:
    """Detect an existing framework in the directory."""
    if (project_dir / "manage.py").exists():
        return "django"
    for py_file in project_dir.glob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "FastAPI" in content:
            return "fastapi"
        if "Flask" in content:
            return "flask"
    return None


def _scaffold(project_dir: Path, project_name: str, framework: str,
              database: str, features: List[str]) -> None:
    """Write all scaffold files."""
    for sub in ("src", "src/config", "tessera_migrations", "tests"):
        (project_dir / sub).mkdir(parents=True, exist_ok=True)

    _write_env(project_dir, database)
    _write_config_module(project_dir, project_name)
    _write_app_files(project_dir, framework)
    _write_sample_migration(project_dir)
    _write_requirements(project_dir, framework, database, features)
    _write_gitignore(project_dir)
    _write_readme(project_dir, project_name, framework, database, features)


def _write_env(project_dir: Path, database: str) -> None:
    """Write .env with a REAL generated secret + .env.example without one."""
    jwt_secret = secrets.token_urlsafe(48)  # §0.3 — never a placeholder (§9)
    db_type = DB_TYPE_MAP[database]
    db_url = DB_URL_TEMPLATES[database]

    env_lines = [
        "# Generated by `tessera init` — rotate any value you suspect was exposed.",
        "TESSERA_ENV=development",
        f"TESSERA_JWT_SECRET={jwt_secret}",
        f"TESSERA_DB_TYPE={db_type}",
    ]
    if db_url:
        env_lines.append(
            f"# Replace USER:PASSWORD with real credentials (never commit them):\n"
            f"TESSERA_DB_URL={db_url}"
        )
    else:
        env_lines.append("# DynamoDB uses the standard AWS credential chain:\nAWS_REGION=us-east-1")
    env_lines.append("TESSERA_CACHE_ENABLED=false  # enable + set TESSERA_REDIS_URL when ready")

    (project_dir / ".env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    example = "\n".join(env_lines).replace(jwt_secret, "")
    (project_dir / ".env.example").write_text(
        example + "\n# Generate a secret with: "
        "python -c 'import secrets; print(secrets.token_urlsafe(48))'\n",
        encoding="utf-8",
    )


def _write_config_module(project_dir: Path, project_name: str) -> None:
    """src/config/auth_config.py using only real package APIs."""
    content = f'''"""Tessera configuration for {project_name} (generated by `tessera init`)."""

import asyncio

from tessera import AuthConfig, AuthManager
from tessera.db import get_database


def build_config() -> AuthConfig:
    """Load and validate configuration from the environment (.env)."""
    config = AuthConfig.from_env()
    config.validate()  # raises ConfigError on invalid configuration
    return config


config = build_config()
db = get_database(config)
auth = AuthManager(config)


async def connect() -> None:
    """Connect the database (call once at application startup)."""
    await db.connect()


if __name__ == "__main__":
    async def _main() -> None:
        await connect()
        healthy = await db.health_check()
        print("database healthy:", healthy)
        await db.close()

    asyncio.run(_main())
'''
    (project_dir / "src" / "config" / "auth_config.py").write_text(content, encoding="utf-8")


def _write_app_files(project_dir: Path, framework: str) -> None:
    """Framework boilerplate using the §10 adapter parity API only."""
    if framework == "fastapi":
        content = '''"""FastAPI application wired to Tessera (generated by `tessera init`)."""

from fastapi import Depends, FastAPI

# Real import path (CONTRACTS.md §10):
from tessera.frameworks.fastapi_adapter import FastAPIAuth

from src.config.auth_config import auth, connect, db

app = FastAPI(title="Tessera App")
fastapi_auth = FastAPIAuth(auth)


@app.on_event("startup")
async def startup() -> None:
    await connect()


@app.get("/")
async def root():
    return {"message": "Welcome to Tessera!"}


@app.get("/protected")
async def protected_route(user: dict = Depends(fastapi_auth.require_auth)):
    """Route requiring authentication (§10 require_auth)."""
    return {"user_id": user.get("id"), "status": "authenticated"}


@app.get("/admin")
async def admin_route(user: dict = Depends(fastapi_auth.require_role("admin"))):
    """Admin-only route (§10 require_role)."""
    return {"message": "Admin access granted"}


if __name__ == "__main__":
    import uvicorn

    # Development server binds localhost only.
    uvicorn.run(app, host="127.0.0.1", port=8000)
'''
        (project_dir / "src" / "main.py").write_text(content, encoding="utf-8")

    elif framework == "flask":
        content = '''"""Flask application wired to Tessera (generated by `tessera init`)."""

from flask import Flask, jsonify, request

# Real import path (CONTRACTS.md §10):
from tessera.frameworks.flask_adapter import FlaskAuth

from src.config.auth_config import auth

app = Flask(__name__)
flask_auth = FlaskAuth(auth)


@app.route("/")
def root():
    return jsonify({"message": "Welcome to Tessera!"})


@app.route("/protected")
@flask_auth.require_auth
def protected_route():
    """Route requiring authentication (§10 require_auth)."""
    return jsonify({"status": "authenticated"})


@app.route("/admin")
@flask_auth.require_role("admin")
def admin_route():
    """Admin-only route (§10 require_role)."""
    return jsonify({"message": "Admin access granted"})


if __name__ == "__main__":
    # Development server binds localhost only.
    app.run(debug=True, host="127.0.0.1", port=8000)
'''
        (project_dir / "src" / "app.py").write_text(content, encoding="utf-8")

    elif framework == "django":
        # DjangoAuth parity API after §10: require_auth, require_role,
        # rate_limit, optional_auth. Nothing else is referenced.
        content = '''"""Django views wired to Tessera (generated by `tessera init`).

Uses ONLY the DjangoAuth §10 parity API: require_auth, require_role,
rate_limit, optional_auth. Authenticated user is exposed as
``request.tessera_user`` (Django's ``request.user`` is left untouched).
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

# Real import path (CONTRACTS.md §10):
from tessera.frameworks.django_adapter import DjangoAuth

from src.config.auth_config import auth

django_auth = DjangoAuth(auth)


@require_http_methods(["GET"])
def root(request):
    return JsonResponse({"message": "Welcome to Tessera!"})


@require_http_methods(["GET"])
@django_auth.require_auth
def protected_route(request):
    """View requiring authentication (§10 require_auth)."""
    user = getattr(request, "tessera_user", None) or {}
    return JsonResponse({"user_id": user.get("id"), "status": "authenticated"})


@require_http_methods(["GET"])
@django_auth.require_role("admin")
def admin_route(request):
    """Admin-only view (§10 require_role)."""
    return JsonResponse({"message": "Admin access granted"})


@require_http_methods(["POST"])
@django_auth.rate_limit(5, 300)
@django_auth.optional_auth
def login(request):
    """Login view: rate-limited, auth optional (§10 parity API)."""
    return JsonResponse({"status": "login endpoint"})
'''
        (project_dir / "src" / "views.py").write_text(content, encoding="utf-8")

    else:
        content = '''"""Generic application wired to Tessera (generated by `tessera init`)."""

import asyncio

from src.config.auth_config import connect, db


async def main() -> None:
    await connect()
    total = await db.count_users()
    print(f"connected; users in database: {total}")
    await db.close()


if __name__ == "__main__":
    asyncio.run(main())
'''
        (project_dir / "src" / "app.py").write_text(content, encoding="utf-8")


def _write_sample_migration(project_dir: Path) -> None:
    """tessera_migrations/ with one real sample migration (CONTRACTS.md §9)."""
    content = '''"""Sample migration created by `tessera init`.

Applied versions are tracked in the db settings kv under
``schema_migrations`` (CONTRACTS.md §9).
"""


async def upgrade(db):
    """Example: seed a settings flag via the §4 db contract."""
    await db.set_setting("tessera_sample_migrated", True)


async def downgrade(db):
    """Revert the sample migration."""
    await db.set_setting("tessera_sample_migrated", None)
'''
    (project_dir / "tessera_migrations" / "0001_sample.py").write_text(
        content, encoding="utf-8"
    )


def _write_requirements(project_dir: Path, framework: str, database: str,
                        features: List[str]) -> None:
    """requirements.txt matching the chosen extras."""
    deps = ["tessera>=2.0.0", "rich>=13.0.0", "click>=8.0.0", "python-dotenv>=1.0.0"]
    if framework == "fastapi":
        deps += ["fastapi>=0.100.0", "uvicorn[standard]>=0.23.0"]
    elif framework == "flask":
        deps.append("flask>=2.3.0")
    elif framework == "django":
        deps += ["django>=4.2.0", "asgiref>=3.7.0"]
    if database in ("postgresql", "mysql", "sqlite"):
        deps.append("sqlalchemy[asyncio]>=2.0.0")
    if database == "postgresql":
        deps.append("asyncpg>=0.29.0")
    elif database == "mysql":
        deps.append("aiomysql>=0.2.0")
    elif database == "sqlite":
        deps.append("aiosqlite>=0.19.0")
    elif database == "mongodb":
        deps.append("motor>=3.3.0")
    elif database == "dynamodb":
        deps.append("boto3>=1.28.0")
    if "saml" in features:
        deps.append("pysaml2>=6.5.0")
    if "oidc" in features:
        deps.append("authlib>=1.2.0")
    (project_dir / "requirements.txt").write_text("\n".join(deps) + "\n", encoding="utf-8")


def _write_gitignore(project_dir: Path) -> None:
    (project_dir / ".gitignore").write_text(
        "__pycache__/\n*.py[cod]\n.env\n.venv/\nvenv/\n*.egg-info/\n"
        ".pytest_cache/\ndeploy-out/\n*.db\n",
        encoding="utf-8",
    )


def _write_readme(project_dir: Path, project_name: str, framework: str,
                  database: str, features: List[str]) -> None:
    feature_block = "\n".join(f"- {f}" for f in features) or "- none selected"
    (project_dir / "README.md").write_text(
        f"""# {project_name}

Authentication application scaffolded by `tessera init`.

Framework: **{framework}** — Database: **{database}**

Features:
{feature_block}

## Quick start

```bash
pip install -r requirements.txt
tessera doctor          # verify configuration
tessera migrate run     # apply tessera_migrations/
tessera dev             # start the development server (127.0.0.1)
```

The `.env` file contains a freshly generated `TESSERA_JWT_SECRET`
(`secrets.token_urlsafe(48)`). Rotate it if it was ever exposed; never
commit real credentials.
""",
        encoding="utf-8",
    )
