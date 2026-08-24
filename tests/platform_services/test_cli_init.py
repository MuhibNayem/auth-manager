"""``tessera init`` tests — real templates, generated secrets, no placeholders."""

from __future__ import annotations

import re
from pathlib import Path

from tessera.cli import cli

PLACEHOLDER_MARKERS = ("change-me", "changeme", "placeholder", "your-secret")


def _scaffold(runner, tmp_path: Path, framework: str) -> Path:
    result = runner.invoke(
        cli, ["init", "--name", "demo", "-f", framework, "-d", "sqlite", "-y"]
    )
    assert result.exit_code == 0, result.output
    return tmp_path / "demo"


def _env_secret(project: Path) -> str:
    env = (project / ".env").read_text(encoding="utf-8")
    match = re.search(r"^TESSERA_JWT_SECRET=(.+)$", env, re.MULTILINE)
    assert match, "TESSERA_JWT_SECRET missing from generated .env"
    return match.group(1).strip()


def test_init_env_has_real_generated_secret(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    project = _scaffold(runner, tmp_path, "fastapi")

    secret = _env_secret(project)
    assert len(secret) >= 40  # secrets.token_urlsafe(48)
    lowered = secret.lower()
    assert not any(marker in lowered for marker in PLACEHOLDER_MARKERS)

    # .env.example must NOT contain the generated secret.
    example = (project / ".env.example").read_text(encoding="utf-8")
    assert secret not in example


def test_init_fastapi_template_uses_real_import_path(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    project = _scaffold(runner, tmp_path, "fastapi")

    main = (project / "src" / "main.py").read_text(encoding="utf-8")
    assert "tessera.frameworks.fastapi_adapter" in main
    assert "tessera.fastapi_adapter" not in main  # old bogus path
    assert "FastAPIAuth" in main
    assert "127.0.0.1" in main  # dev server binds localhost


def test_init_django_template_uses_parity_api_only(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    project = _scaffold(runner, tmp_path, "django")

    views = (project / "src" / "views.py").read_text(encoding="utf-8")
    assert "tessera.frameworks.django_adapter" in views
    # Only the §10 parity methods are referenced.
    for method in ("require_auth", "require_role", "rate_limit", "optional_auth"):
        assert f"django_auth.{method}" in views
    # request.tessera_user, never clobbering request.user.
    assert "tessera_user" in views
    assert "request.user =" not in views


def test_init_creates_migrations_dir_with_sample(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    project = _scaffold(runner, tmp_path, "none")

    sample = project / "tessera_migrations" / "0001_sample.py"
    assert sample.exists()
    content = sample.read_text(encoding="utf-8")
    assert "async def upgrade(db)" in content
    assert "async def downgrade(db)" in content


def test_init_no_hardcoded_passwords_anywhere(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    project = _scaffold(runner, tmp_path, "flask")

    for path in project.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "secure-password-123" not in text
            assert "password = " not in text.lower() or "USER:PASSWORD" in text
