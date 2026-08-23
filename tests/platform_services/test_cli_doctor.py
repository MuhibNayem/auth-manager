"""``authy doctor`` CLI tests — honest pass/fail with real exit codes."""

from __future__ import annotations

import secrets

from authy_package.cli import cli


def test_doctor_fails_when_config_invalid(runner, monkeypatch):
    """No AUTHY_JWT_SECRET -> ConfigError -> exit code 1."""
    monkeypatch.delenv("AUTHY_JWT_SECRET", raising=False)
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "jwt_secret" in result.output


def test_doctor_passes_with_healthy_memory_db(runner, monkeypatch):
    monkeypatch.setenv("AUTHY_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("AUTHY_DB_TYPE", "memory")
    monkeypatch.setenv("AUTHY_CACHE_ENABLED", "false")

    result = runner.invoke(cli, ["doctor"])
    assert result.output  # render something even on failure for debugging
    assert result.exit_code == 0, result.output
    assert "FAIL" not in result.output
    assert "All checks passed" in result.output


def test_doctor_reports_missing_db_url(runner, monkeypatch):
    """sql backend without AUTHY_DB_URL must fail the database check."""
    monkeypatch.setenv("AUTHY_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("AUTHY_DB_TYPE", "sql")
    monkeypatch.delenv("AUTHY_DB_URL", raising=False)
    monkeypatch.setenv("AUTHY_CACHE_ENABLED", "false")

    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 1
    assert "AUTHY_DB_URL" in result.output


def test_doctor_reports_optional_extras_honestly(runner, monkeypatch):
    """Missing optional extras are reported but do not fail the run."""
    monkeypatch.setenv("AUTHY_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("AUTHY_DB_TYPE", "memory")
    monkeypatch.setenv("AUTHY_CACHE_ENABLED", "false")

    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0, result.output
    # At least one extra was probed and reported.
    assert "Extra:" in result.output
