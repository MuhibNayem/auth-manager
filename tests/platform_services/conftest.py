"""Shared fixtures for platform-services tests (CONTRACTS.md §0.10).

Everything runs against the in-memory fakes (InMemoryCache /
InMemoryDatabase) — no network, no docker, no external services.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

#: Env vars wiped before every test so AuthConfig.from_env is deterministic.
_ENV_PREFIXES = (
    "TESSERA_",
    "TWILIO_",
    "HCAPTCHA_",
    "RECAPTCHA_",
    "AWS_",
    "MAILJET_",
    "SENDGRID_",
    "SES_",
    "GOOGLE_",
    "GITHUB_",
    "FACEBOOK_",
    "APPLE_",
    "SENDER_",
    "HIBP_",
)


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    """Wipe auth-related env vars and reset the CLI memory-db registry."""
    for var in list(os.environ):
        if var.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("TESSERA_CONFIG_FILE", raising=False)

    from tessera.cli import utils as cli_utils

    cli_utils._memory_dbs.clear()
    yield
    cli_utils._memory_dbs.clear()


@pytest.fixture
def runner(monkeypatch) -> CliRunner:
    """Click test runner with a wide viewport (no rich truncation)."""
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("LINES", "50")
    return CliRunner()


@pytest.fixture
def memory_db(monkeypatch):
    """A fresh InMemoryDatabase registered as the CLI's connected database.

    The CLI resolves ``TESSERA_DB_TYPE=memory`` through a per-process registry;
    seeding it here lets CliRunner invocations share this exact instance.
    """
    monkeypatch.setenv("TESSERA_DB_TYPE", "memory")

    from tessera.cli import utils as cli_utils
    from tessera.db import InMemoryDatabase

    db = InMemoryDatabase()
    cli_utils._memory_dbs["memory"] = db
    return db
