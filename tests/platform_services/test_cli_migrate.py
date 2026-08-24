"""``tessera migrate`` CLI tests — real migrations, schema_migrations ledger."""

from __future__ import annotations

from tessera.cli import cli

FAILING_MIGRATION = '''"""Fails on purpose."""


async def upgrade(db):
    raise RuntimeError("boom")


async def downgrade(db):
    pass
'''


async def _ledger(db):
    return await db.get_setting("schema_migrations")


def test_migrate_create_run_status(runner, memory_db, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli, ["migrate", "create", "-n", "add flag"])
    assert result.exit_code == 0, result.output
    migrations = list((tmp_path / "tessera_migrations").glob("*.py"))
    assert len(migrations) == 1
    assert migrations[0].name.endswith("_add_flag.py")
    version = migrations[0].stem

    result = runner.invoke(cli, ["migrate", "status"])
    assert result.exit_code == 0, result.output
    assert "pending" in result.output

    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 0, result.output
    assert "Applied" in result.output

    # Ledger is tracked in the db settings kv under schema_migrations.
    import asyncio

    applied = asyncio.run(_ledger(memory_db))
    assert isinstance(applied, list) and len(applied) == 1
    assert applied[0]["version"] == version
    assert applied[0]["applied_at"]

    result = runner.invoke(cli, ["migrate", "status"])
    assert result.exit_code == 0, result.output
    assert "applied" in result.output

    # Idempotent: running again applies nothing.
    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 0
    assert "No pending migrations" in result.output


def test_migrate_failed_migration_exits_nonzero(runner, memory_db, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "tessera_migrations").mkdir()
    (tmp_path / "tessera_migrations" / "0001_ok.py").write_text(
        'async def upgrade(db):\n    await db.set_setting("m1", True)\n\n'
        'async def downgrade(db):\n    await db.set_setting("m1", None)\n',
        encoding="utf-8",
    )
    (tmp_path / "tessera_migrations" / "0002_bad.py").write_text(
        FAILING_MIGRATION, encoding="utf-8"
    )

    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 1, result.output
    assert "Failed migration" in result.output
    assert "0002_bad" in result.output

    import asyncio

    applied = asyncio.run(_ledger(memory_db))
    versions = [entry["version"] for entry in applied or []]
    assert "0001_ok" in versions
    assert "0002_bad" not in versions  # no fake success


def test_migrate_rollback(runner, memory_db, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli, ["migrate", "create", "-n", "seed"])
    assert result.exit_code == 0

    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 0, result.output

    result = runner.invoke(cli, ["migrate", "rollback"])
    assert result.exit_code == 0, result.output
    assert "Rolled back" in result.output

    import asyncio

    applied = asyncio.run(_ledger(memory_db))
    assert applied == [] or applied is None


def test_migrate_run_without_directory_fails(runner, memory_db, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 1
    assert "tessera_migrations" in result.output


def test_migrate_run_without_db_fails_with_guidance(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tessera_migrations").mkdir()
    monkeypatch.setenv("TESSERA_DB_TYPE", "sql")
    monkeypatch.delenv("TESSERA_DB_URL", raising=False)

    result = runner.invoke(cli, ["migrate", "run"])
    assert result.exit_code == 1
    assert "not configured" in result.output
