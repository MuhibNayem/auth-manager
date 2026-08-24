"""``tessera users`` CLI tests against a seeded InMemoryDatabase."""

from __future__ import annotations

import asyncio

from tessera.cli import cli


def _seed(db):
    async def seed():
        await db.create_user(
            {
                "username": "alice",
                "email": "alice@example.com",
                "hashed_password": "$2b$12$notarealhash",
                "role": "admin",
            }
        )
        await db.create_user(
            {
                "username": "bob",
                "email": "bob@example.com",
                "hashed_password": "$2b$12$anotherhash",
                "role": "user",
                "is_active": False,
            }
        )

    asyncio.run(seed())


def test_users_list_shows_seeded_users(runner, memory_db):
    _seed(memory_db)
    result = runner.invoke(cli, ["users", "list"])
    assert result.exit_code == 0, result.output
    assert "alice@example.com" in result.output
    assert "bob@example.com" in result.output
    assert "2 total" in result.output
    # Password hashes must never be rendered.
    assert "notarealhash" not in result.output


def test_users_list_without_db_prints_guidance(runner, monkeypatch):
    monkeypatch.setenv("TESSERA_DB_TYPE", "sql")
    monkeypatch.delenv("TESSERA_DB_URL", raising=False)
    result = runner.invoke(cli, ["users", "list"])
    assert result.exit_code == 1
    assert "not configured" in result.output


def test_users_get_by_email(runner, memory_db):
    _seed(memory_db)
    result = runner.invoke(cli, ["users", "get", "--email", "ALICE@example.com"])
    assert result.exit_code == 0, result.output
    assert "alice" in result.output
    assert "admin" in result.output


def test_users_get_not_found(runner, memory_db):
    result = runner.invoke(cli, ["users", "get", "--email", "ghost@example.com"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_users_delete_requires_confirmation(runner, memory_db):
    _seed(memory_db)
    user_id = next(
        uid for uid, u in memory_db._users.items() if u["email"] == "alice@example.com"
    )

    # Declining leaves the user intact.
    result = runner.invoke(cli, ["users", "delete", user_id], input="n\n")
    assert "Aborted" in result.output
    assert result.exit_code == 1

    # Confirming deletes for real.
    result = runner.invoke(cli, ["users", "delete", user_id], input="y\n")
    assert result.exit_code == 0, result.output
    assert "Deleted user" in result.output

    lookup = asyncio.run(memory_db.get_user_by_id(user_id))
    assert lookup is None


def test_users_delete_with_yes_flag(runner, memory_db):
    _seed(memory_db)
    user_id = next(
        uid for uid, u in memory_db._users.items() if u["email"] == "bob@example.com"
    )
    result = runner.invoke(cli, ["users", "delete", user_id, "--yes"])
    assert result.exit_code == 0, result.output
    assert asyncio.run(memory_db.get_user_by_id(user_id)) is None


def test_users_delete_missing_user(runner, memory_db):
    result = runner.invoke(cli, ["users", "delete", "does-not-exist", "--yes"])
    assert result.exit_code == 1
    assert "not found" in result.output
