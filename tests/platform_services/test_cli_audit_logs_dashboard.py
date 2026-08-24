"""``authy audit`` / ``authy logs`` / dashboard honesty tests."""

from __future__ import annotations

import asyncio
import csv
import io
import json

from authy_package.cli import cli


def _seed_events(db):
    async def seed():
        await db.save_audit_event(
            {"event_type": "auth.login", "actor": "alice", "target": "session-1"}
        )
        await db.save_audit_event(
            {"event_type": "auth.logout", "actor": "bob", "target": "session-2"}
        )

    asyncio.run(seed())


def test_audit_search_shows_real_events(runner, memory_db):
    _seed_events(memory_db)
    result = runner.invoke(cli, ["audit", "search"])
    assert result.exit_code == 0, result.output
    assert "auth.login" in result.output
    assert "alice" in result.output
    assert "2 total" in result.output


def test_audit_search_filters_by_type_and_json(runner, memory_db):
    _seed_events(memory_db)
    result = runner.invoke(
        cli, ["audit", "search", "-t", "auth.login", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["total"] == 1
    assert payload["events"][0]["event_type"] == "auth.login"


def test_audit_export_json_and_csv_files(runner, memory_db, tmp_path):
    _seed_events(memory_db)

    json_out = tmp_path / "events.json"
    result = runner.invoke(cli, ["audit", "export", "-f", "json", "-o", str(json_out)])
    assert result.exit_code == 0, result.output
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["exported"] == 2

    csv_out = tmp_path / "events.csv"
    result = runner.invoke(cli, ["audit", "export", "-f", "csv", "-o", str(csv_out)])
    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(io.StringIO(csv_out.read_text(encoding="utf-8"))))
    assert len(rows) == 2
    assert {r["event_type"] for r in rows} == {"auth.login", "auth.logout"}


def test_audit_search_without_db_guidance(runner, monkeypatch):
    monkeypatch.setenv("AUTHY_DB_TYPE", "sql")
    result = runner.invoke(cli, ["audit", "search"])
    assert result.exit_code == 1
    assert "not configured" in result.output


def test_logs_one_shot_lists_events(runner, memory_db):
    _seed_events(memory_db)
    result = runner.invoke(cli, ["logs"])
    assert result.exit_code == 0, result.output
    assert "auth.login" in result.output
    assert "auth.logout" in result.output


def test_logs_follow_polls_honestly_with_bounded_iterations(runner, memory_db):
    _seed_events(memory_db)
    result = runner.invoke(
        cli, ["logs", "--follow", "--interval", "0.05", "--iterations", "2"]
    )
    assert result.exit_code == 0, result.output
    assert "Polling audit log" in result.output
    assert "poll, not a live stream" in result.output


def test_dashboard_renders_not_connected_without_db(runner, monkeypatch):
    monkeypatch.setenv("AUTHY_DB_TYPE", "sql")
    monkeypatch.delenv("AUTHY_DB_URL", raising=False)
    result = runner.invoke(cli, ["dashboard"])
    assert result.exit_code == 0, result.output
    assert "not connected" in result.output
    # Footer must not advertise keybindings that do nothing.
    assert "Press 'q'" not in result.output


def test_dashboard_renders_real_counts_with_memory_db(runner, memory_db):
    async def seed():
        await memory_db.create_user({"email": "x@example.com", "username": "x"})

    asyncio.run(seed())
    result = runner.invoke(cli, ["dashboard"])
    assert result.exit_code == 0, result.output
    assert "not connected" not in result.output
    assert "healthy" in result.output
