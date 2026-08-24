"""Session manager tests: type enforcement, rotation, eviction, revocation."""

from __future__ import annotations

import asyncio

import pytest

from tessera.sessions.session_manager import (
    SESSION_KEY_TEMPLATE,
    USER_SESSIONS_KEY_TEMPLATE,
    Session,
    SessionManager,
)


@pytest.fixture
def sm(config, db, cache):
    return SessionManager(config, db, cache)


async def test_create_session_persists_db_and_cache(sm, db, cache):
    session = await sm.create_session("user-1", device_info={"device_id": "d1"})
    assert isinstance(session, Session)

    db_record = await db.get_session(session.id)
    assert db_record is not None
    assert db_record["user_id"] == "user-1"
    assert db_record["status"] == "active"

    cached = await cache.get_json(SESSION_KEY_TEMPLATE.format(session_id=session.id))
    assert cached is not None
    assert cached["id"] == session.id

    indexed = await cache.lrange(USER_SESSIONS_KEY_TEMPLATE.format(user_id="user-1"), 0, -1)
    assert session.id in indexed


async def test_validate_session_accepts_access_rejects_refresh(sm):
    session = await sm.create_session("user-2")
    good = await sm.validate_session(session.access_token)
    assert good is not None and good.id == session.id

    # A refresh token must NOT validate as an access session.
    assert await sm.validate_session(session.refresh_token) is None


async def test_validate_session_rejects_after_revoke(sm):
    session = await sm.create_session("user-3")
    await sm.revoke_session(session.id)
    assert await sm.validate_session(session.access_token) is None


async def test_refresh_session_rotates_tokens(sm):
    session = await sm.create_session("user-4")
    old_access, old_refresh = session.access_token, session.refresh_token

    refreshed = await sm.refresh_session(session.refresh_token)
    assert refreshed is not None
    assert refreshed.access_token != old_access
    assert refreshed.refresh_token != old_refresh

    # The OLD refresh token is dead after rotation.
    assert await sm.refresh_session(old_refresh) is None
    # The NEW refresh token works.
    assert (await sm.refresh_session(refreshed.refresh_token)) is not None


async def test_eviction_beyond_max_concurrent(make_config, db, cache):
    config = make_config(max_concurrent_sessions=2)
    sm = SessionManager(config, db, cache)
    s1 = await sm.create_session("user-5")
    await asyncio.sleep(0.01)
    s2 = await sm.create_session("user-5")
    await asyncio.sleep(0.01)
    s3 = await sm.create_session("user-5")  # should evict the oldest (s1)

    active = await db.get_active_sessions("user-5")
    active_ids = {r["id"] for r in active}
    assert len(active) == 2
    assert s1.id not in active_ids
    assert s2.id in active_ids and s3.id in active_ids


async def test_revoke_all_user_sessions(sm, db):
    await sm.create_session("user-6")
    await sm.create_session("user-6")
    revoked = await sm.revoke_all_user_sessions("user-6")
    assert revoked == 2
    assert await db.get_active_sessions("user-6") == []


async def test_last_active_update_retains_task_and_advances(sm):
    session = await sm.create_session("user-7")
    before = session.last_active
    await asyncio.sleep(0.02)
    assert await sm.validate_session(session.access_token) is not None
    # Let the fire-and-forget last-active task complete.
    await asyncio.gather(*list(sm._background_tasks), return_exceptions=True)
    record = await sm.db.get_session(session.id)
    assert record["last_active"] >= before.isoformat()
