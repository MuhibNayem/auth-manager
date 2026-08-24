"""Webhook tests: SSRF validation, signatures, retries, secret masking."""

from __future__ import annotations

import json
import socket
import time

import httpx
import pytest
import pytest_asyncio

from tessera.cache import InMemoryCache
from tessera.webhooks.webhook_manager import (
    RETRY_DELAYS_SECONDS,
    WEBHOOK_QUEUE_KEY,
    WebhookEventType,
    WebhookManager,
    canonical_payload_bytes,
    sign_payload,
    validate_endpoint_url,
)


def _addrinfo_for(ip: str):
    """Build a getaddrinfo-style result list for one IPv4 address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))]


@pytest.fixture
def fake_dns(monkeypatch):
    """Patch DNS resolution inside the webhook module (no real network)."""

    def _install(mapping: dict):
        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host in mapping:
                return _addrinfo_for(mapping[host])
            raise socket.gaierror(f"no such host: {host}")

        monkeypatch.setattr(
            "tessera.webhooks.webhook_manager.socket.getaddrinfo",
            fake_getaddrinfo,
        )

    return _install


@pytest.mark.asyncio
async def test_registration_rejects_forbidden_targets(client, admin_headers, fake_dns):
    """http loopback, metadata IP and private IPs are all rejected (400)."""
    fake_dns(
        {
            "127.0.0.1": "127.0.0.1",
            "169.254.169.254": "169.254.169.254",
            "10.0.0.5": "10.0.0.5",
        }
    )
    for url in (
        "http://127.0.0.1/hooks",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/hooks",
    ):
        response = await client.post(
            "/admin/api/v1/webhooks", headers=admin_headers, json={"url": url}
        )
        assert response.status_code == 400, (url, response.text)


@pytest.mark.asyncio
async def test_registration_rejects_https_hostname_resolving_to_private_ip(
    client, admin_headers, fake_dns
):
    fake_dns({"internal.example.com": "192.168.1.10"})
    response = await client.post(
        "/admin/api/v1/webhooks",
        headers=admin_headers,
        json={"url": "https://internal.example.com/hooks"},
    )
    assert response.status_code == 400
    assert "forbidden address" in response.json()["message"]


@pytest.mark.asyncio
async def test_registration_succeeds_for_public_host_and_masks_secret(
    client, admin_headers, fake_dns
):
    fake_dns({"hooks.example.com": "93.184.216.34"})
    created = await client.post(
        "/admin/api/v1/webhooks",
        headers=admin_headers,
        json={"url": "https://hooks.example.com/hooks", "events": []},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert len(body["secret"]) == 64  # shown once at registration

    listed = await client.get("/admin/api/v1/webhooks", headers=admin_headers)
    endpoint = listed.json()["webhooks"][0]
    assert "secret" not in endpoint
    assert endpoint["secret_masked"].endswith(body["secret"][-4:])


def test_validate_endpoint_url_https_required_in_production():
    with pytest.raises(ValueError):
        validate_endpoint_url("http://public.example.com/hooks", env="production")


@pytest.mark.asyncio
async def test_signature_roundtrip_and_tamper_and_replay():
    cache = InMemoryCache()
    secret = "ab" * 32
    payload = {"id": "evt1", "type": "user.created", "data": {"a": 1}}
    timestamp = str(int(time.time()))
    signature = sign_payload(secret, timestamp, payload)

    ok = await WebhookManager.verify_webhook_signature(
        payload,
        signature,
        secret,
        timestamp,
        delivery_id="d1",
        replay_store=cache,
    )
    assert ok is True

    # Tampered payload must fail.
    tampered = dict(payload)
    tampered["data"] = {"a": 2}
    assert (
        await WebhookManager.verify_webhook_signature(
            tampered, signature, secret, timestamp
        )
        is False
    )

    # Wrong secret must fail.
    assert (
        await WebhookManager.verify_webhook_signature(
            payload, signature, "other-secret", timestamp
        )
        is False
    )

    # Stale timestamp outside the ±300s window must fail.
    stale = str(int(time.time()) - 600)
    stale_signature = sign_payload(secret, stale, payload)
    assert (
        await WebhookManager.verify_webhook_signature(
            payload, stale_signature, secret, stale
        )
        is False
    )

    # Replaying the same delivery id must fail (replay store).
    assert (
        await WebhookManager.verify_webhook_signature(
            payload,
            signature,
            secret,
            timestamp,
            delivery_id="d1",
            replay_store=cache,
        )
        is False
    )


@pytest.mark.asyncio
async def test_delivery_success_retry_schedule_and_scheduled_for(
    db, config, fake_dns
):
    """Non-2xx → failure + retry per [60,...]; processor honors scheduled_for."""
    fake_dns({"hooks.example.com": "93.184.216.34"})
    cache = InMemoryCache()

    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)
    manager = WebhookManager(config, db, cache, http_client=http_client)

    endpoint = await manager.register_endpoint(
        "https://hooks.example.com/hooks", [WebhookEventType.USER_CREATED.value]
    )
    await manager.dispatch_event(WebhookEventType.USER_CREATED, {"user_id": "u1"})

    processed = await manager.process_pending_events()
    assert processed == 1
    assert attempts["count"] == 1
    deliveries = await db.get_webhook_deliveries(endpoint["id"])
    assert deliveries[0]["status"] == "failed"
    assert deliveries[0]["status_code"] == 500

    # A retry job was queued with scheduled_for ≈ now + RETRY_DELAYS_SECONDS[0].
    raw_jobs = await cache.lrange(WEBHOOK_QUEUE_KEY, 0, -1)
    assert len(raw_jobs) == 1
    job = json.loads(raw_jobs[0])
    assert job["attempts"] == 1
    assert job["scheduled_for"] > time.time() + RETRY_DELAYS_SECONDS[0] - 5

    # Processing again must NOT deliver early (scheduled_for honored).
    processed_again = await manager.process_pending_events()
    assert processed_again == 0
    assert attempts["count"] == 1

    # Make the job due and switch the endpoint to a healthy responder.
    def ok_handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return httpx.Response(200)

    manager._http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(ok_handler), follow_redirects=False
    )
    due_job = dict(job)
    due_job["scheduled_for"] = time.time() - 1
    await cache.delete(WEBHOOK_QUEUE_KEY)
    await cache.lpush(WEBHOOK_QUEUE_KEY, json.dumps(due_job))
    processed_final = await manager.process_pending_events()
    assert processed_final == 1
    deliveries = await db.get_webhook_deliveries(endpoint["id"])
    assert deliveries[0]["status"] == "success"

    await http_client.aclose()


@pytest.mark.asyncio
async def test_events_empty_means_subscribe_all(db, config, fake_dns):
    fake_dns({"hooks.example.com": "93.184.216.34"})
    cache = InMemoryCache()
    delivered: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        delivered.append(json.loads(request.content))
        return httpx.Response(204)

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )
    manager = WebhookManager(config, db, cache, http_client=http_client)
    await manager.register_endpoint("https://hooks.example.com/hooks", [])  # all
    await manager.dispatch_event(WebhookEventType.MFA_ENABLED, {"user_id": "u2"})
    await manager.process_pending_events()
    assert len(delivered) == 1
    assert delivered[0]["type"] == WebhookEventType.MFA_ENABLED.value
    # Signature headers are present and valid (§7 names).
    await http_client.aclose()
