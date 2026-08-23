"""Webhook delivery system (CONTRACTS.md §7).

Complete implementation of the §7 contract:

- **Endpoint URL safety** (:func:`validate_endpoint_url`): https required in
  production (http allowed elsewhere); the hostname is resolved via
  ``socket.getaddrinfo`` and EVERY A/AAAA record is checked with
  ``ipaddress`` — private, loopback, link-local (incl. the
  ``169.254.169.254`` cloud-metadata address), reserved, unspecified and
  multicast targets are rejected. Validation runs at registration AND again
  at every delivery/test attempt.
- **Signatures**: HMAC-SHA256 over ``f"{timestamp}.{canonical_json_bytes}"``;
  headers ``X-Authy-Signature: sha256=<hex>``, ``X-Authy-Timestamp``
  (unix seconds), ``X-Authy-Event``, ``X-Authy-Delivery-Id``. The receiver
  helper :meth:`WebhookManager.verify_webhook_signature` verifies with
  ``hmac.compare_digest``, a ±300s window and an optional delivery-id
  replay store backed by the cache contract.
- **Delivery**: ``httpx.AsyncClient(follow_redirects=False)``; any non-2xx
  response (or transport error) is a failure and is retried on the schedule
  ``[60, 300, 900, 3600, 14400]`` seconds. ``process_pending_events``
  honors each job's ``scheduled_for`` timestamp.
- **Secrets**: endpoint secrets are ``secrets.token_hex(32)``; list/get
  responses mask everything except the last 4 characters. ``events=[]``
  subscribes the endpoint to ALL events.
- Persistence uses the §4 db webhook methods; the pending-queue lives in
  the cache list ``authy:webhook:queue`` (§3.1).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from authy_package.cache.abstract_cache import AbstractCache
from authy_package.config import AuthConfig
from authy_package.db.abstract_db import AbstractDatabase

logger = logging.getLogger("authy.webhooks")

__all__ = [
    "WebhookEventType",
    "WebhookEvent",
    "WebhookManager",
    "validate_endpoint_url",
    "canonical_payload_bytes",
    "sign_payload",
    "WEBHOOK_QUEUE_KEY",
    "RETRY_DELAYS_SECONDS",
    "SIGNATURE_HEADER",
    "TIMESTAMP_HEADER",
    "EVENT_HEADER",
    "DELIVERY_ID_HEADER",
]

#: Cache list key holding pending delivery jobs (§3.1).
WEBHOOK_QUEUE_KEY = "authy:webhook:queue"

#: Cache key prefix for the delivery-id replay ledger (receiver side).
DELIVERY_SEEN_KEY_TEMPLATE = "authy:webhook:seen:{delivery_id}"

#: Retry schedule in seconds for failed deliveries (§7).
RETRY_DELAYS_SECONDS: List[int] = [60, 300, 900, 3600, 14400]

#: Signature / metadata header names (§7).
SIGNATURE_HEADER = "X-Authy-Signature"
TIMESTAMP_HEADER = "X-Authy-Timestamp"
EVENT_HEADER = "X-Authy-Event"
DELIVERY_ID_HEADER = "X-Authy-Delivery-Id"

#: Default signature timestamp tolerance (seconds) for receivers.
SIGNATURE_TOLERANCE_SECONDS = 300

#: HTTP timeout for delivery attempts.
DELIVERY_TIMEOUT_SECONDS = 10.0


class WebhookEventType(Enum):
    """Supported webhook event types."""

    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_LOGGED_IN = "user.logged_in"
    USER_LOGGED_OUT = "user.logged_out"
    PASSWORD_RESET_REQUESTED = "password.reset_requested"
    PASSWORD_RESET_COMPLETED = "password.reset_completed"
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"
    MEMBER_ADDED = "member.added"
    MEMBER_REMOVED = "member.removed"
    INVITATION_SENT = "invitation.sent"
    INVITATION_ACCEPTED = "invitation.accepted"


@dataclass
class WebhookEvent:
    """One webhook event (queued or delivered)."""

    id: str
    event_type: str
    payload: Dict[str, Any]
    created_at: datetime
    delivered: bool = False
    delivery_attempts: int = 0
    last_status_code: Optional[int] = None
    next_retry_at: Optional[datetime] = None


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _coerce_event_type(event_type: "WebhookEventType | str") -> str:
    if isinstance(event_type, WebhookEventType):
        return event_type.value
    # Validates unknown values.
    return WebhookEventType(event_type).value


def canonical_payload_bytes(payload: Dict[str, Any]) -> bytes:
    """Deterministic canonical JSON encoding of a webhook payload."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(secret: str, timestamp: str, payload: Dict[str, Any]) -> str:
    """Compute the ``sha256=<hex>`` signature for a payload (§7).

    The signed message is ``f"{timestamp}.{canonical_json_bytes}"``.
    """
    message = f"{timestamp}.".encode("utf-8") + canonical_payload_bytes(payload)
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


#: RFC 6598 shared address space (CGNAT): not covered by ``is_private``;
#: must be rejected explicitly (review NEW-4).
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def validate_endpoint_url(url: str, *, env: str = "development") -> str:
    """Validate a webhook endpoint URL for SSRF safety (§7).

    Rules:
    - scheme must be ``https`` in production; ``http`` is only allowed when
      ``env != "production"``;
    - the host must resolve (``socket.getaddrinfo``) and EVERY resolved
      A/AAAA address must be a public unicast address — private, loopback,
      link-local (covers ``169.254.169.254``), reserved, unspecified and
      multicast addresses are rejected.

    Args:
        url: Candidate endpoint URL.
        env: Deployment environment (``config.env``).

    Returns:
        The normalized URL string.

    Raises:
        ValueError: When the URL is unsafe, with a specific reason.
    """
    if not url or not isinstance(url, str):
        raise ValueError("url must be a non-empty string")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL scheme must be http or https")
    if parsed.scheme == "http" and env == "production":
        raise ValueError("Webhook URLs must use https in production")
    host = parsed.hostname
    if not host:
        raise ValueError("Webhook URL must include a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        raise ValueError(f"Webhook hostname {host!r} does not resolve") from exc
    if not addrinfo:
        raise ValueError(f"Webhook hostname {host!r} did not resolve to any address")

    for family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip_raw = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_raw)
        except ValueError as exc:
            raise ValueError(
                f"Webhook hostname {host!r} resolved to an unparsable address"
            ) from exc
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
            or (ip.version == 4 and ip in _CGNAT_NET)
        ):
            raise ValueError(
                f"Webhook URL {url!r} resolves to a forbidden address "
                f"({ip}: private/loopback/link-local/reserved/unspecified/"
                "multicast/CGNAT)"
            )
    return url


def _mask_secret(secret: str) -> str:
    """Mask an endpoint secret, exposing only the last 4 characters."""
    if not secret:
        return "****"
    return "*" * 12 + secret[-4:]


def _public_endpoint_view(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Endpoint dict safe for list/get responses (secret masked)."""
    view = dict(endpoint)
    raw_secret = view.pop("secret", None)
    view["secret_masked"] = _mask_secret(raw_secret or "")
    return view


class WebhookManager:
    """Signed webhook delivery over the §4 db contract and §3.1 cache queue.

    Args:
        config: Auth configuration (``env`` controls https enforcement).
        db: Database implementing the §4 webhook methods.
        cache: Cache implementing §3 primitives (queue + replay ledger).
        http_client: Optional pre-built ``httpx.AsyncClient`` (tests inject
            a MockTransport here). When omitted a client with
            ``follow_redirects=False`` is created per delivery batch.
    """

    def __init__(
        self,
        config: AuthConfig,
        db: AbstractDatabase,
        cache: AbstractCache,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.config = config
        self.db = db
        self.cache = cache
        self._http_client = http_client
        self._owns_client = http_client is None

    # -- lifecycle -------------------------------------------------------------

    async def close(self) -> None:
        """Release the HTTP client when this manager owns it."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(follow_redirects=False)
        return self._http_client

    # -- endpoint management -----------------------------------------------------

    async def register_endpoint(
        self,
        url: str,
        events: Optional[List[str]] = None,
        *,
        description: Optional[str] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Register an endpoint after URL-safety validation.

        ``events=[]`` (or omitted) subscribes the endpoint to ALL events.
        The response includes the plaintext signing secret ONCE; subsequent
        list/get calls only expose the masked form.

        Raises:
            ValueError: When the URL fails §7 safety validation or events
                contain unknown types.
        """
        validate_endpoint_url(url, env=self.config.env)
        normalized_events = (
            [_coerce_event_type(event) for event in events] if events else []
        )
        secret = secrets.token_hex(32)
        endpoint = await self.db.save_webhook_endpoint(
            {
                "url": url,
                "secret": secret,
                "events": normalized_events,
                "description": description,
                "enabled": enabled,
                "created_at": _utcnow(),
            }
        )
        logger.info("Registered webhook endpoint %s (%s)", endpoint["id"], url)
        # Registration response is the only place the full secret is shown.
        return dict(endpoint)

    async def get_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Fetch an endpoint (secret masked)."""
        endpoint = await self.db.get_webhook_endpoint(endpoint_id)
        if endpoint is None:
            return None
        return _public_endpoint_view(endpoint)

    async def list_endpoints(self) -> List[Dict[str, Any]]:
        """List endpoints (secrets masked)."""
        endpoints = await self.db.list_webhook_endpoints()
        return [_public_endpoint_view(endpoint) for endpoint in endpoints]

    async def update_endpoint(
        self,
        endpoint_id: str,
        *,
        url: Optional[str] = None,
        events: Optional[List[str]] = None,
        enabled: Optional[bool] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update endpoint fields; a new URL is re-validated (§7)."""
        updates: Dict[str, Any] = {}
        if url is not None:
            validate_endpoint_url(url, env=self.config.env)
            updates["url"] = url
        if events is not None:
            updates["events"] = [_coerce_event_type(event) for event in events]
        if enabled is not None:
            updates["enabled"] = bool(enabled)
        if description is not None:
            updates["description"] = description
        if not updates:
            raise ValueError("No fields to update")
        endpoint = await self.db.update_webhook_endpoint(endpoint_id, updates)
        if endpoint is None:
            from authy_package.errors import NotFoundError

            raise NotFoundError(f"Webhook endpoint {endpoint_id!r} does not exist")
        return _public_endpoint_view(endpoint)

    async def rotate_endpoint_secret(self, endpoint_id: str) -> Dict[str, Any]:
        """Replace the endpoint secret; the new secret is returned once."""
        endpoint = await self.db.get_webhook_endpoint(endpoint_id)
        if endpoint is None:
            from authy_package.errors import NotFoundError

            raise NotFoundError(f"Webhook endpoint {endpoint_id!r} does not exist")
        new_secret = secrets.token_hex(32)
        updated = await self.db.update_webhook_endpoint(
            endpoint_id, {"secret": new_secret}
        )
        assert updated is not None
        logger.info("Rotated secret for webhook endpoint %s", endpoint_id)
        return dict(updated)

    async def delete_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint and its delivery history."""
        return await self.db.delete_webhook_endpoint(endpoint_id)

    async def get_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Recent delivery attempts for an endpoint (newest first)."""
        return await self.db.get_webhook_deliveries(endpoint_id, limit=limit)

    # -- dispatch / delivery -----------------------------------------------------

    async def dispatch_event(
        self,
        event_type: "WebhookEventType | str",
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Queue an event for delivery to every subscribed endpoint.

        Returns the event envelope (id/type/created_at/data). Endpoints
        with ``events=[]`` receive every event (§7 subscribe-all).
        """
        type_value = _coerce_event_type(event_type)
        event = {
            "id": secrets.token_hex(16),
            "type": type_value,
            "created_at": _utcnow().isoformat(),
            "data": dict(payload or {}),
        }
        endpoints = await self.db.list_webhook_endpoints()
        queued = 0
        for endpoint in endpoints:
            if not endpoint.get("enabled", True):
                continue
            subscribed = endpoint.get("events") or []
            if subscribed and type_value not in subscribed:
                continue
            job = {
                "event": event,
                "endpoint_id": endpoint["id"],
                "attempts": 0,
                "scheduled_for": time.time(),
            }
            await self.cache.lpush(WEBHOOK_QUEUE_KEY, json.dumps(job, default=str))
            queued += 1
        logger.info(
            "Dispatched webhook event %s to %d endpoint(s)", type_value, queued
        )
        return event

    async def process_pending_events(self, *, max_jobs: int = 1000) -> int:
        """Drain the cache queue, honoring per-job ``scheduled_for``.

        Jobs whose ``scheduled_for`` lies in the future are re-queued
        untouched. Returns the number of delivery attempts executed.
        """
        processed = 0
        requeued = 0
        seen = 0
        now = time.time()
        while seen < max_jobs:
            raw = await self.cache.rpop(WEBHOOK_QUEUE_KEY)
            if raw is None:
                break
            seen += 1
            try:
                job = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Dropping malformed webhook queue item")
                continue
            scheduled_for = float(job.get("scheduled_for") or 0)
            if scheduled_for > now:
                # Not due yet: put it back and keep draining other jobs.
                await self.cache.lpush(WEBHOOK_QUEUE_KEY, raw)
                requeued += 1
                if requeued >= seen:
                    # Only not-yet-due jobs remain; stop this cycle.
                    break
                continue
            await self._deliver_job(job)
            processed += 1
        return processed

    async def _deliver_job(self, job: Dict[str, Any]) -> None:
        """Attempt one delivery; record the result and schedule retries."""
        event = job["event"]
        endpoint_id = job["endpoint_id"]
        attempts = int(job.get("attempts", 0))
        endpoint = await self.db.get_webhook_endpoint(endpoint_id)
        if endpoint is None or not endpoint.get("enabled", True):
            return

        delivery_id = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        signature = sign_payload(endpoint["secret"], timestamp, event)

        status_code: Optional[int] = None
        error: Optional[str] = None
        try:
            # Re-validate at delivery time: DNS may have changed since
            # registration (defense against DNS rebinding).
            validate_endpoint_url(endpoint["url"], env=self.config.env)
            response = await self._client().post(
                endpoint["url"],
                content=canonical_payload_bytes(event),
                headers={
                    "Content-Type": "application/json",
                    SIGNATURE_HEADER: signature,
                    TIMESTAMP_HEADER: timestamp,
                    EVENT_HEADER: event["type"],
                    DELIVERY_ID_HEADER: delivery_id,
                    "User-Agent": "Authy-Webhooks/2.0",
                },
                timeout=DELIVERY_TIMEOUT_SECONDS,
            )
            status_code = response.status_code
        except ValueError as exc:  # URL became unsafe
            error = f"url_validation_failed: {exc}"
        except httpx.HTTPError as exc:
            error = f"transport_error: {type(exc).__name__}"
        except Exception as exc:  # noqa: BLE001 - never kill the processor
            error = f"delivery_error: {type(exc).__name__}"

        success = status_code is not None and 200 <= status_code < 300
        record = {
            "endpoint_id": endpoint_id,
            "event_id": event["id"],
            "delivery_id": delivery_id,
            "event_type": event["type"],
            "status": "success" if success else "failed",
            "status_code": status_code,
            "attempt": attempts + 1,
            "error": None if success else error or f"HTTP {status_code}",
            "created_at": _utcnow(),
        }
        await self.db.save_webhook_delivery(record)

        if success:
            return

        if attempts < len(RETRY_DELAYS_SECONDS):
            delay = RETRY_DELAYS_SECONDS[attempts]
            retry_job = {
                "event": event,
                "endpoint_id": endpoint_id,
                "attempts": attempts + 1,
                "scheduled_for": time.time() + delay,
            }
            await self.cache.lpush(WEBHOOK_QUEUE_KEY, json.dumps(retry_job, default=str))
            logger.info(
                "Webhook delivery %s failed; retry %d scheduled in %ds",
                delivery_id,
                attempts + 1,
                delay,
            )
        else:
            logger.warning(
                "Webhook delivery for endpoint %s permanently failed after %d attempts",
                endpoint_id,
                attempts + 1,
            )

    async def send_test_event(self, endpoint_id: str) -> Dict[str, Any]:
        """Deliver a signed ``webhook.test`` event immediately.

        Validates URL safety first (§7); returns the delivery record.
        """
        endpoint = await self.db.get_webhook_endpoint(endpoint_id)
        if endpoint is None:
            from authy_package.errors import NotFoundError

            raise NotFoundError(f"Webhook endpoint {endpoint_id!r} does not exist")
        event = {
            "id": secrets.token_hex(16),
            "type": "webhook.test",
            "created_at": _utcnow().isoformat(),
            "data": {"endpoint_id": endpoint_id, "test": True},
        }
        job = {
            "event": event,
            "endpoint_id": endpoint_id,
            "attempts": 0,
            "scheduled_for": 0,
        }
        await self._deliver_job(job)
        deliveries = await self.db.get_webhook_deliveries(endpoint_id, limit=1)
        return deliveries[0] if deliveries else {"status": "failed"}

    # -- receiver-side verification -------------------------------------------------

    @staticmethod
    async def verify_webhook_signature(
        payload: "Dict[str, Any] | bytes",
        signature: str,
        secret: str,
        timestamp: str,
        *,
        delivery_id: Optional[str] = None,
        replay_store: Optional[AbstractCache] = None,
        tolerance_seconds: int = SIGNATURE_TOLERANCE_SECONDS,
    ) -> bool:
        """Verify an incoming webhook signature (receiver helper, §7).

        Checks, in order:
        1. ``timestamp`` is within ±``tolerance_seconds`` of now;
        2. ``signature`` equals ``sha256=<hmac>`` over
           ``f"{timestamp}.{canonical_json}"`` (``hmac.compare_digest``);
        3. when ``delivery_id`` + ``replay_store`` are provided, the
           delivery id has not been seen before (recorded with a TTL of
           twice the tolerance window).
        """
        if not signature or not secret or not timestamp:
            return False
        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return False
        if abs(int(time.time()) - ts) > tolerance_seconds:
            return False

        payload_bytes = (
            payload if isinstance(payload, bytes) else canonical_payload_bytes(payload
            )
        )
        message = f"{timestamp}.".encode("utf-8") + payload_bytes
        expected = hmac.new(
            secret.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        provided = signature.removeprefix("sha256=")
        if not hmac.compare_digest(
            expected.encode("utf-8"), provided.encode("utf-8")
        ):
            return False

        if delivery_id and replay_store is not None:
            key = DELIVERY_SEEN_KEY_TEMPLATE.format(delivery_id=delivery_id)
            if await replay_store.exists(key):
                logger.warning("Replayed webhook delivery id %s rejected", delivery_id)
                return False
            await replay_store.set(
                key, "1", ttl_seconds=max(60, tolerance_seconds * 2)
            )
        return True
