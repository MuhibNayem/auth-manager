"""Unified async database contract (CONTRACTS.md §4).

Single abstract base replacing the legacy ``AbstractDatabase`` and
``EnterpriseDatabaseAdapter`` classes (both removed). All methods are async;
records are dicts with stable keys (``id``, ``username``, ``email``,
``phone``, ``hashed_password``, ``mfa_enabled``, ``mfa_secret``,
``created_at``, ``updated_at``, ``is_active``, ``role`` plus
provider-specific extras). Identity lookups are case-insensitive for
email/username.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["AbstractDatabase"]


class AbstractDatabase(ABC):
    """Canonical async persistence contract for the Tessera package."""

    # -- lifecycle -----------------------------------------------------------

    @abstractmethod
    async def connect(self) -> None:
        """Initialize connections/pools and verify connectivity."""

    @abstractmethod
    async def close(self) -> None:
        """Gracefully release all connections."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return ``True`` when the backend is reachable."""

    # -- users ----------------------------------------------------------------

    @abstractmethod
    async def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user; returns the stored document including ``id``.

        Raises:
            IntegrityError: On duplicate email/username/phone.
        """

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a user by primary id."""

    @abstractmethod
    async def get_user_by_identifier(
        self,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch a user by one identifier; email/username case-insensitive."""

    @abstractmethod
    async def update_user(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Apply a partial update; returns the updated doc or ``None``."""

    @abstractmethod
    async def delete_user(self, user_id: str) -> bool:
        """Delete a user; ``True`` when a user was removed."""

    @abstractmethod
    async def list_users(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List users with pagination; returns ``(rows, total_matching)``."""

    @abstractmethod
    async def count_users(
        self,
        *,
        active_only: bool = False,
        mfa_enabled: Optional[bool] = None,
        created_since: Optional[datetime] = None,
    ) -> int:
        """Count users with optional filters."""

    # -- credentials / sessions ------------------------------------------------

    @abstractmethod
    async def save_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a session document (requires ``id``, ``user_id``)."""

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a session by id (any status)."""

    @abstractmethod
    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Return only sessions with ``status == 'active'``."""

    @abstractmethod
    async def revoke_session(self, session_id: str) -> bool:
        """Atomically flip an active session to revoked; ``True`` on flip."""

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke every active session of a user; returns the count revoked."""

    # -- organizations -----------------------------------------------------------

    @abstractmethod
    async def create_organization(self, org: Dict[str, Any]) -> Dict[str, Any]:
        """Create an organization; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch an organization by id."""

    @abstractmethod
    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Fetch an organization by unique slug."""

    @abstractmethod
    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Apply a partial update; returns the updated doc or ``None``."""

    @abstractmethod
    async def delete_organization(self, org_id: str) -> bool:
        """Delete an organization (and its member/invitation links)."""

    @abstractmethod
    async def list_organizations(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List organizations with pagination; returns ``(rows, total)``."""

    @abstractmethod
    async def add_org_member(self, org_id: str, member: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member (dict with ``user_id``); returns the stored member."""

    @abstractmethod
    async def get_org_members(self, org_id: str) -> List[Dict[str, Any]]:
        """List members of an organization."""

    @abstractmethod
    async def update_org_member(
        self, org_id: str, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a member record (e.g. role); returns it or ``None``."""

    @abstractmethod
    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        """Remove a member; ``True`` when removed."""

    @abstractmethod
    async def create_invitation(self, invitation: Dict[str, Any]) -> Dict[str, Any]:
        """Create an org invitation; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Fetch an invitation by its token."""

    @abstractmethod
    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        """List invitations of an org with ``status == 'pending'``."""

    @abstractmethod
    async def delete_invitation(self, invitation_id: str) -> bool:
        """Delete an invitation; ``True`` when removed."""

    # -- audit log -----------------------------------------------------------------
    # Append-only. Adapters must store ``checksum`` = sha256 over the canonical
    # JSON of the event WITHOUT db-assigned fields; hash-chain by including the
    # previous event's checksum in the checksummed payload and storing it.

    @abstractmethod
    async def save_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append one audit event; returns the stored doc with id/checksum."""

    @abstractmethod
    async def save_audit_events(self, events: List[Dict[str, Any]]) -> int:
        """Append multiple audit events in order; returns the count stored."""

    @abstractmethod
    async def search_audit_events(
        self,
        *,
        event_types: Optional[List[str]] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Search audit events; returns ``(rows, total_matching)``."""

    @abstractmethod
    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single audit event by id."""

    @abstractmethod
    async def delete_audit_events_before(self, ts: datetime) -> int:
        """Prune events older than ``ts``; returns the count deleted."""

    @abstractmethod
    async def get_audit_statistics(
        self, *, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Aggregate audit statistics (totals, per-type, per-actor)."""

    @abstractmethod
    async def get_audit_time_series(
        self, *, since: datetime, bucket_seconds: int
    ) -> List[Dict[str, Any]]:
        """Bucketed event counts from ``since`` until now."""

    # -- webhooks ---------------------------------------------------------------------

    @abstractmethod
    async def save_webhook_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a webhook endpoint; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_webhook_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a webhook endpoint by id."""

    @abstractmethod
    async def list_webhook_endpoints(self) -> List[Dict[str, Any]]:
        """List all webhook endpoints."""

    @abstractmethod
    async def update_webhook_endpoint(
        self, endpoint_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a webhook endpoint; returns the updated doc or ``None``."""

    @abstractmethod
    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint (and its delivery history)."""

    @abstractmethod
    async def save_webhook_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        """Record a delivery attempt; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_webhook_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List recent deliveries for an endpoint, newest first."""

    # -- RBAC -----------------------------------------------------------------------------

    @abstractmethod
    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a role; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a role by id."""

    @abstractmethod
    async def list_roles(self) -> List[Dict[str, Any]]:
        """List all roles."""

    @abstractmethod
    async def delete_role(self, role_id: str) -> bool:
        """Delete a role; ``True`` when removed."""

    @abstractmethod
    async def save_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role assignment; returns the stored doc including ``id``."""

    @abstractmethod
    async def query_role_assignments(
        self,
        *,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query assignments; provided filters combine with AND."""

    @abstractmethod
    async def delete_role_assignment(self, assignment_id: str) -> bool:
        """Delete a role assignment; ``True`` when removed."""

    # -- api keys (admin v2) ---------------------------------------------------------------
    # Keys are stored HASHED (sha256), never plaintext.

    @abstractmethod
    async def save_api_key(self, key_record: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key record (requires ``key_hash``); returns stored doc."""

    @abstractmethod
    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch an API key record by its sha256 hash."""

    @abstractmethod
    async def list_api_keys(self) -> List[Dict[str, Any]]:
        """List all API key records (hashed only)."""

    @abstractmethod
    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key; ``True`` when the record existed."""

    # -- settings (white-label/branding/localization) ---------------------------------------

    @abstractmethod
    async def get_setting(self, key: str) -> Any:
        """Fetch a setting value (JSON) or ``None``."""

    @abstractmethod
    async def set_setting(self, key: str, value: Any) -> None:
        """Persist a JSON-serializable setting value."""

    # -- SAML ----------------------------------------------------------------------------------
    # Request ids and response ids are replay ledgers; consume = atomic
    # get+delete.

    @abstractmethod
    async def save_saml_request(
        self, request_id: str, data: Dict[str, Any], *, ttl_seconds: int
    ) -> None:
        """Store transient SAML request state with a TTL."""

    @abstractmethod
    async def consume_saml_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Atomically fetch-and-delete SAML request state (single use)."""

    @abstractmethod
    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None:
        """Record a consumed SAML ResponseID for replay protection."""

    @abstractmethod
    async def check_and_record_saml_response_id(self, response_id: str) -> bool:
        """Return ``True`` when the ResponseID is fresh (and record it).

        ``False`` means the ResponseID was already seen (replay).
        """

    @abstractmethod
    async def save_saml_user_mapping(
        self, name_id: str, sp_entity_id: str, user_id: str
    ) -> None:
        """Persist the SAML NameID -> local user mapping."""

    @abstractmethod
    async def get_saml_user_mapping(
        self, name_id: str, sp_entity_id: str
    ) -> Optional[str]:
        """Resolve a SAML NameID to a local user id."""

    # -- OIDC ------------------------------------------------------------------------------------

    @abstractmethod
    async def save_oidc_provider(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OIDC provider; returns the stored doc including ``id``."""

    @abstractmethod
    async def get_oidc_provider(self, issuer_or_slug: str) -> Optional[Dict[str, Any]]:
        """Fetch a provider by issuer or slug."""

    @abstractmethod
    async def update_oidc_provider(
        self, identifier: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a provider (by issuer or slug).

        Adapters MUST whitelist updatable columns (no caller-key
        interpolation); unknown keys are rejected with ``ValueError``.
        """
