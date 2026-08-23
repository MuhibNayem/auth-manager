"""Migration tools — import users from external auth providers.

Honest registry in this revision:

- Implemented importers: **Firebase**, **Auth0**, **Django**.
- ``get_importer("cognito")`` / ``get_importer("supabase")`` raise
  :class:`NotImplementedError` with an explicit message (they were listed
  in docs before but never implemented).
- ``preview_migration`` no longer raises ``StopIteration``/``StopAsyncIteration``
  on empty sources.
- Migrations run against the §4 database contract (``create_user`` /
  ``get_user_by_identifier``), not mongo-style collection access.
- :func:`verify_and_upgrade_legacy_hash` verifies legacy hashes (Django
  ``pbkdf2_sha256`` and Firebase ``scrypt``) and rehashes the password to
  bcrypt on success; core login calls it when ``user["password_algorithm"]``
  is set.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional

logger = logging.getLogger("authy.migration")

__all__ = [
    "BaseImporter",
    "FirebaseImporter",
    "Auth0Importer",
    "DjangoImporter",
    "get_importer",
    "verify_and_upgrade_legacy_hash",
    "SUPPORTED_PROVIDERS",
    "KNOWN_UNIMPLEMENTED_PROVIDERS",
]

SUPPORTED_PROVIDERS = ("firebase", "auth0", "django")
KNOWN_UNIMPLEMENTED_PROVIDERS = ("cognito", "supabase")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BaseImporter(ABC):
    """Base class for provider importers (db-contract based)."""

    provider_name = "base"

    def __init__(self, config: Dict[str, Any], db: Any):
        """Args:
        config: Provider-specific settings.
        db: A §4 database adapter (the migration target).
        """
        if db is None:
            raise ValueError("BaseImporter requires a database adapter (db)")
        self.config = config or {}
        self.db = db
        self.stats = {"total": 0, "migrated": 0, "failed": 0, "skipped": 0}

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the source provider."""

    @abstractmethod
    def fetch_users(self, batch_size: int = 100) -> AsyncIterator[List[Dict[str, Any]]]:
        """Yield user batches from the source provider."""

    @abstractmethod
    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Translate a source password hash, or None when not possible."""

    def preview_migration(self) -> Dict[str, Any]:
        """Honest preview: no fake counts without a live connection."""
        return {
            "provider": self.provider_name,
            "estimated_users": "Unknown (connect() required for a real count)",
            "warnings": [],
            "strategy": "lazy-password-migration",
        }

    async def _count_first_batch(self) -> Optional[int]:
        """Count users in the first batch without raising on empty sources."""
        try:
            iterator = self.fetch_users().__aiter__()
            try:
                batch = await iterator.__anext__()
            except StopAsyncIteration:
                return 0
            return len(batch)
        except Exception as exc:
            logger.warning("Preview count failed: %s", exc)
            return None

    async def migrate(self, strategy: str = "lazy-password-migration") -> Dict[str, Any]:
        """Execute the user migration against the db contract."""
        await self.connect()
        results: Dict[str, Any] = {"count": 0, "warnings": [], "errors": []}
        try:
            async for user_batch in self.fetch_users():
                for user_data in user_batch:
                    try:
                        migrated = await self._migrate_user(user_data, strategy)
                        if migrated:
                            results["count"] += 1
                            self.stats["migrated"] += 1
                    except Exception as exc:
                        results["errors"].append(
                            {"user_id": user_data.get("id", "unknown"), "error": str(exc)}
                        )
                        self.stats["failed"] += 1
                self.stats["total"] += len(user_batch)
        except Exception as exc:
            results["errors"].append({"error": f"Migration failed: {exc}"})
        return results

    async def _migrate_user(
        self, user_data: Dict[str, Any], strategy: str
    ) -> Optional[Dict[str, Any]]:
        """Migrate a single user via the §4 contract."""
        email = user_data.get("email")
        if email:
            existing = await self.db.get_user_by_identifier(email=email)
            if existing:
                self.stats["skipped"] += 1
                return None

        authy_user = {
            "email": email,
            "username": user_data.get("username"),
            "email_verified": user_data.get("email_verified", False),
            "is_active": user_data.get("is_active", True),
            "external_provider": self.provider_name,
            "external_id": user_data.get("id"),
        }
        authy_user = {k: v for k, v in authy_user.items() if v is not None}

        if "password_hash" in user_data and user_data["password_hash"]:
            if strategy == "full":
                translated = self.translate_password_hash(
                    user_data["password_hash"],
                    user_data.get("password_algorithm", "unknown"),
                )
                if translated:
                    authy_user["hashed_password"] = translated
                    authy_user["password_needs_rehash"] = True
                else:
                    authy_user["password_reset_required"] = True
            else:  # lazy-password-migration
                authy_user["legacy_password_hash"] = {
                    "hash": user_data["password_hash"],
                    "algorithm": user_data.get("password_algorithm", "unknown"),
                    "provider": self.provider_name,
                    "scrypt_params": user_data.get("scrypt_params"),
                }
                authy_user["password_algorithm"] = user_data.get(
                    "password_algorithm", "unknown"
                )

        return await self.db.create_user(authy_user)


class FirebaseImporter(BaseImporter):
    """Import users from Firebase Authentication (firebase-admin)."""

    provider_name = "firebase"

    async def connect(self) -> None:
        try:
            import firebase_admin
            from firebase_admin import auth, credentials
        except ImportError as exc:
            raise ImportError(
                "Firebase migration requires 'firebase-admin': "
                "pip install firebase-admin"
            ) from exc

        def _init() -> None:
            if not firebase_admin._apps:
                cred_path = self.config.get("service_account_file")
                if cred_path:
                    firebase_admin.initialize_app(credentials.Certificate(cred_path))
                else:
                    firebase_admin.initialize_app()

        await asyncio.to_thread(_init)
        self.firebase_auth = auth
        logger.info("Connected to Firebase")

    async def fetch_users(
        self, batch_size: int = 100
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        page_token: Optional[str] = None
        while True:
            users_page = await asyncio.to_thread(
                self.firebase_auth.list_users,
                page_token=page_token,
                max_results=batch_size,
            )
            batch: List[Dict[str, Any]] = []
            for user in users_page.users:
                batch.append(
                    {
                        "id": user.uid,
                        "email": user.email,
                        "email_verified": user.email_verified,
                        "password_hash": getattr(user, "password_hash", None),
                        "password_algorithm": getattr(
                            user, "password_hash_algorithm", None
                        ),
                        "display_name": user.display_name,
                        "photo_url": user.photo_url,
                    }
                )
            if batch:
                yield batch
            if not users_page.page_token:
                break
            page_token = users_page.page_token

    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """bcrypt passes through; scrypt/unknown use lazy migration."""
        if algorithm in ("BCRYPT", "bcrypt"):
            return hash_str
        return None

    async def preview_migration_safe(self) -> Dict[str, Any]:
        """Preview that connects and counts the first batch (no crashes)."""
        try:
            await self.connect()
            count = await self._count_first_batch()
        except Exception as exc:
            return {
                "provider": "Firebase",
                "estimated_users": "Unknown",
                "warnings": [f"Connection error: {exc}"],
                "strategy": "lazy-password-migration",
            }
        return {
            "provider": "Firebase",
            "estimated_users": f"{count}+ (first batch)" if count is not None else "Unknown",
            "warnings": [
                "Password hashes may require lazy migration",
                "Custom claims will not be migrated automatically",
            ],
            "strategy": "lazy-password-migration",
        }


class Auth0Importer(BaseImporter):
    """Import users from Auth0 Management API (hashes are not exported)."""

    provider_name = "auth0"

    async def connect(self) -> None:
        import aiohttp

        self.domain = self.config.get("domain")
        client_id = self.config.get("client_id")
        client_secret = self.config.get("client_secret")
        if not self.domain or not client_id or not client_secret:
            raise ValueError("Auth0 migration requires domain, client_id, client_secret")

        async with aiohttp.ClientSession() as session:
            token_url = f"https://{self.domain}/oauth/token"
            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": f"https://{self.domain}/api/v2/",
            }
            async with session.post(token_url, json=payload) as resp:
                if resp.status != 200:
                    raise ValueError(f"Auth0 token request failed: {await resp.text()}")
                token_data = await resp.json()
                self.access_token = token_data["access_token"]
        logger.info("Connected to Auth0")

    async def fetch_users(
        self, batch_size: int = 100
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        import aiohttp

        headers = {"Authorization": f"Bearer {self.access_token}"}
        page = 0
        async with aiohttp.ClientSession() as session:
            while True:
                url = f"https://{self.domain}/api/v2/users"
                params = {"per_page": batch_size, "page": page, "include_totals": "false"}
                async with session.get(url, headers=headers, params=params) as resp:
                    if resp.status != 200:
                        raise ValueError(f"Auth0 user fetch failed: {await resp.text()}")
                    users = await resp.json()
                if not users:
                    break
                batch = [
                    {
                        "id": user["user_id"],
                        "email": user.get("email"),
                        "email_verified": user.get("email_verified", False),
                        "password_hash": None,  # Auth0 never exports hashes
                    }
                    for user in users
                ]
                yield batch
                page += 1

    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        return None


class DjangoImporter(BaseImporter):
    """Import users from a Django ``auth_user`` table via SQLAlchemy."""

    provider_name = "django"

    async def connect(self) -> None:
        from sqlalchemy import MetaData, Table, create_engine  # noqa: F401
        from sqlalchemy.ext.asyncio import create_async_engine

        db_url = self.config.get("database_url")
        if not db_url:
            raise ValueError("Django database URL required")
        if "postgresql://" in db_url:
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://")
        elif "mysql://" in db_url:
            db_url = db_url.replace("mysql://", "mysql+aiomysql://")

        self.engine = create_async_engine(db_url)
        self.metadata = MetaData()
        async with self.engine.begin() as conn:
            self.user_table = Table("auth_user", self.metadata, autoload_with=conn)
        logger.info("Connected to Django database")

    async def fetch_users(
        self, batch_size: int = 100
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        from sqlalchemy import select

        offset = 0
        async with self.engine.begin() as conn:
            while True:
                stmt = select(self.user_table).limit(batch_size).offset(offset)
                result = await conn.execute(stmt)
                users = result.fetchall()
                if not users:
                    break
                batch = [
                    {
                        "id": user.id,
                        "email": user.email,
                        "username": user.username,
                        "is_active": user.is_active,
                        "password_hash": user.password,
                        "password_algorithm": "pbkdf2_sha256",
                    }
                    for user in users
                ]
                yield batch
                offset += batch_size

    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Django hashes stay as-is; verified via the legacy verifier."""
        if not hash_str:
            return None
        parts = hash_str.split("$")
        if len(parts) == 4 and parts[0] in (
            "pbkdf2_sha256",
            "pbkdf2_sha1",
            "bcrypt",
            "argon2",
        ):
            return hash_str
        return None


def get_importer(provider: str, config: Dict[str, Any], db: Any = None) -> BaseImporter:
    """Factory for provider importers.

    Raises:
        NotImplementedError: For providers documented as not yet
            implemented (cognito, supabase).
        ValueError: For unknown providers.
        ValueError: When no db adapter is supplied.
    """
    provider_key = str(provider or "").lower()
    if provider_key in KNOWN_UNIMPLEMENTED_PROVIDERS:
        raise NotImplementedError(
            f"The {provider_key!r} importer is not implemented yet; "
            f"supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
        )
    importers = {
        "firebase": FirebaseImporter,
        "auth0": Auth0Importer,
        "django": DjangoImporter,
    }
    if provider_key not in importers:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            f"Supported: {sorted(importers)}"
        )
    return importers[provider_key](config or {}, db)


# ---------------------------------------------------------------------------
# legacy hash verification + upgrade (called by core login)
# ---------------------------------------------------------------------------

#: Memoized Firebase scrypt parameter objects keyed by
#: (signer_key, rounds, memory_cost, salt_separator).
_scrypt_param_cache: Dict[tuple, Dict[str, Any]] = {}


def _b64d(value: Optional[str]) -> bytes:
    """Tolerant base64 decode (standard or urlsafe, padded or not)."""
    if not value:
        return b""
    raw = str(value).strip()
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw)
    except Exception:
        return base64.b64decode(raw)


def _verify_django_pbkdf2(candidate: str, stored_hash: str) -> bool:
    """Verify Django's ``pbkdf2_sha256$iterations$salt$hash`` format."""
    try:
        algo, iterations_raw, salt, digest_b64 = stored_hash.split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    try:
        iterations = int(iterations_raw)
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac(
        "sha256", candidate.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    expected = _b64d(digest_b64)
    return hmac.compare_digest(derived, expected)


def _firebase_scrypt_params(
    signer_key: str, rounds: int, memory_cost: int, salt_separator: str
) -> Dict[str, Any]:
    """Memoized prepared parameters for Firebase scrypt verification."""
    cache_key = (signer_key, rounds, memory_cost, salt_separator)
    cached = _scrypt_param_cache.get(cache_key)
    if cached is not None:
        return cached
    params = {
        "signer_key_bytes": _b64d(signer_key),
        "salt_separator_bytes": _b64d(salt_separator),
        "n": 1 << max(1, int(rounds)),
        "r": max(1, int(memory_cost)),
    }
    _scrypt_param_cache[cache_key] = params
    return params


def _verify_firebase_scrypt(
    candidate: str,
    stored_hash: str,
    salt: str,
    *,
    signer_key: str,
    rounds: int = 8,
    memory_cost: int = 14,
    salt_separator: str = "",
) -> bool:
    """Verify a Firebase SCRYPT-exported hash.

    Pipeline (per the Firebase scrypt export format):
    salt = b64decode(salt) + b64decode(salt_separator); derive with
    scrypt(N=1<<rounds, r=memory_cost, p=1, dklen=32); the signer key is
    XOR-combined with the derived key before comparison.
    """
    params = _firebase_scrypt_params(signer_key, rounds, memory_cost, salt_separator)
    salt_bytes = _b64d(salt) + params["salt_separator_bytes"]
    try:
        derived = hashlib.scrypt(
            candidate.encode("utf-8"),
            salt=salt_bytes,
            n=params["n"],
            r=params["r"],
            p=1,
            dklen=32,
            maxmem=256 * 1024 * 1024,
        )
    except (ValueError, OverflowError):
        return False
    signer = params["signer_key_bytes"]
    if signer:
        derived = bytes(b ^ signer[i % len(signer)] for i, b in enumerate(derived))
    return hmac.compare_digest(derived, _b64d(stored_hash))


def _resolve_legacy(user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Locate the legacy hash record on a user document."""
    legacy = user.get("legacy_password_hash")
    if isinstance(legacy, dict) and legacy.get("hash"):
        return legacy
    algorithm = str(user.get("password_algorithm") or "").lower()
    # Standard algorithms are handled by the normal verify path, not legacy.
    if algorithm in ("", "bcrypt", "argon2"):
        return None
    hash_str = user.get("password_hash") or user.get("hashed_password")
    if algorithm and hash_str:
        return {
            "hash": hash_str,
            "algorithm": algorithm,
            "salt": user.get("password_salt") or user.get("salt"),
            "signer_key": user.get("password_signer_key") or user.get("signer_key"),
            "rounds": user.get("password_rounds") or user.get("rounds"),
            "memory_cost": user.get("password_memory_cost") or user.get("memory_cost"),
            "salt_separator": user.get("password_salt_separator")
            or user.get("salt_separator"),
        }
    return None


async def verify_and_upgrade_legacy_hash(
    user: Dict[str, Any], candidate: str, db: Any
) -> bool:
    """Verify a candidate password against a legacy hash and upgrade it.

    Supports Django ``pbkdf2_sha256`` and Firebase ``scrypt``. On success
    the password is rehashed to bcrypt (via ``utils.security.hash_password``)
    and the legacy fields are cleared, returning ``True``. Returns ``False``
    for a bad password or an unsupported algorithm — callers treat that as
    an authentication failure.
    """
    from authy_package.utils.security import hash_password

    if not user or not candidate or db is None:
        return False
    legacy = _resolve_legacy(user)
    if not legacy:
        return False

    algorithm = str(legacy.get("algorithm") or "").lower()
    stored_hash = str(legacy.get("hash") or "")
    verified = False

    if algorithm in ("pbkdf2_sha256", "django_pbkdf2", "django"):
        verified = _verify_django_pbkdf2(candidate, stored_hash)
    elif algorithm in ("scrypt", "firebase_scrypt", "firebase"):
        scrypt_params = legacy.get("scrypt_params") or {}
        verified = _verify_firebase_scrypt(
            candidate,
            stored_hash,
            str(legacy.get("salt") or ""),
            signer_key=str(
                legacy.get("signer_key") or scrypt_params.get("signer_key") or ""
            ),
            rounds=int(legacy.get("rounds") or scrypt_params.get("rounds") or 8),
            memory_cost=int(
                legacy.get("memory_cost") or scrypt_params.get("memory_cost") or 14
            ),
            salt_separator=str(
                legacy.get("salt_separator")
                or scrypt_params.get("salt_separator")
                or ""
            ),
        )
    else:
        logger.info("Unsupported legacy password algorithm: %r", algorithm)
        return False

    if not verified:
        return False

    user_id = user.get("id")
    if not user_id:
        return False
    new_hash = hash_password(candidate)  # bcrypt, default rounds
    await db.update_user(
        str(user_id),
        {
            "hashed_password": new_hash,
            "password_algorithm": "bcrypt",
            "legacy_password_hash": None,
            "password_hash": None,
            "password_needs_rehash": False,
            "updated_at": _utcnow(),
        },
    )
    logger.info("Upgraded legacy password hash for user %s", user_id)
    return True
