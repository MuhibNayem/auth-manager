# Remediation status — FOUNDATION workstream

Owner: `foundation-contracts` (coder agent), branch `chorus/sota-auth-remediation`.
Binding spec: `docs/CONTRACTS.md`. Scope: §1–§6 foundation-owned files plus
`tests/foundation/`.

## §1 — Errors module (`authy_package/errors.py`, NEW)

- Implemented the full `AuthyError` hierarchy exactly as specified:
  `ConfigError`, `AuthenticationError`, `AuthorizationError`, `RateLimitError`,
  `NotFoundError`, `IntegrityError`, `ProviderError`, `DatabaseError`,
  `TokenError`.
- Every error carries `.code` (stable machine-readable, subclass
  `default_code` overridable via `code=` kwarg) and `.message`.
- `RateLimitError` carries `.retry_after: int` and serializes it in
  `to_dict()` for HTTP mapping (429).
- `to_dict()` provided on the base for uniform API error bodies.

## §2 — AuthConfig (`authy_package/config.py`, REWRITTEN)

- Kept the dataclass-tree style; all flat canonical attributes added directly
  on `AuthConfig`: `env`, `jwt_secret`, `jwt_algorithm`,
  `access_token_ttl_seconds`, `refresh_token_ttl_days`, `jwt_issuer`,
  `jwt_audience`, `jwt_clock_skew_seconds`, `session_expiry_seconds`,
  `max_concurrent_sessions`, `revoke_sessions_on_password_change`,
  `rate_limit_enabled`, `rate_limit_max_attempts`,
  `rate_limit_window_seconds`, `account_lockout_duration_seconds`,
  `mfa_required`, `password_hash_algorithm`, `bcrypt_rounds`,
  `reset_token_ttl_seconds`, `base_url`, `magic_link_ttl_seconds`,
  `default_redirect_url`, `auto_create_users`, `rp_id`, `rp_name`,
  `email_provider` + flat provider keys (mailjet/sendgrid/ses) +
  `email_enabled`, `sender_email`, `sender_name`.
- Nested configs retained: `DatabaseConfig`, `CacheConfig`,
  `SocialAuthConfig`, `CognitoConfig`, `SMSConfig`, `BotProtectionConfig`,
  `PasswordSecurityConfig`. Removed `JWTConfig`, `SecurityConfig`,
  `EmailConfig` (their fields moved flat onto `AuthConfig` per §2).
- **No hardcoded default secret survives**: `jwt_secret` defaults to `None`;
  the legacy `JWTConfig.__post_init__` env-fallback to
  `"your-secret-key-change-in-production"` is deleted; that string is now
  only referenced as `PUBLIC_DEFAULT_JWT_SECRET` so `validate()` can reject
  it explicitly.
- `from_env()` preserves every legacy `AUTHY_*` name (AUTHY_DB_TYPE,
  AUTHY_DB_URL, AUTHY_DB_NAME, AUTHY_DB_COLLECTION, AUTHY_CACHE_ENABLED,
  AUTHY_REDIS_URL, AUTHY_TOKEN_EXPIRATION, AUTHY_REFRESH_TOKEN_EXPIRATION,
  AUTHY_JWT_SECRET, AUTHY_RATE_LIMIT_ENABLED, AUTHY_RATE_LIMIT_MAX_ATTEMPTS,
  AUTHY_COGNITO_ENABLED, AUTHY_EMAIL_ENABLED, AUTHY_SMS_*,
  AUTHY_BOT_PROTECTION_ENABLED, AUTHY_CAPTCHA_PROVIDER,
  AUTHY_MAX_REQUESTS_PER_*, AUTHY_PASSWORD_*, MAILJET_API_KEY/SECRET,
  SENDER_EMAIL/SENDER_NAME, provider vars) and adds new `AUTHY_*` vars for
  the new fields (AUTHY_ENV, AUTHY_JWT_ALGORITHM/ISSUER/AUDIENCE/
  CLOCK_SKEW_SECONDS, AUTHY_SESSION_EXPIRY_SECONDS,
  AUTHY_MAX_CONCURRENT_SESSIONS, AUTHY_REVOKE_SESSIONS_ON_PASSWORD_CHANGE,
  AUTHY_RATE_LIMIT_WINDOW_SECONDS, AUTHY_ACCOUNT_LOCKOUT_DURATION_SECONDS,
  AUTHY_MFA_REQUIRED, AUTHY_PASSWORD_HASH_ALGORITHM, AUTHY_BCRYPT_ROUNDS,
  AUTHY_RESET_TOKEN_TTL_SECONDS, AUTHY_BASE_URL, AUTHY_MAGIC_LINK_TTL_SECONDS,
  AUTHY_DEFAULT_REDIRECT_URL, AUTHY_AUTO_CREATE_USERS, AUTHY_RP_ID,
  AUTHY_RP_NAME, AUTHY_REFRESH_TOKEN_TTL_DAYS, AUTHY_EMAIL_PROVIDER,
  SENDGRID_API_KEY, SES_*). Malformed int env values raise `ConfigError`.
- `validate()` raises `ConfigError` when: jwt_secret is None/empty, equals
  the public default string, or is placeholder-like; `env` invalid;
  `password_hash_algorithm` not bcrypt|argon2; `bcrypt_rounds` outside
  4..31; non-positive TTLs/session limits; `database.db_type` unknown or
  (non-memory) connection string missing; cache enabled without redis URL;
  `base_url` not http(s); production with http base_url (HTTPS enforced per
  §6); production with placeholder secrets, `example.com` URLs or sender.
- Deviation note: `get_auth()`/`init_auth()` (must call `validate()` per §2)
  live in `authy_package/__init__.py` / core workstream files, which are NOT
  foundation-owned; they must call `config.validate()` in Wave-2 core-auth.

## §3 / §3.1 — Cache (`authy_package/cache/`, REWRITTEN)

- `abstract_cache.py`: exactly the listed async primitives (`get`, `set`,
  `set_json`, `get_json`, `delete`, `exists`, `incr`, `expire`, `ttl`,
  `lpush`, `rpop`, `lrange`, `hset`, `hgetall`, `hdel`, `close`,
  `health_check`). `set_json`/`get_json` are concrete base-class helpers
  built on `get`/`set`; everything else is abstract.
- `memory_cache.py`: `InMemoryCache` with monotonic-clock TTL expiry
  (checked lazily on access), Redis-like type replacement semantics, lists
  (inclusive/negative `lrange`), hashes, counter semantics (`incr` creates
  at 0→1), ttl sentinels (-2 missing / -1 no TTL). String values enforced.
- `redis_cache.py`: `RedisCache` on `redis.asyncio` (NOT aioredis; the
  `aioredis` import is gone), same primitive surface, `decode_responses=True`,
  `aclose`/`close` fallback, non-raising `health_check`. Client may be
  injected; constructed clients are owned and closed.
- `__init__.py` exports `AbstractCache`, `InMemoryCache`, `RedisCache`.
- Old names removed entirely: `RedisCaching`, `create_token_pair`,
  `store_reset_token` etc. are gone; consumers combine primitives with the
  §3.1 key schema (constants for login rate-limit/lockout/reset keys are
  exported from `utils/security.py`).

## §4 — Database (`authy_package/db/`, REWRITTEN)

- `abstract_db.py`: the EXACT unified async contract from §4 (legacy
  `AbstractDatabase` body replaced; `EnterpriseDatabaseAdapter` gone).
  All methods async, typed, docstring'd; audit and SAML semantics documented
  on the abstract methods.
- `enterprise_abstract.py`: DELETED (preferred over a shim per task
  instruction). Its legacy exception classes are superseded by
  `authy_package.errors`.
- `memory.py`: `InMemoryDatabase` implementing the FULL §4 surface:
  - users: case-insensitive email/username indexes (phone exact), unique
    identifier enforcement (`IntegrityError`), immutable `id`/`created_at`,
    list with pagination/search/filters + totals, `count_users` filters.
  - sessions: `save_session` upsert, `get_active_sessions` filtering
    `status == "active"`, `revoke_session` atomic status flip (asyncio lock;
    concurrent callers get exactly one True), `revoke_all_user_sessions`.
  - organizations/members/invitations: slug uniqueness + reindex on update,
    member uniqueness, pending invitation filtering, cascade delete of
    members/invitations with the org.
  - audit: append-only; db assigns `id`, `timestamp` (when absent),
    `sequence`, `checksum`, `previous_checksum`. `checksum` = sha256 over
    canonical JSON (`sort_keys`, `separators=(",", ":")`, `default=str`) of
    the event WITHOUT db-assigned fields `{id, sequence, checksum}`;
    `previous_checksum` is part of the checksummed payload and stored
    (genesis sentinel 64 zero hex chars). Search newest-first with totals;
    statistics; bucketed time series; pruning via
    `delete_audit_events_before` (oldest remaining event becomes the new
    genesis for verification). Extra utility `verify_audit_chain()`
    re-verifies checksums + linkage (used by the mandated tamper test).
  - webhooks: endpoints + deliveries (FK-style `IntegrityError`), deliveries
    newest-first with limit; deleting an endpoint removes its history.
  - RBAC: role name uniqueness, upsert by id, assignment FK enforcement,
    AND-combined queries, role deletion blocked while assignments exist.
  - api keys: sha256-hash-only storage — plaintext `key`/`api_key` fields
    are rejected with `ValueError`; duplicate hash → `IntegrityError`;
    revoke stamps `revoked`/`revoked_at`.
  - settings: JSON-serializable kv with deep copies in/out.
  - SAML: request ledger with TTL + atomic consume (asyncio lock, exactly
    one winner), response-id replay ledger (`check_and_record_*` returns
    False on replay; records from `save_saml_response_id` honor their TTL,
    records from `check_and_record_*` persist since the contract gives that
    call no TTL parameter), NameID mappings.
  - OIDC: unique issuer/slug, lookup by either, `update_oidc_provider`
    enforces an explicit whitelist (`OIDC_UPDATABLE_FIELDS`); non-whitelisted
    keys raise `ValueError`; issuer/slug changes reindex.
- `enterprise_utils.py`: KEPT and FIXED — `RetryConfig.retryable_exceptions`
  default is now `(DatabaseError, TimeoutError)` from `authy_package.errors`
  (NOT the builtin `ConnectionError`); circuit breaker OPEN state raises
  `DatabaseError(code="circuit_open")`; circuit timing uses
  `time.monotonic()`; retry jitter uses `random.SystemRandom()`;
  `ConnectionPool.health_check` executes `text("SELECT 1")` (lazy SQLAlchemy
  import, §0.9) with a raw-string fallback only when SQLAlchemy is absent;
  `CircuitBreaker`/`ObservabilityMixin` retained; logger renamed to
  `authy.db.enterprise_utils` (§0.6).
- `db/__init__.py`: exports `AbstractDatabase`, `InMemoryDatabase`,
  `get_database()`; `SQLDatabase`/`MongoDB`/`DynamoDBAdapter` resolve via
  PEP 562 module `__getattr__` with guarded `importlib` loads that raise an
  informative `ImportError` ("unavailable") instead of breaking
  `import authy_package.db`. `get_database()` keys on
  `DatabaseConfig.db_type` (`sql|mongodb|dynamodb|memory`, accepts either
  `AuthConfig` or `DatabaseConfig`) and raises `ConfigError` for unknown
  types. All Neo4j references removed. `MongoDBDatabase` kept as a lazy
  alias of `MongoDB` for one release.
  - Note: `cassandra_adapter.py`/`redis_adapter.py` still exist on disk
    (owned by the adapters team per §4 "RedisAdapter/CassandraAdapter:
    DELETED"); `db/__init__.py` no longer imports or exports them.

## §5 — FastAPI DI pattern

Not foundation-owned (admin/platform workstreams). `JWTTokenManager`,
`AbstractDatabase`, `AbstractCache`, and the error hierarchy needed by §5
are provided by this workstream.

## §6 — JWT / token contract (`authy_package/utils/security.py`, REWRITTEN)

- passlib is gone; hashing uses the `bcrypt` library directly (explicit
  72-byte truncation, documented) with argon2-cffi lazily when
  `password_hash_algorithm == "argon2"` (§0.9). `hash_password` /
  `verify_password` dispatch on hash prefix; malformed input returns False.
- `verify_password_constant_time(candidate, hashed_or_None)` always runs a
  real verification: dummy-hash compare when the stored hash is missing
  (precomputed constant for bcrypt rounds=12; lazily cached dummy per
  algorithm/rounds), then returns False.
- `JWTTokenManager(config)` issues access/refresh tokens with claims
  `{sub, type, jti, iat, exp, iss?, aud?}` (`jti` via
  `secrets.token_urlsafe(16)`, times timezone-aware UTC). Reserved claims
  cannot be overridden via `additional_claims` (ValueError).
  `create_token_pair` also returns `access_jti`/`refresh_jti` for the §3.1
  cache pairing. `validate_token(token, *, expected_type)` enforces the
  `type` claim and raises `TokenError` with codes `token_expired`,
  `token_invalid`, `token_wrong_type`; `jwt_clock_skew_seconds` applied as
  pyjwt leeway; issuer/audience validated when configured. Constructor
  raises `ConfigError` without a secret (no default fallback anywhere).
- Rate limiting + lockout helpers (module-level, async):
  `enforce_login_rate_limit`, `record_login_failure`,
  `clear_login_failures` over cache counters
  `authy:ratelimit:login:{identifier}` and `authy:lockout:{identifier}`
  (§3.1). Behavior: failures increment the counter (fixed window of
  `rate_limit_window_seconds`); at `rate_limit_max_attempts` a lockout
  marker is set for `account_lockout_duration_seconds` and the counter is
  reset (lockout supersedes). `enforce` raises `AuthenticationError`
  (`code="account_locked"`) during lockout and `RateLimitError` (with
  `retry_after` from the counter TTL) when the window budget is exhausted.
  Disabled rate limiting is a no-op.
- Reset flow (`SecurityManager(db, cache, config)`): tokens via
  `secrets.token_urlsafe(32)`, stored ONLY as sha256 hashes under
  `authy:reset:{token_hash}` with `config.reset_token_ttl_seconds`;
  single-use consume (get → compare_digest → delete); constant-time compare
  via `hmac.compare_digest`; link built from `config.base_url`
  (`{base_url}/auth/reset-password?token=...`); the raw token never appears
  in email bodies outside the link; unknown identifiers get the same
  response (no account enumeration). HTTPS-in-production is enforced by
  `AuthConfig.validate()` (§2).
- Email: Mailjet sending kept; `mailjet_rest` lazy-imported and the client
  constructed only when keys are present; when email is unconfigured,
  sending is a logged no-op (`{"sent": False, "reason": "email_unconfigured"}`)
  so tests never need network. `sendgrid`/`ses` selection raises an honest
  `ProviderError` (only Mailjet transport is implemented in this build).
  Blocking provider calls are dispatched via `asyncio.to_thread` (§0.1).

## §0 ground rules

Applied throughout: async-only public APIs, full type hints, `logging`
(`authy.<module>` loggers), `secrets` for tokens/ids, timezone-aware UTC
datetimes (`datetime.utcnow` never used), `hmac.compare_digest` for secret
comparisons, no `print`, lazy imports for optional deps, typed errors.

## Tests (`tests/foundation/`, NEW)

- `test_errors.py` — hierarchy, codes, `retry_after`, serialization.
- `test_config.py` — from_env (legacy + new env names, malformed ints),
  validate (missing/empty/public-default/placeholder secret, missing DB URL,
  production placeholder/HTTP rejection, valid prod config).
- `test_passwords.py` — bcrypt direct (rounds, 72-byte truncation, unicode),
  argon2, malformed-hash False path, dummy-hash constant-time path.
- `test_jwt.py` — claims, pair jtis, iss/aud, type enforcement, expiry,
  clock-skew leeway, tamper/wrong-secret/missing-claim rejection.
- `test_reset_flow.py` — hashed-at-rest storage, link construction, no bare
  token in email, enumeration-safe responses, single-use consume, full
  reset incl. session revocation, unconfigured-email no-op.
- `test_rate_limit.py` — counters, window TTL, lockout engagement,
  RateLimitError/AuthenticationError paths, clear on success.
- `test_cache.py` — every primitive incl. TTL expiry (forced + real sleep),
  lists/hashes/type replacement, json helpers, RedisCache constructability.
- `test_db_users_sessions.py`, `test_db_orgs.py`, `test_db_audit.py`
  (chain integrity + tamper detection + search/stats/time series),
  `test_db_webhooks_rbac_keys_settings.py`,
  `test_db_saml_oidc_factory.py` (atomic consume races, replay rejection,
  OIDC whitelist, factory + guarded lazy imports).

## Verification (all green on this branch)

- `./.venv/bin/python -m pytest tests/foundation -q` — **201 passed, 0
  failed** (exit 0).
- `./.venv/bin/python -m compileall authy_package/errors.py authy_package/config.py authy_package/utils authy_package/cache authy_package/db` — clean.
- `./.venv/bin/python -c "import authy_package.db, authy_package.cache, authy_package.config, authy_package.errors"` — succeeds.

## Deviations / notes (with justification)

1. **Atomic consume of reset tokens on cache primitives**: §3 exposes no
   `getdel`; consume is get → constant-time compare → delete. In-process
   (InMemoryCache) this is atomic because no await yields between the steps;
   Redis backends retain a small race window by design of the §3 contract
   (same tolerance documented for refresh rotation in §3.1).
2. **`check_and_record_saml_response_id` has no TTL parameter** in the §4
   contract; entries recorded through it persist until process end, while
   `save_saml_response_id` entries honor their TTL. Real adapters should map
   this to their replay-window policy.
3. **Audit pruning breaks the original genesis link**: after
   `delete_audit_events_before`, the oldest remaining event is treated as
   the new genesis by `verify_audit_chain`; its `previous_checksum` remains
   stored for external verifiers.
4. **`get_auth()`/`init_auth()` `validate()` call** (§2) is owed by the
   Wave-2 core-auth workstream (file outside foundation ownership).
5. **Top-level package import resilience**: `authy_package/__init__.py`
   still eagerly imports modules with heavy optional deps (cognito/social/
   framework adapters). Foundation's own subtree (`errors`, `config`,
   `utils`, `cache`, `db`) is import-safe per §0.9; the top-level lazy-import
   hardening is pending under the core-auth workstream (per parent
   instruction 2026-07-18: foundation must NOT modify that file).
6. **`cassandra_adapter.py` / `redis_adapter.py`** remain on disk (deletion
   owned by the adapters team per §4); they are no longer imported or
   exported by `db/__init__.py`.
