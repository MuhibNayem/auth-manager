# tessera — Canonical Architecture Contracts (SOTA remediation)

Status: BINDING SPEC. All remediation work implements against these contracts.
Owner: architecture (parent-maintained). Changes require updating this file first.

## 0. Ground rules (apply to every module)

1. All I/O-bound public APIs are `async`. No sync/async mixing within one contract.
2. Errors: raise typed exceptions (`ValueError` for input, `PermissionError` for authz,
   `tessera.errors.TesseraError` hierarchy for domain errors). Never bare `Exception`.
3. Secrets/tokens/challenges/IDs: `secrets.token_urlsafe(n)` / `secrets.token_hex(n)` only.
   Never `random`, never time-seeded hashes.
4. All secret comparisons: `hmac.compare_digest`.
5. Datetimes: timezone-aware `datetime.now(timezone.utc)`. `datetime.utcnow()` is banned.
6. Logging via `logging.getLogger("tessera.<module>")`. No `print()` in library code (CLI
   user-facing output uses `rich` only).
7. Full type hints on public functions; concise docstrings.
8. No hardcoded credentials/URLs; everything configurable via `AuthConfig` / env.
9. Every module must import cleanly WITHOUT optional heavy deps (lazy-import pattern with
   `*_AVAILABLE` flags or in-method imports raising informative `ImportError`).
10. Tests: every fixed/implemented behavior gets pytest coverage under `tests/<area>/`
    using the in-memory fakes; no external services required.

## 1. Errors module — tessera/errors.py (NEW, owned by foundation)

```python
class TesseraError(Exception): ...            # base, carries .code: str, .message
class ConfigError(TesseraError): ...          # invalid/missing config
class AuthenticationError(TesseraError): ...  # bad credentials/token
class AuthorizationError(TesseraError): ...   # insufficient permissions
class RateLimitError(TesseraError): ...       # carries .retry_after: int
class NotFoundError(TesseraError): ...
class IntegrityError(TesseraError): ...       # duplicate/foreign-key style
class ProviderError(TesseraError): ...        # upstream provider failure
class DatabaseError(TesseraError): ...        # persistence failure
class TokenError(TesseraError): ...           # expired/invalid/wrong-type token
```
All existing call sites migrate to these. HTTP layers map them to status codes
(400/401/403/404/409/429/500, 502 for ProviderError).

## 2. AuthConfig — canonical attributes (foundation owns config.py)

`AuthConfig` MUST expose (dataclass fields, with env-var overrides in `from_env()`):

- core: `env: str = "development"` ("development"|"staging"|"production")
- jwt: `jwt_secret: str | None`, `jwt_algorithm: str = "HS256"`,
  `access_token_ttl_seconds: int = 3600`, `refresh_token_ttl_days: int = 7`,
  `jwt_issuer: str | None`, `jwt_audience: str | None`, `jwt_clock_skew_seconds: int = 30`
- sessions: `session_expiry_seconds: int = 86400*7`, `max_concurrent_sessions: int = 5`,
  `revoke_sessions_on_password_change: bool = True`
- security: `rate_limit_enabled: bool = True`, `rate_limit_max_attempts: int = 5`,
  `rate_limit_window_seconds: int = 300`, `account_lockout_duration_seconds: int = 900`,
  `mfa_required: bool = False`, `password_hash_algorithm: str = "bcrypt"`
  (`"bcrypt"|"argon2"`), `bcrypt_rounds: int = 12`,
  `reset_token_ttl_seconds: int = 900`, `base_url: str = "http://localhost:8000"`
- passwordless: `magic_link_ttl_seconds: int = 600`,
  `default_redirect_url: str | None`, `auto_create_users: bool = False`,
  `rp_id: str | None`, `rp_name: str = "Tessera"`
- email: `email_provider: str = "mailjet"`, mailjet/sendgrid/ses keys as today
- nested configs retained: database, cache, social, cognito, sms, bot_protection,
  password_security (existing dataclasses, extended as needed)

`AuthConfig.validate()` MUST raise `ConfigError` when:
- `jwt_secret` is None/empty or equals the public default string;
- `env == "production"` and any placeholder value remains (secrets, `example.com` URLs);
- database URL missing.
`get_auth()`/`init_auth()` MUST call `validate()` before returning.
Password hashing: implement in `utils/security.py` with `bcrypt` library directly
(passlib is removed project-wide). Argon2 optional via `argon2-cffi` when configured.

## 3. AbstractCache — tessera/cache/abstract_cache.py

Async-first, generic primitives ONLY (token semantics live in consumers):

```python
class AbstractCache(ABC):
    async def get(self, key: str) -> str | None
    async def set(self, key: str, value: str, *, ttl_seconds: int | None = None) -> None
    async def set_json(self, key, obj, *, ttl_seconds=None) -> None      # json helper
    async def get_json(self, key) -> Any | None
    async def delete(self, key: str) -> bool
    async def exists(self, key: str) -> bool
    async def incr(self, key: str) -> int                                 # creates at 0->1
    async def expire(self, key: str, ttl_seconds: int) -> bool
    async def ttl(self, key: str) -> int                                  # -2 missing,-1 no ttl
    async def lpush(self, key: str, *values: str) -> int
    async def rpop(self, key: str) -> str | None
    async def lrange(self, key: str, start: int, stop: int) -> list[str]
    async def hset(self, key: str, mapping: dict[str, str]) -> None
    async def hgetall(self, key: str) -> dict[str, str]
    async def hdel(self, key: str, *fields: str) -> int
    async def close(self) -> None
    async def health_check(self) -> bool
```

Implementations: `RedisCache` (redis.asyncio, replaces aioredis) and `InMemoryCache`
(TTL-expiring dict + lists/hashes; single-process; used by tests and dev).
Old names (`RedisCaching`, `create_token_pair`, ...) are REMOVED; consumers use
primitives with the key schema in §3.1. `cache/__init__.py` exports both classes.

### 3.1 Key schema (namespaces)
- `tessera:tokenpair:{user_id}` -> json {access_jti, refresh_jti} (optional)
- `tessera:refresh:{refresh_jti}` -> user_id ; `tessera:access:{access_jti}` -> user_id
- `tessera:session:{session_id}` -> json Session ; `tessera:user_sessions:{user_id}` -> set/list
- `tessera:magiclink:{token}` -> json ; `tessera:passkey:reg:{user_id}` / `tessera:passkey:auth:{challenge_key}`
- `tessera:oauth:state:{state}` -> json ; `tessera:oauth:nonce:{nonce}`
- `tessera:saml:request:{request_id}` / `tessera:saml:response:{response_id}` (replay ledgers)
- `tessera:ratelimit:{scope}:{id}` counter ; `tessera:lockout:{identifier}`
- `tessera:sms:{phone}` code/state ; `tessera:webhook:queue` list
Refresh-token ROTATION: on refresh, old `tessera:refresh:{jti}` is deleted atomically
(delete-then-create, tolerate race by verifying old jti still exists before issuing).

## 4. AbstractDatabase — tessera/db/abstract_db.py

Single unified async contract (replaces legacy AbstractDatabase + EnterpriseDatabaseAdapter;
both old classes are REMOVED). All methods async; dict-based records with stable keys
(`id`, `username`, `email`, `phone`, `hashed_password`, `mfa_enabled`, `mfa_secret`,
`created_at`, `updated_at`, `is_active`, `role`, plus provider-specific extras).
Identity lookups are case-insensitive for email/username.

```python
class AbstractDatabase(ABC):
    # lifecycle
    async def connect(self) -> None
    async def close(self) -> None
    async def health_check(self) -> bool

    # users
    async def create_user(self, user: dict) -> dict                      # returns stored doc w/ id
    async def get_user_by_id(self, user_id: str) -> dict | None
    async def get_user_by_identifier(self, *, username=None, email=None, phone=None) -> dict | None
    async def update_user(self, user_id: str, updates: dict) -> dict | None
    async def delete_user(self, user_id: str) -> bool
    async def list_users(self, *, limit=50, offset=0, search: str|None=None,
                         filters: dict|None=None) -> tuple[list[dict], int]   # (rows, total)
    async def count_users(self, *, active_only=False, mfa_enabled=None,
                          created_since: datetime|None=None) -> int

    # credentials / sessions
    async def save_session(self, session: dict) -> None
    async def get_session(self, session_id: str) -> dict | None
    async def get_active_sessions(self, user_id: str) -> list[dict]      # status=='active' only
    async def revoke_session(self, session_id: str) -> bool              # atomic status flip
    async def revoke_all_user_sessions(self, user_id: str) -> int

    # organizations
    async def create_organization(self, org: dict) -> dict
    async def get_organization(self, org_id: str) -> dict | None
    async def get_organization_by_slug(self, slug: str) -> dict | None
    async def update_organization(self, org_id: str, updates: dict) -> dict | None
    async def delete_organization(self, org_id: str) -> bool
    async def list_organizations(self, *, limit=50, offset=0) -> tuple[list[dict], int]
    async def add_org_member(self, org_id: str, member: dict) -> dict
    async def get_org_members(self, org_id: str) -> list[dict]
    async def update_org_member(self, org_id, user_id, updates: dict) -> dict | None
    async def remove_org_member(self, org_id: str, user_id: str) -> bool
    async def create_invitation(self, invitation: dict) -> dict
    async def get_invitation_by_token(self, token: str) -> dict | None
    async def get_pending_invitations(self, org_id: str) -> list[dict]
    async def delete_invitation(self, invitation_id: str) -> bool

    # audit log (append-only; adapter must store checksum = sha256 over canonical json
    # of the event WITHOUT db-assigned fields; hash-chain: include previous checksum)
    async def save_audit_event(self, event: dict) -> dict
    async def save_audit_events(self, events: list[dict]) -> int
    async def search_audit_events(self, *, event_types=None, actor=None, target=None,
                                  start=None, end=None, limit=50, offset=0) -> tuple[list[dict], int]
    async def get_audit_event(self, event_id: str) -> dict | None
    async def delete_audit_events_before(self, ts: datetime) -> int
    async def get_audit_statistics(self, *, since: datetime|None=None) -> dict
    async def get_audit_time_series(self, *, since: datetime, bucket_seconds: int) -> list[dict]

    # webhooks
    async def save_webhook_endpoint(self, endpoint: dict) -> dict
    async def get_webhook_endpoint(self, endpoint_id: str) -> dict | None
    async def list_webhook_endpoints(self) -> list[dict]
    async def update_webhook_endpoint(self, endpoint_id, updates: dict) -> dict | None
    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool
    async def save_webhook_delivery(self, delivery: dict) -> dict
    async def get_webhook_deliveries(self, endpoint_id: str, *, limit=50) -> list[dict]

    # RBAC
    async def save_role(self, role: dict) -> dict
    async def get_role(self, role_id: str) -> dict | None
    async def list_roles(self) -> list[dict]
    async def delete_role(self, role_id: str) -> bool
    async def save_role_assignment(self, assignment: dict) -> dict
    async def query_role_assignments(self, *, user_id=None, role_id=None,
                                     scope_type=None, scope_id=None) -> list[dict]
    async def delete_role_assignment(self, assignment_id: str) -> bool

    # api keys (admin v2) — store HASHED keys (sha256), never plaintext
    async def save_api_key(self, key_record: dict) -> dict
    async def get_api_key_by_hash(self, key_hash: str) -> dict | None
    async def list_api_keys(self) -> list[dict]
    async def revoke_api_key(self, key_id: str) -> bool

    # settings (white-label/branding/localization): generic kv with json values
    async def get_setting(self, key: str) -> Any | None
    async def set_setting(self, key: str, value: Any) -> None

    # SAML (request/response ids are replay ledgers; consume = atomic get+delete)
    async def save_saml_request(self, request_id: str, data: dict, *, ttl_seconds: int) -> None
    async def consume_saml_request(self, request_id: str) -> dict | None
    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None
    async def check_and_record_saml_response_id(self, response_id: str) -> bool  # False=replay
    async def save_saml_user_mapping(self, name_id: str, sp_entity_id: str, user_id: str) -> None
    async def get_saml_user_mapping(self, name_id: str, sp_entity_id: str) -> str | None

    # OIDC
    async def save_oidc_provider(self, provider: dict) -> dict
    async def get_oidc_provider(self, issuer_or_slug: str) -> dict | None
    async def update_oidc_provider(self, identifier: str, updates: dict) -> dict | None
       # adapter MUST whitelist updatable columns (no caller-key interpolation)
```

Implementations:
- `SQLDatabase` (SQLAlchemy async) — REFERENCE implementation, full surface. SQLite for
  tests/dev; Postgres/MySQL supported. Identifier lookups case-insensitive.
- `MongoDB` (motor) — full surface. Class name stays `MongoDB`.
- `DynamoDBAdapter` — keep existing key design; fix bool serialization (bool checked
  BEFORE int), missing `time` import, audit PK collisions (include event id), GSI index
  mismatch, atomic consume via conditional expressions, revoked-session filtering.
- `RedisAdapter`/`CassandraAdapter`: DELETED (files removed; exports and docs updated).
- `InMemoryDatabase` (db/memory.py, foundation-owned) — full-contract dict-based impl for
  tests/dev; used by the entire test suite.
`db/__init__.py` exports: AbstractDatabase, SQLDatabase, MongoDB, DynamoDBAdapter,
InMemoryDatabase, get_database() factory keyed on `DatabaseConfig.db_type`
(`sql|mongodb|dynamodb|memory`). No Neo4j.

## 5. FastAPI dependency-injection pattern (admin & adapters)

No bare `= None` default params on route handlers. Canonical pattern:

```python
class AdminDependencies:
    def __init__(self, auth_manager, db, cache, audit_logger, rbac, orgs, webhooks, sessions): ...
    # registered on app: app.state.admin_deps = AdminDependencies(...)
def get_admin_deps(request: Request) -> AdminDependencies:
    deps = getattr(request.app.state, "admin_deps", None)
    if deps is None: raise HTTPException(503, "Admin services not configured")
    return deps
async def get_current_admin_user(credentials = Depends(HTTPBearer()), deps = Depends(get_admin_deps)): ...
    # bearer ONLY via Authorization header; never query param; verify token via
    # JWTTokenManager; require role in {admin, owner, superadmin} OR RBAC admin:* grant.
```
`require_org_admin` enforced on org-scoped routes. Rate limiting dependency for bulk
ops. `/admin/v2` gets the SAME auth dependencies; API-key routes additionally validate
hashed keys via db. Webhook test/delivery endpoints validate URL safety (§7).

## 6. JWT / token contract (utils/security.py, foundation)

`JWTTokenManager` issues/validates BOTH token types with claims:
`{sub, type: "access"|"refresh", jti, iat, exp, iss?, aud?}`.
- `validate_token(token, *, expected_type)` MUST enforce `type` claim and raise TokenError.
- Refresh rotation handled with cache per §3.1.
- `verify_password` ALWAYS runs bcrypt against a dummy hash when the user is missing
  (constant-time path); login failure responses identical for bad-user/bad-password.
- Rate limiting + lockout enforced in login paths via cache counters (§3.1 keys).
- Reset tokens: `secrets.token_urlsafe(32)`, hashed (sha256) at rest, single-use with
  atomic consume, constant-time compare, NEVER printed in email body; reset link built
  from `config.base_url` (`{base_url}/auth/reset-password?token=...`), HTTPS enforced
  in production (ConfigError if base_url is http:// in production).

## 7. Webhook delivery semantics (platform-services)

- Endpoint URL validation at registration AND delivery: scheme must be https (http only
  if `config.env != "production"`), resolve hostname; reject private/link-local/loopback/
  metadata ranges (use `ipaddress` on all resolved A/AAAA records); reject redirects to
  disallowed hosts (max_redirects=0 by default).
- Signatures: HMAC-SHA256 over `f"{timestamp}.{canonical_json_bytes}"`, header
  `X-Tessera-Signature: sha256=<hex>`, `X-Tessera-Timestamp`, `X-Tessera-Event`, `X-Tessera-Delivery-Id`;
  receiver helper verifies with `hmac.compare_digest`, ±300s window, delivery-id replay store.
- Delivery: any non-2xx = failure → schedule retry per `[60,300,900,3600,14400]`;
  `_process_pending_events` MUST honor `scheduled_for`.
- Endpoint secrets: generated `secrets.token_hex(32)`, stored hashed? No — HMAC secret must
  be retrievable for signing, so store plaintext but NEVER return it in list/get APIs
  (return only last-4 masked). Rotate endpoint available.
- `events=[]` means subscribe-all (documented + implemented).

## 8. Admin v2 (enterprise) — real implementations (platform-admin)

- API keys: create returns plaintext ONCE; store sha256 hash + scopes + expiry; middleware
  validates `Authorization: Bearer tessera_ak_...` against db on every /admin/v2 route.
- Branding/localization/settings: persisted via db settings kv.
- Reports: real CSV/JSON generated from users/audit data via db contract; job ids are
  `secrets.token_hex(8)`; no fake sleeps beyond real work.
- Bulk user actions: implemented via db.list_users/update_user/delete_user with bounded
  `user_ids` (max 1000) and audit events emitted per action.
- Security analytics (replaces "AI"): rule-based detectors over audit events —
  impossible travel (geo-free: velocity by IP/user-agent change + time), brute force
  (N failed logins/window), MFA bypass attempts. Endpoints documented as heuristics.
- Advanced audit search: structured filters compiled to `search_audit_events` kwargs.

## 9. CLI (platform-services)

- `tessera init`: fix templates (real import paths `tessera.frameworks.*`, no
  placeholder secrets — generate `secrets.token_urlsafe(48)` into scaffolded .env,
  valid Jinja-free config).
- `tessera dev`: keep; restrict static fallback to 127.0.0.1.
- `tessera doctor`: REAL checks — python version, import probes, DB/Redis connectivity via
  health_check(), config.validate(), report table honestly (✓/✗ with reasons).
- `tessera migrate`: REAL migrations against db contract: `schema_migrations` tracking via
  db settings kv; migration modules from `tessera_migrations/` dir; run/rollback/status
  truthful output.
- `tessera users|audit|logs|config|webhooks`: implement against db/cache/config files
  (`users list/get/delete` via db; `audit search/export` via db; `config show/set` on
  `.tessera.json` with 0600 perms; `webhooks list/create/test` via db + webhook manager).
- `tessera deploy`: Docker path implemented for real (build image via docker SDK/CLI, run);
  AWS/GCP/Azure/K8s paths generate IaC artifacts (CloudFormation/K8s manifests/compose)
  into `./deploy-out/` and say exactly that — no fake "deployed" output.
- TUI dashboard: real metrics via db counts or honest "not connected".

## 10. Framework adapters

- FastAPI: `require_auth` uses `Depends(HTTPBearer())`; `require_role`, org-aware checks,
  `optional_auth`, `rate_limit` via cache primitives; uniform error mapping (§1).
- Flask: single shared event loop per worker (module-level), not one loop per request;
  never leak raw exception text to clients.
- Django: `require_auth`, `require_role`, `rate_limit`, `optional_auth` all present;
  set `request.tessera_user` (dict) WITHOUT clobbering `request.user`; middleware logs
  and re-raises auth errors (no bare `except: pass`).
- All three expose identical decorator/dependency names and behavior (parity matrix tested).

## 11. Packaging & CI (docs/packaging workstream)

- Single source of truth: root `pyproject.toml` (Poetry) renamed project `tessera`,
  version synced to `tessera.__version__`, python `>=3.9,<4.0`, slim core deps
  (pyjwt, cryptography, bcrypt, httpx, aiohttp, click, rich, python-dotenv, redis) +
  extras: `fastapi`, `flask`, `django`, `postgresql`, `mongodb`, `dynamodb`, `saml`,
  `oidc`, `sms`, `captcha`, `webauthn`, `all`, `dev` (pytest, pytest-asyncio, ruff, mypy).
- `tessera/pyproject.toml` DELETED (one packaging config only); version bump
  automation keeps `tessera/__init__.py:__version__` as source.
- CI: on PR → ruff + mypy (lenient baseline ok) + full pytest matrix; on main/tag →
  publish with tests passed, fix bot guard, fix tag collision, actions v4.
- README/RUNBOOK/reports reconciled to actual features; remove unverified metrics and
  compliance badges; install instructions match published metadata; no placeholder secrets.
- LICENSE: rename product references handled in docs workstream; keep MIT.

## 12. Definition of done (all workstreams)

1. `python -m compileall tessera` clean.
2. `pytest tests/` green (InMemory fakes only; no network).
3. No finding from the analysis remains unaddressed (fixed, or explicitly documented
   as out-of-scope with rationale in docs/REMEDIATION_STATUS.md maintained by each agent
   for its area under a heading named for the workstream).
4. Examples run against InMemory/memory db + fake providers where applicable.
