# Remediation status — PLATFORM/ADMIN workstream

Owner: `platform-admin-fix` (coder agent), branch `chorus/sota-auth-remediation`.
Binding spec: `docs/CONTRACTS.md`. Scope: `authy_package/admin`,
`authy_package/organizations`, `authy_package/webhooks`,
`authy_package/frameworks`, `authy_package/cognito`, `tests/platform_admin`.

Verification: `./.venv/bin/python -m pytest tests/platform_admin tests/foundation -q`
→ **exit 0, all tests pass (50 new platform_admin tests + foundation suite)**.
`python -m compileall` clean on all owned directories. No network in tests
(DNS monkeypatched; webhook delivery via `httpx.MockTransport`).

## §5 — Admin dashboard API (`admin/dashboard_api.py`, `admin/deps.py`) — REBUILT

- `AdminDependencies` dataclass registered on `app.state.admin_deps`;
  `get_admin_deps` resolves it (503 when absent). Every route uses `Depends`.
- Bearer-only auth via `HTTPBearer(auto_error=False)`; **no query-parameter
  tokens anywhere** (regression-tested).
- `POST /admin/api/v1/auth/login` accepts `{username_or_email, password}` and
  returns `{access_token, refresh_token, token_type, expires_in, user}`
  (exact UI-kit contract). Issues real JWTs via `JWTTokenManager`,
  enforces `enforce_login_rate_limit` / `record_login_failure` /
  `clear_login_failures`, writes `auth.login.success` / `auth.login.failed`
  audit events, identical error bodies for bad-user vs bad-password,
  admin-role gating (role or RBAC `admin:*` grant).
- `POST /auth/refresh` implements §3.1 rotation: old
  `authy:refresh:{jti}` verified + deleted before re-issue; replayed
  refresh tokens get 401.
- User CRUD/search/bulk via `db.list_users/count_users/get_user_by_id/
  update_user/delete_user` with pagination totals; bulk bounded at 1000
  ids (422 above), audited per action; self-delete refused.
- Impersonation: audit-logged (`admin.user_impersonation`), 15-minute TTL
  token signed with the same JWT material (validates through the normal
  path, `impersonation` claims), privileged targets
  (admin/owner/superadmin) refused with 403.
- Orgs via `OrganizationManager` with `require_org_admin` on org-scoped
  routes (platform admins always pass); members, role changes,
  invitations (create/list/accept/decline) with last-owner protection.
- Audit search/export via `db.search_audit_events`; CSV export uses the
  `csv` module with `QUOTE_ALL` (malicious-string regression test).
- Sessions via db contract (`get_active_sessions`, `revoke_session`,
  `revoke_all_user_sessions`).
- Webhooks via `WebhookManager`; health via `db.health_check()` +
  `cache.health_check()`.
- The fake WebSocket endpoint was **removed** (no honest heartbeat
  implementation was warranted; UI kit does not require it).
- AuthyError→HTTP mapping (§1) registered app-wide (401/403/404/409/429
  +Retry-After/502/500), plus ValueError→400, PermissionError→403.

## §8 — Admin v2 (`admin/dashboard_enterprise.py`, `admin/rbac_api.py`, `admin/rbac_manager.py`) — REAL

- **API keys**: `authy_ak_` + `secrets.token_hex(32)`; plaintext returned
  ONCE; only the sha256 hash is stored via `db.save_api_key`. Every
  `/admin/v2` route authenticates via `get_v2_principal` (API key or admin
  JWT). Revocation + expiry enforced. Scope enforcement via
  `require_v2_scope` (JWT admins always pass; keys need the scope or
  `admin:*`).
- Branding/localization/settings persisted via db settings kv
  (`admin:branding`, `admin:localization`, `admin:settings:{key}`).
- Reports: REAL CSV/JSON generated from users/audit data; job ids
  `secrets.token_hex(8)`; artifacts stored in settings kv and served at
  `/reports/{job_id}/download`; index listing maintained.
- Bulk v2 actions real + bounded (1000, 422 above) + audited per action.
- Security analytics = **rule-based detectors** over audit events,
  documented as heuristics (response carries `"heuristic": true` and
  `"method": "rule-based detectors over audit events (no AI/ML)"`):
  brute force (N failed logins per identifier/IP in window),
  impossible-travel proxy (rapid IP change on successful logins — no geo
  claims), MFA failure spikes. The fake "AI" endpoints, NLQ, predictions
  and the fake WebSocket were removed.
- Advanced audit search compiles structured filters to
  `search_audit_events` kwargs.
- RBAC: roles/assignments persisted via db contract; cache loaded at init
  (`RBACManager.create`) and refreshed after writes; 4 scope levels;
  inheritance with cycle guard (create/update + evaluation visited-set);
  time-limited assignments checked at evaluation; system-role protection;
  wildcard `admin:*` permissions; `granted_by` always the authenticated
  principal (placeholder removed).

## §4/§5 — Audit logger (`admin/audit_logger.py`) — REWRITTEN

- Kept the 34-event `EventType` enum and `AuditEvent`.
- Queue with periodic flush task (`start()`) + flush on `close()`;
  `sync=True` writes immediately for security-critical events; flush
  failures re-queue events.
- Persistence via `db.save_audit_event(s)`; search/export/stats/time-series
  delegate to the db contract. Event docs carry both `actor`/`target`
  (db search keys) and legacy aliases; timezone-aware timestamps.
- CSV export via `csv` module `QUOTE_ALL` (was hand-rolled comma
  replacement). IDs from `secrets.token_hex` (was `uuid`).

## §5 — Organizations (`organizations/org_manager.py`) — REWRITTEN

- Constructor takes `db` (+ optional `cache`, `email_service`); when
  `email_service` is None invitations are still created and returned with
  their token, email skipped + logged.
- API aligned with the admin routes: `create_organization(description,
  plan...)`, `add_member(..., added_by=...)`,
  `get_organizations_paginated`, `get_pending_invitations`.
- Slug uniqueness fallback (`acme` → `acme-<hex>`); plan-based member caps
  (`PLAN_MAX_MEMBERS`); last-owner removal AND demotion refused.
- Invitations: expiry checked, single-use accept via
  `get_invitation_by_token` + delete; duplicate pending invite rejected;
  invitation sends rate-limited via cache counters (§3.1 key);
  tokens `secrets.token_urlsafe(32)`; accepting user's email must match.

## §7 — Webhooks (`webhooks/webhook_manager.py`) — COMPLETE

- `validate_endpoint_url`: https required in production (http elsewhere);
  resolves ALL A/AAAA via `socket.getaddrinfo`; rejects
  private/loopback/link-local (incl. 169.254.169.254)/reserved/
  unspecified/multicast. Enforced at registration AND delivery AND test.
- Delivery via `httpx.AsyncClient(follow_redirects=False)`; non-2xx →
  failure record + retry on `[60, 300, 900, 3600, 14400]`;
  `process_pending_events` honors `scheduled_for` (regression-tested).
- Signatures exactly per §7: HMAC-SHA256 over
  `f"{timestamp}.{canonical_json}"`, headers `X-Authy-Signature:
  sha256=<hex>`, `X-Authy-Timestamp`, `X-Authy-Event`,
  `X-Authy-Delivery-Id`; receiver-side static
  `verify_webhook_signature` (compare_digest, ±300s, delivery-id replay
  store via cache).
- Secrets `secrets.token_hex(32)`; shown once at registration/rotation;
  list/get mask all but last 4. `events=[]` = subscribe-all (documented +
  implemented). Persistence via db webhook methods + `authy:webhook:queue`
  cache list.

## §10 — Framework adapters (`frameworks/`) — FIXED

- FastAPI: `require_auth` is a proper dependency using
  `Depends(HTTPBearer(auto_error=False))` (the missing-`Depends` defect is
  gone); `require_role`, `require_org_membership`, `optional_auth`,
  `rate_limit` via cache (§3.1 keys); AuthyError→HTTPException mapping +
  installable handlers.
- Flask: ONE module-level event loop reused across requests, driven via
  lock-guarded `loop.run_until_complete`; sync decorators; error bodies
  carry only stable codes + generic messages (never `str(e)`).
- Django: `require_auth`, `require_role`, `rate_limit`, `optional_auth`
  all present; sets `request.authy_user` and NEVER touches `request.user`;
  middleware logs + propagates auth errors (bare `except: pass` removed),
  with a `set_auth_manager()` registry instead of `get_auth()` guessing.
- Identical decorator/dependency names and behavior across adapters;
  components resolved from explicit kwargs or `auth_manager` attributes.

## Cognito (`cognito/cognito_manager.py`) — FIXED

- `exchange_code_for_tokens` performs a REAL POST to the user-pool
  hosted-UI `/oauth2/token` endpoint (form body; HTTP Basic auth when a
  client secret is configured) — the invalid `AUTHORIZATION_CODE`
  InitiateAuth call is removed.
- All query strings built with `urllib.parse.urlencode`.
- `authenticate_user` uses USER_SRP_AUTH with a minimal, secrets-safe
  SRP-6a implementation (RFC 5054 3072-bit group, HKDF "Caldera Derived
  Key", SECRET_HASH support) — no plaintext-password flow.
- All errors raised as AuthyError subclasses (AuthenticationError /
  RateLimitError / ProviderError) — never `{"Error": str(e)}` dicts.
- TOTP: associate software token FIRST, then set preference (optional
  verification step when a code is provided).
- boto3 import is optional/lazy per §0.9.

## Tests — `tests/platform_admin/` (NEW, 50 tests)

Own `conftest.py` wires InMemoryDatabase + InMemoryCache +
JWTTokenManager into `create_admin_app`; httpx ASGI transport (no
network). Coverage:

- Unauthenticated `/admin/api/v1` and `/admin/v2` → 401; query-param
  token rejected; login happy path (exact UI-kit shape); identical
  bad-user/bad-password errors; lockout after 3 failures; non-admin 403;
  refresh rotation invalidates old tokens; wrong token type rejected.
- User CRUD + pagination totals; 409 on duplicate email; bulk >1000 → 422;
  bulk applies + audits; impersonation refuses privileged targets and
  issues a validating 15-min token.
- Org create/slug fallback/plan caps/last-owner protection; invitation
  flow without email service (token returned), single-use accept, expiry,
  API routes.
- Webhooks: registration rejects `http://127.0.0.1`,
  `http://169.254.169.254`, `http://10.0.0.5` and an https hostname
  resolving only to a private IP (monkeypatched getaddrinfo); secret
  masking; signature roundtrip + tamper + stale timestamp + replay
  rejection; non-2xx → retry schedule + `scheduled_for` honored;
  subscribe-all.
- API keys: create-once/validate/revoke; scope enforcement; branding &
  localization persisted; real report CSV download; v2 bulk audited;
  rule-based analytics incidents; advanced audit search.
- RBAC: grant→check→expiry, inheritance + wildcard + cycle guard, scoped
  grants, system-role protection, API granted_by from principal, 401
  without auth.
- Audit CSV QUOTE_ALL neutralizes malicious delimiter/quote/newline
  injection; audit search API; session list/revoke; queued flush on close.

## Cross-workstream fix (parent-approved)

- `tests/foundation/conftest.py::_make_config` had a latent flake:
  `jwt_secret=secrets.token_urlsafe(32)` can rarely contain a placeholder
  marker (e.g. `xxx`), failing `AuthConfig.validate()` at fixture setup
  (~2-3% per full-suite run; reproduced twice in combined runs). With
  chorus approval (msg f9fe502f / f6325676), changed ONLY that line to
  `jwt_secret=secrets.token_hex(32)` — provably marker-safe (every marker
  contains a non-hex character) with the same 256-bit entropy. No other
  foundation file and no production code was touched. Combined run
  `pytest tests/platform_admin tests/foundation -q` verified green 10/10
  consecutive runs afterward (248 tests).

## Known limitations / honest notes

- Cognito SRP math is implemented per the documented Cognito SRP protocol
  but cannot be integration-tested here (no AWS/network); the flow is
  unit-verifiable only at the protocol level.
- `active_sessions` dashboard metric iterates users (bounded at 10k) via
  the db contract — there is no global session listing method in §4.
- Org listing/search fetches all orgs then paginates in memory (db
  contract lacks org search); acceptable at admin scale, documented.
