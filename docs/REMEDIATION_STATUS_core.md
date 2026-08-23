# Remediation Status — CORE AUTH workstream

Owner: core-auth-fix (coder role). Scope: `authy_package/core`, `sessions`,
`mfa`, `passwordless`, `password_security`, `saml`, `oidc`, `social`,
`migration`, `compliance`, package `__init__.py`, and `tests/core`.

All work is implemented against the frozen foundation contracts
(`docs/CONTRACTS.md` §1–§6) and verified with `InMemoryDatabase` +
`InMemoryCache` (no network, no external services).

## Verification summary

- `pytest tests/core tests/foundation -q` — **green** (foundation stays green).
- `python -m compileall` on every owned directory — **clean**.
- `python -c "import authy_package; authy_package.get_auth.__doc__"` — works;
  `import authy_package` succeeds and every name in `__all__` resolves.

## Numbered defect list → resolution

### 1. `core/auth_manager.py`
**Fixed / rewritten.**
- Removed all stray-`self` calls (`_handle_social_login(self, ...)` in the
  Facebook/GitHub/Google branches and the Cognito `register_user(self, ...)`),
  which previously raised `TypeError` the moment the paths ran.
- `login_user` now: fetches the user, verifies with
  `verify_password_constant_time` (dummy-hash path when the user is missing),
  raises an **identical** `AuthenticationError` ("Invalid credentials",
  `authentication_failed`) for unknown-user and wrong-password, enforces
  rate limiting + lockout via `enforce_login_rate_limit` /
  `record_login_failure` / `clear_login_failures`, and gates on MFA with
  attempt limiting.
- Legacy hashes: when `user["password_algorithm"]` is set and is not
  `bcrypt`/`argon2`, login calls
  `authy_package.migration.verify_and_upgrade_legacy_hash`, rehashing to
  bcrypt on success (see item 11).
- `hashed_password` / `mfa_secret` / backup codes / legacy hash fields are
  stripped from **every** response via `sanitize_user`.
- `refresh_token` validates the JWT with `expected_type="refresh"` and rotates
  through the §3.1 cache ledger (old `authy:refresh:{jti}` deleted on use;
  replay rejected).
- Duplicated MFA enable/reconfigure logic unified into a single
  `_begin_mfa_setup` helper shared by `TraditionalAuthManager` and
  `SocialAuthManager`.
- Sessions wired through the db contract: login creates a session via
  `SessionManager` (→ `db.save_session`), logout revokes it
  (`db.revoke_session`).

### 2. `authy_package/__init__.py`
**Fixed.** Fully guarded per §0.9: only the pure `errors`/`config` modules are
imported eagerly; every other submodule is probed with a try/except that sets a
`*_AVAILABLE` flag (`CORE_AVAILABLE`, `SESSIONS_AVAILABLE`, …,
`ORGANIZATIONS_AVAILABLE`, `WEBHOOKS_AVAILABLE`, `ADMIN_AVAILABLE`,
`FRAMEWORKS_AVAILABLE`, `SMS_AVAILABLE`, `BOT_PROTECTION_AVAILABLE`).
`__all__` is built **only** from names whose owning submodule imported
successfully, and a PEP 562 `__getattr__` resolves exported names lazily with an
informative `ImportError` when unavailable. `__version__ = "2.0.0"`. Both
`get_auth()` and `init_auth()` call `config.validate()` before constructing the
manager. `import authy_package` succeeds with no optional dependencies present.

### 3. `sessions/session_manager.py`
**Rebuilt.** Uses foundation config attributes (`session_expiry_seconds`,
`max_concurrent_sessions`) and `JWTTokenManager` (which enforces the token
`type` claim). Sessions are cached under §3.1 keys
(`authy:session:{session_id}`, `authy:user_sessions:{user_id}`) and persisted
through the db contract (`save_session`/`revoke_session`/
`get_active_sessions`). `validate_session` accepts only access tokens (a
refresh token is rejected); `refresh_session` rotates both tokens and
invalidates the old refresh token; the oldest sessions are evicted beyond
`max_concurrent_sessions`; all timestamps are timezone-aware UTC; last-active
updates run as background tasks whose references are retained.

### 4. `mfa/mfa_setup.py`
**Rewritten.** Enabling MFA is two-step: `setup_mfa` issues a *pending* secret
and `confirm_mfa` activates it **only after a valid TOTP code** is confirmed.
Confirmation and verification are attempt-limited via cache counters
(`authy:ratelimit:mfa:{user_id}`). Code comparison uses pyotp `verify`
semantics (constant-time). Eight single-use backup codes are issued at
activation and stored only as sha256 digests; each is deleted on first use.
Secrets come from `pyotp.random_base32`.

### 5. `passwordless/magic_link.py`
**Rewritten.** Tokens are `secrets.token_urlsafe(32)`, stored under
`authy:magiclink:{token}` with TTL `config.magic_link_ttl_seconds`.
Verification is single-use (get_json → delete; missing record is treated as
consumed/expired). `redirect_url` is validated against the host of
`config.default_redirect_url`/`config.base_url` (open redirects rejected).
Sending is rate-limited via cache counters (`authy:ratelimit:magiclink:{email}`).
Users are auto-created only when `config.auto_create_users` is set. All events
go through `db.save_audit_event`.

### 6. `passwordless/passkey.py`
**Rewritten.** Per-user challenge keys per §3.1
(`authy:passkey:reg:{user_id}` and `authy:passkey:auth:{user_id}:{challenge}`).
Challenges are generated by the `webauthn` library and the library-generated
challenge is stored and returned consistently (base64url). Challenges are
single-use. Credentials persist through the db settings kv. The `webauthn`
import remains lazy.

### 7. `password_security/`
**Fixed.**
- `password_validator.py`: embedded a ~1000-entry static common-password
  dataset (`COMMON_PASSWORDS_TOP1000`, ≥900 entries) replacing the 40-entry
  sample; the policy engine is preserved.
- `hibp_provider.py`: fixed the `UnboundLocalError` in the `except
  httpx.HTTPError` handler (a connection failure before any response no longer
  dereferences an unbound `response`); added a `fail_closed` config flag
  (default `False` → warn/fail-open; `True` → an unreachable breach DB fails
  validation). k-anonymity (5-char SHA-1 prefix) unchanged.

### 8. `saml/saml_manager.py` (critical hardening)
**Rewritten.**
- The xmlsec `Signature`'s `Reference URI` must match the `ID` of the
  assertion that is consumed, and **only that signed assertion** is parsed
  (all lookups anchored under it). Verified with real xmlsec signatures.
- `AudienceRestriction` is mandatory and must contain `sp_entity_id`; a
  missing `AudienceRestriction` is rejected.
- `InResponseTo` is consumed atomically via the db contract
  (`consume_saml_request`); response IDs go through the replay ledger
  (`check_and_record_saml_response_id`).
- `SubjectConfirmation` is validated (Recipient, NotOnOrAfter, InResponseTo).
- AuthnRequests are signed when an SP private key is configured and the
  metadata `AuthnRequestsSigned` flag reflects that. SLO responses are
  signature-verified when the IdP certificate is present.
- Constructor raises `ConfigError` when db/cache collaborators are missing.

### 9. `oidc/oidc_manager.py`
**Fixed.** `nonce` is generated, stored, validated against the ID token and
deleted on use. `state` is ALWAYS generated, stored, validated and consumed
(single-use); the constructor raises `ConfigError` when neither cache nor db is
provided. The base64url padding idiom is `'=' * (-len(s) % 4)`. JWKS is
force-refreshed exactly once on an unknown `kid`. `client_secret_basic` token
authentication is implemented. `azp` is enforced when the audience is a list
with more than one entry. Cached tokens are keyed by the sha256 of the **full**
token. PKCE is mandatory for public clients (no client secret).

### 10. `social/`
**Fixed.**
- `github.py`: real random `state` + constant-time validation hook; HTTP
  status checked and in-body `error` surfaced; `get_primary_email` resolves the
  primary **verified** email.
- `facebook.py`: real `state`; expiry from the provider's `expires_in`;
  `appsecret_proof` attached; tokens moved out of query strings into POST
  bodies.
- `google.py`: the `InstalledAppFlow` stdin/print loop replaced with a
  redirect-based authorization-code flow (`create_authorization_url` +
  `exchange_code`); refresh via `google-auth`.
- `apple.py`: kept (already solid).
- **ALL** providers: `_handle_social_login` checks the provider's
  `email_verified` (or equivalent) before linking to an existing account by
  email — unverified email + existing account raises `AuthenticationError`
  (`email_unverified`, the account-takeover fix). Accounts are only created
  from unverified emails when `config.auto_create_users` is set.

### 11. `migration/__init__.py`
**Fixed.** Honest registry: Firebase, Auth0 and Django are implemented;
`get_importer("cognito")` / `get_importer("supabase")` raise
`NotImplementedError` with an explicit message. The `preview_migration`
`StopIteration` crash is fixed. Added
`verify_and_upgrade_legacy_hash(user, candidate, db)` supporting Django
`pbkdf2_sha256` and Firebase `scrypt` (memoized verifier), rehashing to bcrypt
on success; core login calls it when `user["password_algorithm"]` is set.

### 12. `compliance/__init__.py`
**Rebuilt** on the db contract. Checksum semantics now live in the db adapter;
`verify_audit_chain` is exposed. GDPR export/delete run through the db contract.
Anonymization covers `*token*` / `*secret*` / `*password*` field patterns
(recursively). The crashing aiohttp dashboard server is replaced by a pure
async report function `build_security_report(db)` returning a dict (no server,
no missing-import crash).

### 13. Tests (`tests/core/`, own `conftest.py`)
**Added.** Uses `InMemoryDatabase` + `InMemoryCache`, no network. Coverage
includes regression tests for each former crash (social login paths now run),
the account-takeover rejection, magic-link single-use race (`asyncio.gather`),
passkey per-user challenges, TOTP enable-requires-code, SAML
audience/InResponseTo/replay rejection with real xmlsec-signed fixtures, OIDC
nonce/state enforcement, legacy-hash upgrade login, and the audit report
function.

## Risks / notes
- `authy_package/saml` signing/verification depends on the `xmlsec` native
  library (installed in the venv); ID attributes are registered via
  `ctx.register_id` so `Reference URI="#ID"` resolves.
- The Firebase scrypt verifier implements the documented export pipeline
  (salt+separator, scrypt, signer-key mix); parameters are memoized.
