# tessera — Operations Runbook

Status: reconciled with the binding contracts in `docs/CONTRACTS.md`
(2.0 remediation). Where this document and the code disagree, the code +
contracts win — please file an issue.

## Table of Contents
1. [Quick start](#quick-start)
2. [Installation](#installation)
3. [Configuration reference](#configuration-reference)
4. [Authentication flows](#authentication-flows)
5. [Organization management](#organization-management)
6. [Audit logging & webhooks](#audit-logging--webhooks)
7. [Deployment](#deployment)
8. [Releasing a new version](#releasing-a-new-version)
9. [Monitoring & troubleshooting](#monitoring--troubleshooting)
10. [FAQs](#faqs)

---

## Quick start

Generate strong secrets first. **Never copy sample values** — anything in
documentation is a placeholder by definition.

```bash
# JWT signing secret (required; 32+ characters)
python -c "import secrets; print(secrets.token_urlsafe(48))"

# Example: database password (if your DB user needs one)
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

```bash
pip install "tessera[postgresql]"

export TESSERA_ENV=development
export TESSERA_JWT_SECRET="<generated above>"
export TESSERA_DB_TYPE=sql
export TESSERA_DB_URL="postgresql+asyncpg://<user>:<password>@localhost:5432/<db>"
export TESSERA_REDIS_URL="redis://localhost:6379"

python main.py
```

Zero-service trial (no Postgres/Redis needed): run
`examples/example_memory_quickstart.py`, which uses the in-memory database
and cache implementations.

---

## Installation

```bash
pip install tessera                 # slim core
pip install "tessera[all]"          # every optional feature
pip install "tessera[dev]"          # pytest, pytest-asyncio, pytest-cov, ruff, mypy
```

Extras: `fastapi`, `flask`, `django`, `postgresql`, `mongodb`, `dynamodb`,
`saml`, `oidc`, `sms`, `captcha`, `webauthn`, `all`, `dev`. Python
`>=3.9,<4.0`.

### Local services (dev)

```bash
docker run -d -p 6379:6379 redis:7-alpine
docker run -d -p 5432:5432 \
  -e POSTGRES_DB=tessera \
  -e POSTGRES_USER=tessera \
  -e POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')" \
  postgres:15-alpine
```

Print the generated password into your shell (or a git-ignored `.env`)
before running the container, and put the same value in `TESSERA_DB_URL`.

---

## Configuration reference

Configuration is a single `AuthConfig` object (see
`tessera/config.py`), constructible directly or via
`AuthConfig.from_env()`. `config.validate()` raises
`tessera.errors.ConfigError` when:

- `jwt_secret` is missing/empty or equal to a known public default;
- `env == "production"` and any placeholder value remains (secrets,
  `example.com` URLs);
- the database URL is missing;
- `env == "production"` and `base_url` is not HTTPS.

`get_auth()` / `init_auth()` always call `validate()` before returning.

### Core settings (`AuthConfig` fields and `TESSERA_*` env overrides)

| Env var | Field | Default | Notes |
|---|---|---|---|
| `TESSERA_ENV` | `env` | `development` | `development` \| `staging` \| `production` |
| `TESSERA_JWT_SECRET` | `jwt_secret` | — (required) | Generate with `secrets.token_urlsafe(48)` |
| `TESSERA_JWT_ALGORITHM` | `jwt_algorithm` | `HS256` | |
| `TESSERA_TOKEN_EXPIRATION` | `access_token_ttl_seconds` | `3600` | Legacy variable name kept for compatibility; also feeds the cache token TTL |
| `TESSERA_REFRESH_TOKEN_TTL_DAYS` | `refresh_token_ttl_days` | `7` | |
| `TESSERA_JWT_ISSUER` | `jwt_issuer` | `None` | Optional `iss` claim |
| `TESSERA_JWT_AUDIENCE` | `jwt_audience` | `None` | Optional `aud` claim |
| `TESSERA_JWT_CLOCK_SKEW_SECONDS` | `jwt_clock_skew_seconds` | `30` | |
| `TESSERA_SESSION_EXPIRY_SECONDS` | `session_expiry_seconds` | `604800` | 7 days |
| `TESSERA_MAX_CONCURRENT_SESSIONS` | `max_concurrent_sessions` | `5` | |
| `TESSERA_REVOKE_SESSIONS_ON_PASSWORD_CHANGE` | `revoke_sessions_on_password_change` | `true` | |
| `TESSERA_RATE_LIMIT_ENABLED` | `rate_limit_enabled` | `true` | |
| `TESSERA_RATE_LIMIT_MAX_ATTEMPTS` | `rate_limit_max_attempts` | `5` | |
| `TESSERA_RATE_LIMIT_WINDOW_SECONDS` | `rate_limit_window_seconds` | `300` | |
| `TESSERA_ACCOUNT_LOCKOUT_DURATION_SECONDS` | `account_lockout_duration_seconds` | `900` | |
| `TESSERA_MFA_REQUIRED` | `mfa_required` | `false` | |
| `TESSERA_PASSWORD_HASH_ALGORITHM` | `password_hash_algorithm` | `bcrypt` | `bcrypt` \| `argon2` (argon2 needs `argon2-cffi`) |
| `TESSERA_BCRYPT_ROUNDS` | `bcrypt_rounds` | `12` | |
| `TESSERA_RESET_TOKEN_TTL_SECONDS` | `reset_token_ttl_seconds` | `900` | |
| `TESSERA_BASE_URL` | `base_url` | `http://localhost:8000` | Must be HTTPS in production; used to build reset/magic links |
| `TESSERA_MAGIC_LINK_TTL_SECONDS` | `magic_link_ttl_seconds` | `600` | |
| `TESSERA_DEFAULT_REDIRECT_URL` | `default_redirect_url` | `None` | |
| `TESSERA_AUTO_CREATE_USERS` | `auto_create_users` | `false` | Social/SSO auto-provisioning |
| `TESSERA_RP_ID` | `rp_id` | `None` | WebAuthn relying-party id |
| `TESSERA_RP_NAME` | `rp_name` | `Tessera` | WebAuthn relying-party name |
| `TESSERA_EMAIL_ENABLED` | `email_enabled` | `false` | Master switch for transactional email |
| `TESSERA_EMAIL_PROVIDER` | `email_provider` | `mailjet` | `mailjet` \| `sendgrid` \| `ses` |

### Database selection

| Env var | Purpose |
|---|---|
| `TESSERA_DB_TYPE` | `sql` \| `mongodb` \| `dynamodb` \| `memory` |
| `TESSERA_DB_URL` | Connection string (SQL/MongoDB). `memory` needs none |
| `TESSERA_DB_NAME` | Database name (MongoDB) |

DynamoDB reads AWS configuration via the standard credential provider
chain — prefer IAM roles over any static keys
(see [AWS_SECURITY_GUIDE.md](AWS_SECURITY_GUIDE.md)). Table prefix and
optional cross-account role ARN come from
`TESSERA_DYNAMODB_TABLE_PREFIX` / `TESSERA_DYNAMODB_ROLE_ARN`.

### Nested configs

`AuthConfig` carries nested dataclasses: `database`, `cache`, `social`,
`cognito`, `sms`, `bot_protection`, `password_security`. Representative
env vars (full list in `config.py::from_env`):

| Area | Env vars |
|---|---|
| Cache | `TESSERA_CACHE_ENABLED`, `TESSERA_REDIS_URL`, `TESSERA_REFRESH_TOKEN_EXPIRATION` (cache-level refresh TTL, seconds) |
| Social | `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`, `FACEBOOK_APP_ID`/`FACEBOOK_APP_SECRET`, `APPLE_CLIENT_ID`/`APPLE_TEAM_ID`/`APPLE_KEY_ID`/`APPLE_PRIVATE_KEY_PATH` (+ per-provider redirect URIs) |
| Cognito | `TESSERA_COGNITO_ENABLED`, `AWS_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_APP_CLIENT_ID` |
| SMS | `TESSERA_SMS_ENABLED`, `TESSERA_SMS_PROVIDER` (`twilio`\|`aws_sns`), `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` |
| Bot protection | `TESSERA_BOT_PROTECTION_ENABLED`, `TESSERA_CAPTCHA_PROVIDER` (`hcaptcha`\|`recaptcha`), `HCAPTCHA_SITE_KEY`/`HCAPTCHA_SECRET_KEY`, `RECAPTCHA_SITE_KEY`/`RECAPTCHA_SECRET_KEY` |
| Email | `MAILJET_API_KEY`, `MAILJET_API_SECRET`, `SENDER_EMAIL`, `SENDER_NAME` (sendgrid/ses equivalents) |

Store all of these in a git-ignored `.env` (loaded via `python-dotenv`)
or your platform's secret manager — never in version control.

### Programmatic configuration

```python
from tessera.config import AuthConfig
from tessera.errors import ConfigError

config = AuthConfig.from_env()   # reads TESSERA_* variables
try:
    config.validate()
except ConfigError as exc:
    raise SystemExit(f"Invalid auth configuration: {exc}") from exc
```

---

## Authentication flows

All flows below are async and return dicts. Token payloads are always
`{"access_token": ..., "refresh_token": ...}` (lowercase keys).

### 1. Traditional username/password

```python
from tessera.core.auth_manager import TraditionalAuthManager

auth = TraditionalAuthManager(db=db, cache=cache, mfa_manager=mfa,
                              security_manager=security)

await auth.register_user(username="janedoe", email="jane@example.com",
                         phone="+15551234567", password=user_password)

tokens = await auth.login_user(username="janedoe", password=user_password)
tokens = await auth.login_user(email="jane@example.com",
                               password=user_password, mfa_code="424242")

new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])
await auth.logout_user(access_token=new_tokens["access_token"],
                       username="janedoe")
```

Login failures are identical for unknown-user vs bad-password, and a
constant-time dummy hash runs either way (contract §6). Rate limiting and
account lockout are enforced via the cache (`tessera:ratelimit:*`,
`tessera:lockout:*` keys).

### 2. MFA (TOTP)

```python
setup = await auth.enable_mfa(username="janedoe")
# setup["mfa_secret"] -> render as otpauth:// URI / QR for authenticator apps
await auth.reconfigure_mfa(username="janedoe")
```

### 3. Password reset

```python
await auth.request_password_reset(email="jane@example.com", username=None,
                                  phone=None, sender_email="noreply@myapp.example",
                                  sender_name="My App")
# The user receives a link: {TESSERA_BASE_URL}/auth/reset-password?token=...
await auth.reset_password(email="jane@example.com", token=token_from_link,
                          new_password=new_user_password)
```

Reset tokens are single-use, hashed at rest, and expire per
`TESSERA_RESET_TOKEN_TTL_SECONDS`. They are never echoed in responses or
logs.

### 4. Magic links

```python
from tessera.passwordless.magic_link import MagicLinkManager

magic = MagicLinkManager(db=db, cache=cache, config=config)
await magic.send_magic_link(email="jane@example.com",
                            redirect_url="https://app.example.com/auth/callback")
user = await magic.verify_magic_link(token=token_from_email)
```

### 5. Passkeys / WebAuthn

```python
from tessera.passwordless.passkey import PasskeyManager

passkeys = PasskeyManager(db=db, config=config)
options = await passkeys.register_start(user_id=user_id, email="jane@example.com")
credential = await passkeys.register_complete(user_id=user_id, response=browser_response)

options = await passkeys.authenticate_start()
user = await passkeys.authenticate_complete(response=browser_response)
```

Requires the `webauthn` extra.

### 6. Social OAuth

```python
from tessera.social.google import GoogleManager

google = GoogleManager(client_id=..., client_secret=...,
                       redirect_uri="https://app.example.com/auth/google/callback")
auth_url = google.get_authorization_url()          # redirect the user here
tokens = await google.exchange_code(code=code_from_callback)
user_info = await google.get_user_info(access_token=tokens["access_token"])
```

`SocialAuthManager` wraps provider exchange + user provisioning; see
`examples/example_social.py`.

### 7. AWS Cognito

```python
from tessera.cognito.cognito_manager import CognitoManager
from tessera.core.auth_manager import CognitoAuthManager

cognito = CognitoManager(region_name=os.environ["AWS_REGION"],
                         user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
                         app_client_id=os.environ["COGNITO_APP_CLIENT_ID"])
cognito_auth = CognitoAuthManager(cognito_manager=cognito)

await cognito_auth.register_user(username="janedoe", password=user_password,
                                 email="jane@example.com")
tokens = await cognito_auth.login_user(username="janedoe", password=user_password)
```

Full flow (social login, confirmation, MFA) in
`examples/example_cognito.py`.

---

## Organization management

```python
from tessera.organizations.org_manager import OrganizationManager, OrgRole

orgs = OrganizationManager(config=config, db=db, cache=cache)

org = await orgs.create_organization(name="Acme Corp", owner_id=owner_id,
                                     slug="acme-corp")
await orgs.add_member(org["id"], member_user_id, OrgRole.MEMBER,
                      invited_by=owner_id)
invitation = await orgs.send_invitation(org_id=org["id"],
                                        email="new@example.com",
                                        role=OrgRole.GUEST,
                                        invited_by=owner_id)
member = await orgs.accept_invitation(token=invitation["token"],
                                      user_id=invited_user_id)
role = await orgs.get_member_role(org["id"], member_user_id)
await orgs.update_member_role(org["id"], member_user_id, OrgRole.ADMIN)
await orgs.remove_member(org["id"], member_user_id)  # last owner cannot be removed
```

Roles: `OWNER → ADMIN → MEMBER → GUEST`. Invitations expire (default
7 days). For fine-grained permissions beyond org roles, use the RBAC
manager (`TESSERA_RBAC_IMPLEMENTATION_REPORT.md`).

---

## Audit logging & webhooks

### Audit log

Append-only events with a checksum hash chain (each event stores a
SHA-256 checksum over its canonical payload including the previous
checksum — tampering breaks the chain).

```python
from tessera.admin.audit_logger import AuditLogger, EventType

audit = AuditLogger(config=config, db=db, cache=cache)
await audit.log(event_type=EventType.LOGIN_SUCCESS, action="User logged in",
                actor_id=user_id, actor_email=email, ip_address=client_ip,
                user_agent=user_agent, metadata={"session_id": session_id},
                severity="info", status="success")

events = await audit.search(actor_id=user_id, limit=100)
csv_export = await audit.export_events(filters={"organization_id": org_id},
                                       format="csv")
stats = await audit.get_statistics(start_date=since, end_date=now)
deleted = await audit.cleanup_old_events()   # honors retention setting
```

CLI equivalents: `tessera audit search`, `tessera audit export`.

### Webhooks

Delivery is HMAC-SHA256 signed: signature covers
`f"{timestamp}.{canonical_json}"`. Receivers get these headers:

- `X-Tessera-Signature: sha256=<hex>`
- `X-Tessera-Timestamp`
- `X-Tessera-Event`
- `X-Tessera-Delivery-Id`

```python
import httpx
from tessera.webhooks.webhook_manager import WebhookManager

webhooks = WebhookManager(config=config, db=db, cache=cache,
                          http_client=httpx.AsyncClient())
endpoint = await webhooks.register_endpoint(url="https://receiver.example.com/hooks/auth",
                                            events=[])  # [] = subscribe to ALL events
await webhooks.dispatch_event(event_type=WebhookEventType.USER_CREATED,
                              payload={"user_id": user_id}, sync=False)
```

Semantics (contract §7): endpoint URLs are validated at registration and
delivery (HTTPS in production, DNS resolution, private/loopback/metadata
ranges rejected, redirects disabled by default); non-2xx responses retry
on `[60, 300, 900, 3600, 14400]` seconds; endpoint secrets are generated
(`secrets.token_hex(32)`), never returned by list/get APIs (masked
last-4 only), and can be rotated.

Receiver-side verification must use `hmac.compare_digest` with a ±300s
timestamp window and a delivery-id replay store — see the helpers in
`tessera/webhooks/`.

---

## Deployment

### Docker Compose

Secrets are injected from the environment; the compose file itself
contains no credentials. `${VAR:?message}` makes Compose fail fast when
a secret is unset.

```yaml
services:
  app:
    build: .
    environment:
      TESSERA_ENV: production
      TESSERA_JWT_SECRET: ${TESSERA_JWT_SECRET:?set TESSERA_JWT_SECRET}
      TESSERA_DB_TYPE: sql
      TESSERA_DB_URL: ${TESSERA_DB_URL:?set TESSERA_DB_URL}
      TESSERA_REDIS_URL: redis://redis:6379
      TESSERA_BASE_URL: ${TESSERA_BASE_URL:?set TESSERA_BASE_URL (https)}
    depends_on: [db, redis]
    ports: ["8000:8000"]

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: tessera
      POSTGRES_USER: tessera
      POSTGRES_PASSWORD: ${TESSERA_DB_PASSWORD:?set TESSERA_DB_PASSWORD}
    volumes: [postgres_data:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    volumes: [redis_data:/data]

volumes:
  postgres_data:
  redis_data:
```

Generate each secret (`python -c "import secrets; print(secrets.token_urlsafe(32))"`),
export it in the deploying shell/CI secret store, and never commit it.

### Kubernetes

Use `Secret` objects + `secretKeyRef` (never inline values), a readiness
probe on your `/health` endpoint, and TLS termination at the ingress:

```yaml
env:
  - name: TESSERA_JWT_SECRET
    valueFrom: {secretKeyRef: {name: tessera-secrets, key: jwt-secret}}
  - name: TESSERA_DB_URL
    valueFrom: {secretKeyRef: {name: tessera-secrets, key: database-url}}
readinessProbe:
  httpGet: {path: /health, port: 8000}
```

### Production checklist

- `TESSERA_ENV=production`, HTTPS `TESSERA_BASE_URL` (config validation enforces both)
- Strong unique `TESSERA_JWT_SECRET` (rotate periodically; re-issue sessions after rotation)
- Rate limiting + lockout enabled; MFA for privileged accounts
- Webhook receivers verify signatures; endpoint URLs are public HTTPS
- AWS features on IAM roles (no static keys) — see AWS_SECURITY_GUIDE.md
- Backups + retention policy for the audit log

---

## Releasing a new version

Releases are cut from semver tags; publishing never happens on plain
pushes to `main` (see `.github/workflows/publish.yml`).

1. Bump the version in **both** `pyproject.toml` (`[tool.poetry] version`)
   and `tessera/__init__.py` (`__version__`). The CI `version-sync`
   job fails if they drift.
2. Merge to `main`; CI (ruff + pytest matrix 3.9–3.12) must pass.
3. Tag and push:
   ```bash
   git tag v2.1.0
   git push origin v2.1.0
   ```
4. The workflow verifies the tag equals the package version, re-runs the
   test matrix, builds sdist+wheel, publishes to PyPI via OIDC trusted
   publishing (protected `pypi` environment), and creates the GitHub
   Release. The tag is created exactly once — by you, in step 3.

First-time PyPI setup: configure `tessera` on PyPI as a trusted
publisher for the `MuhibNayem/auth-manager` workflow `publish.yml` with
the `pypi` environment.

---

## Monitoring & troubleshooting

### Health checks

```python
@app.get("/health")
async def health():
    db_ok = await db.health_check()
    cache_ok = await cache.health_check()
    return {"database": db_ok, "cache": cache_ok,
            "status": "healthy" if (db_ok and cache_ok) else "degraded"}
```

Both `AbstractDatabase` and `AbstractCache` implement `health_check()`
(contract §3/§4).

### Common issues

| Symptom | Check |
|---|---|
| `ConfigError` at startup | `TESSERA_JWT_SECRET` set and not a placeholder; DB URL present; production requires HTTPS `TESSERA_BASE_URL` and no placeholder values |
| Redis connection failures | `redis-cli -u "$TESSERA_REDIS_URL" ping` returns PONG; network/security groups |
| DB connection timeout | Reachability + pool sizing (SQLAlchemy `pool_size`/`max_overflow` in `TESSERA_DB_URL` options) |
| Magic links / resets not arriving | Email provider credentials (`MAILJET_API_KEY`/...), `TESSERA_BASE_URL` reachable by users |
| `RateLimitError` on login | Expected behavior after `TESSERA_RATE_LIMIT_MAX_ATTEMPTS` failures in the window; lockout lasts `TESSERA_ACCOUNT_LOCKOUT_DURATION_SECONDS` |
| Refresh rejected after rotation | Old refresh token is deleted on rotation (contract §3.1) — clients must store the newest pair |

`tessera doctor` runs these checks locally: Python version, imports, DB and
Redis connectivity (`health_check()`), and `config.validate()`, reporting
an honest ✓/✗ table.

---

## FAQs

**Q: How do I migrate users from another provider (Auth0, Cognito, …)?**
A: Export users from the source system, import them with your own scripts
against the `AbstractDatabase` contract (`db.create_user(...)`), and force
a password reset on first login unless you can carry compatible password
hashes (bcrypt hashes are importable as-is). `tessera migrate` manages
schema migrations of this package's own tables; it does not import
third-party user data.

**Q: Can I run without Redis?**
A: For development/tests, use the in-memory cache (`db_type="memory"`
quick start, or `InMemoryCache`). Production needs Redis: session,
rate-limit, rotation and replay state live there.

**Q: How do I add custom JWT claims?**
A: Claims are `{sub, type, jti, iat, exp, iss?, aud?}` by contract. Add
application claims in your own token layer rather than mutating the
library's token manager — adapters give you the authenticated user dict
to enrich.

**Q: Is session persistence guaranteed?**
A: Sessions persist in Redis. Enable Redis persistence (AOF) if you need
sessions to survive Redis restarts.

**Q: Can I disable password login entirely?**
A: Yes — expose only the passwordless/social/SSO endpoints and set
`TESSERA_MFA_REQUIRED`/policies as needed.

**Q: GDPR deletion requests?**
A: Export the user's audit trail with `audit.export_events(...)`, then
delete the user via `db.delete_user(...)` and revoke their sessions.
Retention cleanup: `db.delete_audit_events_before(ts)`.

**Q: Recommended token lifetimes?**
A: Defaults: access 1 hour, refresh 7 days. Shorten access tokens
(5–15 min) for high-security apps; refresh rotation limits exposure.

**Q: Serverless (Lambda)?**
A: Yes — prefer managed services (RDS/DynamoDB, ElastiCache) and IAM
roles; see AWS_SECURITY_GUIDE.md.

---

**Version**: 2.0.0 — see `docs/REMEDIATION_STATUS_packaging.md` for what
changed in this document during the remediation.
