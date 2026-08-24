# tessera — Authentication Platform for Python

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

> ## Renamed to Tessera
> This framework was formerly distributed as `authy-package` / `authy_package`.
> It has been renamed to **Tessera** (distribution `tessera`, import
> `tessera`). All code, config prefixes (`TESSERA_*`), cache keys
> (`tessera:*`), and docs now use the new name. The rename also resolves the
> prior trademark collision with Twilio's "Authy" product.

`tessera` is an async-first authentication platform for Python:
traditional credentials, MFA, passwordless flows, session management,
multi-tenant organizations, RBAC, audit logging, webhooks, enterprise SSO
(SAML 2.0 / OIDC), and framework adapters for FastAPI, Flask, and Django —
backed by SQL, MongoDB, or DynamoDB.

Version 2.0 is the result of a ground-up remediation against a binding
architecture spec (`docs/CONTRACTS.md`). Many subsystems were rebuilt rather
than patched; see [Status of features](#status-of-features).

---

## Installation

Slim core (traditional auth, sessions, MFA, CLI):

```bash
pip install tessera
```

Extras install only what a feature needs:

```bash
pip install "tessera[fastapi]"       # FastAPI adapter (+ uvicorn)
pip install "tessera[flask]"         # Flask adapter
pip install "tessera[django]"        # Django adapter
pip install "tessera[postgresql]"    # SQLAlchemy + asyncpg
pip install "tessera[mongodb]"       # motor
pip install "tessera[dynamodb]"      # aioboto3
pip install "tessera[saml]"          # SAML 2.0 SP (lxml, xmlsec, python3-saml)
pip install "tessera[oidc]"          # OIDC (no extra deps beyond core)
pip install "tessera[sms]"           # Twilio + AWS SNS (boto3)
pip install "tessera[captcha]"       # hCaptcha/reCAPTCHA (no extra deps)
pip install "tessera[webauthn]"      # Passkeys / WebAuthn
pip install "tessera[all]"           # all of the above (+ argon2 backend)
pip install "tessera[dev]"           # pytest, pytest-asyncio, pytest-cov, ruff, mypy
```

Requires Python **3.9 – 3.12** (`>=3.9,<4.0`).

---

## Quick start

```python
import asyncio
import os

from tessera.config import AuthConfig
from tessera.core.auth_manager import TraditionalAuthManager
from tessera.db.sql import SQLDatabase
from tessera.cache.redis_cache import RedisCache
from tessera.mfa.mfa_setup import MFAAuthManager
from tessera.utils.security import SecurityManager


async def main() -> None:
    # Connection settings come from the environment — never hardcode them.
    db = SQLDatabase(os.environ["TESSERA_DB_URL"])
    cache = RedisCache(os.environ["TESSERA_REDIS_URL"])
    await db.connect()

    mfa = MFAAuthManager(db=db)
    security = SecurityManager(db=db, cache=cache)
    auth = TraditionalAuthManager(
        db=db, cache=cache, mfa_manager=mfa, security_manager=security
    )

    await auth.register_user(
        username="janedoe", email="jane@example.com", password=os.environ["DEMO_PASSWORD"]
    )

    tokens = await auth.login_user(username="janedoe", password=os.environ["DEMO_PASSWORD"])
    print(tokens["access_token"], tokens["refresh_token"])

    new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])
    await auth.logout_user(access_token=new_tokens["access_token"], username="janedoe")

    await db.close()


asyncio.run(main())
```

Before running it, export a strong JWT secret and the other required
variables — see [Security configuration](#security-configuration). A
zero-service quick start on the built-in in-memory fakes lives in
[`examples/example_memory_quickstart.py`](examples/example_memory_quickstart.py).

---

## Features

| Capability | What you get | Status in 2.0 |
|---|---|---|
| Traditional auth | Username/email/phone + password, bcrypt (argon2 optional) | Rebuilt |
| JWT tokens | Access + refresh with rotation, `type` claim enforcement | Rebuilt |
| MFA | TOTP (authenticator apps) | Rebuilt |
| Sessions | Multi-device tracking, concurrent-session limits, revocation | Rebuilt |
| Magic links | One-click email login with TTL + replay protection | Rebuilt |
| Passkeys | WebAuthn registration/authentication (`[webauthn]` extra) | Rebuilt |
| Social login | Google, GitHub, Facebook, Apple OAuth flows | Rebuilt |
| AWS Cognito | Register/login/MFA/social through Cognito user pools | Rebuilt |
| Organizations | Multi-tenancy, slugs, roles, invitations | Rebuilt |
| RBAC | Roles, permissions, scoped assignments | Rebuilt |
| Audit logging | Append-only, checksum-chained events, search/export | Rebuilt |
| Webhooks | HMAC-SHA256 signed delivery, retries, SSRF-safe URLs | Rebuilt |
| Admin dashboard | REST API + React dashboard, API keys, reports | Rebuilt |
| SAML 2.0 | Service-provider SSO (`[saml]` extra) | Rebuilt |
| OIDC | Relying-party SSO with discovery + PKCE (`[oidc]` extra) | Rebuilt |
| SMS verification | Twilio / AWS SNS providers (`[sms]` extra) | Rebuilt |
| Bot protection | hCaptcha / reCAPTCHA + rate limiting (`[captcha]` extra) | Rebuilt |
| Framework adapters | FastAPI, Flask, Django (identical decorator surface) | Rebuilt |
| CLI | `tessera init/dev/doctor/migrate/users/audit/logs/config/webhooks/deploy` | Rebuilt |

"Rebuilt" means the subsystem was re-implemented against the binding
contracts in [`docs/CONTRACTS.md`](docs/CONTRACTS.md) during the 2.0
remediation. Previously mocked or placeholder surfaces (enterprise admin
endpoints, DynamoDB edge cases, CLI commands) were replaced with real
implementations or removed.

### Framework adapters

All three adapters expose the same names and behavior:
`require_auth`, `require_role(...)`, `optional_auth`, `rate_limit(...)`,
and organization-aware checks.

```python
from fastapi import Depends, FastAPI
from tessera.frameworks.fastapi_adapter import FastAPIAuth

app = FastAPI()
fastapi_auth = FastAPIAuth(auth_manager)


@app.get("/protected")
async def protected(user=Depends(fastapi_auth.require_auth())):
    return {"hello": user["email"]}


@app.get("/admin")
async def admin(user=Depends(fastapi_auth.require_role("admin", "owner"))):
    return {"ok": True}
```

Flask and Django equivalents live in `tessera.frameworks`
(`FlaskAuth`, `DjangoAuth`); see the examples and RUNBOOK.

---

## Databases

One unified async `AbstractDatabase` contract with these implementations:

| Backend | Class | Notes |
|---|---|---|
| PostgreSQL / MySQL / SQLite | `SQLDatabase` (SQLAlchemy async) | Reference implementation; SQLite for tests/dev |
| MongoDB | `MongoDB` (motor) | Full contract surface |
| DynamoDB | `DynamoDBAdapter` (aioboto3) | IAM-role credentials; see [AWS_SECURITY_GUIDE.md](AWS_SECURITY_GUIDE.md) |
| In-memory | `InMemoryDatabase` | Tests and local dev only |

Select via `TESSERA_DB_TYPE`: `sql` | `mongodb` | `dynamodb` | `memory`.

Legacy `CassandraAdapter` and `RedisAdapter` (Redis as a primary database)
were **removed** in 2.0: Redis is the cache/session store (`RedisCache`),
not a system of record.

---

## Security configuration

**Generate strong secrets — never reuse samples or placeholders.**

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the result (and your connection strings) in the environment or a
`.env` file that is excluded from version control:

```env
TESSERA_ENV=production
TESSERA_JWT_SECRET=<generated above, 32+ chars>
TESSERA_DB_TYPE=sql
TESSERA_DB_URL=postgresql+asyncpg://<user>:<password>@<host>:5432/<db>
TESSERA_REDIS_URL=redis://<host>:6379
TESSERA_BASE_URL=https://auth.example.com
```

Guidance:

- `AuthConfig.validate()` refuses to start with an empty/default JWT
  secret, and in `production` it rejects remaining placeholder values and
  non-HTTPS `TESSERA_BASE_URL`. Treat those errors as blocking.
- Keep secrets out of code, logs, and error messages. Password reset
  tokens are delivered by email link only — never printed.
- Password hashing uses **bcrypt directly** (passlib was removed
  project-wide); argon2 via `argon2-cffi` is available when configured
  (install the `all` extra or `argon2-cffi` separately).
- For AWS-backed features (DynamoDB, SNS), use IAM roles — never static
  keys. See [AWS_SECURITY_GUIDE.md](AWS_SECURITY_GUIDE.md).
- Webhook receiver endpoints must verify `X-Tessera-Signature` with the
  provided verifier; see the RUNBOOK.

Compliance note: this library ships **audit-logging primitives**
(append-only, checksum-chained events, retention cleanup, exports) that
can support compliance programs (SOC 2, HIPAA, ISO 27001, GDPR). It does
not by itself certify or guarantee compliance — that depends on your
configuration, infrastructure, and processes.

---

## Examples

Runnable examples are in [`examples/`](examples):

| File | Demonstrates |
|---|---|
| `example_memory_quickstart.py` | End-to-end register/login/refresh/logout on the in-memory fakes (no services needed) |
| `example_sql.py` | Full traditional-auth flow on SQL (PostgreSQL) + Redis |
| `example_mongo.py` | Same flow on MongoDB + Redis |
| `example_social.py` | Google/GitHub/Facebook/Apple OAuth login flows |
| `example_cognito.py` | AWS Cognito register/login/MFA/social flows |

All examples read credentials from environment variables; none contain
hardcoded secrets.

---

## Development

```bash
git clone https://github.com/MuhibNayem/auth-manager.git
cd auth-manager
pip install -e ".[all,dev]"
pytest tests/
ruff check tessera tests examples
```

CI runs ruff + a pytest matrix on Python 3.9–3.12 (see
`.github/workflows/ci.yml`). Releases are published from semver tags via
OIDC trusted publishing (`.github/workflows/publish.yml`) — publishing
never happens on plain pushes to `main`.

---

## Documentation

- [`RUNBOOK.md`](RUNBOOK.md) — configuration reference, auth flows,
  deployment, troubleshooting.
- [`ENTERPRISE_SECURITY_FEATURES.md`](ENTERPRISE_SECURITY_FEATURES.md) —
  SMS verification, bot protection, breached-password detection.
- [`AWS_SECURITY_GUIDE.md`](AWS_SECURITY_GUIDE.md) — AWS credential best
  practices (IAM roles, IRSA, cross-account).
- [`tessera/README.md`](tessera/README.md) — SAML 2.0 / OIDC
  enterprise SSO guide.
- Status documents: `TESSERA_ADMIN_DASHBOARD_REPORT.md`,
  `TESSERA_ENTERPRISE_PHASES_REPORT.md`,
  `TESSERA_RBAC_IMPLEMENTATION_REPORT.md`, and
  `docs/REMEDIATION_STATUS_packaging.md`.

---

## License

MIT — see [LICENSE](LICENSE).

Inspired by Auth0, Clerk, Supabase Auth, NextAuth.js, and Django Allauth.
