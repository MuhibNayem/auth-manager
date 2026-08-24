# Remediation status — packaging, docs & CI workstream

Workstream owner: packaging-docs-ci agent. Binding spec:
`docs/CONTRACTS.md` §11; definition of done: §12.
Branch: `chorus/sota-auth-remediation`. Package version: **2.0.0**.

## 1. Packaging — single source of truth

**Changed:** `pyproject.toml` (root) — fully rewritten:

- Project renamed `authy_package` → **`authy-package`**, version
  `0.1.12` → **`2.0.0`** (matches `authy_package/__init__.py:__version__`;
  drift is now caught by the CI `version-sync` job and by
  `tests/packaging`).
- Python constraint `^3.12` → **`>=3.9,<4.0`**.
- Heavy mandatory deps (fastapi, sqlalchemy, motor, boto3, asyncpg,
  uvicorn, google-auth*, mailjet-rest, **passlib**) replaced by a slim
  core: `pyjwt, cryptography, bcrypt, httpx, aiohttp, requests, click,
  rich, python-dotenv, redis, pyotp, python-multipart` (previously
  undeclared but used: `httpx`, `bcrypt` — now declared).
- Extras added (exactly these 13): `fastapi` (fastapi+uvicorn), `flask`,
  `django`, `postgresql` (sqlalchemy+asyncpg), `mongodb` (motor),
  `dynamodb` (aioboto3), `saml` (lxml+xmlsec+python3-saml), `oidc`
  (marker extra — OIDC implementation needs only core deps),
  `sms` (twilio+boto3), `captcha` (marker extra — providers use core
  httpx), `webauthn` (webauthn), `all`, `dev` (pytest, pytest-asyncio,
  pytest-cov, ruff, mypy). `all` also carries the optional
  `argon2-cffi` hashing backend required by CONTRACTS.md §2.
- `[tool.poetry.scripts] authy = "authy_package.cli:main"` kept (entry
  point verified to exist).
- `[tool.ruff]` (lenient baseline: E4/E7/E9/F, py39, line-length 120)
  and `[tool.mypy]` (lenient) config added per §11.
- Build backend remains **poetry-core** (PEP 517); CI builds with plain
  `pip + build` — the simpler reliable path: no Poetry installer, no
  lock-file coupling, identical metadata.

**Deleted (superseded, per §11):**

- `authy_package/pyproject.toml` — the setuptools `authy-package 2.0.0`
  file that matched marketing but was never published. Its extras design
  was folded into the root file.
- `authy_package/requirements-enterprise.txt` — SAML/OIDC deps are now
  the `saml` extra; OIDC needs nothing beyond core.

**passlib:** removed from root `pyproject.toml` (the only packaging file
that declared it). Remaining repo references are outside this
workstream's ownership and tracked by theirs:
`authy_package/utils/security.py` (foundation migrated hashing to direct
bcrypt per §2/§6) and `poetry.lock` (see known issues below).

## 2. CI/CD — `.github/workflows/`

**`publish.yml` rewritten.** Previous bugs, each fixed:

| Old bug | Fix |
|---|---|
| Published on *every push to main* with zero tests | Triggers **only on semver tag push** (`v*.*.*`); a full pytest matrix (3.9–3.12) runs in-workflow and `needs:`-gates build → publish → release |
| Broken bot guard (checked `github-actions[bot]`, bump commits authored `GitHub Action`) | Guard **removed**; replaced by tag-only trigger + protected `pypi` environment + OIDC trusted publishing |
| Tag collision (softprops created the tag, then a second `git tag` step failed) | Workflow never runs `git tag`; the tag is created exactly once by whoever pushes it. A guard step also asserts tag == pyproject version |
| Deprecated `actions/checkout@v2`, `setup-python@v2`, `softprops@v1` | checkout@v4, setup-python@v5, upload/download-artifact@v4, softprops@v2, `pypa/gh-action-pypi-publish@release/v1` |
| Poetry-installer coupling | Build via `pip install build && python -m build` |

OIDC trusted publishing retained (`id-token: write`, `pypi` environment).
Release procedure documented in RUNBOOK.md §"Releasing a new version".

**`ci.yml` added:** on PR + push-to-main: `version-sync` (pyproject vs
`__version__`), ruff lint (gating), pytest matrix 3.9/3.10/3.11/3.12
installing `.[all,dev]` (gating), mypy lenient baseline (advisory,
`continue-on-error`).

## 3. README.md — rewritten to contract truth

- Fixed imports: `MongoDB` (not nonexistent `MongoDBDatabase`),
  `RedisCache` (not removed `RedisCaching`), lowercase token keys.
- Install instructions now match the real extras (no phantom `[full]`).
- Feature matrix limited to delivered features, each marked "Rebuilt"
  with pointer to CONTRACTS.md.
- Unverified metrics removed (none existed with evidence); compliance
  badges (SOC2/HIPAA/ISO claims) downgraded to "audit-logging primitives
  that can support compliance programs".
- New "Security configuration" section: generate-strong-secret guidance,
  `AuthConfig.validate()` behavior, no placeholder secrets anywhere.
- Database matrix renamed: Cassandra/Redis-as-primary-db removed;
  SQL/MongoDB/DynamoDB + InMemory (dev/test) supported.
- Prominent RENAMING NOTE at top: "Authy" collides with Twilio's Authy
  trademark; rename recommended before wider publication (not performed
  here, per task scope).

## 4. RUNBOOK.md — reconciled with the contract

- Env-var table rebuilt from `AuthConfig` fields per CONTRACTS.md §2 and
  verified against the landed `config.py::from_env()` (including legacy
  compat names: `AUTHY_TOKEN_EXPIRATION` drives `access_token_ttl_seconds`).
- `AUTHY_DB_TYPE` options fixed to `sql | mongodb | dynamodb | memory`.
- All placeholder secrets/passwords removed (incl. the `POSTGRES_PASSWORD=password`
  docker-compose sample); replaced by `secrets.token_urlsafe(...)`
  generation guidance and `${VAR:?...}` fail-fast compose interpolation.
- Token keys standardized lowercase; webhook headers/signature semantics
  match §7; health checks use the contract `health_check()` methods.
- "Coming soon" FAQ claims resolved honestly (migrations CLI delivered;
  third-party user import is DIY against the db contract).
- New section: release procedure aligned with the new publish workflow.

## 5. Status reports — contradictions removed

- `AUTHY_ADMIN_DASHBOARD_REPORT.md`: rewritten as a status document;
  previously-mocked "AI" surfaces marked replaced by rule-based
  heuristics (per §8); unverified Lighthouse/latency/bundle metrics
  removed; the Phase 2–4 TODO list (which contradicted the phases
  report) removed.
- `AUTHY_ENTERPRISE_PHASES_REPORT.md`: rewritten; Phases 2–3 delivered
  via real db-contract implementations, Phase 4 delivered as documented
  heuristics; mocked NLQ/predictive-analytics/WebSocket-alert claims
  marked **not delivered**; line-count and "Production Ready" claims
  removed. The two reports no longer contradict each other.
- `AUTHY_RBAC_IMPLEMENTATION_REPORT.md`: rewritten; unverifiable
  latency/throughput/cache-hit figures and vendor comparison table
  removed; persistence mapped to §4 db contract; "unit tests TODO"
  resolved by the remediation suite (§0 rule 10, §12).
- `ENTERPRISE_SECURITY_FEATURES.md`: static AWS key exports
  (`AWS_ACCESS_KEY_ID=AKIA...`) removed from the SNS setup and env
  reference; replaced with IAM/credential-chain guidance pointing at
  `AWS_SECURITY_GUIDE.md`; install hints point at the `sms` extra;
  status pointer to CONTRACTS.md added.
- `AWS_SECURITY_GUIDE.md`: kept as-is (verified: no local cross-
  references needed fixing).
- `authy_package/README.md`: aligned with root README (2.0 context,
  extras install lines for `[saml]`/`[oidc]`, rename-note pointer);
  technical SAML/OIDC content retained and verified against real
  `SAMLManager/OIDCManager` exports and the shipped
  `migration/saml_oidc_tables.sql`.

## 6. examples/ — rewritten (5 files)

All examples are syntactically valid, env-var configured, free of
pseudocode, and use consistent lowercase `access_token`/`refresh_token`
keys. Functional verification against services happens later in the
integration workstream.

- `example_memory_quickstart.py` **(new)** — written against the
  intended public API (`authy_package.core.auth_manager`):
  register/login/refresh/logout on `InMemoryDatabase` + `InMemoryCache`,
  demonstrating §6 semantics including refresh-token rotation replay
  rejection. Runs with zero external services; the login/refresh/logout
  steps are **pending-core-migration** (see §8/§9).
- `example_sql.py` — SQL (declarative ORM model matching §4 record keys)
  + Redis; removed hardcoded `user:password` URL and dummy ORM stub.
- `example_mongo.py` — MongoDB + Redis; removed hardcoded URLs and
  placeholder mailjet keys.
- `example_social.py` — real provider constructors (incl.
  `GoogleManager(client_secrets_file, redirect_uri, scopes)` and Apple
  private-key contents), skip-when-unconfigured logic; removed the
  `'email' or 'username' or 'phone'` pseudocode and the wrong
  `apple_social_login(code)` call.
- `example_cognito.py` — consistent lowercase token keys (removed mixed
  `AccessToken` usage), env-var pool config, real redirect_uri on
  logout, no `your_confirmation_code` placeholder flow (codes read from
  env, steps skipped with honest messages).

## 7. tests/packaging/ — new guard suite

`tests/packaging/test_packaging_metadata.py` (stdlib `tomllib` + PyYAML,
no package import):

- name `authy-package`, version `2.0.0`, version sync with
  `authy_package/__init__.py`, python `>=3.9,<4.0`, poetry-core backend;
- inner `pyproject.toml` / `requirements-enterprise.txt` stay deleted;
- core deps present; all 13 extras present with contract contents;
  `dev` contains pytest/pytest-asyncio/pytest-cov/ruff/mypy; `all`
  covers every feature extra;
- **no `passlib`** in any dependency list or anywhere in pyproject text;
- every workflow YAML parses; ci.yml has PR+main pytest; publish.yml is
  tag-only, its publish/release jobs are transitively `needs:`-gated by
  a pytest job, no `git tag` step exists anywhere, the broken bot guard
  is gone, OIDC trusted publishing retained.

## 8. Verification results

- `./.venv/bin/python -m pytest tests/packaging -q` → **green, 17 passed**.
- `./.venv/bin/python -m compileall examples` → **clean** (all 5 files).
- Workflows validated structurally by the packaging tests above.
- `example_memory_quickstart.py` — verified (executed green) up to the
  boundary of the not-yet-migrated core: `AuthConfig.from_env()` +
  `validate()`, `InMemoryDatabase`/`InMemoryCache` construction +
  `connect()`, and `register_user()` all succeed through the intended
  public API, no core workarounds. **pending-core-migration**:
  login / refresh (rotation) / logout go green with zero example edits
  once the Wave-2 core-auth-fix team migrates `core/auth_manager.py`
  to CONTRACTS.md §3/§6.

## 9. Known issues / handoffs (outside this workstream's ownership)

1. **`poetry.lock` is stale**: it still encodes the pre-remediation
   dependency set (incl. passlib). CI no longer uses it (pip+build), but
   whoever owns dependency management should `poetry lock` (or delete it)
   after this change lands. Not deleted here: outside owned paths.
2. **pending-core-migration** — `authy_package/core/auth_manager.py`
   is still the legacy implementation, intentionally owned by the
   Wave-2 core-auth-fix team and untouched here: it calls the removed
   legacy cache API `cache.create_token_pair(...)` (line 79), which
   raises `AttributeError` against the new §3 caches. Effect: the
   quickstart and the sql/mongo examples pass
   config/validation/fakes/register today; their login/refresh/logout
   steps become green with zero example edits once core migrates to
   §3/§6. All my examples construct `SecurityManager(db, cache, config)`
   per the foundation-landed §6 signature.
3. `examples/*` functional runs (real Postgres/Mongo/Redis/Cognito/OAuth)
   are scheduled with the integration team per the delegation note.
4. Product rename (Twilio Authy trademark) is recommended but
   intentionally NOT performed (docs-only mandate).

---

*Generated by the packaging-docs-ci agent, 2.0 remediation.*
