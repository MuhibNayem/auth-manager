# Remediation Status — platform-services (sms, bot_protection, cli)

Workstream owner: platform-services-fix (Chorus SOTA remediation).
Binding spec: `docs/CONTRACTS.md` (§0 ground rules, §1 errors, §3/§3.1 cache,
§4 db, §9 CLI). Frozen foundation APIs (`errors.py`, `config.py`,
`cache/`, `db/abstract_db.py` + `db/memory.py`, `utils/security.py`) were used
as-is and never modified.

Verification (this workstream):
- `./.venv/bin/python -m pytest tests/platform_services tests/foundation -q` → exit 0 (green).
- `python -m compileall authy_package/sms authy_package/bot_protection authy_package/cli tests/platform_services` → clean.
- No network, no docker, no external services required by tests.

## 1. sms/ — FIXED

| Defect | Fix |
|---|---|
| Codes via `random.choices` (predictable) | `secrets.choice` per digit (CSPRNG, §0.3); regression test inspects the source |
| Plain `!=` code comparison | sha256(code) compared via `hmac.compare_digest` (§0.4); only `code_hash` persisted, never plaintext |
| Sliding rate-limit window (TTL re-set on every increment) | Fixed window: `incr` + `expire` ONLY on the first increment; `retry_after` from real remaining TTL (§3 primitives) |
| Legacy cache API (`set(..., expire=)`) + ad-hoc keys | §3 primitives (`set_json/get_json/incr/expire/ttl/delete`) with §3.1 key `authy:sms:{phone}` → `{code_hash, attempts, expires_at, last_sent_at}`; counter at `authy:ratelimit:sms:{phone}` |
| Naive `datetime.now()` | timezone-aware UTC (§0.5) |
| Untyped exceptions | `SMSProviderError → ProviderError`, `TooManyAttemptsError → RateLimitError(retry_after)`, expired/invalid → `AuthenticationError` (§1; legacy names kept as subclasses) |
| Providers returned `success=False` on upstream failure | `twilio_provider.py` / `aws_sns_provider.py` raise `SMSProviderError` after retry budget; manager surfaces structured `{success: False, error}` (delivery passthrough) |
| `e.code` could be `None` (TypeError on 4xx check) | guarded: `code is not None and 400 <= int(code) < 500` |
| deprecated `asyncio.get_event_loop()` | `asyncio.get_running_loop()` |
| `sms/__init__.py` NameError when twilio absent + boto3 present (`__all__ = __all__ + ...`) | independent guarded blocks; `TWILIO_AVAILABLE` / `AWS_SNS_AVAILABLE` reflect the provider modules' SDK flags; `__all__` built defensively (all 4 SDK combinations tested) |

## 2. bot_protection/ — FIXED

- Sliding-window rate limiting rebuilt on §3 list primitives
  (`lpush`/`lrange`/`expire`); expired timestamps are trimmed on every read
  (AbstractCache has no `ltrim`, so the list is rebuilt from surviving
  entries — documented in code). Keys moved to the §3.1
  `authy:ratelimit:{scope}:{id}` namespace.
- Fake `SUSPICIOUS_IP_PATTERNS = []` replaced by an HONEST local heuristic in
  `analyze_ip_address` (`ipaddress`-based: cloud-metadata IPs, link-local,
  loopback, private ranges, unparseable input), explicitly documented as a
  heuristic, not threat intelligence.
- Risk scoring made coherent: behavioral risk can only RAISE the provider
  verdict; thresholds validated at construction; `CaptchaVerificationResult`
  gained a real `flags` field (the old code wrote to an attribute that did
  not exist).
- Async-property client quirk fixed in both providers:
  `@property async def client` → `async def get_client()` (cached client,
  awaited correctly); call sites updated.
- Docstring env-var typo fixed (`HCATCHA_*` → `HCAPTCHA_*` in
  hcaptcha_provider and the package docstring).
- `bot_protection/__init__.py` uses the same defensive flag-based export
  pattern as sms (no `__all__` NameError path).
- `verify_captcha` without a provider raises `BotProtectionError` instead of
  crashing on `None.verify_token`.

## 3. cli/ — REWRITTEN per §9 (every command honest and functional)

Shared plumbing (`cli/utils`):
- `save_config` writes JSON with **0600** (`os.open` + `O_NOFOLLOW` + chmod;
  `~/.authy` dir 0700); `load_config`/`mask_value`/`is_secret_key` for safe
  display of secret-looking keys.
- `get_connected_db()` via the §4 `get_database` factory; a per-process
  registry makes the in-memory backend shareable across CLI invocations in
  one process (documented). Non-memory backend without `AUTHY_DB_URL` is
  reported as **not configured** (never faked). All commands print
  configuration guidance and exit 1 when the db is unreachable.

Commands:
- `__init__.py`: click group kept; NO import-time logging side effect
  (basicConfig moved into `main()`; basicConfig is itself a handler guard).
  Added `authy dashboard` command. Version comes from
  `authy_package.__version__` (single source of truth).
- `commands/__init__.py`: ADDED (was missing; packaging robustness).
- `doctor`: REAL checks — Python version, core import, per-extra import
  probes (missing optional extras reported as "missing (optional)", not
  failures), `AuthConfig.from_env().validate()`, db + cache `health_check()`
  with 5s timeout (cache disabled → "not configured" pass). Honest ✓/✗/○
  table; exit 1 on any failure.
- `migrate`: REAL migrations. Modules discovered in `./authy_migrations/`
  (async `upgrade(db)`/`downgrade(db)` against the §4 contract); applied
  versions tracked in db settings kv under `schema_migrations`
  (`[{version, applied_at}]`); run/rollback/status truthful; failed
  migration → stops + exit 1, earlier committed migrations recorded; no fake
  success. `migrate create` scaffolds a real template.
- `users`: list/get/delete via `db.list_users` /
  `get_user_by_id|by_identifier` / `delete_user` with confirmation prompt
  (`--yes` to skip); `hashed_password`/`mfa_secret` never rendered.
- `audit`: search/export via `db.search_audit_events` → table / JSON / CSV
  file with real record fields.
- `logs`: one-shot tail of the audit log; `--follow` is HONEST polling
  (interval + bounded `--iterations`; help text says "poll, not a live
  stream").
- `config`: show/set/get persisted at `~/.authy/config.json` (override via
  `--file` / `AUTHY_CONFIG_FILE`) with 0600 perms; secrets masked in `show`.
- `webhooks`: list/create/test via db. URL validation per §7 (https enforced
  in production; DNS resolution; loopback/private/link-local/metadata
  rejected); `secrets.token_hex(32)` signing secret shown ONCE at creation,
  masked (last-4) everywhere after. `test` attempts a real delivery through
  `WebhookManager` when importable and reports the actual delivery record;
  clear message otherwise.
- `deploy`: docker path REAL (`shutil.which` detection, `docker build` /
  optional `docker run` via subprocess, verbatim error surfacing, non-zero
  exit on docker failure; generates a Dockerfile only when missing).
  aws/gcp/azure/kubernetes generate IaC artifacts into `./deploy-out/`
  (CloudFormation YAML, compose YAML, k8s manifests) and print EXACTLY that;
  no fake resource ids, no fake success, explicit "No X resources were
  created".
- `deploy/aws_engine.py`: reimplemented as an artifact generator
  (`AWSDeploymentEngine.build_template/write`); `health_check()` validates
  the built template structure and returns False when nothing valid exists
  (never unconditionally True).
- `dev`: default bind 127.0.0.1; the static fallback ALWAYS binds
  127.0.0.1 regardless of `--host` (§9); cert generation uses
  timezone-aware datetimes (§0.5, `utcnow()` removed).
- `init`: REAL templates — `authy_package.frameworks.*` import paths; §10
  parity API only (`require_auth`/`require_role`/`rate_limit`/
  `optional_auth`; Django template uses `request.authy_user` and never
  touches `request.user`); generated `.env` gets
  `AUTHY_JWT_SECRET=<secrets.token_urlsafe(48)>` (never a placeholder;
  `.env.example` contains no secret); no hardcoded passwords anywhere;
  scaffolds `authy_migrations/` with one working sample migration; `--yes`
  non-interactive mode.
- `tui/dashboard.py`: single snapshot render of REAL db metrics
  (`count_users`, audit totals, webhook count, `health_check()`); every
  panel says "not connected" when the db is unreachable; footer no longer
  advertises non-functional keybindings.

## 4. Tests — tests/platform_services (new, own conftest.py)

70 tests, all in-memory (`InMemoryCache`, `InMemoryDatabase`,
`click.testing.CliRunner`), no network/docker:
- SMS: CSPRNG source regression, send→verify lifecycle, hashed-at-rest key
  schema, wrong-code attempt cap, expiry (forced + natural TTL), fixed
  window (TTL never refreshed; window reopens), provider-failure + delivery
  passthrough, resend invalidation.
- SMS `__init__` import safety across all four twilio/boto3 combinations
  (including the historical NameError path).
- Bot protection: minute/hour window counting, trimming of expired
  timestamps, disabled mode, UA/IP heuristics (metadata/loopback/private/
  unparseable/public), scoring monotonicity, no-provider error, threshold
  mapping, `get_client` async-method regression + client caching, docstring
  typo regression.
- CLI: doctor exit 1 on invalid config / exit 0 healthy (memory db) /
  missing-DB-URL failure / extras honesty; config set/get/show roundtrip +
  0600 perms (fresh and pre-existing files) + secret masking + JSON values;
  migrate create/run/status/rollback + failed-migration non-zero exit +
  ledger integrity + no-dir/no-db guidance; users list/get/delete against a
  seeded db (confirmation flow, hash never rendered); deploy aws/gcp/azure/
  k8s artifact generation (parsed YAML, honest messaging, no fake ids) +
  docker-absent honest error (docker never required); audit search/export
  (table/JSON/CSV); logs one-shot + bounded follow; dashboard real-counts
  vs not-connected; init scaffolding (generated secret strength, real
  import paths, parity-API-only Django template, migrations dir, no
  hardcoded passwords).

## 5. Notes / coordination

- During the run, two cross-workstream import breakages blocked
  `import authy_package` (stale `core/__init__.py` name, stale
  `organizations/__init__.py` names). Both were reported with file/line
  evidence to the owning agents (core-auth-fix, platform-admin-fix) and
  confirmed fixed by them; no files outside this workstream's ownership
  were modified here.
- Out of scope (owned elsewhere): webhook delivery engine internals
  (`webhooks/webhook_manager.py`, platform-admin), framework adapter §10
  rewrites (core-auth), db adapters (platform-data), packaging/CI (docs
  workstream). The CLI consumes those surfaces defensively (import guards +
  honest error reporting) so it stays functional while they land.
