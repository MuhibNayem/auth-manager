# Remediation status — Wave 3 integration + independent review hardening

Owner: chorus (parent). Complements the per-workstream status docs in this folder.

## Integration fixes (examples aligned to the remediated APIs)
- `examples/example_memory_quickstart.py` — verified end-to-end green (register → login →
  refresh rotation → replay rejection → logout) on InMemory fakes; fixed `MFAAuthManager`
  constructor (db+cache+config), `TraditionalAuthManager` config wiring, `logout_user`
  signature; added source-checkout sys.path bootstrap.
- `examples/example_sql.py` — rewritten for the new contract: `SQLDatabase(url)` (adapter
  owns its own schema; removed the legacy `orm_model=` usage), config-wired managers,
  MFA begin→confirm flow with a real TOTP code, sender-free password reset.
- `examples/example_mongo.py` — `MongoDB({"url", "db_name"})` constructor, same fixes.
- `examples/example_social.py` — `SocialAuthManager(db, config, cache=...)`, MFA
  begin→confirm, `logout(provider, user)` signature, email-verified linking note.
- `examples/example_cognito.py` — audited: already coherent with the rebuilt
  `CognitoManager`/`CognitoAuthManager` APIs (SRP auth, hosted-UI token exchange).

## Independent security review (fresh reviewer agent, read-only)
Verdict: PASS with concerns — all 12 remediated fixes confirmed real and effective under
adversarial re-testing; full suite re-run green. Residual findings NEW-1..NEW-9 were
triaged; the following hardening was implemented in the same wave:

- **NEW-1 (flake + rare prod false-reject):** `config._contains_placeholder` now matches
  long characteristic phrases as substrings and short markers ("xxx", "example", "dummy")
  only as delimited tokens; "your-" replaced with specific "your-secret"/"your-super-secret"
  style phrases. 300×random-secret validation test added; classic placeholders still rejected.
- **NEW-2 (SAML signed-assertion replay):** assertion IDs are now recorded in the replay
  ledger (`assertion:{id}`) so a captured signed assertion re-wrapped in a fresh Response
  is rejected; regression test added.
- **NEW-3 (social linking by display name):** `_handle_social_login` links ONLY on the
  provider email — attacker-controllable display names can no longer link into unrelated
  accounts; regression test added.
- **NEW-4 (SSRF CGNAT gap):** webhook endpoint validation now rejects RFC 6598 shared
  space (100.64.0.0/10) in addition to private/loopback/link-local/reserved/multicast.
- **NEW-5 (OIDC issuer optional):** `validate_id_token` raises ConfigError when no issuer
  is configured instead of skipping `iss` verification.
- **NEW-7 (admin v2 read scopes):** GET /api-keys, /config/branding, /config/localization,
  /settings/{key}, /reports, /reports/{job_id}/download now require
  `read:only`/resource-specific scopes (JWT human admins unaffected).
- **NEW-8 (Apple state):** `apple_social_login` validates CSRF state via the shared
  `_check_state` helper (`expected_state` parameter), consistent with other providers.
- **NEW-9 (rate limiting fails open):** login rate-limit helpers now log a one-time
  explicit warning when no cache is configured instead of silently skipping.

## Documented residual limitations (accepted, not code-fixed)
- **NEW-6:** reset-token consume is get→delete; `AbstractCache` intentionally has no atomic
  pop primitive — narrow double-use race window documented (foundation deviation notes).
- Full-suite determinism re-verified: 5 consecutive green runs after the NEW-1 fix
  (previously ~50%/run flake probability).
