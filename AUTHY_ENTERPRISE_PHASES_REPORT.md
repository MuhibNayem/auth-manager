# Authy Enterprise Phases 2–4 — Status Report (2.0 remediation)

Status document. Supersedes earlier versions of this report. The previous
edition claimed Phases 2–4 were fully "Complete" (including AI/ML features)
while `AUTHY_ADMIN_DASHBOARD_REPORT.md` listed the same phases as TODO.
Both were wrong in different ways; this document states the reconciled
truth. Authoritative spec: [`docs/CONTRACTS.md`](docs/CONTRACTS.md) §8
(admin v2, real implementations).

## Phase summary

| Phase | Scope | Status in 2.0 |
|---|---|---|
| Phase 2 | Advanced user & audit management | Delivered — rebuilt against the db contract |
| Phase 3 | White-label, i18n, API keys, reports | Delivered — rebuilt against the db contract |
| Phase 4 | Security analytics | Delivered as rule-based heuristics; "AI/ML" claims removed |

## Phase 2 — Advanced operations

- Bulk user actions (delete / disable / enable / force password reset):
  implemented via `db.list_users` / `update_user` / `delete_user` with a
  bounded `user_ids` list (max 1000) and an audit event emitted per
  action (CONTRACTS.md §8).
- Advanced audit log search: structured filters compiled to
  `search_audit_events` kwargs (§8), with CSV/JSON export of filtered
  results.

## Phase 3 — Enterprise configuration

- White-label branding: persisted via the db settings key-value store.
- Localization (i18n): settings-based configuration (en-US, es-ES, fr-FR,
  de-DE, ja-JP shipped as starter catalogs).
- API keys: create returns plaintext **once**; only the sha256 hash,
  scopes, and expiry are stored; middleware validates
  `Authorization: Bearer authy_ak_...` against the db on every
  `/admin/v2` route (§8).
- Reports: real CSV/JSON generated from users/audit data through the db
  contract; job ids are `secrets.token_hex(8)`; no fake progress sleeps.

## Phase 4 — Security analytics (previously "AI")

What exists:

- Impossible-travel detection (geo-free: velocity by IP/user-agent
  change + time).
- Brute-force detection (N failed logins per window).
- MFA-bypass attempt detection.
- All detectors are rule-based over audit events and are documented as
  heuristics (§8).

What was removed / never delivered:

- "LLM-powered natural language query" and "predictive analytics with
  confidence intervals" from the previous report were mocked UI/backend
  stubs; they are **not delivered** and are not on the contract surface.
- WebSocket real-time alert push is not part of the contract; the
  endpoints above are polled.

## Endpoints (admin v2)

| Endpoint | Method | Phase | Notes |
|---|---|---|---|
| `/admin/v2/users/bulk-action` | POST | 2 | bounded, audit-logged |
| `/admin/v2/audit-logs/search` | POST | 2 | filters → `search_audit_events` |
| `/admin/v2/config/branding` | GET/PUT | 3 | settings kv |
| `/admin/v2/config/localization` | GET/PUT | 3 | settings kv |
| `/admin/v2/api-keys` | POST/GET | 3 | hashed at rest; masked in listings |
| `/admin/v2/reports/generate` | POST | 3 | real CSV/JSON |
| `/admin/v2/security/anomalies` | GET | 4 | heuristics, documented as such |

All routes are protected per CONTRACTS.md §5 (bearer-only JWT or hashed
API key; admin role or RBAC `admin:*` grant; org-admin checks on
org-scoped routes).

## Verification

Previously-mocked surfaces were rebuilt and are covered by the
remediation test suite (in-memory fakes, no external services) per
CONTRACTS.md §0 rule 10 and §12. Line-count and "Production Ready"
claims from the previous report were removed as unverifiable.

---

*Changed in the 2.0 remediation — see
`docs/REMEDIATION_STATUS_packaging.md` for the documentation changelog.*
