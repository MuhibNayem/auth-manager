# Authy Admin Dashboard — Status Report (2.0 remediation)

Status document. Supersedes all earlier versions of this report, which
contained unverified performance metrics and TODO lists that contradicted
`AUTHY_ENTERPRISE_PHASES_REPORT.md`. The authoritative spec for every
claim below is [`docs/CONTRACTS.md`](docs/CONTRACTS.md) (§5 admin
dependency pattern, §8 admin v2, §4 db contract).

## Scope

- Backend admin REST API: `authy_package/admin/dashboard_api.py`
  (v1 dashboard endpoints) and the `/admin/v2` surface (CONTRACTS.md §8).
- React admin dashboard: `authy_package/ui_kits/react/admin-dashboard/`.
- RBAC integration: see `AUTHY_RBAC_IMPLEMENTATION_REPORT.md`.

## Delivery status

| Area | Status in 2.0 | Contract reference |
|---|---|---|
| Dashboard metrics & chart data from real db counts | Delivered (rebuilt against db contract) | §4, §8 |
| User management (CRUD, bounded bulk ops, impersonation) | Delivered; bulk ops bounded and audit-logged | §8 |
| Organizations endpoints | Delivered | §4 |
| Audit log list/search/export (CSV/JSON) | Delivered via `search_audit_events` | §4, §8 |
| Sessions monitoring & revocation | Delivered | §4 |
| Webhook endpoint management, test delivery, delivery history | Delivered; endpoint URLs SSRF-validated | §7 |
| Security analytics | Delivered as **rule-based heuristics** (impossible travel without geo, brute force, MFA-bypass attempts) — documented as heuristics, not ML | §8 |
| API keys (`authy_ak_...`) | Delivered: plaintext returned once at creation, sha256 hash stored, middleware validates on every `/admin/v2` route | §8 |
| Branding / localization / settings | Delivered: persisted through db settings key-value | §8 |
| Reports | Delivered: real CSV/JSON generated from users/audit data; no fake progress sleeps | §8 |
| Advanced audit search | Delivered: structured filters compiled to `search_audit_events` kwargs | §8 |
| Health endpoint | Delivered via `health_check()` on db/cache | §3, §4 |

### Removed / not delivered (previously claimed)

- **"AI/ML intelligence", predictive analytics, LLM natural-language
  query**: not delivered. The earlier "AI" endpoints were mocked and were
  replaced by the rule-based security analytics above (CONTRACTS.md §8).
- Unverified frontend performance figures (Lighthouse scores, FCP/TTI,
  bundle sizes, API latency) were removed from this report; no benchmark
  evidence existed for them.

## Security model (how admin routes are protected)

Per CONTRACTS.md §5:

- Route handlers use dependency injection (`AdminDependencies` on
  `app.state`); no bare `= None` handler defaults.
- Bearer tokens via `Authorization` header only — never query params.
- `get_current_admin_user` verifies JWTs with `JWTTokenManager` and
  requires role `admin`/`owner`/`superadmin` **or** an RBAC `admin:*`
  grant; org-scoped routes additionally enforce org admin.
- `/admin/v2` API-key routes validate hashed keys against the db on every
  request; webhook test endpoints validate URL safety (CONTRACTS.md §7).
- Errors map to the typed `AuthyError` hierarchy (CONTRACTS.md §1).

## Frontend

The React dashboard is a TypeScript application (React 18, Vite, Zustand,
TanStack Query). It was rebuilt to authenticate against the API for real
(token/expiry checks on protected routes) instead of bypassing them. No
performance claims are made here; measure on your deployment if needed.

## Verification

Behavior above is covered by the remediation test suite (in-memory fakes,
no external services) per CONTRACTS.md §0 rule 10 and §12. Historical
claims of "40+ endpoints fully implemented" from the pre-remediation
report were replaced by the per-area status table above.

---

*Changed in the 2.0 remediation — see
`docs/REMEDIATION_STATUS_packaging.md` for the documentation changelog.*
