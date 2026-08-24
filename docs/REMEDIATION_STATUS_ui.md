# Remediation Status — UI Kits (`ui-kits-fix` workstream)

Scope: `authy_package/ui_kits/**`, `tests/ui/**`, this document.
Binding spec: `docs/CONTRACTS.md` (§5 admin DI/auth, §8 admin v2).

## Fixed items

### 1. React admin dashboard build — FIXED
- Added `tsconfig.node.json` (resolves the project reference in `tsconfig.json`).
- Added `index.html` + `src/main.tsx` dev entry; added `src/vite-env.d.ts`
  so CSS imports typecheck.
- Added `tailwind.config.js`, `postcss.config.js`, `src/index.css`
  (tailwindcss/postcss/autoprefixer were declared deps with no config).
- Added `.eslintrc.cjs` so `npm run lint` has a real config; changed
  `test` to `vitest run` (watch mode would hang CI) and added a real unit
  test (`src/lib/auth.test.ts`, 8 tests).
- Verified on node v24.19.0 / npm 11.17.0 (both available in this env):
  `npm install --no-audit --no-fund` → ok; `npm run build`
  (`tsc && vite build`) → **passes** (ES + UMD bundles emitted);
  `npm run lint` → 0 warnings; `npm test` → 8/8 pass.
  (An opt-in pytest re-run of this exists: `tests/ui/test_ui_kits_node_build.py`,
  enabled with `AUTHY_UI_RUN_NODE=1`; skipped by default to keep pytest node-free.)

### 2. Real admin login — FIXED
- New `src/components/Login.tsx`: POSTs JSON `{username_or_email, password}`
  to `/admin/api/v1/auth/login` via the v1 axios client (`authAPI.login`),
  maps 401/403/404/429/network errors to user-facing messages.
- Token stored under **`authy_admin_token`** via `src/lib/auth.ts` helpers
  (single source of truth for the key; JWT `exp` decode + skew-aware
  `isTokenValid`).
- `store/index.ts` hydrates the session synchronously from localStorage and
  exposes `checkExpiry()`; `ProtectedRoute` now requires token presence AND
  a non-expired `exp` claim, and auto-logs-out on a timer at expiry.
- Note: the backend endpoint is still being added by platform-admin; until it
  exists the form reports “Login endpoint not available on this server yet.”

### 3. RBAC v2 double-prefix + scope_type — FIXED
- Added dedicated `apiClientV2` / `apiV2` (baseURL `/admin/v2`) sharing the
  bearer-token interceptor; all `/admin/v2` call sites (`RBACManager.tsx`,
  `EnterpriseFeatures.tsx`) now use relative paths through `apiV2`. No
  `/admin/api/v1/admin/v2` URLs remain (test-enforced).
- `RoleAssignments` now takes `scopeType` (default `'global'`) and optional
  `scopeId` props and sends `scope_type` (+ `scope_id`) query params required
  by `GET /admin/v2/rbac/users/{user_id}/roles`.

### 4. Dashboard real data + Enterprise features — FIXED
- `Dashboard.tsx`: fabricated metric deltas removed — cards render “—”
  (metrics API returns no deltas); health panel wired to `healthAPI`
  (`useHealthStatus`) with status→tone mapping and “—”/message when
  unavailable; the time-range select now actually drives the metrics query.
- `EnterpriseFeatures.tsx`: Dialog re-implemented with real open/close state
  (context provider, trigger, backdrop/Escape/close-button dismissal,
  `aria-modal`); no-op Select shims removed; API-key create dialog closes on
  success and now **displays the one-time secret**; Advanced Audit Search
  “Run Search” POSTs a backend-shaped `AuditSearchFilter` payload
  (event_types list, ISO datetimes) to `POST /admin/v2/audit-logs/search`;
  dead buttons (Export CSV, Investigate) removed.
- Reachability: `/enterprise` route added + sidebar links for Enterprise and
  RBAC; components exported from the library entry.

### 5. `ui_kits/README.md` — REWRITTEN
No more Svelte-5-runes or `SignUpForm`/`MFAInput` claims; documents exactly
what exists, the real props/defaults, the `authy_admin_token` convention,
and which endpoints are host-provided conventions.

### 6. Svelte/Vue LoginForms — FIXED (kept, per instruction)
- API location is now `apiBaseUrl` (default `''`) + `loginPath`
  (default `/api/auth/login`) props; final URL composed from both.
- Social buttons wired to `` `${apiBaseUrl}/api/auth/social/{provider}` ``
  behind the existing `showSocial` flag (Svelte previously had dead
  handlers).
- No asserted routes remain: magic-link/forgot-password/sign-up links render
  only when URLs are provided; auto-redirect only when `redirectUrl` set.
- Removed unused `onMount` import and misleading runes comments (Svelte);
  kept event dispatch/emit contracts unchanged.

### 7. `react/__init__.py` — KEPT + ALIGNED (documented choice)
Nothing imports it (verified by grep), but it is the only React scaffold
source for CLI/copy-paste, so deleting it would leave a gap. Rewritten:
templates now use `authy_admin_token`, `apiBaseUrl`/`loginPath` props, and
module docstring clearly labels them scaffold strings, not components.

### 8. `tests/ui/` — ADDED (node-free by default)
- `test_ui_kits_dashboard_structure.py` — package.json script/dep coherence,
  tsconfig references resolve, index.html entry exists, tailwind/postcss
  configs exist, lint config exists, vitest test file exists.
- `test_ui_kits_api_surface.py` — no double-prefixed URLs, no v2 paths via
  the v1 client, v2 client exists, scope_type passed, login contract
  payload/path, token key consistency, ProtectedRoute expiry check,
  health wired, Dialog/search wired, /enterprise reachable.
- `test_ui_kits_login_forms.py` — configurable endpoints, wired social
  handlers, no asserted routes (Svelte + Vue).
- `test_ui_kits_react_templates.py` — scaffold token-key alignment.
- `test_ui_kits_node_build.py` — opt-in npm install/build (env-gated).

## Verification results
- `./.venv/bin/python -m pytest tests/ui -q` → **38 passed, 1 skipped**
  (the skip is the opt-in node build test).
- `npm run build` in the dashboard dir → passes (see item 1).

## Remaining known gaps
- `POST /admin/api/v1/auth/login` is not implemented in the backend yet
  (owned by platform-admin); UI is ready and fails gracefully until then.
- Dashboard pages Users/Organizations/Security/Audit/Sessions/Webhooks/
  Health/Settings are still simple placeholder shells (routes + API layer
  exist; building their full UIs is out of this workstream's scope).
- Svelte/Vue forms still POST `{email, password}` (their long-standing
  contract); the admin form uses the new `{username_or_email, password}`
  contract. Unifying them is a backend-contract decision, not a UI one.
- Sidebar nav uses `<a href>` (full page loads) rather than router `Link`s —
  pre-existing behavior, left untouched to keep this change minimal.
- `vite preview`/dev-server proxy targets `http://localhost:8000` hardcoded —
  fine for dev, documented.
