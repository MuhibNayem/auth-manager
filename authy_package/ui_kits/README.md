# Authy UI Kits

Frontend building blocks that ship **inside the repository** as source files.
Everything in this directory is plain source you copy into your own app —
there is no published `authy-ui` npm package and no Python-rendered UI.

## What is actually here

| Path | What it is | Status |
|------|------------|--------|
| `react/admin-dashboard/` | React 18 + TypeScript + Vite + Tailwind admin dashboard (app **and** importable `AdminDashboard` component) | Working against admin API v1 (`/admin/api/v1`) and v2 (`/admin/v2`) |
| `svelte/LoginForm.svelte` | End-user login form, Svelte 4-compatible syntax (compiles under Svelte 5; **no runes** are used) | Working, configurable endpoints |
| `vue/LoginForm.vue` | End-user login form, Vue 3 `<script setup lang="ts">` | Working, configurable endpoints |
| `react/__init__.py` | Python string templates (`REACT_COMPONENTS`) for CLI scaffolding / copy-paste only — **not** importable React components | Scaffold-only, token key aligned with the dashboard (`authy_admin_token`) |

There is no React `LoginForm`/`SignUpForm`/`MFAInput` component in this
package. The React surface is the admin dashboard; the React templates in
`react/__init__.py` are scaffolding strings.

---

## React admin dashboard (`react/admin-dashboard/`)

Routes: `/login`, `/` (overview), `/users`, `/organizations`, `/security`,
`/audit-logs`, `/sessions`, `/webhooks`, `/health`, `/settings`, `/rbac`,
`/enterprise`.

- **Login** POSTs `{username_or_email, password}` as JSON to
  `/admin/api/v1/auth/login` and stores the returned access token under
  localStorage key **`authy_admin_token`**. `ProtectedRoute` requires token
  presence **and** validates the JWT `exp` claim (client-side expiry check;
  signature verification is the backend's job).
- **API clients**: `apiClient` (baseURL `/admin/api/v1`) for dashboard,
  users, orgs, audit, sessions, webhooks, health, reports; `apiClientV2`
  (baseURL `/admin/v2`) for RBAC, API keys, branding, security analytics and
  advanced audit search. v2 calls never go through the v1 client (that would
  produce double-prefixed URLs).
- **Health panel** renders live data from `GET /admin/api/v1/health` and
  shows “—” when unavailable. Metric cards show “—” for period deltas because
  the metrics endpoint does not return them (no fabricated numbers).

### Run it

```bash
cd authy_package/ui_kits/react/admin-dashboard
npm install
npm run dev        # dev server on :3000, proxies /admin/api and /admin/v2 to :8000
npm run build      # tsc typecheck + vite build (library mode)
npm test           # vitest unit tests for the token helpers
npm run lint       # eslint
```

Styling uses Tailwind classes; the dev server loads `src/index.css`. When you
embed the exported `AdminDashboard` component in your own app, provide
Tailwind (or equivalent utility classes) yourself.

---

## Svelte & Vue login forms

Both forms POST `{"email", "password"}` as JSON to a configurable endpoint,
emit `success` / `error` events with `{user, token}` from the response, and
never store the token themselves — the host app decides what to do with it.

### Endpoint configuration (the important part)

The API base URL and the login path are **props with defaults**:

| Prop | Type | Default | Meaning |
|------|------|---------|---------|
| `apiBaseUrl` | string | `''` (current origin) | Backend origin, e.g. `https://auth.example.com` |
| `loginPath` | string | `/api/auth/login` | Login route on that backend |
| `redirectUrl` | string | `''` | Post-login redirect; empty disables auto-redirect |
| `showSocial` | boolean | `true` | Render Google/GitHub buttons |
| `showMagicLink` | boolean | `true` | Render the magic-link button (only if `magicLinkUrl` set) |
| `magicLinkUrl` | string | `''` | Magic-link page; link hidden when empty |
| `forgotPasswordUrl` | string | `''` | "Forgot?" link; hidden when empty |
| `signUpUrl` | string | `''` | Sign-up link; hidden when empty |
| `titleLabel` / `submitLabel` | string | `'Welcome back'` / `'Sign In'` | Copy |

The final login URL is `` `${apiBaseUrl}${loginPath}` ``. Optional links
(magic link, forgot password, sign up) render **only when a URL is
provided**, so the component never asserts routes your app does not
implement. Social buttons navigate to
`` `${apiBaseUrl}/api/auth/social/{provider}` `` — implement that route on
your backend, or set `showSocial={false}`.

### Svelte usage

```svelte
<script lang="ts">
  import LoginForm from './LoginForm.svelte';
  function onSuccess(e: CustomEvent<{ user: unknown; token: string }>) {
    localStorage.setItem('authy_admin_token', e.detail.token);
  }
</script>

<LoginForm
  apiBaseUrl="https://auth.example.com"
  loginPath="/api/auth/login"
  showSocial={false}
  on:success={onSuccess}
/>
```

### Vue usage

```vue
<script setup lang="ts">
import LoginForm from './LoginForm.vue';

function handleSuccess({ user, token }: { user: unknown; token: string }) {
  localStorage.setItem('authy_admin_token', token);
}
</script>

<template>
  <LoginForm
    api-base-url="https://auth.example.com"
    login-path="/api/auth/login"
    :show-social="false"
    @success="handleSuccess"
  />
</template>
```

### Theming

Both components style via CSS variables (all optional, with fallbacks):

```css
:root {
  --authy-primary: #3b82f6;
  --authy-bg-color: #f3f4f6;
  --authy-text-primary: #111827;
  --authy-text-secondary: #6b7280;
  --authy-border: #d1d5db;
}
```

---

## Backend expectations

- Default user-facing paths (`/api/auth/login`, `/api/auth/social/{provider}`)
  are **conventions**: point the props at whatever your auth server
  implements. They are not guaranteed to exist on a stock authy server.
- The admin dashboard speaks the routes defined in
  `authy_package/admin/dashboard_api.py` (v1), `rbac_api.py` and
  `dashboard_enterprise.py` (v2). The admin login endpoint
  `POST /admin/api/v1/auth/login` is being added by the backend team; until
  it exists, the login form reports the endpoint as unavailable.

## Security notes

- The admin dashboard keeps the admin JWT in `localStorage`
  (`authy_admin_token`). This is a pragmatic SPA choice; if your threat model
  requires it, host the dashboard behind a session-cookie proxy instead.
- Login forms pass tokens to the parent via events and store nothing
  themselves.

See the main [README.md](../../README.md) for the package overview and
[docs/CONTRACTS.md](../../../docs/CONTRACTS.md) for the binding API
contracts.
