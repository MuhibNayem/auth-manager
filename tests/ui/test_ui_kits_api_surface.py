"""API-surface tests for the React admin dashboard.

Guards the fixes for:
- double-prefixed admin URLs (/admin/api/v1 + /admin/v2),
- the RBAC v2 client + required scope_type query param,
- the real admin login flow ({username_or_email, password} ->
  /admin/api/v1/auth/login, token stored as authy_admin_token),
- ProtectedRoute doing a real token presence + expiry check,
- Enterprise features being reachable and actually wired.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = REPO_ROOT / "authy_package" / "ui_kits" / "react" / "admin-dashboard"
SRC = DASHBOARD / "src"


def read(rel: str) -> str:
    return (SRC / rel).read_text(encoding="utf-8")


def all_source_files():
    for path in sorted(SRC.rglob("*")):
        if path.is_file() and path.suffix in {".ts", ".tsx"}:
            yield path


def all_source_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in all_source_files())


# --- double-prefix protection ------------------------------------------------

def test_no_double_prefixed_admin_paths_anywhere():
    for path in all_source_files():
        text = path.read_text(encoding="utf-8")
        assert "/admin/api/v1/admin/v2" not in text, (
            f"double-prefixed URL found in {path}"
        )


def test_no_v2_paths_issued_through_v1_client():
    """Any call like api.get('/admin/v2/...') uses the v1 client's baseURL
    and would resolve to /admin/api/v1/admin/v2/... — forbid it."""
    pattern = re.compile(
        r"\b(?:api|apiClient)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`'\"]/admin/v2"
    )
    for path in all_source_files():
        text = path.read_text(encoding="utf-8")
        assert not pattern.search(text), (
            f"{path} issues an /admin/v2 path through the v1 client"
        )


def test_dedicated_v2_client_exists():
    api = read("lib/api.ts")
    assert "apiClientV2" in api and "apiV2" in api
    assert re.search(r"API_V2_BASE\s*=\s*'/admin/v2'", api), (
        "v2 client baseURL must be exactly /admin/v2"
    )
    # both clients attach the same bearer token interceptor
    assert api.count("attachAdminToken") >= 2


# --- RBAC --------------------------------------------------------------------

def test_rbac_manager_uses_v2_client_with_relative_paths():
    rbac = read("components/RBACManager.tsx")
    assert "apiV2" in rbac, "RBACManager must use the dedicated v2 client"
    for endpoint in ("'/rbac/permissions'", "'/rbac/roles'"):
        assert endpoint in rbac, f"RBACManager must call {endpoint} via apiV2"
    assert "'/admin/v2/rbac/" not in rbac, (
        "RBACManager must not hardcode the /admin/v2 prefix in call paths"
    )


def test_role_assignments_pass_required_scope_type():
    rbac = read("components/RBACManager.tsx")
    assert "scope_type" in rbac, "RoleAssignments must send the scope_type query param"
    assert re.search(r"scope_type:\s*scopeType", rbac), (
        "scope_type must be passed from the scopeType prop"
    )
    # default scope is provided so the backend's required param is always set
    assert "scopeType = 'global'" in rbac


# --- login flow ---------------------------------------------------------------

def test_login_api_matches_contract():
    api = read("lib/api.ts")
    assert "'/auth/login'" in api, "authAPI must call /auth/login on the v1 client"
    assert "username_or_email" in api and "password" in api, (
        "login payload must be {username_or_email, password}"
    )
    assert re.search(r"apiClient\.post<LoginResponse>\('/auth/login'", api), (
        "login must go through the v1 apiClient (baseURL /admin/api/v1)"
    )


def test_login_response_type_defined():
    types = read("types/index.ts")
    assert "LoginResponse" in types and "access_token" in types
    assert "LoginRequest" in types and "username_or_email" in types


def test_login_page_posts_real_credentials():
    login = read("components/Login.tsx")
    assert "authAPI.login" in login
    assert "Login functionality to be implemented" not in login
    assert "navigate('/'" in login or 'navigate("/"' in login, (
        "successful login must redirect into the dashboard"
    )


def test_token_key_consistent_across_dashboard():
    auth = read("lib/auth.ts")
    assert "ADMIN_TOKEN_KEY = 'authy_admin_token'" in auth
    # No legacy/divergent storage keys anywhere in the dashboard source.
    combined = all_source_text()
    assert "'access_token'" not in combined and '"access_token"' not in combined, (
        "found a divergent token storage key; must be authy_admin_token"
    )
    # The store and api layer must go through the shared helpers/key.
    store = read("store/index.ts")
    assert "from '../lib/auth'" in store and "storeToken" in store
    api = read("lib/api.ts")
    assert "readStoredToken" in api


def test_protected_route_enforces_presence_and_expiry():
    index = read("index.tsx")
    assert "isTokenValid(token)" in index, (
        "ProtectedRoute must validate the token, not just a boolean flag"
    )
    store = read("store/index.ts")
    assert "checkExpiry" in store and "expiresAt" in store
    auth = read("lib/auth.ts")
    assert "exp" in auth and "EXPIRY_SKEW_SECONDS" in auth


def test_store_hydrates_session_from_storage():
    store = read("store/index.ts")
    assert "readStoredToken" in store and "loadInitialSession" in store


# --- dashboard data wiring -----------------------------------------------------

def test_dashboard_health_is_live_not_hardcoded():
    dashboard = read("components/Dashboard.tsx")
    assert "useHealthStatus" in dashboard, "health panel must call healthAPI"
    assert ">Healthy</span>" not in dashboard, "health status must not be hardcoded"
    assert "—" in dashboard, "unavailable values must render an explicit dash"
    assert "change: 12.5" not in dashboard and "change: 8.2" not in dashboard, (
        "metric deltas must not be fabricated"
    )


# --- enterprise features --------------------------------------------------------

def test_enterprise_components_use_v2_client():
    ent = read("components/EnterpriseFeatures.tsx")
    assert "apiV2" in ent
    for endpoint in ("'/api-keys'", "'/config/branding'", "'/audit-logs/search'",
                     "'/ai/anomalies'", "'/ai/predictions'", "'/ai/nlq'"):
        assert endpoint in ent, f"EnterpriseFeatures must call {endpoint} via apiV2"
    assert "'/admin/v2/" not in ent, (
        "EnterpriseFeatures must not hardcode /admin/v2 prefixes in call paths"
    )


def test_dialog_has_real_open_state():
    ent = read("components/EnterpriseFeatures.tsx")
    assert "DialogContext" in ent and "setOpen" in ent
    assert re.search(r"if \(!open\) return null", ent), (
        "DialogContent must render nothing while closed"
    )
    assert "Escape" in ent and "aria-modal" in ent


def test_advanced_audit_search_is_wired():
    ent = read("components/EnterpriseFeatures.tsx")
    assert "enabled: false" not in ent, "search must not be a disabled query"
    assert "runSearch" in ent and "onClick={runSearch}" in ent
    assert "apiV2.post<AuditSearchResponse>('/audit-logs/search'" in ent
    # payload must match the backend AuditSearchFilter (list + ISO datetimes)
    assert "event_types" in ent and "toISOString()" in ent


def test_enterprise_page_is_reachable():
    index = read("index.tsx")
    assert 'path="/enterprise"' in index and "EnterprisePage" in index
    layout = read("components/Layout.tsx")
    assert "'/enterprise'" in layout, "sidebar must link to /enterprise"


# --- hygiene --------------------------------------------------------------------

def test_no_placeholder_text_left_in_dashboard():
    combined = all_source_text()
    assert "to be implemented" not in combined.lower()
