"""Tests for the React scaffold templates in ui_kits/react/__init__.py.

Decision (documented in ui_kits README + remediation status): the file is
KEPT — it is the only React scaffold source for CLI/copy-paste use — but its
token key and endpoint handling are aligned with the admin dashboard:
- token persisted under localStorage key `authy_admin_token`
- endpoints configurable via apiBaseUrl + loginPath props.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "authy_package" / "ui_kits" / "react" / "__init__.py"


def read_module() -> str:
    return MODULE.read_text(encoding="utf-8")


def test_module_exists_and_parses():
    assert MODULE.is_file()
    code = compile(read_module(), str(MODULE), "exec")
    namespace: dict = {}
    exec(code, namespace)  # noqa: S102 - our own file, deliberate in test
    assert "REACT_COMPONENTS" in namespace
    assert namespace.get("ADMIN_TOKEN_KEY") == "authy_admin_token"


def test_templates_use_dashboard_token_key():
    text = read_module()
    assert "authy_admin_token" in text
    # the old divergent key must be gone entirely
    assert "'access_token'" not in text and '"access_token"' not in text


def test_templates_have_configurable_endpoints():
    text = read_module()
    assert "apiBaseUrl" in text
    assert "loginPath" in text
    # LoginForm template must compose the URL from the props
    assert "${apiBaseUrl}${loginPath}" in text
    # social template routes through the configured base as well
    assert "${apiBaseUrl}/api/auth/social/${provider}" in text
