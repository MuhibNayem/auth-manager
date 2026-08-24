"""Tests for the Svelte and Vue LoginForm components.

Guards the fixes for:
- API base URL + login path are props with defaults (final URL composed),
- social buttons are wired to {base}/api/auth/social/{provider} behind the
  showSocial flag (no dead handlers),
- the components no longer assert routes that may not exist (magic link,
  forgot password, sign up, auto-redirect all opt-in).
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_KITS = REPO_ROOT / "tessera" / "ui_kits"
SVELTE = (UI_KITS / "svelte" / "LoginForm.svelte").read_text(encoding="utf-8")
VUE = (UI_KITS / "vue" / "LoginForm.vue").read_text(encoding="utf-8")


# --- Svelte -------------------------------------------------------------------

def test_svelte_api_location_is_configurable():
    assert "export let apiBaseUrl = ''" in SVELTE
    assert "export let loginPath = '/api/auth/login'" in SVELTE
    # final URL composed from both props
    assert "`${apiBaseUrl}${loginPath}`" in SVELTE
    assert "fetch(actionUrl" in SVELTE
    # the old single hardcoded endpoint prop is gone
    assert "export let actionUrl" not in SVELTE


def test_svelte_social_buttons_are_wired_behind_flag():
    assert "function handleSocialLogin" in SVELTE
    assert "`${apiBaseUrl}/api/auth/social/${provider}`" in SVELTE
    assert "on:click={() => handleSocialLogin('google')}" in SVELTE
    assert "on:click={() => handleSocialLogin('github')}" in SVELTE
    # still gated by the showSocial prop
    assert "export let showSocial" in SVELTE
    assert "{#if showSocial}" in SVELTE


def test_svelte_does_not_assert_missing_routes():
    # magic link only renders when a URL is configured
    assert "export let magicLinkUrl = ''" in SVELTE
    assert "{#if showMagicLink && magicLinkUrl}" in SVELTE
    assert 'href="/auth/magic"' not in SVELTE
    # forgot/sign-up links are opt-in
    assert "export let forgotPasswordUrl = ''" in SVELTE
    assert "export let signUpUrl = ''" in SVELTE
    assert "{#if signUpUrl}" in SVELTE
    # no forced redirect to a route that may not exist
    assert "export let redirectUrl = ''" in SVELTE
    assert "export let redirectUrl = '/dashboard'" not in SVELTE


def test_svelte_no_misleading_runes_claims():
    assert "$state(" not in SVELTE, "runes references must not remain (not used)"


def test_svelte_still_dispatches_events():
    assert "createEventDispatcher" in SVELTE
    assert "dispatch('success'" in SVELTE and "dispatch('error'" in SVELTE


# --- Vue ----------------------------------------------------------------------

def test_vue_api_location_is_configurable():
    assert "apiBaseUrl?: string" in VUE
    assert "loginPath?: string" in VUE
    assert "apiBaseUrl: ''" in VUE
    assert "loginPath: '/api/auth/login'" in VUE
    assert "fetch(actionUrl.value" in VUE
    assert "props.apiBaseUrl}${props.loginPath}" in VUE.replace("`", "")
    assert "actionUrl: '/api/auth/login'" not in VUE


def test_vue_social_buttons_are_wired_behind_flag():
    assert "function handleSocialLogin" in VUE
    assert "props.apiBaseUrl}/api/auth/social/${provider}" in VUE.replace("`", "")
    assert "@click=\"handleSocialLogin('google')\"" in VUE
    assert "@click=\"handleSocialLogin('github')\"" in VUE
    assert "showSocial?: boolean" in VUE


def test_vue_does_not_assert_missing_routes():
    assert "magicLinkUrl: ''" in VUE
    assert "magicLinkUrl && !success" in VUE
    assert 'href="/auth/magic"' not in VUE
    assert "forgotPasswordUrl: ''" in VUE
    assert "signUpUrl: ''" in VUE
    assert "signUpUrl && !success" in VUE
    assert "redirectUrl: ''" in VUE
    assert "redirectUrl: '/dashboard'" not in VUE


def test_vue_still_emits_events():
    assert "defineEmits" in VUE
    assert "emit('success'" in VUE and "emit('error'" in VUE
