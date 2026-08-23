"""Password-security tests: top-1000 list, policy engine, fail_closed, HIBP."""

from __future__ import annotations

import pytest

from authy_package.password_security import (
    HibpProvider,
    PasswordPolicy,
    PasswordSecurityManager,
)
from authy_package.password_security.password_validator import (
    COMMON_PASSWORDS_TOP1000,
)


def _manager(**policy_kwargs):
    policy = PasswordPolicy(check_breached=False, **policy_kwargs)
    return PasswordSecurityManager(hibp_provider=None, policy=policy)


async def test_common_password_dataset_is_top1000_scale():
    assert len(COMMON_PASSWORDS_TOP1000) >= 900
    for sample in ("password", "123456", "qwerty", "letmein", "admin"):
        assert sample in COMMON_PASSWORDS_TOP1000


@pytest.mark.parametrize("common", ["password", "123456", "qwerty", "letmein"])
async def test_common_passwords_rejected(common):
    manager = _manager(min_length=1, require_uppercase=False, require_lowercase=False,
                       require_numbers=False, require_special_chars=False)
    valid, errors = await manager.validate_password(common)
    assert valid is False
    assert any("common" in e.lower() for e in errors)


async def test_length_upper_lower_number_special_enforced():
    manager = _manager(min_length=12)
    valid, errors = await manager.validate_password("short")
    assert valid is False
    joined = " ".join(errors).lower()
    assert "at least 12" in joined

    # Missing uppercase / number / special
    valid2, errors2 = await manager.validate_password("alllowercaseonly")
    assert valid2 is False
    joined2 = " ".join(errors2).lower()
    assert "uppercase" in joined2
    assert "number" in joined2
    assert "special" in joined2


async def test_strong_password_passes():
    manager = _manager(min_length=12)
    valid, errors = await manager.validate_password("C0rrect!Horse_Battery9")
    assert valid is True
    assert errors == []


async def test_sequential_and_rejected_and_username():
    manager = _manager(min_length=8, require_uppercase=False, require_numbers=False,
                       require_special_chars=False)
    valid_seq, errors_seq = await manager.validate_password("abcdefgh")
    assert valid_seq is False and any("sequential" in e.lower() for e in errors_seq)

    valid_rep, errors_rep = await manager.validate_password("aaaaaaaab")
    assert valid_rep is False and any("repeated" in e.lower() for e in errors_rep)

    valid_user, errors_user = await manager.validate_password("xxalicezz", username="alice")
    assert valid_user is False and any("username" in e.lower() for e in errors_user)


class _FailingHibp:
    """Provider whose check always raises (simulates unreachable API)."""

    def __init__(self, fail_closed):
        self.config = type("C", (), {"fail_closed": fail_closed})()

    async def check_password(self, password):
        raise Exception("network down")


async def test_fail_closed_true_blocks_validation():
    policy = PasswordPolicy(check_breached=True, min_length=1, require_uppercase=False,
                            require_lowercase=False, require_numbers=False,
                            require_special_chars=False)
    manager = PasswordSecurityManager(hibp_provider=_FailingHibp(True), policy=policy)
    valid, errors = await manager.validate_password("S0mething!Else")
    assert valid is False
    assert any("fail_closed" in e for e in errors)


async def test_fail_closed_false_only_warns():
    policy = PasswordPolicy(check_breached=True, min_length=1, require_uppercase=False,
                            require_lowercase=False, require_numbers=False,
                            require_special_chars=False)
    manager = PasswordSecurityManager(hibp_provider=_FailingHibp(False), policy=policy)
    valid, errors = await manager.validate_password("S0mething!Else")
    assert valid is True
    assert errors == []


async def test_hibp_connection_error_no_unbound_local():
    """Regression: a connection failure before any response must not raise
    UnboundLocalError from the httpx.HTTPError handler."""
    import httpx

    provider = HibpProvider(api_key="k")

    class _BoomClient:
        is_closed = False

        async def get(self, url):
            raise httpx.ConnectError("connection refused")

    provider._client = _BoomClient()

    with pytest.raises(Exception) as exc:
        await provider.check_password("whatever")
    # Must be our wrapped error, NOT UnboundLocalError.
    assert not isinstance(exc.value, UnboundLocalError)
    assert "HIBP API error" in str(exc.value)
