"""sms package import safety (CONTRACTS.md §0.9).

Covers the historical NameError path: twilio absent while boto3 is present.
"""

from __future__ import annotations

import importlib
import sys

import pytest


def _reload_sms_package() -> None:
    """Drop cached sms modules and re-import fresh."""
    for name in [
        "tessera.sms.twilio_provider",
        "tessera.sms.aws_sns_provider",
        "tessera.sms.sms_manager",
        "tessera.sms.abstract_provider",
        "tessera.sms",
    ]:
        sys.modules.pop(name, None)
    importlib.import_module("tessera.sms")


@pytest.fixture
def restore_sms_modules():
    """Ensure the real sms modules are restored after module poisoning."""
    yield
    for name in [
        "tessera.sms.twilio_provider",
        "tessera.sms.aws_sns_provider",
        "tessera.sms.sms_manager",
        "tessera.sms.abstract_provider",
        "tessera.sms",
    ]:
        sys.modules.pop(name, None)
    importlib.import_module("tessera.sms")


def test_sms_imports_with_all_providers():
    import tessera.sms as sms

    assert "SMSManager" in sms.__all__
    assert sms.TWILIO_AVAILABLE is True
    assert sms.AWS_SNS_AVAILABLE is True
    assert "TwilioProvider" in sms.__all__
    assert "AWSSNSProvider" in sms.__all__


def test_sms_import_without_twilio_boto3_present(monkeypatch, restore_sms_modules):
    """twilio absent + boto3 present used to raise NameError — never again."""
    # Poison the twilio import chain; boto3 stays importable.
    for poisoned in ("twilio", "twilio.rest", "twilio.base", "twilio.base.exceptions"):
        monkeypatch.setitem(sys.modules, poisoned, None)

    import boto3  # noqa: F401 — precondition of the regression

    _reload_sms_package()
    sms = importlib.import_module("tessera.sms")

    assert sms.TWILIO_AVAILABLE is False
    assert sms.AWS_SNS_AVAILABLE is True
    assert "TwilioProvider" not in sms.__all__
    assert "AWSSNSProvider" in sms.__all__
    # Core API always present.
    assert {"SMSManager", "AbstractSMSProvider", "SMSProviderError"} <= set(sms.__all__)


def test_sms_import_without_boto3_twilio_present(monkeypatch, restore_sms_modules):
    for poisoned in ("boto3", "botocore", "botocore.exceptions"):
        monkeypatch.setitem(sys.modules, poisoned, None)

    _reload_sms_package()
    sms = importlib.import_module("tessera.sms")

    assert sms.TWILIO_AVAILABLE is True
    assert sms.AWS_SNS_AVAILABLE is False
    assert "TwilioProvider" in sms.__all__
    assert "AWSSNSProvider" not in sms.__all__


def test_sms_import_without_both_providers(monkeypatch, restore_sms_modules):
    for poisoned in (
        "twilio",
        "twilio.rest",
        "twilio.base",
        "twilio.base.exceptions",
        "boto3",
        "botocore",
        "botocore.exceptions",
    ):
        monkeypatch.setitem(sys.modules, poisoned, None)

    _reload_sms_package()
    sms = importlib.import_module("tessera.sms")

    assert sms.TWILIO_AVAILABLE is False
    assert sms.AWS_SNS_AVAILABLE is False
    assert "TwilioProvider" not in sms.__all__
    assert "AWSSNSProvider" not in sms.__all__
    assert "SMSManager" in sms.__all__
