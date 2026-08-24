"""SAML hardening tests: signed fixtures (real xmlsec), audience, replay."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from tessera.cache import InMemoryCache
from tessera.db import InMemoryDatabase
from tessera.errors import ConfigError
from tessera.saml import SAMLConfig, SAMLManager

SP_ENTITY_ID = "https://sp.example.com/metadata"
ACS_URL = "https://sp.example.com/acs"
SLO_URL = "https://sp.example.com/slo"
IDP_ENTITY_ID = "https://idp.example.com/metadata"
IDP_SSO_URL = "https://idp.example.com/sso"
NAME_ID = "user@example.com"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_idp_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


IDP_KEY, IDP_CERT = _make_idp_keypair()


def _sign_element(element: etree._Element, private_key) -> None:
    """Enveloped-sign an element carrying an ID attribute."""
    signature = xmlsec.template.create(
        element,
        c14n_method=xmlsec.Transform.EXCL_C14N,
        sign_method=xmlsec.Transform.RSA_SHA256,
    )
    element.append(signature)
    reference = xmlsec.template.add_reference(
        signature, xmlsec.Transform.SHA256, uri=f"#{element.get('ID')}"
    )
    xmlsec.template.add_transform(reference, xmlsec.Transform.ENVELOPED)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(pem, xmlsec.KeyFormat.PEM)
    ctx.register_id(element, id_attr="ID")
    ctx.sign(signature)


def _response_xml(
    *,
    response_id: str,
    in_response_to: str,
    assertion_id: str,
    audience: str = SP_ENTITY_ID,
    include_audience: bool = True,
    recipient: str = ACS_URL,
    name_id: str = NAME_ID,
    destination: str = ACS_URL,
) -> str:
    now = _utcnow()
    not_before = (now - timedelta(minutes=5)).isoformat()
    not_on_or_after = (now + timedelta(minutes=10)).isoformat()
    audience_block = (
        f"<saml:Conditions NotBefore='{not_before}' NotOnOrAfter='{not_on_or_after}'>"
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
        if include_audience
        else f"<saml:Conditions NotBefore='{not_before}' NotOnOrAfter='{not_on_or_after}'/>"
    )
    return f"""<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'
        xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'
        ID='{response_id}' InResponseTo='{in_response_to}' Version='2.0'
        IssueInstant='{now.isoformat()}' Destination='{destination}'>
      <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status>
      <saml:Assertion ID='{assertion_id}' Version='2.0' IssueInstant='{now.isoformat()}'>
        <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'>{name_id}</saml:NameID>
          <saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>
            <saml:SubjectConfirmationData Recipient='{recipient}'
              NotOnOrAfter='{not_on_or_after}' InResponseTo='{in_response_to}'/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        {audience_block}
        <saml:AuthnStatement AuthnInstant='{now.isoformat()}' SessionIndex='sess-1'>
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name='email'>
            <saml:AttributeValue>{name_id}</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>"""


def _signed_response_b64(**kwargs) -> str:
    """Build a response, sign its assertion with the IdP key, base64 it."""
    xml_str = _response_xml(**kwargs)
    root = etree.fromstring(xml_str.encode("utf-8"))
    assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    _sign_element(assertion, IDP_KEY)
    return base64.b64encode(etree.tostring(root)).decode("ascii")


@pytest.fixture
async def saml_stack():
    db = InMemoryDatabase()
    await db.connect()
    cache = InMemoryCache()
    config = SAMLConfig(
        sp_entity_id=SP_ENTITY_ID,
        acs_url=ACS_URL,
        slo_url=SLO_URL,
        idp_entity_id=IDP_ENTITY_ID,
        idp_sso_url=IDP_SSO_URL,
        idp_certificate=IDP_CERT,
    )
    manager = SAMLManager(config, db, cache)
    return manager, db


async def _start(manager) -> str:
    _url, request_id = await manager.create_auth_request(relay_state="rs")
    return request_id


# -- happy path -----------------------------------------------------------------

async def test_valid_signed_response_creates_user_and_session(saml_stack):
    manager, db = saml_stack
    request_id = await _start(manager)
    saml_response = _signed_response_b64(
        response_id="_resp_1", in_response_to=request_id, assertion_id="_assert_1"
    )
    result = await manager.validate_response(saml_response, relay_state="rs")
    assert result["name_id"] == NAME_ID
    assert result["user"]["email"] == NAME_ID
    assert result["session_id"]


# -- audience -------------------------------------------------------------------

async def test_missing_audience_restriction_rejected(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    saml_response = _signed_response_b64(
        response_id="_resp_2",
        in_response_to=request_id,
        assertion_id="_assert_2",
        include_audience=False,
    )
    with pytest.raises(ValueError, match="AudienceRestriction"):
        await manager.validate_response(saml_response)


async def test_wrong_audience_rejected(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    saml_response = _signed_response_b64(
        response_id="_resp_3",
        in_response_to=request_id,
        assertion_id="_assert_3",
        audience="https://other-sp.example.com",
    )
    with pytest.raises(ValueError, match="audience"):
        await manager.validate_response(saml_response)


# -- InResponseTo ------------------------------------------------------------------

async def test_unknown_in_response_to_rejected(saml_stack):
    manager, _db = saml_stack
    saml_response = _signed_response_b64(
        response_id="_resp_4",
        in_response_to="_never_issued",
        assertion_id="_assert_4",
    )
    with pytest.raises(ValueError):
        await manager.validate_response(saml_response)


async def test_request_consumed_once(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    first = _signed_response_b64(
        response_id="_resp_5", in_response_to=request_id, assertion_id="_assert_5"
    )
    await manager.validate_response(first)
    # A second response answering the SAME (now consumed) request is rejected.
    second = _signed_response_b64(
        response_id="_resp_5b", in_response_to=request_id, assertion_id="_assert_5b"
    )
    with pytest.raises(ValueError):
        await manager.validate_response(second)


async def test_response_id_replay_rejected(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    saml_response = _signed_response_b64(
        response_id="_resp_6", in_response_to=request_id, assertion_id="_assert_6"
    )
    await manager.validate_response(saml_response)

    # Re-deliver the identical Response (with a fresh outstanding request so
    # the replay ledger is the check that bites).
    await _start(manager)  # irrelevant request id, just to be realistic
    # Forge the same response id against the consumed request's InResponseTo:
    with pytest.raises(ValueError, match="replay"):
        await manager.validate_response(saml_response)


# -- signed-assertion-only consumption ---------------------------------------------

async def test_only_signed_assertion_is_consumed(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    xml_str = _response_xml(
        response_id="_resp_7",
        in_response_to=request_id,
        assertion_id="_assert_7",
        name_id="safe@example.com",
    )
    root = etree.fromstring(xml_str.encode("utf-8"))
    signed_assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    _sign_element(signed_assertion, IDP_KEY)

    # Inject an unsigned, attacker-controlled assertion into the response.
    evil = etree.fromstring(
        _response_xml(
            response_id="_resp_x",
            in_response_to=request_id,
            assertion_id="_evil_assertion",
            name_id="evil@example.com",
        )
        .encode("utf-8")
    ).find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    root.append(evil)

    saml_response = base64.b64encode(etree.tostring(root)).decode("ascii")
    result = await manager.validate_response(saml_response)
    # The consumed assertion MUST be the signed one, never the injected one.
    assert result["name_id"] == "safe@example.com"
    assert result["name_id"] != "evil@example.com"


async def test_tampered_signed_assertion_rejected(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    xml_str = _response_xml(
        response_id="_resp_8", in_response_to=request_id, assertion_id="_assert_8"
    )
    root = etree.fromstring(xml_str.encode("utf-8"))
    assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    _sign_element(assertion, IDP_KEY)

    # Tamper with the NameID after signing -> digest mismatch.
    name_id_el = assertion.find(
        "{urn:oasis:names:tc:SAML:2.0:assertion}Subject/"
        "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
    )
    name_id_el.text = "attacker@example.com"

    saml_response = base64.b64encode(etree.tostring(root)).decode("ascii")
    with pytest.raises(ValueError):
        await manager.validate_response(saml_response)


# -- SubjectConfirmation --------------------------------------------------------------

async def test_subject_confirmation_recipient_mismatch_rejected(saml_stack):
    manager, _db = saml_stack
    request_id = await _start(manager)
    saml_response = _signed_response_b64(
        response_id="_resp_9",
        in_response_to=request_id,
        assertion_id="_assert_9",
        recipient="https://evil.example.com/acs",
    )
    with pytest.raises(ValueError, match="SubjectConfirmation"):
        await manager.validate_response(saml_response)


# -- metadata + constructor ---------------------------------------------------------------

async def test_metadata_authn_requests_signed_flag(saml_stack):
    manager, _db = saml_stack
    metadata_unsigned = manager.generate_metadata()
    assert 'AuthnRequestsSigned="false"' in metadata_unsigned

    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    sp_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    manager.config.sp_private_key = sp_key
    metadata_signed = manager.generate_metadata()
    assert 'AuthnRequestsSigned="true"' in metadata_signed


def test_constructor_requires_db_and_cache():
    config = SAMLConfig(
        sp_entity_id=SP_ENTITY_ID, acs_url=ACS_URL, slo_url=SLO_URL
    )
    with pytest.raises(ConfigError):
        SAMLManager(config, None, InMemoryCache())
    with pytest.raises(ConfigError):
        SAMLManager(config, InMemoryDatabase(), None)
