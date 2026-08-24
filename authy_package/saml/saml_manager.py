"""SAML 2.0 Service Provider (hardened).

Security model in this revision:

- The xmlsec ``Signature`` is verified and its ``Reference URI`` must match
  the ``ID`` of the assertion that is consumed; **only that signed
  assertion** is parsed (all XPath lookups are anchored under it).
- ``AudienceRestriction`` is mandatory and must contain ``sp_entity_id``;
  a missing ``AudienceRestriction`` is a rejection.
- ``InResponseTo`` is consumed atomically via the db contract
  (``consume_saml_request``) — a response can only answer an outstanding,
  un-consumed AuthnRequest.
- Response/assertion IDs go through a replay ledger
  (``db.check_and_record_saml_response_id``).
- ``SubjectConfirmation`` is validated (Recipient, NotOnOrAfter,
  InResponseTo).
- AuthnRequests are signed when an SP private key is configured, and the
  metadata ``AuthnRequestsSigned`` flag reflects that.
- SLO responses are signature-verified when the IdP certificate is present.
- The constructor raises :class:`ConfigError` when required collaborators
  (cache/db) are missing instead of failing mid-flow.
"""

from __future__ import annotations

import base64
import logging
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from authy_package.errors import ConfigError

logger = logging.getLogger("authy.saml")

__all__ = ["SAMLManager", "SAMLConfig"]

try:  # §0.9 lazy heavy deps
    from lxml import etree as _lxml_etree

    LXML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _lxml_etree = None
    LXML_AVAILABLE = False

try:
    import xmlsec as _xmlsec

    XMLSEC_AVAILABLE = True
except ImportError:  # pragma: no cover
    _xmlsec = None
    XMLSEC_AVAILABLE = False

NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

_NS = {"md": NS_MD, "saml": NS_SAML, "samlp": NS_SAMLP, "ds": NS_DS}

_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def _require_lxml():
    if not LXML_AVAILABLE:
        raise ImportError(
            "SAML support requires the 'lxml' package; install authy-package "
            "with the 'saml' extra"
        )
    return _lxml_etree


def _require_xmlsec():
    if not XMLSEC_AVAILABLE:
        raise ImportError(
            "SAML signature handling requires the 'xmlsec' package; install "
            "authy-package with the 'saml' extra"
        )
    return _xmlsec


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_instant(value: Optional[str]) -> Optional[datetime]:
    """Parse a SAML timestamp into a timezone-aware datetime."""
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class SAMLConfig:
    """Configuration for the SAML Service Provider."""

    def __init__(
        self,
        sp_entity_id: str,
        acs_url: str,
        slo_url: str,
        name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        certificate_path: Optional[str] = None,
        private_key_path: Optional[str] = None,
        idp_metadata_url: Optional[str] = None,
        idp_entity_id: Optional[str] = None,
        idp_sso_url: Optional[str] = None,
        idp_slo_url: Optional[str] = None,
        idp_certificate_path: Optional[str] = None,
        certificate: Optional[Any] = None,
        private_key: Optional[Any] = None,
        idp_certificate: Optional[Any] = None,
        allow_create: bool = True,
        force_authn: bool = False,
        requested_authn_context: Optional[List[str]] = None,
        clock_skew_seconds: int = 300,
        assertion_lifetime_seconds: int = 300,
        request_ttl_seconds: int = 300,
    ):
        """Initialize SAML configuration.

        Certificates/keys may be supplied as already-loaded cryptography
        objects (``certificate`` / ``private_key`` / ``idp_certificate``)
        or as PEM file paths (``*_path`` variants).
        """
        if not sp_entity_id or not acs_url or not slo_url:
            raise ConfigError(
                "sp_entity_id, acs_url and slo_url are required for SAML"
            )
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.slo_url = slo_url
        self.name_id_format = name_id_format
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.idp_metadata_url = idp_metadata_url
        self.idp_entity_id = idp_entity_id
        self.idp_sso_url = idp_sso_url
        self.idp_slo_url = idp_slo_url
        self.idp_certificate_path = idp_certificate_path
        self.allow_create = allow_create
        self.force_authn = force_authn
        self.requested_authn_context = requested_authn_context or [
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        ]
        self.clock_skew_seconds = clock_skew_seconds
        self.assertion_lifetime_seconds = assertion_lifetime_seconds
        self.request_ttl_seconds = request_ttl_seconds

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        def _load_cert(path: Optional[str], obj: Optional[Any]) -> Optional[Any]:
            if obj is not None:
                return obj
            if path:
                with open(path, "rb") as handle:
                    return x509.load_pem_x509_certificate(handle.read())
            return None

        def _load_key(path: Optional[str], obj: Optional[Any]) -> Optional[Any]:
            if obj is not None:
                return obj
            if path:
                with open(path, "rb") as handle:
                    return serialization.load_pem_private_key(handle.read(), password=None)
            return None

        self.sp_certificate = _load_cert(certificate_path, certificate)
        self.sp_private_key = _load_key(private_key_path, private_key)
        self.idp_certificate = _load_cert(idp_certificate_path, idp_certificate)

    @staticmethod
    def load_certificate_from_pem(pem_str: str) -> Any:
        """Load an X.509 certificate from a PEM string."""
        from cryptography import x509

        return x509.load_pem_x509_certificate(pem_str.encode())

    @property
    def sign_authn_requests(self) -> bool:
        """True when AuthnRequests will be signed (SP key configured)."""
        return self.sp_private_key is not None


class SAMLManager:
    """SAML 2.0 Service Provider manager.

    Args:
        config: :class:`SAMLConfig`.
        database: §4 database adapter (request consume, replay ledger,
            sessions, JIT users). Required.
        cache: §3 cache adapter. Required.
    """

    def __init__(self, config: SAMLConfig, database: Any, cache: Any):
        if config is None:
            raise ConfigError("SAMLManager requires a SAMLConfig")
        if database is None:
            raise ConfigError("SAMLManager requires a database adapter")
        if cache is None:
            raise ConfigError("SAMLManager requires a cache adapter")
        self.config = config
        self.db = database
        self.cache = cache

    # -- XML helpers ----------------------------------------------------------

    def _parse_xml(self, xml_str: str) -> Any:
        """Parse XML with a hardened parser (no entities, no network)."""
        etree = _require_lxml()
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            huge_tree=False,
        )
        try:
            return etree.fromstring(xml_str.encode("utf-8"), parser=parser)
        except Exception as exc:
            raise ValueError(f"Invalid XML: {exc}") from exc

    # -- metadata -----------------------------------------------------------------

    def generate_metadata(self) -> str:
        """Generate SP metadata XML.

        ``AuthnRequestsSigned`` truthfully reflects whether the SP private
        key is configured.
        """
        import xml.etree.ElementTree as ET

        etree = _require_lxml()
        root = ET.Element(
            "md:EntityDescriptor",
            {
                "xmlns:md": NS_MD,
                "entityID": self.config.sp_entity_id,
                "validUntil": (_utcnow() + timedelta(days=365)).isoformat(),
            },
        )
        sp_sso_descriptor = ET.SubElement(
            root,
            "md:SPSSODescriptor",
            {
                "protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequestsSigned": "true" if self.config.sign_authn_requests else "false",
                "WantAssertionsSigned": "true",
            },
        )
        name_id_format = ET.SubElement(sp_sso_descriptor, "md:NameIDFormat")
        name_id_format.text = self.config.name_id_format
        ET.SubElement(
            sp_sso_descriptor,
            "md:AssertionConsumerService",
            {
                "index": "1",
                "isDefault": "true",
                "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "Location": self.config.acs_url,
            },
        )
        ET.SubElement(
            sp_sso_descriptor,
            "md:SingleLogoutService",
            {
                "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                "Location": self.config.slo_url,
            },
        )

        if self.config.sp_certificate:
            from cryptography.hazmat.primitives import serialization

            key_descriptor = ET.SubElement(
                sp_sso_descriptor, "md:KeyDescriptor", {"use": "signing"}
            )
            key_info = ET.SubElement(
                key_descriptor, "ds:KeyInfo", {"xmlns:ds": NS_DS}
            )
            x509_data = ET.SubElement(key_info, "ds:X509Data")
            x509_cert = ET.SubElement(x509_data, "ds:X509Certificate")
            cert_bytes = self.config.sp_certificate.public_bytes(
                serialization.Encoding.DER
            )
            x509_cert.text = base64.b64encode(cert_bytes).decode("utf-8")

        xml_str = ET.tostring(root, encoding="unicode")
        parsed = etree.fromstring(xml_str.encode())
        return etree.tostring(parsed, pretty_print=True, encoding="unicode")

    async def load_idp_metadata(self, metadata_url: str) -> Dict[str, Any]:
        """Fetch and parse IdP metadata from a URL."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url) as response:
                if response.status != 200:
                    raise ValueError(
                        f"Failed to fetch IdP metadata: {response.status}"
                    )
                metadata_xml = await response.text()
        return self._parse_idp_metadata(metadata_xml)

    def _parse_idp_metadata(self, metadata_xml: str) -> Dict[str, Any]:
        """Parse IdP metadata XML into a configuration dict."""
        etree = _require_lxml()
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, load_dtd=False
        )
        root = etree.fromstring(metadata_xml.encode(), parser=parser)

        if root.tag == f"{{{NS_MD}}}EntityDescriptor":
            entity_descriptor = root
        else:
            entity_descriptor = root.find(".//md:EntityDescriptor", namespaces=_NS)
        if entity_descriptor is None:
            raise ValueError("Invalid IdP metadata: no EntityDescriptor found")

        idp_entity_id = entity_descriptor.get("entityID")
        idp_sso_desc = entity_descriptor.find(".//md:IDPSSODescriptor", namespaces=_NS)
        if idp_sso_desc is None:
            raise ValueError("Invalid IdP metadata: no IDPSSODescriptor found")

        sso_service = idp_sso_desc.find(
            './/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
            namespaces=_NS,
        )
        slo_service = idp_sso_desc.find(
            './/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]',
            namespaces=_NS,
        )
        cert_elem = idp_sso_desc.find(".//ds:X509Certificate", namespaces=_NS)

        idp_certificate = None
        if cert_elem is not None and cert_elem.text:
            cert_pem = (
                "-----BEGIN CERTIFICATE-----\n"
                f"{cert_elem.text.strip()}\n"
                "-----END CERTIFICATE-----"
            )
            idp_certificate = self.config.load_certificate_from_pem(cert_pem)

        return {
            "entity_id": idp_entity_id,
            "sso_url": sso_service.get("Location") if sso_service is not None else None,
            "slo_url": slo_service.get("Location") if slo_service is not None else None,
            "certificate": idp_certificate,
        }

    # -- AuthnRequest --------------------------------------------------------------

    def _sign_element(self, root_element: Any) -> None:
        """Enveloped-sign an element carrying an ``ID`` attribute."""
        xmlsec = _require_xmlsec()
        from cryptography.hazmat.primitives import serialization

        element_id = root_element.get("ID")
        if not element_id:
            raise ValueError("Cannot sign an element without an ID attribute")

        signature_template = xmlsec.template.create(
            root_element,
            c14n_method=xmlsec.Transform.EXCL_C14N,
            sign_method=xmlsec.Transform.RSA_SHA256,
        )
        root_element.append(signature_template)
        reference = xmlsec.template.add_reference(
            signature_template, xmlsec.Transform.SHA256, uri=f"#{element_id}"
        )
        xmlsec.template.add_transform(reference, xmlsec.Transform.ENVELOPED)
        if self.config.sp_certificate is not None:
            key_info = xmlsec.template.ensure_key_info(signature_template)
            x509_data = xmlsec.template.add_x509_data(key_info)
            xmlsec.template.x509_data_add_certificate(x509_data)

        private_pem = self.config.sp_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key = xmlsec.Key.from_memory(private_pem, xmlsec.KeyFormat.PEM)
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        ctx.register_id(root_element, id_attr="ID")
        ctx.sign(signature_template)

    async def create_auth_request(
        self, relay_state: Optional[str] = None
    ) -> Tuple[str, str]:
        """Create (and persist) an AuthnRequest.

        Returns ``(redirect_url, request_id)``. The request is signed when
        an SP private key is configured.
        """
        import xml.etree.ElementTree as ET

        if not self.config.idp_sso_url:
            raise ValueError(
                "IdP SSO URL is not configured. Set idp_sso_url in SAMLConfig."
            )

        request_id = f"_request_{secrets.token_hex(16)}"
        now = _utcnow()

        root = ET.Element(
            "samlp:AuthnRequest",
            {
                "xmlns:samlp": NS_SAMLP,
                "xmlns:saml": NS_SAML,
                "ID": request_id,
                "Version": "2.0",
                "IssueInstant": now.isoformat(),
                "Destination": self.config.idp_sso_url,
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "AssertionConsumerServiceURL": self.config.acs_url,
                "ForceAuthn": str(self.config.force_authn).lower(),
                "IsPassive": "false",
            },
        )
        issuer = ET.SubElement(root, "saml:Issuer")
        issuer.text = self.config.sp_entity_id
        ET.SubElement(
            root,
            "samlp:NameIDPolicy",
            {
                "Format": self.config.name_id_format,
                "AllowCreate": str(self.config.allow_create).lower(),
            },
        )
        if self.config.requested_authn_context:
            authn_context = ET.SubElement(
                root, "samlp:RequestedAuthnContext", {"Comparison": "exact"}
            )
            for context_class in self.config.requested_authn_context:
                context = ET.SubElement(authn_context, "saml:AuthnContextClassRef")
                context.text = context_class

        xml_str = ET.tostring(root, encoding="unicode")

        if self.config.sign_authn_requests:
            etree = _require_lxml()
            signed_root = etree.fromstring(xml_str.encode("utf-8"))
            self._sign_element(signed_root)
            xml_str = etree.tostring(signed_root, encoding="unicode")

        # Raw DEFLATE for the HTTP-Redirect binding.
        compressor = zlib.compressobj(wbits=-15)
        deflated = compressor.compress(xml_str.encode("utf-8")) + compressor.flush()
        encoded = base64.b64encode(deflated).decode("utf-8")

        params = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state
        redirect_url = f"{self.config.idp_sso_url}?{urlencode(params)}"

        # Persist outstanding request state (§4 SAML ledger).
        await self.db.save_saml_request(
            request_id,
            {
                "issue_instant": now.isoformat(),
                "relay_state": relay_state,
            },
            ttl_seconds=self.config.request_ttl_seconds,
        )
        return redirect_url, request_id


    # -- signature verification ---------------------------------------------------

    def _verify_signature(self, sig_node: Any, certificate: Any) -> None:
        """Verify one ds:Signature node against a certificate (xmlsec).

        Raises:
            ValueError: When the signature does not verify.
        """
        xmlsec = _require_xmlsec()
        from cryptography.hazmat.primitives import serialization

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_memory(
            certificate.public_bytes(serialization.Encoding.PEM),
            xmlsec.KeyFormat.CERT_PEM,
        )
        # Register ID attributes so Reference URIs (#ID) resolve.
        node = sig_node.getparent()
        while node is not None:
            if node.get("ID"):
                ctx.register_id(node, id_attr="ID")
            node = node.getparent()
        try:
            ctx.verify(sig_node)
        except Exception as exc:
            raise ValueError(f"Signature verification failed: {exc}") from exc

    def _verify_and_extract_signed_assertion(self, root: Any) -> Any:
        """Verify signatures and return the signed Assertion to consume.

        The Reference URI of a verified Signature must match the ID of the
        assertion; only that element is returned and consumed. Signatures
        whose reference points elsewhere (or fails verification) are
        rejected.
        """
        if self.config.idp_certificate is None:
            raise ValueError(
                "SAML response validation requires an IdP certificate"
            )

        signatures = root.findall(f".//{{{NS_DS}}}Signature")
        if not signatures:
            raise ValueError("No signature found in SAML response")

        last_error: Optional[str] = None
        for sig_node in signatures:
            reference = sig_node.find(f"./{{{NS_DS}}}SignedInfo/{{{NS_DS}}}Reference")
            if reference is None:
                last_error = "Signature has no Reference"
                continue
            uri = reference.get("URI") or ""
            if not uri.startswith("#"):
                last_error = "Signature Reference URI does not point to an element"
                continue
            referenced_id = uri[1:]

            # XPath injection guard: parameterized lookup.
            candidates = root.xpath(".//*[@ID=$ref_id]", ref_id=referenced_id)
            if len(candidates) != 1:
                last_error = f"Signature Reference URI {uri!r} matches no unique element"
                continue
            target = candidates[0]
            if target.tag != f"{{{NS_SAML}}}Assertion":
                last_error = "Signature Reference URI does not reference an Assertion"
                continue

            try:
                self._verify_signature(sig_node, self.config.idp_certificate)
            except ValueError as exc:
                last_error = str(exc)
                continue
            return target

        raise ValueError(
            f"No valid signed assertion found in SAML response ({last_error})"
        )

    # -- response validation ---------------------------------------------------------

    async def validate_response(
        self, saml_response: str, relay_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate a SAML Response and return the authenticated identity.

        Raises:
            ValueError: On any validation failure (signature, audience,
                InResponseTo, replay, timing, subject confirmation...).
        """
        try:
            decoded_xml = base64.b64decode(saml_response).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Invalid base64 encoding: {exc}") from exc

        root = self._parse_xml(decoded_xml)

        # 1. Signature: verify and select the signed assertion to consume.
        assertion = self._verify_and_extract_signed_assertion(root)

        # 1b. Assertion-ID replay ledger (review NEW-2): a captured signed
        # assertion re-wrapped in a fresh Response must not be accepted twice.
        assertion_id = assertion.get("ID")
        if assertion_id:
            fresh_assertion = await self.db.check_and_record_saml_response_id(
                f"assertion:{assertion_id}"
            )
            if not fresh_assertion:
                raise ValueError(
                    f"SAML assertion {assertion_id!r} was already consumed "
                    "(signed assertion replayed inside a fresh response)"
                )

        # 2. Response-level checks.
        response_id = root.get("ID")
        if response_id:
            fresh = await self.db.check_and_record_saml_response_id(response_id)
            if not fresh:
                raise ValueError(
                    f"SAML response {response_id!r} was already consumed (replay)"
                )

        status = root.find(".//samlp:Status/samlp:StatusCode", namespaces=_NS)
        if status is None or status.get("Value") != _STATUS_SUCCESS:
            raise ValueError("SAML response status is not Success")

        destination = root.get("Destination")
        if destination and destination != self.config.acs_url:
            raise ValueError("Invalid SAML response destination")

        in_response_to = root.get("InResponseTo")
        if not in_response_to:
            raise ValueError("Missing InResponseTo in SAML response")
        request_data = await self.db.consume_saml_request(in_response_to)
        if request_data is None:
            raise ValueError(
                "SAML response InResponseTo does not match any outstanding "
                "AuthnRequest (unknown, expired or already consumed)"
            )

        # 3. Assertion checks — everything anchored under the signed node.
        issuer_elem = assertion.find("saml:Issuer", namespaces=_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None
        if self.config.idp_entity_id and issuer != self.config.idp_entity_id:
            raise ValueError("Assertion issuer does not match the IdP entity ID")

        self._validate_conditions(assertion)
        subject = self._validate_subject(assertion, in_response_to)

        # 4. Attributes from the signed assertion only.
        attributes = self._extract_attributes(assertion)
        user = await self._provision_user(attributes, subject)

        session_id = await self._create_saml_session(
            user=user,
            subject=subject,
            issuer=issuer,
            request_id=in_response_to,
            relay_state=relay_state,
        )
        return {
            "user": user,
            "session_id": session_id,
            "attributes": attributes,
            "name_id": subject["name_id"],
            "session_index": subject["session_index"],
        }

    def _validate_conditions(self, assertion: Any) -> None:
        """Timing + mandatory audience validation on the signed assertion."""
        now = _utcnow()
        skew = timedelta(seconds=self.config.clock_skew_seconds)

        conditions_elem = assertion.find("saml:Conditions", namespaces=_NS)
        if conditions_elem is not None:
            not_before = _parse_instant(conditions_elem.get("NotBefore"))
            if not_before is not None and now < not_before - skew:
                raise ValueError("Assertion is not yet valid (NotBefore)")
            not_on_or_after = _parse_instant(conditions_elem.get("NotOnOrAfter"))
            if not_on_or_after is not None and now >= not_on_or_after + skew:
                raise ValueError("Assertion has expired (NotOnOrAfter)")

        audience_nodes = assertion.findall(
            "saml:Conditions/saml:AudienceRestriction/saml:Audience",
            namespaces=_NS,
        )
        restriction = assertion.find(
            "saml:Conditions/saml:AudienceRestriction", namespaces=_NS
        )
        if restriction is None:
            raise ValueError(
                "Assertion is missing AudienceRestriction; rejecting"
            )
        audiences = [node.text for node in audience_nodes if node.text]
        if self.config.sp_entity_id not in audiences:
            raise ValueError(
                "SAML audience does not include this service provider"
            )

    def _validate_subject(self, assertion: Any, in_response_to: str) -> Dict[str, Any]:
        """Validate Subject/SubjectConfirmation and return subject data."""
        subject_elem = assertion.find("saml:Subject", namespaces=_NS)
        if subject_elem is None:
            raise ValueError("Assertion is missing a Subject")
        name_id_elem = subject_elem.find("saml:NameID", namespaces=_NS)
        if name_id_elem is None or not name_id_elem.text:
            raise ValueError("Missing NameID in subject")

        now = _utcnow()
        skew = timedelta(seconds=self.config.clock_skew_seconds)
        confirmations = subject_elem.findall(
            "saml:SubjectConfirmation", namespaces=_NS
        )
        confirmed = False
        for confirmation in confirmations:
            if confirmation.get("Method") != _BEARER:
                continue
            data = confirmation.find("saml:SubjectConfirmationData", namespaces=_NS)
            if data is None:
                continue
            recipient = data.get("Recipient")
            if recipient and recipient != self.config.acs_url:
                continue
            not_on_or_after = _parse_instant(data.get("NotOnOrAfter"))
            if not_on_or_after is not None and now >= not_on_or_after + skew:
                continue
            sc_in_response_to = data.get("InResponseTo")
            if sc_in_response_to and sc_in_response_to != in_response_to:
                continue
            confirmed = True
            break
        if not confirmed:
            raise ValueError(
                "No valid bearer SubjectConfirmation (Recipient/NotOnOrAfter/"
                "InResponseTo checks failed)"
            )

        authn_statement = assertion.find("saml:AuthnStatement", namespaces=_NS)
        return {
            "name_id": name_id_elem.text,
            "name_id_format": name_id_elem.get("Format"),
            "session_index": authn_statement.get("SessionIndex")
            if authn_statement is not None
            else None,
        }

    def _extract_attributes(self, assertion: Any) -> Dict[str, Any]:
        """Extract attribute statements from the signed assertion only."""
        attributes: Dict[str, Any] = {}
        attr_stmt = assertion.find(".//saml:AttributeStatement", namespaces=_NS)
        if attr_stmt is None:
            return attributes
        for attr in attr_stmt.findall("saml:Attribute", namespaces=_NS):
            attr_name = attr.get("Name")
            values = [
                value.text.strip()
                for value in attr.findall("saml:AttributeValue", namespaces=_NS)
                if value.text
            ]
            if len(values) == 1:
                attributes[attr_name] = values[0]
            elif len(values) > 1:
                attributes[attr_name] = values
        return attributes

    # -- provisioning / session --------------------------------------------------------

    async def _provision_user(
        self, attributes: Dict[str, Any], subject: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Just-in-time user provisioning from signed attributes."""
        email = (
            attributes.get("email")
            or attributes.get("mail")
            or attributes.get("EmailAddress")
        )
        name_id = subject.get("name_id")

        if email:
            user = await self.db.get_user_by_identifier(email=email)
            if user:
                return user

        if not self.config.allow_create:
            raise ValueError(
                "User does not exist and JIT provisioning is disabled"
            )

        username = (
            attributes.get("uid")
            or attributes.get("username")
            or (email.split("@")[0] if email else None)
            or name_id
        )
        user_data = {
            "email": email,
            "username": username,
            "full_name": attributes.get("displayName")
            or attributes.get("cn")
            or attributes.get("fullName"),
            "first_name": attributes.get("givenName")
            or attributes.get("firstName"),
            "last_name": attributes.get("sn") or attributes.get("lastName"),
            "phone": attributes.get("mobile")
            or attributes.get("telephoneNumber"),
            "saml_subject": name_id,
            "idp_entity_id": self.config.idp_entity_id,
            "auth_method": "saml",
        }
        user_data = {k: v for k, v in user_data.items() if v is not None}
        created = await self.db.create_user(user_data)
        return created

    async def _create_saml_session(
        self,
        *,
        user: Dict[str, Any],
        subject: Dict[str, Any],
        issuer: Optional[str],
        request_id: Optional[str],
        relay_state: Optional[str],
    ) -> str:
        """Persist a session through the db contract (§4 save_session)."""
        session_id = f"saml_session_{secrets.token_hex(32)}"
        session_data = {
            "id": session_id,
            "user_id": str(user.get("id") or subject["name_id"]),
            "status": "active",
            "request_id": request_id,
            "name_id": subject["name_id"],
            "session_index": subject["session_index"],
            "idp_entity_id": issuer,
            "authenticated_at": _utcnow().isoformat(),
            "relay_state": relay_state,
            "auth_method": "saml",
        }
        await self.db.save_session(session_data)
        return session_id

    # -- logout -------------------------------------------------------------------------

    def create_logout_request(self, name_id: str, session_index: str) -> str:
        """Create a LogoutRequest redirect URL for the IdP."""
        import xml.etree.ElementTree as ET

        if not self.config.idp_slo_url:
            raise ValueError(
                "IdP SLO URL is not configured. Set idp_slo_url in SAMLConfig."
            )

        request_id = f"_logout_request_{secrets.token_hex(16)}"
        root = ET.Element(
            "samlp:LogoutRequest",
            {
                "xmlns:samlp": NS_SAMLP,
                "xmlns:saml": NS_SAML,
                "ID": request_id,
                "Version": "2.0",
                "IssueInstant": _utcnow().isoformat(),
                "Destination": self.config.idp_slo_url,
            },
        )
        issuer = ET.SubElement(root, "saml:Issuer")
        issuer.text = self.config.sp_entity_id
        name_id_elem = ET.SubElement(
            root, "saml:NameID", {"Format": self.config.name_id_format}
        )
        name_id_elem.text = name_id
        session_index_elem = ET.SubElement(root, "samlp:SessionIndex")
        session_index_elem.text = session_index

        xml_str = ET.tostring(root, encoding="unicode")
        compressor = zlib.compressobj(wbits=-15)
        deflated = compressor.compress(xml_str.encode("utf-8")) + compressor.flush()
        encoded = base64.b64encode(deflated).decode("utf-8")
        return f"{self.config.idp_slo_url}?{urlencode({'SAMLRequest': encoded})}"

    async def handle_logout_response(self, saml_response: str) -> bool:
        """Handle an IdP LogoutResponse.

        The signature is verified when the IdP certificate is configured
        (and a missing signature then fails).
        """
        try:
            decoded_xml = base64.b64decode(saml_response).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Invalid base64 encoding: {exc}") from exc
        root = self._parse_xml(decoded_xml)

        if self.config.idp_certificate:
            sig_node = root.find(f".//{{{NS_DS}}}Signature")
            if sig_node is None:
                raise ValueError("LogoutResponse is not signed")
            self._verify_signature(sig_node, self.config.idp_certificate)

        status = root.find(".//samlp:Status/samlp:StatusCode", namespaces=_NS)
        if status is None or status.get("Value") != _STATUS_SUCCESS:
            return False
        return True
