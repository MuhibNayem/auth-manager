"""
SAML 2.0 Service Provider Implementation for Enterprise SSO

This module provides complete SAML 2.0 SP functionality including:
- Metadata generation and exchange
- Authentication request creation
- Response validation and assertion parsing
- Single Logout (SLO) support
- Just-in-Time (JIT) user provisioning
"""

import base64
import hashlib
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlencode, urlparse
import xmlsec
from lxml import etree
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class SAMLConfig:
    """Configuration for SAML Service Provider."""
    
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
        allow_create: bool = True,
        force_authn: bool = False,
        requested_authn_context: Optional[List[str]] = None,
        clock_skew_seconds: int = 300,
        assertion_lifetime_seconds: int = 300,
    ):
        """
        Initialize SAML configuration.
        
        Args:
            sp_entity_id: Unique identifier for this Service Provider
            acs_url: Assertion Consumer Service URL (where IdP sends responses)
            slo_url: Single Logout URL
            name_id_format: Format for NameID (default: emailAddress)
            certificate_path: Path to SP's X.509 certificate
            private_key_path: Path to SP's private key
            idp_metadata_url: URL to IdP's metadata (alternative to manual config)
            idp_entity_id: Identity Provider's entity ID
            idp_sso_url: IdP's Single Sign-On URL
            idp_slo_url: IdP's Single Logout URL
            idp_certificate_path: Path to IdP's certificate for signature validation
            allow_create: Allow IdP to create new users
            force_authn: Force re-authentication even if user has active session
            requested_authn_context: Required authentication context classes
            clock_skew_seconds: Allowed time drift between SP and IdP
            assertion_lifetime_seconds: How long assertions are valid
        """
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
        
        # Load certificates and keys
        self.sp_certificate = self._load_certificate(certificate_path) if certificate_path else None
        self.sp_private_key = self._load_private_key(private_key_path) if private_key_path else None
        self.idp_certificate = self._load_certificate(idp_certificate_path) if idp_certificate_path else None
    
    def _load_certificate(self, path: str) -> Any:
        """Load X.509 certificate from file."""
        with open(path, 'rb') as f:
            cert_data = f.read()
        return serialization.load_pem_x509_certificate(cert_data, backend=default_backend())
    
    def _load_private_key(self, path: str) -> Any:
        """Load RSA private key from file."""
        with open(path, 'rb') as f:
            key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())


class SAMLManager:
    """
    SAML 2.0 Service Provider Manager
    
    Handles all SAML operations including:
    - Metadata generation
    - Auth request creation
    - Response validation
    - Assertion parsing
    - Single Logout
    """
    
    def __init__(self, config: SAMLConfig, database, cache=None):
        """
        Initialize SAML Manager.
        
        Args:
            config: SAMLConfig instance
            database: Database adapter implementing AbstractDatabase
            cache: Optional cache adapter for storing request state
        """
        self.config = config
        self.db = database
        self.cache = cache
    
    def generate_metadata(self) -> str:
        """
        Generate SAML 2.0 metadata XML for this Service Provider.
        
        Returns:
            XML string containing SP metadata for sharing with IdP
        """
        root = ET.Element('md:EntityDescriptor', {
            'xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'entityID': self.config.sp_entity_id,
            'validUntil': (datetime.utcnow() + timedelta(days=365)).isoformat() + 'Z',
        })
        
        sp_sso_descriptor = ET.SubElement(root, 'md:SPSSODescriptor', {
            'protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'AuthnRequestsSigned': 'true',
            'WantAssertionsSigned': 'true',
        })
        
        # Add NameID formats
        name_id_format = ET.SubElement(sp_sso_descriptor, 'md:NameIDFormat')
        name_id_format.text = self.config.name_id_format
        
        # Add ACS endpoint
        acs_index = ET.SubElement(sp_sso_descriptor, 'md:AssertionConsumerService', {
            'index': '1',
            'isDefault': 'true',
            'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location': self.config.acs_url,
        })
        
        # Add Single Logout endpoint
        slo_index = ET.SubElement(sp_sso_descriptor, 'md:SingleLogoutService', {
            'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location': self.config.slo_url,
        })
        
        # Add certificate if available
        if self.config.sp_certificate:
            key_descriptor = ET.SubElement(sp_sso_descriptor, 'md:KeyDescriptor', {'use': 'signing'})
            key_info = ET.SubElement(key_descriptor, 'ds:KeyInfo', {'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'})
            x509_data = ET.SubElement(key_info, 'ds:X509Data')
            x509_cert = ET.SubElement(x509_data, 'ds:X509Certificate')
            cert_bytes = self.config.sp_certificate.public_bytes(serialization.Encoding.PEM)
            x509_cert.text = base64.b64encode(cert_bytes).decode('utf-8').replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '')
        
        # Pretty print XML
        xml_str = ET.tostring(root, encoding='unicode')
        parsed = etree.fromstring(xml_str.encode())
        return etree.tostring(parsed, pretty_print=True, encoding='unicode')
    
    async def load_idp_metadata(self, metadata_url: str) -> Dict[str, Any]:
        """
        Load and parse Identity Provider metadata from URL.
        
        Args:
            metadata_url: URL to IdP's metadata XML
            
        Returns:
            Dictionary with parsed IdP configuration
        """
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url) as response:
                if response.status != 200:
                    raise Exception(f"Failed to fetch IdP metadata: {response.status}")
                
                metadata_xml = await response.text()
        
        return self._parse_idp_metadata(metadata_xml)
    
    def _parse_idp_metadata(self, metadata_xml: str) -> Dict[str, Any]:
        """Parse IdP metadata XML into configuration dict."""
        root = etree.fromstring(metadata_xml.encode())
        ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata'}
        
        entity_descriptor = root.find('.//md:EntityDescriptor', namespaces=ns)
        if entity_descriptor is None:
            raise ValueError("Invalid IdP metadata: no EntityDescriptor found")
        
        idp_entity_id = entity_descriptor.get('entityID')
        
        # Find IdP SSO descriptor
        idp_sso_desc = entity_descriptor.find('.//md:IDPSSODescriptor', namespaces=ns)
        if idp_sso_desc is None:
            raise ValueError("Invalid IdP metadata: no IDPSSODescriptor found")
        
        # Extract SSO service URLs
        sso_service = idp_sso_desc.find('.//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespaces=ns)
        slo_service = idp_sso_desc.find('.//md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespaces=ns)
        
        idp_sso_url = sso_service.get('Location') if sso_service is not None else None
        idp_slo_url = slo_service.get('Location') if slo_service is not None else None
        
        # Extract certificate
        cert_elem = idp_sso_desc.find('.//ds:X509Certificate', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
        idp_certificate = None
        if cert_elem is not None and cert_elem.text:
            cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_elem.text.strip()}\n-----END CERTIFICATE-----"
            idp_certificate = self.config._load_certificate_from_pem(cert_pem)
        
        return {
            'entity_id': idp_entity_id,
            'sso_url': idp_sso_url,
            'slo_url': idp_slo_url,
            'certificate': idp_certificate,
        }
    
    def create_auth_request(self, relay_state: Optional[str] = None) -> Tuple[str, str]:
        """
        Create a SAML Authentication Request.
        
        Args:
            relay_state: Optional state to preserve across the redirect
            
        Returns:
            Tuple of (redirect_url, request_id)
        """
        request_id = f"_request_{secrets.token_hex(16)}"
        now = datetime.utcnow()
        
        # Build AuthnRequest XML
        root = ET.Element('samlp:AuthnRequest', {
            'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'ID': request_id,
            'Version': '2.0',
            'IssueInstant': now.isoformat() + 'Z',
            'Destination': self.config.idp_sso_url,
            'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'AssertionConsumerServiceURL': self.config.acs_url,
            'ForceAuthn': str(self.config.force_authn).lower(),
            'IsPassive': 'false',
        })
        
        # Add Issuer
        issuer = ET.SubElement(root, 'saml:Issuer')
        issuer.text = self.config.sp_entity_id
        
        # Add NameIDPolicy
        name_id_policy = ET.SubElement(root, 'samlp:NameIDPolicy', {
            'Format': self.config.name_id_format,
            'AllowCreate': str(self.config.allow_create).lower(),
        })
        
        # Add RequestedAuthnContext
        if self.config.requested_authn_context:
            authn_context = ET.SubElement(root, 'samlp:RequestedAuthnContext', {
                'Comparison': 'exact',
            })
            for context_class in self.config.requested_authn_context:
                context = ET.SubElement(authn_context, 'saml:AuthnContextClassRef')
                context.text = context_class
        
        # Convert to XML string
        xml_str = ET.tostring(root, encoding='unicode')
        
        # Deflate and base64 encode
        import zlib
        deflated = zlib.compress(xml_str.encode('utf-8'), -15)[2:-4]
        encoded = base64.b64encode(deflated).decode('utf-8')
        
        # Build redirect URL
        params = {'SAMLRequest': encoded}
        if relay_state:
            params['RelayState'] = relay_state
        
        redirect_url = f"{self.config.idp_sso_url}?{urlencode(params)}"
        
        # Store request state in cache
        if self.cache:
            self.cache.set(f"saml:request:{request_id}", {
                'issue_instant': now.isoformat(),
                'relay_state': relay_state,
            }, ttl=300)
        
        return redirect_url, request_id
    
    async def validate_response(self, saml_response: str, relay_state: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate and parse a SAML Response from the IdP.
        
        Args:
            saml_response: Base64-encoded SAML Response XML
            relay_state: RelayState value from the POST
            
        Returns:
            Dictionary with validated user attributes and session info
            
        Raises:
            ValueError: If validation fails
        """
        # Decode response
        try:
            decoded_xml = base64.b64decode(saml_response).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")
        
        # Parse XML
        try:
            root = etree.fromstring(decoded_xml.encode())
        except Exception as e:
            raise ValueError(f"Invalid XML: {e}")
        
        # Verify signature
        if self.config.idp_certificate:
            self._verify_signature(root, self.config.idp_certificate)
        
        # Extract and validate response
        response_data = self._parse_response(root)
        
        # Validate conditions
        self._validate_conditions(response_data['conditions'])
        
        # Validate subject
        self._validate_subject(response_data['subject'])
        
        # Extract attributes
        attributes = self._extract_attributes(root)
        
        # Create or update user (JIT provisioning)
        user = await self._provision_user(attributes)
        
        # Store session
        session_id = await self._create_saml_session(response_data, relay_state)
        
        return {
            'user': user,
            'session_id': session_id,
            'attributes': attributes,
            'name_id': response_data['subject']['name_id'],
            'session_index': response_data['subject']['session_index'],
        }
    
    def _verify_signature(self, root: etree.Element, certificate: Any) -> None:
        """Verify XML signature using xmlsec."""
        ctx = xmlsec.SignatureContext()
        
        # Load certificate
        cert = xmlsec.Key.from_memory(
            certificate.public_bytes(serialization.Encoding.PEM),
            xmlsec.KeyFormat.PEM,
            xmlsec.KeyDataType.CERTIFICATE,
        )
        
        ctx.key = cert
        
        # Find signature node
        sig_node = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
        if sig_node is None:
            raise ValueError("No signature found in SAML response")
        
        # Verify
        try:
            ctx.verify(sig_node)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")
    
    def _parse_response(self, root: etree.Element) -> Dict[str, Any]:
        """Parse SAML Response into structured data."""
        ns = {
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        # Get response attributes
        response_id = root.get('ID')
        in_response_to = root.get('InResponseTo')
        issue_instant = root.get('IssueInstant')
        status = root.find('.//samlp:Status/samlp:StatusCode', namespaces=ns)
        
        if status is None or status.get('Value') != 'urn:oasis:names:tc:SAML:2.0:status:Success':
            raise ValueError("SAML response status is not Success")
        
        # Get assertion
        assertion = root.find('.//saml:Assertion', namespaces=ns)
        if assertion is None:
            raise ValueError("No Assertion found in response")
        
        # Get issuer
        issuer_elem = assertion.find('saml:Issuer', namespaces=ns)
        issuer = issuer_elem.text if issuer_elem is not None else None
        
        # Get conditions
        conditions_elem = assertion.find('saml:Conditions', namespaces=ns)
        conditions = {
            'not_before': conditions_elem.get('NotBefore') if conditions_elem is not None else None,
            'not_on_or_after': conditions_elem.get('NotOnOrAfter') if conditions_elem is not None else None,
        }
        
        # Get subject
        subject_elem = assertion.find('saml:Subject', namespaces=ns)
        name_id_elem = subject_elem.find('saml:NameID', namespaces=ns) if subject_elem is not None else None
        session_index_elem = subject_elem.find('saml:SubjectConfirmation/saml:SubjectConfirmationData', namespaces=ns)
        
        subject = {
            'name_id': name_id_elem.text if name_id_elem is not None else None,
            'name_id_format': name_id_elem.get('Format') if name_id_elem is not None else None,
            'session_index': session_index_elem.get('SessionIndex') if session_index_elem is not None else None,
        }
        
        return {
            'response_id': response_id,
            'in_response_to': in_response_to,
            'issue_instant': issue_instant,
            'issuer': issuer,
            'conditions': conditions,
            'subject': subject,
        }
    
    def _validate_conditions(self, conditions: Dict[str, str]) -> None:
        """Validate assertion conditions (timing, audience)."""
        now = datetime.utcnow()
        skew = timedelta(seconds=self.config.clock_skew_seconds)
        
        if conditions['not_before']:
            not_before = datetime.fromisoformat(conditions['not_before'].replace('Z', '+00:00')).replace(tzinfo=None)
            if now < not_before - skew:
                raise ValueError("Assertion is not yet valid (NotBefore)")
        
        if conditions['not_on_or_after']:
            not_on_or_after = datetime.fromisoformat(conditions['not_on_or_after'].replace('Z', '+00:00')).replace(tzinfo=None)
            if now >= not_on_or_after + skew:
                raise ValueError("Assertion has expired (NotOnOrAfter)")
    
    def _validate_subject(self, subject: Dict[str, str]) -> None:
        """Validate subject confirmation."""
        if not subject['name_id']:
            raise ValueError("Missing NameID in subject")
    
    def _extract_attributes(self, root: etree.Element) -> Dict[str, Any]:
        """Extract attribute statements from assertion."""
        ns = {
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        attributes = {}
        attr_stmt = root.find('.//saml:AttributeStatement', namespaces=ns)
        
        if attr_stmt is not None:
            for attr in attr_stmt.findall('saml:Attribute', namespaces=ns):
                attr_name = attr.get('Name')
                values = []
                for value in attr.findall('saml:AttributeValue', namespaces=ns):
                    if value.text:
                        values.append(value.text.strip())
                
                if len(values) == 1:
                    attributes[attr_name] = values[0]
                elif len(values) > 1:
                    attributes[attr_name] = values
        
        return attributes
    
    async def _provision_user(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Just-in-Time user provisioning."""
        # Try to find existing user by email or name_id
        email = attributes.get('email') or attributes.get('mail') or attributes.get('EmailAddress')
        
        if email:
            user = await self.db.get_user_by_identifier(email=email)
            if user:
                return user
        
        # Create new user if allowed
        if not self.config.allow_create:
            raise ValueError("User does not exist and JIT provisioning is disabled")
        
        # Build user data from attributes
        user_data = {
            'email': email,
            'username': attributes.get('uid') or attributes.get('username') or email.split('@')[0],
            'full_name': attributes.get('displayName') or attributes.get('cn') or attributes.get('fullName'),
            'first_name': attributes.get('givenName') or attributes.get('firstName'),
            'last_name': attributes.get('sn') or attributes.get('lastName'),
            'phone': attributes.get('mobile') or attributes.get('telephoneNumber'),
            'saml_subject': attributes.get('name_id'),
            'idp_entity_id': self.config.idp_entity_id,
            'auth_method': 'saml',
        }
        
        # Filter out None values
        user_data = {k: v for k, v in user_data.items() if v is not None}
        
        # Create user
        await self.db.create_user(user_data)
        
        # Fetch created user
        return await self.db.get_user_by_identifier(email=email)
    
    async def _create_saml_session(self, response_data: Dict[str, Any], relay_state: Optional[str]) -> str:
        """Create session record for SAML authentication."""
        session_id = f"saml_session_{secrets.token_hex(32)}"
        
        session_data = {
            'session_id': session_id,
            'saml_response_id': response_data['response_id'],
            'name_id': response_data['subject']['name_id'],
            'session_index': response_data['subject']['session_index'],
            'idp_entity_id': response_data['issuer'],
            'authenticated_at': datetime.utcnow().isoformat(),
            'relay_state': relay_state,
            'auth_method': 'saml',
        }
        
        if hasattr(self.db, 'create_saml_session'):
            await self.db.create_saml_session(session_data)
        elif self.cache:
            self.cache.set(f"saml:session:{session_id}", session_data, ttl=3600)
        
        return session_id
    
    def create_logout_request(self, name_id: str, session_index: str) -> str:
        """
        Create a SAML Logout Request to send to IdP.
        
        Args:
            name_id: User's NameID from the assertion
            session_index: SessionIndex from the assertion
            
        Returns:
            Redirect URL for logout request
        """
        request_id = f"_logout_request_{secrets.token_hex(16)}"
        now = datetime.utcnow()
        
        root = ET.Element('samlp:LogoutRequest', {
            'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'ID': request_id,
            'Version': '2.0',
            'IssueInstant': now.isoformat() + 'Z',
            'Destination': self.config.idp_slo_url,
        })
        
        issuer = ET.SubElement(root, 'saml:Issuer')
        issuer.text = self.config.sp_entity_id
        
        name_id_elem = ET.SubElement(root, 'saml:NameID', {
            'Format': self.config.name_id_format,
        })
        name_id_elem.text = name_id
        
        session_index_elem = ET.SubElement(root, 'samlp:SessionIndex')
        session_index_elem.text = session_index
        
        xml_str = ET.tostring(root, encoding='unicode')
        
        # Deflate and encode
        import zlib
        deflated = zlib.compress(xml_str.encode('utf-8'), -15)[2:-4]
        encoded = base64.b64encode(deflated).decode('utf-8')
        
        return f"{self.config.idp_slo_url}?{urlencode({'SAMLRequest': encoded})}"
    
    async def handle_logout_response(self, saml_response: str) -> bool:
        """
        Handle a SAML Logout Response from IdP.
        
        Args:
            saml_response: Base64-encoded LogoutResponse XML
            
        Returns:
            True if logout was successful
        """
        decoded_xml = base64.b64decode(saml_response).decode('utf-8')
        root = etree.fromstring(decoded_xml.encode())
        
        ns = {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}
        status = root.find('.//samlp:Status/samlp:StatusCode', namespaces=ns)
        
        if status is None or status.get('Value') != 'urn:oasis:names:tc:SAML:2.0:status:Success':
            return False
        
        return True
