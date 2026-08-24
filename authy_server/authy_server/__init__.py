"""
Authy Identity Server v3.0.0

Enterprise-grade Identity and Access Management platform.
Competitor to Keycloak, Okta, and Auth0.

Protocols:
- OpenID Connect 1.0 (certification compliant)
- OAuth 2.1 with PKCE
- SAML 2.0 (SP and IdP)
- SCIM 2.0

Features:
- Multi-tenancy with organizations
- Advanced RBAC
- Comprehensive audit logging
- FAPI security profile
- Horizontal scaling
"""

__version__ = "3.0.0"
__author__ = "Authy Team"

from authy_server.main import app

__all__ = ["app", "__version__"]
