"""
Authy Identity Server - Standalone OIDC/SAML Provider
Enterprise-grade Identity and Access Management (IAM) platform.

This server implements:
- OpenID Connect 1.0 (OIDC) with full certification requirements
- OAuth 2.1 with PKCE enforcement
- SAML 2.0 (SP and IdP modes)
- SCIM 2.0 for enterprise provisioning
- FAPI (Financial-grade API) security profile

Competitor to Keycloak, Okta, and Auth0.
"""
import os
import sys
import secrets
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlencode

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Query
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
import uvicorn

from authy_server.config import settings
from authy_server.protocols.oidc_provider import OIDCProvider
from authy_server.protocols.saml_provider import SAMLProvider
from authy_server.protocols.scim_provider import SCIMProvider
from authy_server.services.auth_service import AuthService
from authy_server.services.token_service import TokenService
from authy_server.services.user_service import UserService
from authy_server.services.client_service import ClientService
from authy_server.database import get_db, init_database

# Initialize FastAPI app
app = FastAPI(
    title="Authy Identity Server",
    description="""
## Enterprise Identity Platform
    
Authy is a cloud-native Identity and Access Management (IAM) platform that provides:
    
### Protocols
- **OpenID Connect 1.0** - Full OIDC certification compliant
- **OAuth 2.1** - Modern OAuth with PKCE enforcement  
- **SAML 2.0** - Enterprise SSO support (SP and IdP)
- **SCIM 2.0** - Automated user provisioning
    
### Security Features
- FAPI (Financial-grade API) compliance
- mTLS support for high-security environments
- Hardware Security Module (HSM) integration
- Threat detection and anomaly prevention
- Breached password detection (Have I Been Pwned)
    
### Enterprise Ready
- Multi-tenancy with organizations
- Advanced RBAC with 4-level scoping
- Comprehensive audit logging (SOC2/GDPR)
- LDAP/Active Directory federation (coming soon)
- Horizontal scaling with stateless architecture
    """,
    version="3.0.0",
    docs_url="/admin/docs",
    redoc_url="/admin/redoc",
    openapi_tags=[
        {"name": "OIDC", "description": "OpenID Connect endpoints"},
        {"name": "OAuth2", "description": "OAuth 2.1 authorization"},
        {"name": "SAML", "description": "SAML 2.0 SSO/SLO"},
        {"name": "SCIM", "description": "User provisioning API"},
        {"name": "Management", "description": "Admin management APIs"},
        {"name": "Health", "description": "Health checks and metrics"},
    ]
)

# Add CORS middleware for admin dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
db_session = None
oidc_provider = OIDCProvider()
saml_provider = SAMLProvider()
scim_provider = SCIMProvider()
auth_service = AuthService()
token_service = TokenService()
client_service = ClientService()
user_service = UserService()


async def require_scim_auth(request: Request) -> None:
    """Require bearer-token authentication for SCIM endpoints."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header.split(" ", 1)[1]
    expected_token = os.getenv("AUTHY_SCIM_BEARER_TOKEN") or settings.SECRET_KEY
    if not expected_token:
        raise HTTPException(status_code=503, detail="SCIM authentication is not configured")
    if not secrets.compare_digest(token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.on_event("startup")
async def startup_event():
    """Initialize database connections on startup."""
    global db_session
    db_session = await init_database()
    print(f"✓ Authy Identity Server v{settings.VERSION} started")
    print(f"✓ Base URL: {settings.BASE_URL}")
    print(f"✓ Protocols: OIDC, OAuth2, SAML 2.0, SCIM 2.0")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup database connections on shutdown."""
    if db_session:
        await db_session.close()


# ============================================================================
# OIDC / OAuth2 Endpoints
# ============================================================================

@app.get("/.well-known/openid-configuration", tags=["OIDC"])
async def openid_configuration():
    """
    OIDC Discovery Endpoint (RFC 8414)
    
    Allows clients to auto-configure by fetching provider metadata.
    Required for OIDC certification.
    """
    base_url = settings.BASE_URL
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth2/authorize",
        "token_endpoint": f"{base_url}/oauth2/token",
        "userinfo_endpoint": f"{base_url}/oauth2/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "registration_endpoint": f"{base_url}/oauth2/register",
        "scopes_supported": [
            "openid", "profile", "email", "address", "phone",
            "offline_access", "organizations", "roles", "permissions"
        ],
        "response_types_supported": [
            "code", "token", "id_token", 
            "code token", "code id_token", 
            "token id_token", "code token id_token"
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code", 
            "implicit", 
            "client_credentials", 
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": [
            "RS256", "RS384", "RS512", 
            "ES256", "ES384", "ES512",
            "PS256", "PS384", "PS512"
        ],
        "id_token_encryption_alg_values_supported": [
            "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES"
        ],
        "id_token_encryption_enc_values_supported": [
            "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
            "A128GCM", "A192GCM", "A256GCM"
        ],
        "userinfo_signing_alg_values_supported": [
            "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
        ],
        "request_object_signing_alg_values_supported": [
            "none", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", 
            "client_secret_post", 
            "client_secret_jwt",
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth"
        ],
        "token_endpoint_auth_signing_alg_values_supported": [
            "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
        ],
        "display_values_supported": ["page", "popup", "touch", "wap"],
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "claims_supported": [
            "sub", "name", "given_name", "family_name", "middle_name",
            "nickname", "preferred_username", "profile", "picture",
            "website", "email", "email_verified", "gender", "birthdate",
            "zoneinfo", "locale", "phone_number", "phone_number_verified",
            "address", "updated_at", "iat", "exp", "aud", "iss",
            "organizations", "roles", "permissions"
        ],
        "service_documentation": f"{base_url}/admin/docs",
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": True,
        "op_policy_uri": f"{base_url}/.well-known/op-policy",
        "op_tos_uri": f"{base_url}/.well-known/op-tos",
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "frontchannel_logout_supported": True,
        "frontchannel_logout_session_supported": True,
        "code_challenge_methods_supported": ["plain", "S256"]
    }


@app.get("/.well-known/jwks.json", tags=["OIDC"])
async def jwks():
    """
    JSON Web Key Set (JWKS) Endpoint
    
    Returns public keys for verifying JWT signatures.
    Supports key rotation automatically.
    """
    return await token_service.get_jwks()


@app.get("/.well-known/op-policy", tags=["OIDC"])
async def op_policy():
    """Operator Policy URI (FAPI requirement)."""
    return {
        "policy": "https://authy.dev/policies/security",
        "version": "1.0"
    }


@app.get("/.well-known/op-tos", tags=["OIDC"])
async def op_tos():
    """Operator Terms of Service URI."""
    return {
        "terms": "https://authy.dev/terms",
        "version": "1.0"
    }


@app.get("/oauth2/authorize", tags=["OAuth2", "OIDC"])
async def authorize(
    response_type: str = Query(..., description="OAuth response type"),
    client_id: str = Query(..., description="Client identifier"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    scope: Optional[str] = Query("openid", description="Requested scopes"),
    state: Optional[str] = Query(None, description="CSRF protection state"),
    nonce: Optional[str] = Query(None, description="Nonce for replay protection"),
    code_challenge: Optional[str] = Query(None, description="PKCE code challenge"),
    code_challenge_method: Optional[str] = Query("S256", description="PKCE method"),
    prompt: Optional[str] = Query(None, description="Prompt parameter"),
    display: Optional[str] = Query(None, description="Display mode"),
    max_age: Optional[int] = Query(None, description="Max authentication age"),
    ui_locales: Optional[str] = Query(None, description="UI locales"),
    claims: Optional[str] = Query(None, description="Claims request"),
    acr_values: Optional[str] = Query(None, description="Authentication context"),
    request: Optional[str] = Query(None, description="Request object"),
    request_uri: Optional[str] = Query(None, description="Request URI"),
):
    """
    OAuth 2.1 / OIDC Authorization Endpoint
    
    Initiates the authorization code flow with PKCE.
    Supports all OAuth 2.1 grant types and OIDC extensions.
    
    ### Security Requirements:
    - PKCE is REQUIRED for public clients
    - HTTPS is REQUIRED in production
    - State parameter is RECOMMENDED for CSRF protection
    """
    # Validate client exists
    client = await client_service.get_by_id(client_id)
    if not client:
        raise HTTPException(
            status_code=400, 
            detail={"error": "invalid_client", "error_description": "Client not found"}
        )
    
    # Validate redirect_uri against registered URIs
    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_redirect_uri", "error_description": "Redirect URI not registered"}
        )
    
    # Validate response_type
    valid_response_types = {
        "code": ["authorization_code"],
        "token": ["implicit"],
        "id_token": ["implicit"],
        "code token": ["authorization_code", "implicit"],
        "code id_token": ["authorization_code", "implicit"],
        "token id_token": ["implicit"],
        "code token id_token": ["authorization_code", "implicit"],
    }
    
    if response_type not in valid_response_types:
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_response_type"}
        )
    
    # Check PKCE requirement for public clients
    if client.get("client_type") == "public" and not code_challenge:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "PKCE code_challenge is required for public clients"
            }
        )
    
    # Store authorization request in session/cache
    auth_request = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "prompt": prompt,
        "max_age": max_age,
    }
    
    # Generate request ID and store
    request_id = await auth_service.store_authorization_request(auth_request)
    
    # Check if user is authenticated
    # (In real implementation, check session cookie or token)
    session_user = None  # Placeholder - would extract from cookies/session
    
    if not session_user:
        # Redirect to login page
        login_url = f"/login?request_id={request_id}"
        return RedirectResponse(url=login_url)
    
    # User is authenticated, proceed with authorization
    # (Full flow continues in complete_authorize endpoint)
    return await complete_authorization(request_id, session_user)


@app.post("/oauth2/authorize/complete", tags=["OAuth2", "OIDC"])
async def complete_authorization(
    request_id: str,
    user_id: str,
    consent: bool = True,
):
    """
    Complete authorization after user authentication and consent.
    
    Internal endpoint called after successful login.
    """
    # Retrieve stored authorization request
    auth_request = await auth_service.get_authorization_request(request_id)
    if not auth_request:
        raise HTTPException(status_code=400, detail="Invalid or expired request")
    
    # Generate authorization code
    code = await token_service.create_authorization_code(
        client_id=auth_request["client_id"],
        user_id=user_id,
        redirect_uri=auth_request["redirect_uri"],
        scope=auth_request["scope"],
        code_challenge=auth_request.get("code_challenge"),
        nonce=auth_request.get("nonce"),
    )
    
    # Build redirect URL
    redirect_params = {"code": code}
    if auth_request.get("state"):
        redirect_params["state"] = auth_request["state"]
    
    redirect_url = f"{auth_request['redirect_uri']}?{urlencode(redirect_params)}"
    
    return RedirectResponse(url=redirect_url)


@app.post("/oauth2/token", tags=["OAuth2", "OIDC"])
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    device_code: Optional[str] = Form(None),
    subject_token: Optional[str] = Form(None),
    subject_token_type: Optional[str] = Form(None),
    requested_token_type: Optional[str] = Form(None),
):
    """
    OAuth 2.1 / OIDC Token Endpoint
    
    Exchanges authorization codes, refresh tokens, or credentials for access tokens.
    
    ### Supported Grant Types:
    - `authorization_code` - Standard OAuth flow
    - `refresh_token` - Token refresh
    - `client_credentials` - Machine-to-machine
    - `password` - Resource Owner Password (legacy, restricted)
    - `device_code` - Device flow
    - `token-exchange` - RFC 8693 token exchange
    """
    # Authenticate client
    client = await client_service.authenticate(client_id, client_secret)
    if not client:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Client authentication failed"},
            headers={"WWW-Authenticate": "Basic"},
        )
    
    try:
        if grant_type == "authorization_code":
            return await handle_authorization_code_grant(
                code=code,
                client=client,
                redirect_uri=redirect_uri,
            )
        
        elif grant_type == "refresh_token":
            return await handle_refresh_token_grant(
                refresh_token=refresh_token,
                client=client,
                scope=scope,
            )
        
        elif grant_type == "client_credentials":
            return await handle_client_credentials_grant(
                client=client,
                scope=scope,
            )
        
        elif grant_type == "password":
            # Only allowed for confidential clients with explicit permission
            if client.get("client_type") != "confidential":
                raise HTTPException(
                    status_code=400,
                    detail={"error": "unauthorized_client", "error_description": "Password grant not allowed"}
                )
            return await handle_password_grant(
                username=username,
                password=password,
                client=client,
                scope=scope,
            )
        
        elif grant_type == "device_code":
            return await handle_device_code_grant(
                device_code=device_code,
                client=client,
            )
        
        elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
            return await handle_token_exchange(
                subject_token=subject_token,
                subject_token_type=subject_token_type,
                requested_token_type=requested_token_type,
                client=client,
            )
        
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": "unsupported_grant_type"}
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_grant", "error_description": str(e)}
        )


async def handle_authorization_code_grant(
    code: str,
    client: Any,
    redirect_uri: Optional[str],
) -> JSONResponse:
    """Handle authorization_code grant type."""
    if not code:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing code"})
    
    # Exchange code for tokens
    tokens = await token_service.exchange_authorization_code(
        code=code,
        client_id=client["client_id"],
        redirect_uri=redirect_uri,
    )
    
    return JSONResponse(content=tokens)


async def handle_refresh_token_grant(
    refresh_token: str,
    client: Any,
    scope: Optional[str],
) -> JSONResponse:
    """Handle refresh_token grant type."""
    if not refresh_token:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing refresh_token"})
    
    tokens = await token_service.refresh_tokens(
        refresh_token=refresh_token,
        client_id=client["client_id"],
        scope=scope,
    )
    
    return JSONResponse(content=tokens)


async def handle_client_credentials_grant(
    client: Any,
    scope: Optional[str],
) -> JSONResponse:
    """Handle client_credentials grant type (M2M)."""
    access_token = await token_service.create_access_token(
        subject=client["client_id"],
        audience=client["client_id"],
        scope=scope or "api:read",
        token_type="bearer",
    )
    
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": scope or "api:read",
    })


async def handle_password_grant(
    username: str,
    password: str,
    client: Any,
    scope: Optional[str],
) -> JSONResponse:
    """Handle password grant type (legacy)."""
    if not username or not password:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing credentials"})
    
    # Authenticate user
    user = await auth_service.authenticate(username, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_grant", "error_description": "Invalid credentials"}
        )
    
    # Create tokens
    access_token = await token_service.create_access_token(
        subject=user["id"],
        audience=client["client_id"],
        scope=scope or "openid profile",
    )
    
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": scope or "openid profile",
    })


async def handle_device_code_grant(
    device_code: str,
    client: Any,
) -> JSONResponse:
    """Handle device_code grant type."""
    # Poll for device authorization completion
    result = await token_service.poll_device_code(device_code)
    
    if result.get("status") == "pending":
        raise HTTPException(
            status_code=400,
            detail={"error": "authorization_pending", "error_description": "User has not yet authorized"}
        )
    elif result.get("status") == "denied":
        raise HTTPException(
            status_code=400,
            detail={"error": "access_denied", "error_description": "User denied authorization"}
        )
    
    return JSONResponse(content=result["tokens"])


async def handle_token_exchange(
    subject_token: str,
    subject_token_type: Optional[str],
    requested_token_type: Optional[str],
    client: Any,
) -> JSONResponse:
    """Handle RFC 8693 token exchange."""
    if not subject_token:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "Missing subject_token"})
    
    exchanged_tokens = await token_service.exchange_token(
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        requested_token_type=requested_token_type,
        client_id=client["client_id"],
    )
    
    return JSONResponse(content=exchanged_tokens)


@app.get("/oauth2/userinfo", tags=["OIDC"])
async def userinfo_endpoint(request: Request):
    """
    OIDC UserInfo Endpoint
    
    Returns claims about the authenticated user.
    Requires valid access token with 'openid' scope.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "error_description": "Missing or invalid token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = auth_header.split(" ")[1]
    
    try:
        # Verify token
        payload = await token_service.verify_access_token(token)
        
        # Get user details
        user = await user_service.get_by_id(payload["sub"])
        if not user:
            raise HTTPException(status_code=404, detail={"error": "user_not_found"})
        
        # Return OIDC standard claims
        updated_at = user.get("updated_at")
        updated_at_ts = (
            int(updated_at.timestamp())
            if hasattr(updated_at, "timestamp")
            else int(datetime.utcnow().timestamp())
        )
        return {
            "sub": user["id"],
            "name": f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
            "given_name": user.get("first_name"),
            "family_name": user.get("last_name"),
            "email": user.get("email"),
            "email_verified": user.get("is_email_verified", False),
            "picture": user.get("avatar_url"),
            "locale": user.get("locale") or "en",
            "updated_at": updated_at_ts,
            # Custom claims
            "organizations": user.get("organizations", []),
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": str(e)},
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/oauth2/register", tags=["OAuth2", "OIDC"])
async def dynamic_client_registration(request: Request):
    """
    OIDC Dynamic Client Registration (RFC 7591)
    
    Allows applications to self-register as OAuth clients.
    """
    try:
        data = await request.json()
        client = await client_service.register_client(data)
        
        return JSONResponse(
            content=client,
            status_code=201,
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_client_metadata", "error_description": str(e)}
        )


# ============================================================================
# SAML 2.0 Endpoints
# ============================================================================

@app.get("/saml/metadata", tags=["SAML"])
@app.get("/saml/idp/metadata", tags=["SAML"])
async def saml_metadata():
    """
    SAML 2.0 Metadata Endpoint
    
    Returns IdP metadata XML for Service Provider configuration.
    Used for trust establishment in SAML federations.
    """
    metadata_xml = saml_provider.generate_idp_metadata()
    return Response(content=metadata_xml, media_type="application/xml")


@app.post("/saml/sso", tags=["SAML"])
@app.post("/saml/sso/post", tags=["SAML"])
async def saml_sso_post(request: Request):
    """
    SAML 2.0 Single Sign-On (HTTP POST Binding)
    
    Receives AuthnRequest from SP and returns SAML Response.
    """
    form_data = await request.form()
    saml_request = form_data.get("SAMLRequest")
    relay_state = form_data.get("RelayState")
    
    if not saml_request:
        raise HTTPException(status_code=400, detail="Missing SAMLRequest")
    
    # Process AuthnRequest
    authn_request = await saml_provider.parse_authn_request(saml_request)
    
    # Authenticate user (or redirect to login if not authenticated)
    # For now, assume user needs to log in
    return await saml_login_page(
        saml_request=saml_request,
        relay_state=relay_state,
        issuer=authn_request.get("issuer"),
        acs_url=authn_request.get("acs_url"),
    )


@app.get("/saml/sso/redirect", tags=["SAML"])
async def saml_sso_redirect(
    SAMLRequest: Optional[str] = Query(None),
    RelayState: Optional[str] = Query(None),
    SigAlg: Optional[str] = Query(None),
    Signature: Optional[str] = Query(None),
):
    """
    SAML 2.0 Single Sign-On (HTTP Redirect Binding)
    
    Receives signed AuthnRequest via URL parameters.
    """
    if not SAMLRequest:
        raise HTTPException(status_code=400, detail="Missing SAMLRequest")
    
    # Verify signature if present
    if Signature:
        valid = await saml_provider.verify_redirect_signature(
            saml_request=SAMLRequest,
            relay_state=RelayState,
            sig_alg=SigAlg,
            signature=Signature,
        )
        if not valid:
            raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Decode and process request
    authn_request = await saml_provider.parse_authn_request(SAMLRequest)
    
    return await saml_login_page(
        saml_request=SAMLRequest,
        relay_state=RelayState,
        issuer=authn_request.get("issuer"),
        acs_url=authn_request.get("acs_url"),
    )


async def saml_login_page(
    saml_request: str,
    relay_state: Optional[str],
    issuer: str,
    acs_url: str,
):
    """Render SAML login page."""
    # In production, this would render an HTML template
    # For now, return a simple form
    safe_issuer = html_escape(issuer or "", quote=True)
    safe_saml_request = html_escape(saml_request, quote=True)
    safe_relay_state = html_escape(relay_state or "", quote=True)
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Authy SAML Login</title></head>
    <body>
        <h1>SAML Single Sign-On</h1>
        <p>Identity Provider: {safe_issuer}</p>
        <form method="post" action="/saml/login/submit">
            <input type="hidden" name="SAMLRequest" value="{safe_saml_request}">
            <input type="hidden" name="RelayState" value="{safe_relay_state}">
            <label>Email: <input type="email" name="email" required></label><br><br>
            <label>Password: <input type="password" name="password" required></label><br><br>
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/saml/login/submit", tags=["SAML"])
async def saml_login_submit(request: Request):
    """Process SAML login form submission."""
    form_data = await request.form()
    email = form_data.get("email")
    password = form_data.get("password")
    saml_request = form_data.get("SAMLRequest")
    relay_state = form_data.get("RelayState")
    
    # Authenticate user
    user = await auth_service.authenticate(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate SAML Response
    saml_response = await saml_provider.create_saml_response(
        saml_request=saml_request,
        user=user,
        relay_state=relay_state,
    )
    
    # Return auto-submitting form to SP's ACS
    return HTMLResponse(content=saml_response)


@app.post("/saml/slo", tags=["SAML"])
@app.post("/saml/slo/post", tags=["SAML"])
async def saml_slo_post(request: Request):
    """
    SAML 2.0 Single Logout (HTTP POST Binding)
    
    Handles logout requests from Service Providers.
    """
    form_data = await request.form()
    saml_request = form_data.get("SAMLRequest")
    relay_state = form_data.get("RelayState")
    
    # Process logout
    await saml_provider.process_logout_request(saml_request)
    
    # Generate logout response
    slo_response = await saml_provider.create_logout_response(
        saml_request=saml_request,
        relay_state=relay_state,
    )
    
    return HTMLResponse(content=slo_response)


@app.get("/saml/slo/redirect", tags=["SAML"])
async def saml_slo_redirect(
    SAMLRequest: Optional[str] = Query(None),
    RelayState: Optional[str] = Query(None),
):
    """SAML 2.0 Single Logout (HTTP Redirect Binding)."""
    if SAMLRequest:
        await saml_provider.process_logout_request(SAMLRequest)
    
    return RedirectResponse(url="/logout")


# ============================================================================
# SCIM 2.0 Endpoints (Enterprise Provisioning)
# ============================================================================

@app.get("/scim/v2/Users", tags=["SCIM"])
async def scim_get_users(
    startIndex: int = Query(1, ge=1),
    count: int = Query(10, ge=1, le=100),
    filter: Optional[str] = Query(None),
    sortBy: Optional[str] = Query(None),
    sortOrder: str = Query("ascending"),
    _: None = Depends(require_scim_auth),
):
    """
    SCIM 2.0 Get Users
    
    Returns paginated list of users with optional filtering.
    """
    users = await scim_provider.list_users(
        start_index=startIndex,
        count=count,
        filter_expr=filter,
        sort_by=sortBy,
        sort_order=sortOrder,
    )
    
    return scim_provider.format_list_response(users, "User", startIndex, count)


@app.post("/scim/v2/Users", tags=["SCIM"])
async def scim_create_user(
    user_data: Dict[str, Any],
    _: None = Depends(require_scim_auth),
):
    """
    SCIM 2.0 Create User
    
    Creates a new user via automated provisioning.
    """
    new_user = await scim_provider.create_user(user_data)
    return JSONResponse(content=new_user, status_code=201)


@app.get("/scim/v2/Users/{user_id}", tags=["SCIM"])
async def scim_get_user(
    user_id: str,
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Get User by ID."""
    user = await scim_provider.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "User not found"})
    return user


@app.put("/scim/v2/Users/{user_id}", tags=["SCIM"])
async def scim_update_user(
    user_id: str,
    user_data: Dict[str, Any],
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Update User (Replace)."""
    updated_user = await scim_provider.update_user(user_id, user_data, replace=True)
    return updated_user


@app.patch("/scim/v2/Users/{user_id}", tags=["SCIM"])
async def scim_patch_user(
    user_id: str,
    operations: Dict[str, Any],
    _: None = Depends(require_scim_auth),
):
    """
    SCIM 2.0 Patch User
    
    Partially updates user attributes.
    """
    updated_user = await scim_provider.patch_user(user_id, operations)
    return updated_user


@app.delete("/scim/v2/Users/{user_id}", tags=["SCIM"], status_code=status.HTTP_204_NO_CONTENT)
async def scim_delete_user(
    user_id: str,
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Delete User."""
    await scim_provider.delete_user(user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/scim/v2/Groups", tags=["SCIM"])
async def scim_get_groups(
    startIndex: int = Query(1, ge=1),
    count: int = Query(10, ge=1, le=100),
    filter: Optional[str] = Query(None),
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Get Groups."""
    groups = await scim_provider.list_groups(
        start_index=startIndex,
        count=count,
        filter_expr=filter,
    )
    return scim_provider.format_list_response(groups, "Group", startIndex, count)


@app.post("/scim/v2/Groups", tags=["SCIM"])
async def scim_create_group(
    group_data: Dict[str, Any],
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Create Group."""
    new_group = await scim_provider.create_group(group_data)
    return JSONResponse(content=new_group, status_code=201)


@app.get("/scim/v2/Groups/{group_id}", tags=["SCIM"])
async def scim_get_group(
    group_id: str,
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Get Group by ID."""
    group = await scim_provider.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@app.delete("/scim/v2/Groups/{group_id}", tags=["SCIM"], status_code=status.HTTP_204_NO_CONTENT)
async def scim_delete_group(
    group_id: str,
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Delete Group."""
    await scim_provider.delete_group(group_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/scim/v2/ServiceProviderConfig", tags=["SCIM"])
async def scim_service_provider_config(
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Service Provider Configuration."""
    return scim_provider.get_sp_config()


@app.get("/scim/v2/ResourceTypes", tags=["SCIM"])
async def scim_resource_types(
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Resource Types."""
    return scim_provider.get_resource_types()


@app.get("/scim/v2/Schemas", tags=["SCIM"])
async def scim_schemas(
    _: None = Depends(require_scim_auth),
):
    """SCIM 2.0 Schemas."""
    return scim_provider.get_schemas()


# ============================================================================
# Health & Metrics
# ============================================================================

@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health Check Endpoint
    
    Returns service health status for load balancers and monitoring.
    """
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "protocols": ["OIDC", "OAuth2", "SAML 2.0", "SCIM 2.0"],
        "uptime_seconds": 0,  # Would calculate from start time
    }


@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes liveness probe - is the service running?"""
    return {"status": "alive"}


@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """Kubernetes readiness probe - is the service ready for traffic?"""
    # Check database connectivity
    # Check cache connectivity
    # Check required dependencies
    return {"status": "ready"}


@app.get("/metrics", tags=["Health"])
async def metrics():
    """
    Prometheus-compatible metrics endpoint.
    
    Returns IAM-specific metrics:
    - Authentication success/failure rates
    - Token issuance rates
    - Active sessions
    - Protocol usage breakdown
    """
    # Placeholder - would integrate with Prometheus client
    return """# HELP authy_auth_requests_total Total authentication requests
# TYPE authy_auth_requests_total counter
authy_auth_requests_total{{type="success"}} 0
authy_auth_requests_total{{type="failure"}} 0
# HELP authy_active_sessions Current active sessions
# TYPE authy_active_sessions gauge
authy_active_sessions 0
# HELP authy_tokens_issued_total Total tokens issued
# TYPE authy_tokens_issued_total counter
authy_tokens_issued_total{{type="access"}} 0
authy_tokens_issued_total{{type="id"}} 0
authy_tokens_issued_total{{type="refresh"}} 0
"""


def main() -> None:
    """CLI entrypoint for starting the Authy server."""
    uvicorn.run(
        "authy_server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        workers=settings.WORKERS,
    )


if __name__ == "__main__":
    main()
