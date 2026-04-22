
## 🏢 Enterprise SSO (SAML 2.0 & OIDC)

Authy Package now includes full enterprise SSO support with SAML 2.0 and OpenID Connect.

### SAML 2.0 Service Provider

```python
from authy_package.saml import SAMLManager, SAMLConfig
from authy_package.db.sql import SQLDatabase

# Configure SAML SP
saml_config = SAMLConfig(
    sp_entity_id="https://yourapp.com/saml/metadata",
    acs_url="https://yourapp.com/auth/saml/acs",
    slo_url="https://yourapp.com/auth/saml/slo",
    certificate_path="/path/to/sp_cert.pem",
    private_key_path="/path/to/sp_key.pem",
    idp_entity_id="https://idp.example.com/entity",
    idp_sso_url="https://idp.example.com/sso",
    idp_slo_url="https://idp.example.com/slo",
    idp_certificate_path="/path/to/idp_cert.pem",
)

# Initialize manager
saml_manager = SAMLManager(saml_config, database=db, cache=redis_cache)

# Generate metadata to share with IdP
metadata_xml = saml_manager.generate_metadata()

# Create login URL
login_url, request_id = saml_manager.create_auth_request(relay_state="/dashboard")

# Handle ACS callback
@app.post("/auth/saml/acs")
async def saml_acs(request: Request):
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse")
    relay_state = form_data.get("RelayState")
    
    result = await saml_manager.validate_response(saml_response, relay_state)
    # result contains: user, session_id, attributes, name_id
    
    # Create JWT session
    return {"access_token": create_jwt(result["user"])}
```

### OpenID Connect Client

```python
from authy_package.oidc import OIDCManager, OIDCConfig

# Auto-discover provider configuration
oidc_config = OIDCConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="https://yourapp.com/auth/oidc/callback",
    issuer="https://accounts.google.com",  # Or any OIDC provider
    require_pkce=True,
)

# Discover endpoints automatically
await oidc_config.discover()

# Initialize manager
oidc_manager = OIDCManager(oidc_config, database=db, cache=redis_cache)

# Start authentication flow
auth_url, state, code_verifier = oidc_manager.create_authorization_url(
    prompt="consent",
    login_hint="user@example.com"
)

# Redirect user to auth_url

# Handle callback
@app.get("/auth/oidc/callback")
async def oidc_callback(code: str, state: str):
    result = await oidc_manager.handle_oidc_callback(
        code=code,
        state=state,
        code_verifier=stored_code_verifier
    )
    # result contains: user, tokens, user_info
    
    return {"access_token": create_jwt(result["user"])}
```

### Supported Providers

**SAML 2.0 IdPs:**
- Okta
- Azure AD / Microsoft Entra ID
- Ping Identity
- OneLogin
- Keycloak
- ADFS
- Google Workspace

**OIDC Providers:**
- Google
- Microsoft (Azure AD)
- Auth0
- Keycloak
- Okta
- Any standard OIDC provider

### Database Schema

Run the migration to add SAML/OIDC tables:

```bash
psql -d your_database -f authy_package/migration/saml_oidc_tables.sql
```

### Security Features

✅ XML signature validation (SAML)  
✅ JWT signature validation (OIDC)  
✅ Clock skew tolerance  
✅ Audience/issuer validation  
✅ Replay attack prevention  
✅ CSRF protection via state parameter  
✅ PKCE support (OIDC)  
✅ JIT user provisioning  
✅ Attribute mapping  
