# Authy Package - Enterprise-Grade Authentication for Python

[![PyPI version](https://badge.fury.io/py/authy-package.svg)](https://badge.fury.io/py/authy-package)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**The most comprehensive authentication library for Python** - featuring traditional auth, passwordless login, multi-tenancy, social OAuth, AWS Cognito integration, MFA, and framework adapters for FastAPI, Flask, and Django.

## 🚀 Quick Start

```bash
pip install authy-package
```

### Minimal Setup (Traditional Auth)

```python
import asyncio
from authy_package.core.auth_manager import TraditionalAuthManager
from authy_package.db.sql import SQLDatabase
# For MongoDB: from authy_package.db.mongodb import MongoDBDatabase
# For DynamoDB: from authy_package.db.dynamodb_adapter import DynamoDBAdapter
from authy_package.cache.redis_cache import RedisCaching
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.utils.security import SecurityManager

# Initialize components
# SQL Database
db = SQLDatabase("postgresql+asyncpg://user:pass@localhost/dbname")

# MongoDB Alternative
# db = MongoDBDatabase("mongodb://localhost:27017", "authy_db")

# DynamoDB Alternative (Uses IAM Roles - NO credentials in code!)
# db = DynamoDBAdapter({
#     'region': 'us-east-1',
#     'table_prefix': 'prod_authy_'
#     # Credentials automatically resolved from IAM Role / IRSA / Environment
# })

cache = RedisCaching("redis://localhost:6379")
mfa = MFAAuthManager(db=db)
security = SecurityManager(db=db, cache=cache, api_key="mailjet_key", api_secret="mailjet_secret")

# Create auth manager
auth = TraditionalAuthManager(db=db, cache=cache, mfa_manager=mfa, security_manager=security)

async def main():
    # Register user
    await auth.register_user(username="johndoe", email="john@example.com", password="SecurePass123!")
    
    # Login
    tokens = await auth.login_user(username="johndoe", password="SecurePass123!")
    print(tokens)  # {"access_token": "...", "refresh_token": "..."}

asyncio.run(main())
```

⚠️ **Security Note for DynamoDB**: Never hardcode AWS credentials! The package follows AWS best practices by using the credential provider chain (IAM Roles → Environment → Config files). See [AWS_SECURITY_GUIDE.md](./AWS_SECURITY_GUIDE.md) for details.

### Using Configuration Class

```python
from authy_package.config import AuthConfig, DatabaseConfig, CacheConfig, SecurityConfig

config = AuthConfig(
    database=DatabaseConfig(
        db_type="sql",
        connection_string="postgresql+asyncpg://user:pass@localhost/dbname"
    ),
    cache=CacheConfig(redis_url="redis://localhost:6379"),
    security=SecurityConfig(jwt_config={"secret_key": "your-super-secret-key"})
)

config.validate()  # Raises ValueError if config is invalid
```

## ✨ Core Features

### 🔐 Traditional Authentication
- **Username/Email/Phone Login**: Flexible user identification
- **Password Hashing**: bcrypt and argon2-cffi support
- **JWT Tokens**: Access tokens (1 hour) + refresh tokens (7 days)
- **MFA Support**: TOTP-based (Google Authenticator compatible)
- **Password Reset**: Email-based reset flow with secure tokens

### 🪄 Passwordless Authentication
- **Magic Links**: One-click email login with 10-minute expiry
- **Passkeys/WebAuthn**: Biometric authentication (Touch ID, Face ID, Windows Hello)
- **Click Tracking**: Built-in analytics for magic link usage

### 🏢 Multi-Tenancy & Organizations
- **Organization Model**: Tenant isolation with unique slugs
- **Role Hierarchy**: OWNER → ADMIN → MEMBER → GUEST
- **Invitation System**: Email-based invites with 7-day expiration
- **Member Limits**: Plan-based restrictions (default: 10 members)
- **RBAC Enforcement**: Role checks at route level

### 🎯 Session Management
- Multi-device session tracking with unique session IDs
- Concurrent session limits (configurable)
- Automatic token refresh
- Device fingerprinting (IP, user-agent)
- Session revocation on password change

### 📡 Real-time Webhooks
- **17 Event Types**: user.*, auth.*, mfa.*, org.*, session.*
- **Retry Logic**: 5 attempts with exponential backoff (1m→5m→15m→1h→4h)
- **Signature Verification**: HMAC-SHA256 for endpoint security
- **Delivery Tracking**: Success/failure logging

### 🛡️ Security Features
- **Password Hashing**: bcrypt/argon2-cffi
- **JWT**: HS256/RS256 with configurable expiration
- **Rate Limiting**: Redis-backed (5 attempts/5 min default)
- **Account Lockout**: 15-minute default duration
- **Audit Logging**: SOC2/GDPR compliant with 365-day retention

### 🌐 Social Authentication
- **Google OAuth2**: Full OAuth2 flow
- **Facebook Login**: Graph API integration
- **GitHub OAuth**: Developer-friendly setup
- **Apple Sign-In**: Privacy-focused authentication

### ☁️ AWS Cognito Integration
- User registration and authentication
- Social login through Cognito
- Token management and refresh
- User attribute updates
- Account confirmation flows

### 🔧 Framework Adapters
- **FastAPI**: Dependency injection decorators
- **Flask**: Route decorators
- **Django**: Middleware and view decorators

## 📖 Documentation

### Traditional Authentication

```python
from authy_package.core.auth_manager import TraditionalAuthManager
from authy_package.db.sql import SQLDatabase
from authy_package.cache.redis_cache import RedisCaching
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.utils.security import SecurityManager

# Initialize
db = SQLDatabase("postgresql+asyncpg://user:pass@localhost/dbname")
cache = RedisCaching("redis://localhost:6379")
mfa = MFAAuthManager(db=db)
security = SecurityManager(db=db, cache=cache, api_key="mailjet_key", api_secret="mailjet_secret")
auth = TraditionalAuthManager(db=db, cache=cache, mfa_manager=mfa, security_manager=security)

# Register user
await auth.register_user(username="johndoe", email="john@example.com", password="SecurePass123!")

# Login (returns tokens if cache enabled)
tokens = await auth.login_user(username="johndoe", password="SecurePass123!")
# {"access_token": "...", "refresh_token": "..."}

# Login with MFA
tokens = await auth.login_user(email="john@example.com", password="SecurePass123!", mfa_code="123456")

# Enable MFA
mfa_setup = await auth.enable_mfa(username="johndoe")
# Returns mfa_secret for QR code generation

# Password reset request
await auth.request_password_reset(email="john@example.com", sender_email="noreply@example.com")

# Reset password
await auth.reset_password(email="john@example.com", token="reset_token", new_password="NewPass123!")

# Refresh tokens
new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])

# Logout
await auth.logout_user(access_token=tokens["access_token"], username="johndoe")
```

### Magic Links (Passwordless)

```python
from authy_package.passwordless.magic_link import MagicLinkManager

magic = MagicLinkManager(db=db, cache=cache, config=config)

# Send magic link
await magic.send_magic_link(
    email="user@example.com",
    redirect_url="https://myapp.com/auth/callback"
)

# Verify magic link token
user = await magic.verify_magic_link(token="magic_link_token")
```

### Passkeys/WebAuthn

```python
from authy_package.passwordless.passkey import PasskeyManager

passkeys = PasskeyManager(db=db, config=config)

# Start registration
options = await passkeys.register_start(user_id="user123", email="user@example.com")
# Returns WebAuthn creation options for client-side

# Complete registration
credential = await passkeys.register_complete(user_id="user123", response=client_response)

# Start authentication
options = await passkeys.authenticate_start()

# Complete authentication
user = await passkeys.authenticate_complete(response=client_response)
```

### Organization Management

```python
from authy_package.organizations.org_manager import OrganizationManager, OrgRole

org_mgr = OrganizationManager(config=config, db=db, cache=cache)

# Create organization
org = await org_mgr.create_organization(
    name="Acme Corp",
    owner_id="user123",
    slug="acme-corp"  # Optional, auto-generated if not provided
)

# Get organization by slug
org = await org_mgr.get_organization_by_slug("acme-corp")

# Add member directly
await org_mgr.add_member(org.id, "user456", OrgRole.MEMBER, invited_by="user123")

# Send invitation
invitation = await org_mgr.send_invitation(
    org_id=org.id,
    email="new@example.com",
    role=OrgRole.GUEST,
    invited_by="user123"
)

# Accept invitation
member = await org_mgr.accept_invitation(token="invite_token", user_id="user789")

# Get user's role in organization
role = await org_mgr.get_member_role(org.id, "user456")
# Returns OrgRole.MEMBER

# Get all members
members = await org_mgr.get_members(org.id)

# Update member role
await org_mgr.update_member_role(org.id, "user456", OrgRole.ADMIN)

# Remove member (cannot remove last owner)
await org_mgr.remove_member(org.id, "user456")
```

### Audit Logging

```python
from authy_package.admin.audit_logger import AuditLogger, EventType

audit = AuditLogger(config=config, db=db, cache=cache)

# Log an event
await audit.log(
    event_type=EventType.LOGIN_SUCCESS,
    action="User logged in successfully",
    actor_id="user123",
    actor_email="user@example.com",
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0...",
    metadata={"session_id": "sess_abc123"},
    severity="info",
    status="success"
)

# Search audit logs
events = await audit.search(
    actor_id="user123",
    start_date=datetime.now() - timedelta(days=7),
    limit=100
)

# Get security events
security_events = await audit.get_security_events(organization_id="org123", limit=50)

# Export for compliance (JSON or CSV)
csv_export = await audit.export_events(
    filters={"organization_id": "org123"},
    format="csv"
)

# Get statistics
stats = await audit.get_statistics(
    start_date=datetime.now() - timedelta(days=30),
    end_date=datetime.now(),
    group_by="event_type"
)
```

### Webhooks

```python
from authy_package.webhooks.webhook_manager import WebhookManager, WebhookEventType
import httpx

http_client = httpx.AsyncClient()
webhooks = WebhookManager(config=config, db=db, cache=cache, http_client=http_client)

# Register webhook endpoint
endpoint = await webhooks.register_endpoint(
    url="https://api.example.com/webhooks/auth",
    events=[
        WebhookEventType.USER_CREATED,
        WebhookEventType.USER_LOGGED_IN,
        WebhookEventType.PASSWORD_RESET_REQUESTED
    ],
    secret="your-webhook-secret"  # Optional, auto-generated if not provided
)

# Dispatch event
await webhooks.dispatch_event(
    event_type=WebhookEventType.USER_CREATED,
    payload={"user_id": "user123", "email": "user@example.com"},
    sync=False  # Async delivery (recommended)
)

# List endpoints
endpoints = await webhooks.list_endpoints()

# Delete endpoint
await webhooks.delete_endpoint(endpoint_id="ep_123")

# Verify webhook signature (on receiver side)
from authy_package.webhooks.webhook_manager import WebhookManager

is_valid = WebhookManager.verify_signature(
    payload=request.json,
    signature=request.headers["X-Webhook-Signature"],
    secret="your-webhook-secret",
    timestamp=request.headers["X-Webhook-Timestamp"]
)
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from authy_package.frameworks.fastapi_adapter import FastAPIAuth
from authy_package.core.auth_manager import TraditionalAuthManager

app = FastAPI()
auth = TraditionalAuthManager(...)  # Initialize as shown above
fastapi_auth = FastAPIAuth(auth)

# Protected route (requires authentication)
@app.get("/protected")
async def protected_route(user=Depends(fastapi_auth.require_auth())):
    return {"message": f"Hello {user['email']}", "user": user}

# Role-based access control
@app.get("/admin")
async def admin_route(user=Depends(fastapi_auth.require_role("admin", "owner"))):
    return {"message": "Admin access granted"}

# Organization membership check
@app.get("/org/dashboard")
async def org_dashboard(user=Depends(fastapi_auth.require_org_membership())):
    # user['current_org'] contains org context
    return {"org": user['current_org']}

# Rate limiting
@app.post("/login")
async def login(rate_check=Depends(fastapi_auth.rate_limit(5, 60))):
    # Max 5 requests per minute per IP
    credentials = await request.json()
    tokens = await auth.login_user(**credentials)
    return tokens

# Optional authentication (doesn't fail if no token)
@app.get("/public-or-private")
async def mixed_route(user=Depends(fastapi_auth.optional_auth())):
    if user:
        return {"message": f"Welcome back {user['email']}"}
    return {"message": "Welcome, guest"}
```

### AWS Cognito Integration

```python
from authy_package.cognito.cognito_manager import CognitoManager
from authy_package.core.auth_manager import CognitoAuthManager

cognito = CognitoManager(
    region_name="us-east-1",
    user_pool_id="us-east-1_xxxxxxxxx",
    app_client_id="xxxxxxxxxxxxxxxxxxxx"
)
cognito_auth = CognitoAuthManager(cognito_manager=cognito)

# Register user
await cognito_auth.register_user(
    username="johndoe",
    password="SecurePass123!",
    email="john@example.com",
    phone_number="+1234567890"
)

# Login
tokens = await cognito_auth.login_user(username="johndoe", password="SecurePass123!")

# Social login initiation
auth_url = await cognito_auth.initiate_social_login(
    provider="Google",
    redirect_uri="https://myapp.com/callback"
)

# Exchange authorization code for tokens
tokens = await cognito_auth.exchange_code_for_tokens(
    code="auth_code_from_callback",
    redirect_uri="https://myapp.com/callback"
)

# Refresh tokens
new_tokens = await cognito_auth.refresh_token(refresh_token=tokens["refresh_token"])

# Password reset flow
await cognito_auth.reset_password(username="johndoe")
await cognito_auth.confirm_password(
    username="johndoe",
    confirmation_code="123456",
    new_password="NewPass123!"
)

# Confirm user account (for email/phone verification)
await cognito_auth.confirm_user_account(
    username="johndoe",
    confirmation_code="123456"
)

# Update user attributes
await cognito_auth.update_user_attributes(
    access_token=tokens["access_token"],
    attributes=[{"Name": "custom:department", "Value": "Engineering"}]
)

# Get user info
user_info = await cognito_auth.get_user_info(access_token=tokens["access_token"])

# Logout
logout_url = await cognito_auth.logout_user(
    redirect_uri="https://myapp.com/logged-out",
    access_token=tokens["access_token"]
)
```

### Social Authentication (Direct OAuth)

```python
from authy_package.social.google import GoogleManager
from authy_package.social.github import GitHubManager
from authy_package.social.facebook import FacebookManager
from authy_package.social.apple import AppleManager

# Google OAuth
google = GoogleManager(
    client_id="google_client_id",
    client_secret="google_client_secret",
    redirect_uri="https://myapp.com/auth/google/callback"
)

auth_url = google.get_authorization_url()
tokens = await google.exchange_code(code="auth_code")
user_info = await google.get_user_info(access_token=tokens["access_token"])

# GitHub OAuth
github = GitHubManager(
    client_id="github_client_id",
    client_secret="github_client_secret",
    redirect_uri="https://myapp.com/auth/github/callback"
)

auth_url = github.get_authorization_url()
tokens = await github.exchange_code(code="auth_code")
user_info = await github.get_user_info(access_token=tokens["access_token"])

# Similar patterns for Facebook and Apple
```

## 🔧 Configuration

### Environment Variables

```env
# Database (Required)
AUTHY_DB_TYPE=sql                          # "sql", "mongodb", or "dynamodb"
AUTHY_DB_URL=postgresql+asyncpg://user:pass@localhost:5432/authy
AUTHY_DB_NAME=authy                        # For MongoDB
AUTHY_DB_COLLECTION=users                  # For MongoDB

# AWS DynamoDB (Alternative to SQL/MongoDB)
# ⚠️ SECURITY: Never set these directly! Use IAM Roles instead.
# See AWS_SECURITY_GUIDE.md for secure credential management
AWS_REGION=us-east-1                       # Required for DynamoDB
# AWS_ACCESS_KEY_ID=...                   # ❌ NOT RECOMMENDED - Use IAM Role
# AWS_SECRET_ACCESS_KEY=...               # ❌ NOT RECOMMENDED - Use IAM Role
AUTHY_DYNAMODB_TABLE_PREFIX=prod_authy_    # Prefix for all table names
AUTHY_DYNAMODB_ROLE_ARN=arn:aws:iam::...   # Optional: Cross-account role

# Cache/Redis (Required for JWT tokens)
AUTHY_CACHE_ENABLED=true
AUTHY_REDIS_URL=redis://localhost:6379
AUTHY_TOKEN_EXPIRATION=3600                # 1 hour
AUTHY_REFRESH_TOKEN_EXPIRATION=604800      # 7 days

# JWT Security (Required)
AUTHY_JWT_SECRET=your-super-secret-key-min-32-chars

# Rate Limiting
AUTHY_RATE_LIMIT_ENABLED=true
AUTHY_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHY_RATE_LIMIT_WINDOW_SECONDS=300        # 5 minutes

# Email (for password resets and magic links)
AUTHY_EMAIL_ENABLED=false
MAILJET_API_KEY=xxx
MAILJET_API_SECRET=xxx
SENDER_EMAIL=noreply@example.com
SENDER_NAME=My App

# Social Providers (Optional)
GOOGLE_CLIENT_ID=xxx
GOOGLE_CLIENT_SECRET=xxx
GOOGLE_REDIRECT_URI=https://myapp.com/auth/google/callback

GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx
GITHUB_REDIRECT_URI=https://myapp.com/auth/github/callback

FACEBOOK_APP_ID=xxx
FACEBOOK_APP_SECRET=xxx
FACEBOOK_REDIRECT_URI=https://myapp.com/auth/facebook/callback

APPLE_CLIENT_ID=xxx
APPLE_TEAM_ID=xxx
APPLE_KEY_ID=xxx
APPLE_PRIVATE_KEY=xxx
APPLE_REDIRECT_URI=https://myapp.com/auth/apple/callback

# AWS Cognito (Optional)
AUTHY_COGNITO_ENABLED=false
AWS_REGION=us-east-1
COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxxxxxxxxx

# SAML 2.0 (Enterprise SSO)
AUTHY_SAML_ENABLED=false
SAML_SP_ENTITY_ID=https://myapp.com/saml/metadata
SAML_ACS_URL=https://myapp.com/saml/acs
SAML_SLO_URL=https://myapp.com/saml/slo
SAML_IDP_METADATA_URL=https://idp.example.com/metadata
SAML_IDP_CERTIFICATE=-----BEGIN CERTIFICATE-----...

# OpenID Connect (Enterprise SSO)
AUTHY_OIDC_ENABLED=false
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=xxx
OIDC_CLIENT_SECRET=xxx
OIDC_REDIRECT_URI=https://myapp.com/auth/oidc/callback
OIDC_SCOPES=openid,email,profile

# Audit Logging
AUTHY_AUDIT_LOG_RETENTION_DAYS=365
```

### Programmatic Configuration

```python
from authy_package.config import AuthConfig, DatabaseConfig, CacheConfig, SecurityConfig, SocialAuthConfig, EmailConfig

config = AuthConfig(
    database=DatabaseConfig(
        db_type="sql",
        connection_string="postgresql+asyncpg://user:pass@localhost/dbname",
        orm_model=UserORMModel  # Your SQLAlchemy model
    ),
    cache=CacheConfig(
        enabled=True,
        redis_url="redis://localhost:6379",
        token_expiration=3600,
        refresh_token_expiration=604800
    ),
    security=SecurityConfig(
        jwt_config={
            "secret_key": "your-super-secret-key",
            "algorithm": "HS256"
        },
        rate_limit_enabled=True,
        rate_limit_max_attempts=5,
        account_lockout_duration=900  # 15 minutes
    ),
    social=SocialAuthConfig(
        google_client_id="xxx",
        google_client_secret="xxx",
        github_client_id="xxx",
        github_client_secret="xxx"
    ),
    email=EmailConfig(
        enabled=True,
        provider="mailjet",
        api_key="xxx",
        api_secret="xxx",
        sender_email="noreply@example.com",
        sender_name="My App"
    ),
    app_name="My Application",
    debug=False
)

# Validate configuration before use
config.validate()  # Raises ValueError if invalid
```

## 📦 Installation

### Basic Installation
```bash
pip install authy-package
```

### With All Dependencies
```bash
pip install authy-package[full]
# Includes: asyncpg, motor (MongoDB), redis, httpx, pyjwt[crypto], bcrypt, argon2-cffi
```

### Development Installation
```bash
git clone https://github.com/yourusername/authy-package.git
cd authy-package
pip install -e ".[dev]"
# Includes: pytest, pytest-asyncio, black, flake8, mypy
```

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install authy-package[full]

COPY . .

CMD ["python", "main.py"]
```

## 🔒 Security Best Practices

### Production Checklist
- [ ] Use strong JWT secret (min 32 characters)
- [ ] Enable HTTPS for all endpoints
- [ ] Set secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] Configure rate limiting (default: 5 attempts/5 min)
- [ ] Enable audit logging for compliance
- [ ] Rotate JWT keys periodically
- [ ] Use environment variables for secrets
- [ ] Enable MFA for admin accounts
- [ ] Configure webhook signature verification
- [ ] Set appropriate token expiration times

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Token Security
- Access tokens: Short-lived (default: 1 hour)
- Refresh tokens: Medium-lived (default: 7 days)
- Automatic revocation on password change
- Session tracking with device fingerprinting

## 🧪 Testing

### Unit Tests
```python
import pytest
from authy_package.config import AuthConfig
from authy_package.core.auth_manager import TraditionalAuthManager

@pytest.fixture
def auth_config():
    return AuthConfig(
        database=DatabaseConfig(db_type="memory"),
        cache=CacheConfig(enabled=False),
        security=SecurityConfig(jwt_config={"secret_key": "test-secret"})
    )

@pytest.fixture
def auth_manager(auth_config):
    return TraditionalAuthManager(...)

@pytest.mark.asyncio
async def test_user_registration(auth_manager):
    result = await auth_manager.register_user(
        username="testuser",
        email="test@example.com",
        password="TestPass123!"
    )
    assert result["message"] == "User registered successfully."
```

### Integration Tests
See `/examples` directory for complete integration examples:
- `example_sql.py` - SQL database integration
- `example_mongo.py` - MongoDB integration
- `example_social.py` - Social OAuth flows
- `example_cognito.py` - AWS Cognito integration

## 📊 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (FastAPI / Flask / Django)                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Framework Adapters                         │
│         FastAPIAuth | FlaskAuth | DjangoAuth                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Auth Managers                        │
│  TraditionalAuthManager | CognitoAuthManager | SocialAuth   │
│  SAMLManager | OIDCManager                                  │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Specialized    │ │  Specialized    │ │  Specialized    │
│  Managers       │ │  Managers       │ │  Managers       │
│  - Sessions     │ │  - MFA          │ │  - Webhooks     │
│  - Magic Links  │ │  - Passkeys     │ │  - Audit Log    │
│  - Organizations│ │  - Security     │ │  - Compliance   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Data & Cache Layer                          │
│   PostgreSQL | MySQL | SQLite | MongoDB | DynamoDB | Redis  │
│                                                              │
│   Database Agnostic Interface:                               │
│   - SQLDatabase (SQLAlchemy)                                │
│   - MongoDBDatabase (Motor)                                 │
│   - DynamoDBAdapter (aioboto3)                              │
│   - Custom adapters via AbstractDatabase                    │
└─────────────────────────────────────────────────────────────┘
```

### Database Support Matrix

| Database | Status | Use Case | Credentials |
|----------|--------|----------|-------------|
| **PostgreSQL/MySQL/SQLite** | ✅ Production | General purpose | Connection string |
| **MongoDB** | ✅ Production | Document-based, scalable | Connection string |
| **DynamoDB** | ✅ Production | Serverless, AWS-native | IAM Roles (no secrets!) |
| **Cassandra** | 🔧 Template | High write throughput | Custom implementation |
| **Redis** | 🔧 Template | Session/cache only | Custom implementation |

See [AWS_SECURITY_GUIDE.md](./AWS_SECURITY_GUIDE.md) for secure AWS credential management.

## 🤝 Contributing

We welcome contributions! Please see our workflow:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Run tests**: `pytest tests/`
5. **Format code**: `black authy_package/`
6. **Lint**: `flake8 authy_package/`
7. **Commit**: `git commit -m 'Add amazing feature'`
8. **Push**: `git push origin feature/amazing-feature`
9. **Open a Pull Request**

### Code Standards
- Python 3.8+
- Type hints required
- Docstrings for public APIs
- Test coverage > 80%
- Follow PEP 8 style guide

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Inspired by Auth0, Clerk, Supabase Auth, NextAuth.js, and Django Allauth.

## 📞 Support

- **Documentation**: This README and inline code comments
- **Examples**: `/examples` directory
- **Issues**: GitHub Issues tab
- **Email**: support@authy-package.dev

---

**Built with ❤️ for the Python community**
