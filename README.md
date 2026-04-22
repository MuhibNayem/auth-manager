# Authy Package - Enterprise-Grade Authentication for Python

[![PyPI version](https://badge.fury.io/py/authy-package.svg)](https://badge.fury.io/py/authy-package)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**The most developer-friendly authentication library for Python** - featuring passwordless auth, multi-tenancy, social login, MFA, and one-line framework integration.

## 🚀 Quick Start

```bash
pip install authy-package
```

```python
# One-line setup (auto-loads from environment variables)
from authy_package import get_auth

auth = get_auth()

# Or explicit configuration
from authy_package import init_auth, AuthConfig

config = AuthConfig(
    jwt_secret="your-secret-key",
    database_url="postgresql+asyncpg://user:pass@localhost/dbname",
    redis_url="redis://localhost:6379/0"
)
auth = init_auth(config)
```

## ✨ Market-Leading Features

### 🔐 Passwordless Authentication
- **Magic Links**: One-click email login
- **Passkeys/WebAuthn**: Biometric authentication (Touch ID, Face ID, Windows Hello)
- **OTP**: SMS/email one-time passwords

### 🏢 Multi-Tenancy & Organizations
- Full organization hierarchy
- Role-based access control (RBAC)
- Team management and invitations
- Billing-ready architecture

### 🎯 Advanced Session Management
- Multi-device session tracking
- Automatic token refresh
- Device fingerprinting
- Concurrent session limits
- Predictive session pre-fetching

### 📡 Real-time Webhooks
- Event-driven architecture
- Automatic retries with exponential backoff
- Signature verification
- Delivery tracking

### 🛡️ Security Features
- JWT with automatic rotation
- Rate limiting and bot protection
- Fraud detection and anomaly monitoring
- Comprehensive audit logging (SOC2/GDPR ready)
- Account lockout protection

### 🚀 Framework Integration
- **FastAPI**: One-line dependency injection
- **Flask**: Simple decorators
- **Django**: Middleware and decorators

## 📖 Documentation

### Basic Usage

```python
from authy_package import get_auth

auth = get_auth()

# Register user
user = await auth.register(email="user@example.com", password="SecurePassword123!")

# Login
tokens = await auth.login(email="user@example.com", password="SecurePassword123!")

# Magic link login
await auth.passwordless.send_magic_link("user@example.com")
user = await auth.passwordless.verify_magic_link(token)

# Passkey registration
options = await auth.passkeys.register_start(user_id, email)
# ... client-side WebAuthn ...
credential = await auth.passkeys.register_complete(user_id, response)
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from authy_package import get_auth
from authy_package.frameworks import FastAPIAuth

app = FastAPI()
auth = get_auth()
fastapi_auth = FastAPIAuth(auth)

@app.get("/protected")
async def protected_route(user=Depends(fastapi_auth.require_auth())):
    return {"message": f"Hello {user['email']}"}

@app.get("/admin")
async def admin_route(user=Depends(fastapi_auth.require_role("admin"))):
    return {"message": "Admin access granted"}

@app.post("/login")
async def login(credentials=Depends(fastapi_auth.rate_limit(5, 60))):
    # Rate limited: 5 requests per minute
    pass
```

### Organization Management

```python
from authy_package.organizations import OrgRole

# Create organization
org = await auth.organizations.create_organization("Acme Corp", owner_id=user_id)

# Send invitation
await auth.organizations.send_invitation(
    org.id, 
    "new@example.com", 
    OrgRole.MEMBER,
    invited_by=user_id
)

# Check membership
role = await auth.organizations.get_member_role(org.id, user_id)
```

### Audit Logging

```python
from authy_package.admin import EventType

# Log security event
await auth.audit.log(
    event_type=EventType.LOGIN_FAILED,
    action="Failed login attempt",
    actor_id=user_id,
    ip_address=request_ip,
    severity="warning"
)

# Search audit logs
events = await auth.audit.search(
    actor_id=user_id,
    start_date=datetime.now() - timedelta(days=7)
)

# Export for compliance
csv_export = await auth.audit.export_events(
    filters={"organization_id": org_id},
    format="csv"
)
```

## 🔧 Configuration

### Environment Variables

```env
# Required
AUTHY_JWT_SECRET=your-super-secret-key-min-32-chars
AUTHY_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/authy
AUTHY_REDIS_URL=redis://localhost:6379/0

# Optional
AUTHY_APP_NAME=My Application
AUTHY_BASE_URL=https://myapp.com
AUTHY_SESSION_EXPIRY=3600
AUTHY_REFRESH_TOKEN_EXPIRY_DAYS=30
AUTHY_MAX_CONCURRENT_SESSIONS=5
AUTHY_AUTO_CREATE_USERS=true
AUTHY_AUDIT_LOG_RETENTION_DAYS=365

# Social Providers
AUTHY_GOOGLE_CLIENT_ID=xxx
AUTHY_GOOGLE_CLIENT_SECRET=xxx
AUTHY_GITHUB_CLIENT_ID=xxx
AUTHY_GITHUB_CLIENT_SECRET=xxx

# Email (for magic links)
AUTHY_EMAIL_PROVIDER=mailjet
AUTHY_MAILJET_API_KEY=xxx
AUTHY_MAILJET_SECRET=xxx
```

### Programmatic Configuration

```python
from authy_package import AuthConfig

config = AuthConfig(
    jwt_secret="your-secret-key",
    database_url="postgresql+asyncpg://...",
    redis_url="redis://...",
    app_name="My App",
    base_url="https://myapp.com",
    session_expiry=3600,
    refresh_token_expiry_days=30,
    max_concurrent_sessions=5,
    auto_create_users=True,
    audit_log_retention_days=365,
    
    # Social providers
    google_client_id="xxx",
    google_client_secret="xxx",
    
    # Email
    email_provider="mailjet",
    mailjet_api_key="xxx",
    mailjet_secret="xxx"
)
```

## 🎯 Unique Developer-Loving Features

### 🪄 Magic Import
```python
from authy_package import get_auth
auth = get_auth()  # Auto-configured from ENV
```

### 🧪 Mock Mode for Testing
```python
config = AuthConfig.from_env(mock_mode=True)
# No external dependencies needed for tests
```

### 🎭 User Impersonation
```python
# Debug as another user
impersonated_tokens = await auth.impersonate_user(target_user_id, admin_user_id)
```

### 📈 Built-in Analytics Events
All events automatically tracked:
- Login success/failure rates
- Social provider usage
- MFA adoption
- Session patterns

### 🛠️ CLI Tool (Coming Soon)
```bash
authy init          # Scaffold new project
authy deploy        # Deploy hosted auth
authy migrate       # Run database migrations
```

## 📦 Installation

### Basic
```bash
pip install authy-package
```

### With all features
```bash
pip install authy-package[full]
```

### Development
```bash
git clone https://github.com/yourusername/authy-package.git
cd authy-package
pip install -e ".[dev]"
```

## 🔒 Security

- **JWT Implementation**: RS256/ES256 support with key rotation
- **Password Hashing**: bcrypt and argon2-cffi
- **Webhook Signatures**: HMAC-SHA256 verification
- **Rate Limiting**: Redis-backed distributed rate limiting
- **Audit Logs**: Immutable, compliance-ready logging

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Inspired by Auth0, Clerk, Supabase Auth, and NextAuth.js.

---

**Built with ❤️ for the Python community**

For support, join our [Discord](https://discord.gg/authy) or open an issue on GitHub.
