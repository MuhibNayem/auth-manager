# Authy Package - Comprehensive Runbook

## Table of Contents
1. [Quick Start Guide](#quick-start-guide)
2. [Installation & Setup](#installation--setup)
3. [Configuration Reference](#configuration-reference)
4. [Authentication Flows](#authentication-flows)
5. [Organization Management](#organization-management)
6. [Security & Compliance](#security--compliance)
7. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
8. [Production Deployment](#production-deployment)
9. [API Reference](#api-reference)
10. [FAQs](#faqs)

---

## Quick Start Guide

### 5-Minute Setup

```bash
# Install
pip install authy-package

# Set environment variables
export AUTHY_DB_URL="postgresql+asyncpg://user:pass@localhost/dbname"
export AUTHY_REDIS_URL="redis://localhost:6379"
export AUTHY_JWT_SECRET="your-super-secret-key-min-32-chars"

# Run your app
python main.py
```

### Minimal Working Example

```python
import asyncio
from authy_package.core.auth_manager import TraditionalAuthManager
from authy_package.db.sql import SQLDatabase
from authy_package.cache.redis_cache import RedisCaching
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.utils.security import SecurityManager

async def main():
    # Initialize components
    db = SQLDatabase("postgresql+asyncpg://user:pass@localhost/dbname")
    cache = RedisCaching("redis://localhost:6379")
    mfa = MFAAuthManager(db=db)
    security = SecurityManager(db=db, cache=cache, api_key="mailjet_key", api_secret="mailjet_secret")
    
    # Create auth manager
    auth = TraditionalAuthManager(db=db, cache=cache, mfa_manager=mfa, security_manager=security)
    
    # Register and login
    await auth.register_user(username="testuser", email="test@example.com", password="SecurePass123!")
    tokens = await auth.login_user(username="testuser", password="SecurePass123!")
    
    print(f"Access Token: {tokens['access_token']}")
    print(f"Refresh Token: {tokens['refresh_token']}")

asyncio.run(main())
```

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- PostgreSQL 12+ OR MongoDB 4.4+
- Redis 6+
- (Optional) Mailjet/SendGrid account for emails

### Step-by-Step Installation

#### 1. Install Package
```bash
# Basic installation
pip install authy-package

# Full installation with all dependencies
pip install authy-package[full]

# Development installation
git clone https://github.com/yourusername/authy-package.git
cd authy-package
pip install -e ".[dev]"
```

#### 2. Database Setup

**PostgreSQL:**
```sql
CREATE DATABASE authy;
CREATE USER authy_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE authy TO authy_user;
```

**MongoDB:**
```javascript
use authy
db.createUser({
  user: "authy_user",
  pwd: "secure_password",
  roles: ["readWrite"]
})
```

#### 3. Redis Setup
```bash
# Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or install locally
sudo apt-get install redis-server
sudo systemctl start redis
```

#### 4. Environment Configuration
Create `.env` file:
```env
# Required
AUTHY_DB_TYPE=sql
AUTHY_DB_URL=postgresql+asyncpg://authy_user:secure_password@localhost:5432/authy
AUTHY_REDIS_URL=redis://localhost:6379
AUTHY_JWT_SECRET=your-super-secret-key-min-32-chars-long

# Optional but recommended
AUTHY_RATE_LIMIT_ENABLED=true
AUTHY_AUDIT_LOG_RETENTION_DAYS=365
```

---

## Configuration Reference

### Complete Configuration Class

```python
from authy_package.config import (
    AuthConfig, DatabaseConfig, CacheConfig, 
    SecurityConfig, SocialAuthConfig, EmailConfig, CognitoConfig
)

config = AuthConfig(
    # Database Configuration
    database=DatabaseConfig(
        db_type="sql",  # or "mongodb"
        connection_string="postgresql+asyncpg://user:pass@localhost/dbname",
        db_name=None,  # For MongoDB
        collection_name=None,  # For MongoDB
        orm_model=UserModel  # Your SQLAlchemy model
    ),
    
    # Cache/Redis Configuration
    cache=CacheConfig(
        enabled=True,
        redis_url="redis://localhost:6379",
        token_expiration=3600,  # 1 hour
        refresh_token_expiration=604800,  # 7 days
        id_token_expiration=3600
    ),
    
    # Security Configuration
    security=SecurityConfig(
        password_hash_algorithm="bcrypt",  # or "argon2"
        rate_limit_enabled=True,
        rate_limit_max_attempts=5,
        rate_limit_window_seconds=300,
        account_lockout_duration=900,  # 15 minutes
        mfa_required=False,
        jwt_config=JWTConfig(
            secret_key="your-jwt-secret",
            algorithm="HS256",
            access_token_expiration=3600,
            refresh_token_expiration=604800
        )
    ),
    
    # Social Authentication
    social=SocialAuthConfig(
        google_client_id="xxx",
        google_client_secret="xxx",
        google_redirect_uri="https://myapp.com/auth/google/callback",
        
        github_client_id="xxx",
        github_client_secret="xxx",
        github_redirect_uri="https://myapp.com/auth/github/callback",
        
        facebook_app_id="xxx",
        facebook_app_secret="xxx",
        facebook_redirect_uri="https://myapp.com/auth/facebook/callback",
        
        apple_client_id="xxx",
        apple_team_id="xxx",
        apple_key_id="xxx",
        apple_private_key="xxx",
        apple_redirect_uri="https://myapp.com/auth/apple/callback"
    ),
    
    # AWS Cognito
    cognito=CognitoConfig(
        enabled=False,
        region_name="us-east-1",
        user_pool_id="us-east-1_xxxxxxxxx",
        app_client_id="xxxxxxxxxxxx"
    ),
    
    # Email Configuration
    email=EmailConfig(
        enabled=True,
        provider="mailjet",  # or "sendgrid", "ses"
        api_key="mailjet_api_key",
        api_secret="mailjet_api_secret",
        sender_email="noreply@myapp.com",
        sender_name="My App"
    ),
    
    # Application Settings
    app_name="My Application",
    debug=False
)

# Validate before use
config.validate()
```

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTHY_DB_TYPE` | Yes | `sql` | Database type: `sql` or `mongodb` |
| `AUTHY_DB_URL` | Yes | - | Database connection string |
| `AUTHY_DB_NAME` | No | - | MongoDB database name |
| `AUTHY_DB_COLLECTION` | No | - | MongoDB collection name |
| `AUTHY_CACHE_ENABLED` | No | `true` | Enable/disable Redis cache |
| `AUTHY_REDIS_URL` | If cache enabled | `redis://localhost:6379` | Redis connection URL |
| `AUTHY_TOKEN_EXPIRATION` | No | `3600` | Access token TTL in seconds |
| `AUTHY_REFRESH_TOKEN_EXPIRATION` | No | `604800` | Refresh token TTL in seconds |
| `AUTHY_JWT_SECRET` | Yes | - | JWT signing secret (min 32 chars) |
| `AUTHY_RATE_LIMIT_ENABLED` | No | `true` | Enable rate limiting |
| `AUTHY_RATE_LIMIT_MAX_ATTEMPTS` | No | `5` | Max attempts per window |
| `AUTHY_RATE_LIMIT_WINDOW_SECONDS` | No | `300` | Rate limit window (5 min) |
| `MAILJET_API_KEY` | No | - | Mailjet API key |
| `MAILJET_API_SECRET` | No | - | Mailjet API secret |
| `GOOGLE_CLIENT_ID` | No | - | Google OAuth client ID |
| `GITHUB_CLIENT_ID` | No | - | GitHub OAuth client ID |
| `COGNITO_USER_POOL_ID` | No | - | AWS Cognito user pool ID |
| `AUTHY_AUDIT_LOG_RETENTION_DAYS` | No | `365` | Audit log retention period |

---

## Authentication Flows

### 1. Traditional Username/Password

```python
from authy_package.core.auth_manager import TraditionalAuthManager

# Registration
await auth.register_user(
    username="johndoe",
    email="john@example.com",
    phone="+1234567890",  # Optional
    password="SecurePass123!"
)

# Login (without MFA)
tokens = await auth.login_user(
    username="johndoe",  # or email=, or phone=
    password="SecurePass123!"
)
# Returns: {"access_token": "...", "refresh_token": "..."}

# Login with MFA
tokens = await auth.login_user(
    email="john@example.com",
    password="SecurePass123!",
    mfa_code="123456"  # From authenticator app
)

# Logout
await auth.logout_user(
    access_token=tokens["access_token"],
    username="johndoe"
)

# Token Refresh
new_tokens = await auth.refresh_token(
    refresh_token=tokens["refresh_token"]
)
```

### 2. Magic Link (Passwordless)

```python
from authy_package.passwordless.magic_link import MagicLinkManager

magic = MagicLinkManager(db=db, cache=cache, config=config)

# Send magic link
await magic.send_magic_link(
    email="user@example.com",
    redirect_url="https://myapp.com/auth/callback?next=/dashboard"
)

# User clicks link, verify token
user = await magic.verify_magic_link(token="magic_link_token_from_url")

# Returns user object if valid, raises exception if expired/invalid
```

### 3. Passkeys/WebAuthn

```python
from authy_package.passwordless.passkey import PasskeyManager

passkeys = PasskeyManager(db=db, config=config)

# Registration Flow
# Step 1: Generate creation options
options = await passkeys.register_start(
    user_id="user123",
    email="user@example.com",
    display_name="John Doe"
)
# Return options to client for WebAuthn navigator.credentials.create()

# Step 2: Complete registration with client response
credential = await passkeys.register_complete(
    user_id="user123",
    response=client_credential_response
)

# Authentication Flow
# Step 1: Generate request options
options = await passkeys.authenticate_start()

# Step 2: Verify client response
user = await passkeys.authenticate_complete(
    response=client_assertion_response
)
```

### 4. Multi-Factor Authentication (MFA)

```python
# Enable MFA for user
mfa_setup = await auth.enable_mfa(username="johndoe")
# Returns: {"mfa_secret": "JBSWY3DPEHPK3PXP..."}

# Generate QR code for Google Authenticator
import qrcode
qr_data = f"otpauth://totp/MyApp:johndoe?secret={mfa_setup['mfa_secret']}&issuer=MyApp"
qrcode.make(qr_data).save("mfa_qr.png")

# Reconfigure MFA (generate new secret)
await auth.reconfigure_mfa(username="johndoe")

# Disable MFA (implement in your app logic)
# Set user.mfa_enabled = False in database
```

### 5. Password Reset Flow

```python
# Step 1: User requests reset
await auth.request_password_reset(
    email="john@example.com",
    username=None,
    phone=None,
    sender_email="noreply@myapp.com",
    sender_name="My App Support"
)

# Step 2: User receives email with reset link
# Link contains token: https://myapp.com/reset?token=abc123

# Step 3: Validate token (optional, can skip to step 4)
user_identifier = await auth.security_manager.validate_reset_token(token="abc123")

# Step 4: Reset password
await auth.reset_password(
    email="john@example.com",
    token="abc123",
    new_password="NewSecurePass123!"
)
```

### 6. Social OAuth

```python
from authy_package.social.google import GoogleManager

google = GoogleManager(
    client_id="google_client_id",
    client_secret="google_client_secret",
    redirect_uri="https://myapp.com/auth/google/callback"
)

# Step 1: Redirect user to Google
auth_url = google.get_authorization_url()
# Redirect user to auth_url

# Step 2: Handle callback
# User redirected to: /auth/google/callback?code=authorization_code

# Step 3: Exchange code for tokens
tokens = await google.exchange_code(code="authorization_code")

# Step 4: Get user info
user_info = await google.get_user_info(access_token=tokens["access_token"])
# {"id": "...", "email": "...", "name": "...", "picture": "..."}

# Step 5: Create or update user in your database
```

### 7. AWS Cognito

```python
from authy_package.cognito.cognito_manager import CognitoManager
from authy_package.core.auth_manager import CognitoAuthManager

cognito = CognitoManager(
    region_name="us-east-1",
    user_pool_id="us-east-1_xxxxxxxxx",
    app_client_id="xxxxxxxxxxxx"
)
cognito_auth = CognitoAuthManager(cognito_manager=cognito)

# Register
await cognito_auth.register_user(
    username="johndoe",
    password="SecurePass123!",
    email="john@example.com",
    phone_number="+1234567890"
)

# Login
tokens = await cognito_auth.login_user(
    username="johndoe",
    password="SecurePass123!"
)

# Social login via Cognito
auth_url = await cognito_auth.initiate_social_login(
    provider="Google",
    redirect_uri="https://myapp.com/callback"
)

# Confirm user account (email verification)
await cognito_auth.confirm_user_account(
    username="johndoe",
    confirmation_code="123456"
)

# Password reset
await cognito_auth.reset_password(username="johndoe")
await cognito_auth.confirm_password(
    username="johndoe",
    confirmation_code="123456",
    new_password="NewPass123!"
)
```

---

## Organization Management

### Creating Organizations

```python
from authy_package.organizations.org_manager import OrganizationManager, OrgRole

org_mgr = OrganizationManager(config=config, db=db, cache=cache)

# Create organization
org = await org_mgr.create_organization(
    name="Acme Corporation",
    owner_id="user_123",
    slug="acme-corp",  # Optional, auto-generated if not provided
    metadata={"industry": "tech", "size": "startup"}
)

# Get organization
org = await org_mgr.get_organization(org_id="org_uuid")
org = await org_mgr.get_organization_by_slug(slug="acme-corp")

# Get all organizations for a user
orgs = await org_mgr.get_user_organizations(user_id="user_123")
```

### Managing Members

```python
# Add member directly
member = await org_mgr.add_member(
    org_id="org_uuid",
    user_id="user_456",
    role=OrgRole.MEMBER,  # OWNER, ADMIN, MEMBER, GUEST
    invited_by="user_123"
)

# Get member role
role = await org_mgr.get_member_role(
    org_id="org_uuid",
    user_id="user_456"
)
# Returns: OrgRole.MEMBER

# Update member role
await org_mgr.update_member_role(
    org_id="org_uuid",
    user_id="user_456",
    new_role=OrgRole.ADMIN
)

# Remove member
await org_mgr.remove_member(
    org_id="org_uuid",
    user_id="user_456"
)
# Note: Cannot remove last owner

# Get all members
members = await org_mgr.get_members(org_id="org_uuid")
```

### Invitation System

```python
# Send invitation
invitation = await org_mgr.send_invitation(
    org_id="org_uuid",
    email="newmember@example.com",
    role=OrgRole.GUEST,
    invited_by="user_123"
)

# Accept invitation
member = await org_mgr.accept_invitation(
    token="invitation_token",
    user_id="user_789"
)

# Decline invitation
await org_mgr.decline_invitation(token="invitation_token")

# Invitations expire after 7 days by default
```

### Role Hierarchy

```
OWNER  ──→ Can do everything, transfer ownership, delete org
  │
  └──→ ADMIN  ──→ Manage members, update org settings
       │
       └──→ MEMBER  ──→ Access org resources
            │
            └──→ GUEST  ──→ Read-only access
```

---

## Security & Compliance

### Audit Logging

```python
from authy_package.admin.audit_logger import AuditLogger, EventType

audit = AuditLogger(config=config, db=db, cache=cache)

# Log events
await audit.log(
    event_type=EventType.LOGIN_SUCCESS,
    action="User logged in successfully",
    actor_id="user_123",
    actor_email="user@example.com",
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0...",
    metadata={"session_id": "sess_abc"},
    organization_id="org_123",
    severity="info",  # info, warning, error, critical
    status="success"  # success, failure
)

# Search logs
events = await audit.search(
    actor_id="user_123",
    event_type=EventType.LOGIN_FAILED,
    start_date=datetime.now() - timedelta(days=7),
    end_date=datetime.now(),
    severity="warning",
    limit=100
)

# Get security events
security_events = await audit.get_security_events(
    organization_id="org_123",
    limit=50
)

# Export for compliance
csv_export = await audit.export_events(
    filters={"organization_id": "org_123"},
    format="csv"  # or "json"
)

# Get statistics
stats = await audit.get_statistics(
    start_date=datetime.now() - timedelta(days=30),
    end_date=datetime.now(),
    group_by="event_type"
)

# Cleanup old events
deleted_count = await audit.cleanup_old_events()
```

### Event Types Reference

```python
class EventType(Enum):
    # Authentication
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"
    
    # User Management
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_VERIFIED = "user.verified"
    
    # Session Management
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"
    
    # MFA
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    MFA_CODE_VERIFIED = "mfa.code.verified"
    MFA_CODE_FAILED = "mfa.code.failed"
    
    # Social Auth
    SOCIAL_LINKED = "social.linked"
    SOCIAL_UNLINKED = "social.unlinked"
    SOCIAL_LOGIN = "social.login"
    
    # Organization
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    MEMBER_ADDED = "org.member.added"
    MEMBER_REMOVED = "org.member.removed"
    ROLE_CHANGED = "org.role.changed"
    INVITATION_SENT = "org.invitation.sent"
    INVITATION_ACCEPTED = "org.invitation.accepted"
    
    # Security
    SUSPICIOUS_ACTIVITY = "security.suspicious"
    RATE_LIMIT_EXCEEDED = "security.rate_limit"
    ACCOUNT_LOCKED = "security.account_locked"
    ACCOUNT_UNLOCKED = "security.account_unlocked"
    
    # Admin
    ADMIN_ACTION = "admin.action"
    DATA_EXPORT = "admin.data_export"
    USER_IMPERSONATION = "admin.user_impersonation"
```

### Webhooks

```python
from authy_package.webhooks.webhook_manager import WebhookManager, WebhookEventType
import httpx

http_client = httpx.AsyncClient()
webhooks = WebhookManager(config=config, db=db, cache=cache, http_client=http_client)

# Register endpoint
endpoint = await webhooks.register_endpoint(
    url="https://api.example.com/webhooks/auth",
    events=[
        WebhookEventType.USER_CREATED,
        WebhookEventType.USER_LOGGED_IN,
        WebhookEventType.PASSWORD_RESET_REQUESTED
    ],
    secret="your-webhook-secret"  # Auto-generated if not provided
)

# Dispatch event
await webhooks.dispatch_event(
    event_type=WebhookEventType.USER_CREATED,
    payload={"user_id": "user_123", "email": "user@example.com"},
    sync=False  # Async delivery recommended
)

# List endpoints
endpoints = await webhooks.list_endpoints()

# Delete endpoint
await webhooks.delete_endpoint(endpoint_id="ep_uuid")
```

### Verifying Webhooks (Receiver Side)

```python
from fastapi import FastAPI, Request, HTTPException
from authy_package.webhooks.webhook_manager import WebhookManager

app = FastAPI()

@app.post("/webhooks/auth")
async def handle_webhook(request: Request):
    payload = await request.json()
    signature = request.headers.get("X-Webhook-Signature")
    timestamp = request.headers.get("X-Webhook-Timestamp")
    
    is_valid = WebhookManager.verify_signature(
        payload=payload,
        signature=signature,
        secret="your-webhook-secret",
        timestamp=timestamp,
        tolerance_seconds=300
    )
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Process webhook
    event_type = payload.get("type")
    event_data = payload.get("data")
    
    return {"status": "ok"}
```

### Rate Limiting

```python
# Built-in rate limiting in framework adapters
from authy_package.frameworks.fastapi_adapter import FastAPIAuth

fastapi_auth = FastAPIAuth(auth)

@app.post("/login")
async def login(rate_check=Depends(fastapi_auth.rate_limit(5, 60))):
    # Max 5 requests per minute per IP
    pass

# Manual rate limiting
from authy_package.utils.security import SecurityManager

security = SecurityManager(db=db, cache=cache)

# Check rate limit
is_allowed = await security.check_rate_limit(
    identifier="user_123",  # or IP address
    action="login",
    max_attempts=5,
    window_seconds=300
)

if not is_allowed:
    raise Exception("Rate limit exceeded")
```

---

## Monitoring & Troubleshooting

### Health Checks

```python
async def check_database_health(db):
    try:
        await db.health_check()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

async def check_redis_health(cache):
    try:
        await cache.ping()
        return {"status": "healthy", "cache": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/health")
async def health_check():
    db_health = await check_database_health(db)
    cache_health = await check_redis_health(cache)
    
    overall_status = "healthy" if (
        db_health["status"] == "healthy" and 
        cache_health["status"] == "healthy"
    ) else "unhealthy"
    
    return {
        "status": overall_status,
        "components": {
            "database": db_health,
            "cache": cache_health
        }
    }
```

### Common Issues & Solutions

#### Issue: "Invalid JWT Secret"
```python
# Solution: Ensure JWT secret is at least 32 characters
import secrets
secure_secret = secrets.token_hex(32)  # Generate secure secret
print(f"AUTHY_JWT_SECRET={secure_secret}")
```

#### Issue: "Redis Connection Failed"
```bash
# Check Redis is running
redis-cli ping  # Should return PONG

# Check connection string
echo $AUTHY_REDIS_URL  # Should be redis://localhost:6379

# Test connection
python -c "import redis; r = redis.from_url('redis://localhost:6379'); print(r.ping())"
```

#### Issue: "Database Connection Timeout"
```python
# For PostgreSQL, check connection pool settings
# Add to connection string:
DATABASE_URL="postgresql+asyncpg://user:pass@host/dbname?min_size=5&max_size=20"
```

#### Issue: "Magic Links Not Sending"
```python
# Verify email configuration
config.email.validate()

# Check Mailjet credentials
from authy_package.utils.security import SecurityManager
security = SecurityManager(db=db, cache=cache, api_key="xxx", api_secret="xxx")

# Test send
await security.send_email(
    to="test@example.com",
    subject="Test",
    body="Test email"
)
```

### Logging Best Practices

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('authy.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('authy_package')

# In your code
try:
    await auth.login_user(username="user", password="pass")
except ValueError as e:
    logger.warning(f"Login failed: {str(e)}", extra={"username": "user"})
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
```

---

## Production Deployment

### Docker Compose Setup

```yaml
version: '3.8'

services:
  app:
    build: .
    environment:
      - AUTHY_DB_URL=postgresql+asyncpg://authy:password@db:5432/authy
      - AUTHY_REDIS_URL=redis://redis:6379
      - AUTHY_JWT_SECRET=${AUTHY_JWT_SECRET}
    depends_on:
      - db
      - redis
    ports:
      - "8000:8000"

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=authy
      - POSTGRES_USER=authy
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authy-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authy
  template:
    metadata:
      labels:
        app: authy
    spec:
      containers:
      - name: authy
        image: your-registry/authy:latest
        env:
        - name: AUTHY_DB_URL
          valueFrom:
            secretKeyRef:
              name: authy-secrets
              key: database-url
        - name: AUTHY_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: authy-secrets
              key: jwt-secret
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
```

### Performance Tuning

```python
# Optimize database connection pool
DATABASE_URL = "postgresql+asyncpg://user:pass@host/dbname?min_size=10&max_size=50"

# Tune Redis
REDIS_URL = "redis://localhost:6379?max_connections=100"

# Adjust JWT expiration based on use case
JWT_ACCESS_TOKEN_EXPIRATION = 900  # 15 minutes for high-security apps
JWT_REFRESH_TOKEN_EXPIRATION = 86400  # 1 day

# Batch audit log writes
audit._queue_size_limit = 200  # Increase from default 100
```

---

## API Reference

### TraditionalAuthManager

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `register_user` | username, email, phone, password | dict | Register new user |
| `login_user` | username/email/phone, password, mfa_code | dict | Login and get tokens |
| `logout_user` | access_token, username/pk | dict | Logout and invalidate tokens |
| `refresh_token` | refresh_token | dict | Get new token pair |
| `enable_mfa` | username/email/phone | dict | Enable MFA for user |
| `reconfigure_mfa` | username/email/phone | dict | Regenerate MFA secret |
| `request_password_reset` | email/username/phone, sender_email, sender_name | dict | Send reset email |
| `reset_password` | email, token, new_password | dict | Reset password with token |

### OrganizationManager

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `create_organization` | name, owner_id, slug, metadata | Organization | Create new org |
| `get_organization` | org_id | Organization | Get org by ID |
| `get_organization_by_slug` | slug | Organization | Get org by slug |
| `get_user_organizations` | user_id | List[Organization] | Get user's orgs |
| `add_member` | org_id, user_id, role, invited_by | OrgMember | Add member |
| `remove_member` | org_id, user_id | bool | Remove member |
| `update_member_role` | org_id, user_id, new_role | bool | Update role |
| `get_member_role` | org_id, user_id | OrgRole | Get user's role |
| `send_invitation` | org_id, email, role, invited_by | Invitation | Send invite |
| `accept_invitation` | token, user_id | OrgMember | Accept invite |

### AuditLogger

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `log` | event_type, action, actor_id, ... | None | Log event |
| `search` | actor_id, event_type, dates, limit | List[AuditEvent] | Search logs |
| `get_event` | event_id | AuditEvent | Get single event |
| `get_user_timeline` | user_id, limit | List[AuditEvent] | User's events |
| `get_security_events` | org_id, limit | List[AuditEvent] | Security events |
| `export_events` | filters, format | str | Export logs |
| `get_statistics` | start_date, end_date, group_by | dict | Get stats |

---

## FAQs

### Q: How do I migrate from Auth0?
A: Use the export feature in Auth0 to get user data, then use our migration scripts (coming soon) to import users. Password hashes may need re-hashing on first login.

### Q: Can I use multiple databases?
A: Yes, initialize separate `SQLDatabase` or `MongoDB` instances and route users accordingly.

### Q: How do I implement custom claims in JWT?
A: Modify the `JWTTokenManager.create_access_token()` method to include additional claims in the payload.

### Q: Is session persistence guaranteed?
A: Sessions are stored in Redis for performance. Enable Redis AOF persistence for durability.

### Q: Can I disable password authentication?
A: Yes, don't expose the traditional login endpoints and only enable passwordless/social methods.

### Q: How do I handle GDPR data deletion requests?
A: Use `audit.export_events()` to backup user data, then implement custom deletion logic for your user tables.

### Q: What's the recommended token expiration?
A: Access tokens: 15-60 minutes. Refresh tokens: 1-7 days. Adjust based on security requirements.

### Q: Can I use Authy with serverless (Lambda)?
A: Yes, but use managed services (RDS, ElastiCache) instead of self-hosted databases.

---

**Last Updated**: 2024
**Version**: 2.0.0

For additional support, see the main README.md or open an issue on GitHub.
