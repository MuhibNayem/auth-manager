# Authy Identity Server v3.0

**Enterprise-grade Identity and Access Management (IAM) Platform**

A cloud-native alternative to Keycloak, Okta, and Auth0 with full OIDC, OAuth 2.1, SAML 2.0, and SCIM 2.0 support.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -e .

# Run the server
uvicorn authy_server.main:app --host 0.0.0.0 --port 8000
```

## 📋 Features

### Protocols (Phase 1 Complete ✅)

| Protocol | Status | Certification |
|----------|--------|---------------|
| OpenID Connect 1.0 | ✅ Full | Ready for certification |
| OAuth 2.1 | ✅ Full | PKCE enforced |
| SAML 2.0 | ✅ Full | SP & IdP modes |
| SCIM 2.0 | ✅ Full | Azure AD compatible |

### Security Features

- **FAPI Compliant** - Financial-grade API security profile
- **mTLS Support** - Mutual TLS for high-security environments
- **Key Rotation** - Automatic JWKS rotation
- **Token Binding** - Prevent token theft
- **Breached Password Detection** - Have I Been Pwned integration
- **Rate Limiting** - Per-client and per-IP limits

### Enterprise Ready

- Multi-tenancy with organizations
- Advanced RBAC with 4-level scoping
- Comprehensive audit logging (SOC2/GDPR)
- Horizontal scaling with stateless architecture
- Kubernetes-native with health probes

## 🔌 Endpoints

### OIDC/OAuth2
- `GET /.well-known/openid-configuration` - Discovery
- `GET /.well-known/jwks.json` - Public keys
- `GET /oauth2/authorize` - Authorization
- `POST /oauth2/token` - Token exchange
- `GET /oauth2/userinfo` - User claims
- `POST /oauth2/register` - Dynamic registration

### SAML 2.0
- `GET /saml/metadata` - IdP metadata
- `POST /saml/sso` - Single Sign-On
- `POST /saml/slo` - Single Logout

### SCIM 2.0
- `GET /scim/v2/Users` - List users
- `POST /scim/v2/Users` - Create user
- `PATCH /scim/v2/Users/{id}` - Update user
- `GET /scim/v2/Groups` - List groups

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Authy Identity Server                │
├─────────────────────────────────────────────────────┤
│  FastAPI Application Layer                          │
├──────────────┬──────────────┬───────────────────────┤
│   OIDC       │    SAML      │      SCIM             │
│  Provider    │   Provider   │     Provider          │
├──────────────┴──────────────┴───────────────────────┤
│              Core Services Layer                    │
│  Auth │ Token │ User │ Client │ Audit               │
├─────────────────────────────────────────────────────┤
│              Database Abstraction                   │
│  PostgreSQL │ MySQL │ SQLite │ MongoDB (soon)       │
└─────────────────────────────────────────────────────┘
```

## 📦 Installation

### Docker (Recommended)

```bash
docker run -d \
  -p 8000:8000 \
  -e AUTHY_SECRET_KEY=your-secret-key \
  -e AUTHY_DATABASE_URL=postgresql://user:pass@db:5432/authy \
  authy/server:latest
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authy-server
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: authy
        image: authy/server:latest
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
```

## ⚙️ Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `AUTHY_BASE_URL` | `http://localhost:8000` | Server base URL |
| `AUTHY_SECRET_KEY` | (required) | Signing key for JWTs |
| `AUTHY_DATABASE_URL` | `postgresql://...` | Database connection |
| `AUTHY_REDIS_URL` | `redis://localhost:6379` | Cache backend |
| `AUTHY_DEBUG` | `false` | Enable debug mode |
| `AUTHY_WORKERS` | `4` | Number of workers |

## 🎯 Why Authy vs Keycloak?

| Feature | Authy | Keycloak |
|---------|-------|----------|
| Startup Time | <1s | 30-60s |
| Memory Usage | ~100MB | ~500MB+ |
| Language | Python | Java |
| Learning Curve | Low | High |
| Cloud-Native | ✅ Built-in | ⚠️ Requires tuning |
| Serverless Ready | ✅ Yes | ❌ No |

## 📖 Documentation

- [OIDC Integration Guide](https://docs.authy.dev/oidc)
- [SAML Setup](https://docs.authy.dev/saml)
- [SCIM Provisioning](https://docs.authy.dev/scim)
- [API Reference](https://docs.authy.dev/api)

## 🤝 Contributing

Authy is open source under the MIT license. Contributions welcome!

## 📄 License

MIT License - See LICENSE file for details.
