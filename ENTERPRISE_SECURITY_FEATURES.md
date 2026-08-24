# Enterprise Security Features Guide

This guide covers the three major enterprise security features added to Tessera Package:
1. **Phone/SMS Authentication** - Vendor-agnostic SMS verification
2. **Bot Protection** - CAPTCHA and behavioral analysis
3. **Breached Password Detection** - Have I Been Pwned integration

All features are designed to be **vendor-agnostic** and **easy to configure**.

These subsystems were rebuilt during the 2.0 remediation against
`docs/CONTRACTS.md` (§2 configuration, §3 cache key schema, §6 login
hardening).

---

## 1. Phone/SMS Authentication

### Overview
Enterprise-grade SMS verification with support for multiple providers (Twilio, AWS SNS, etc.). Features include:
- Automatic code generation
- Rate limiting
- Expiration handling
- Attempt tracking
- Customizable message templates

### Quick Setup

#### Option A: Twilio (Recommended)

**Step 1: Install dependency**
```bash
pip install "tessera[sms]"   # twilio + boto3
```

**Step 2: Configure environment variables**
```bash
export TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxx
export TWILIO_AUTH_TOKEN=your_auth_token
export TWILIO_FROM_NUMBER=+1234567890
export TESSERA_SMS_ENABLED=true
export TESSERA_SMS_PROVIDER=twilio
```

**Step 3: Initialize in your application**
```python
from tessera.sms import SMSManager, TwilioProvider

# Initialize provider (auto-loads from env vars)
provider = TwilioProvider.from_env()

# Create manager with Redis cache (recommended for production)
sms_manager = SMSManager(
    provider=provider,
    cache=redis_cache_instance,
    code_length=6,
    expiration_seconds=300,  # 5 minutes
    max_attempts=3
)

# Send verification code
result = await sms_manager.send_verification_code("+1234567890")
print(f"Code sent! Message ID: {result['message_id']}")

# Verify code
try:
    verification = await sms_manager.verify_code("+1234567890", "123456")
    print("Phone verified!")
except InvalidVerificationCodeError as e:
    print(f"Invalid code: {e}")
except VerificationCodeExpiredError as e:
    print(f"Code expired: {e}")
except TooManyAttemptsError as e:
    print(f"Too many attempts: {e}")
```

#### Option B: AWS SNS

**Step 1: Install dependency**
```bash
pip install "tessera[sms]"   # twilio + boto3
```

**Step 2: Configure environment and credentials**
```bash
export AWS_REGION=us-east-1
export TESSERA_SMS_ENABLED=true
export TESSERA_SMS_PROVIDER=aws_sns
```

Credentials must come from the standard AWS credential provider chain —
an IAM role for the service (recommended), AWS SSO, or a shared
credentials file. **Never export static access keys**; see
[AWS_SECURITY_GUIDE.md](AWS_SECURITY_GUIDE.md).

**Step 3: Initialize**
```python
from tessera.sms import SMSManager, AWSSNSProvider

provider = AWSSNSProvider.from_env()
sms_manager = SMSManager(provider=provider, cache=redis_cache_instance)
```

### Advanced Configuration

```python
from tessera.config import AuthConfig, SMSConfig

config = AuthConfig(
    sms=SMSConfig(
        enabled=True,
        provider="twilio",
        twilio_account_sid="AC...",
        twilio_auth_token="token",
        twilio_from_number="+1234567890",
        
        # Verification code settings
        code_length=6,
        expiration_seconds=300,
        max_attempts=3,
        rate_limit_window_seconds=60,
        max_sends_per_window=3,
    )
)
```

### Custom Message Templates

```python
sms_manager = SMSManager(
    provider=provider,
    template="Your {app_name} verification code is: {code}. Valid for {minutes} minutes. Do not share this code."
)

# Or send custom message per request
await sms_manager.send_verification_code(
    phone="+1234567890",
    custom_message="Your login code: {code}. Expires in 5 min."
)
```

### Integration with Auth Flow

```python
from tessera.core.auth_manager import TraditionalAuthManager
from tessera.sms import SMSManager, TwilioProvider

# Setup
provider = TwilioProvider.from_env()
sms_manager = SMSManager(provider=provider, cache=cache)
auth_manager = TraditionalAuthManager(db=db, cache=cache)

# Registration with phone verification
async def register_with_phone(username, email, phone, password):
    # 1. Register user (unverified)
    user = await auth_manager.register_user(
        username=username,
        email=email,
        phone=phone,
        password=password
    )
    
    # 2. Send verification code
    await sms_manager.send_verification_code(phone)
    
    return {"user": user, "requires_phone_verification": True}

# Verify phone after registration
async def verify_phone(phone, code):
    result = await sms_manager.verify_code(phone, code)
    
    if result["success"]:
        # Update user record to mark phone as verified
        await db.update_user_phone_verified(phone, verified=True)
        return {"success": True, "message": "Phone verified"}
    
    return {"success": False}
```

### Adding More Providers

To add a new SMS provider (e.g., Vonage):

```python
# tessera/sms/vonage_provider.py
from .abstract_provider import AbstractSMSProvider, SMSResponse

class VonageProvider(AbstractSMSProvider):
    def __init__(self, api_key, api_secret, from_number):
        self.api_key = api_key
        self.api_secret = api_secret
        self.from_number = from_number
    
    async def send_sms(self, to, body, from_number=None):
        # Implement Vonage API call
        pass
    
    async def check_delivery_status(self, message_id):
        pass
    
    @property
    def provider_name(self):
        return "Vonage"
```

---

## 2. Bot Protection

### Overview
Multi-layered bot protection with CAPTCHA verification, rate limiting, and behavioral analysis. Supports hCaptcha and Google reCAPTCHA.

### Quick Setup

#### Option A: hCaptcha (Recommended)

**Step 1: Get hCaptcha keys**
- Sign up at https://www.hcaptcha.com/
- Create a new site
- Get your Site Key and Secret Key

**Step 2: Configure environment variables**
```bash
export HCAPTCHA_SITE_KEY=your_site_key
export HCAPTCHA_SECRET_KEY=your_secret_key
export TESSERA_BOT_PROTECTION_ENABLED=true
export TESSERA_CAPTCHA_PROVIDER=hcaptcha
```

**Step 3: Initialize**
```python
from tessera.bot_protection import BotProtectionManager, hCaptchaProvider

# Initialize provider
provider = hCaptchaProvider.from_env()

# Create bot protection manager
bot_manager = BotProtectionManager(
    provider=provider,
    cache=redis_cache_instance,
    enable_rate_limiting=True,
    max_requests_per_minute=10,
    max_requests_per_hour=100,
    enable_behavioral_analysis=True
)
```

#### Option B: Google reCAPTCHA

**Step 1: Get reCAPTCHA keys**
- Sign up at https://www.google.com/recaptcha/admin
- Choose reCAPTCHA v3 (recommended) or v2
- Get your Site Key and Secret Key

**Step 2: Configure environment variables**
```bash
export RECAPTCHA_SITE_KEY=your_site_key
export RECAPTCHA_SECRET_KEY=your_secret_key
export RECAPTCHA_VERSION=v3
export RECAPTCHA_MIN_SCORE=0.5
export TESSERA_CAPTCHA_PROVIDER=recaptcha
```

**Step 3: Initialize**
```python
from tessera.bot_protection import BotProtectionManager, ReCaptchaProvider

provider = ReCaptchaProvider.from_env()
bot_manager = BotProtectionManager(provider=provider, cache=cache)
```

### Frontend Integration

#### hCaptcha Widget (HTML/React/Vue)

```html
<!-- Add to your login/register form -->
<div class="h-captcha" data-sitekey="your_site_key"></div>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
```

```javascript
// React example
import { useEffect } from 'react';

function LoginForm() {
  const [captchaToken, setCaptchaToken] = useState(null);
  
  useEffect(() => {
    // Load hCaptcha
    window.hcaptcha.render('captcha-container', {
      sitekey: process.env.HCAPTCHA_SITE_KEY,
      callback: (token) => setCaptchaToken(token)
    });
  }, []);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Send to backend with captcha token
    await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        captcha_token: captchaToken,
        captcha_provider: 'hcaptcha'
      })
    });
  };
  
  return (
    <form onSubmit={handleSubmit}>
      {/* ... other fields ... */}
      <div id="captcha-container" />
      <button type="submit">Login</button>
    </form>
  );
}
```

#### reCAPTCHA v3 (Invisible)

```html
<!-- Add to your page -->
<script src="https://www.google.com/recaptcha/api.js?render=your_site_key"></script>
<script>
  grecaptcha.ready(async function() {
    const token = await grecaptcha.execute('your_site_key', {action: 'login'});
    // Include token in form submission
  });
</script>
```

### Backend Verification

```python
from tessera.bot_protection import (
    BotProtectionManager, 
    hCaptchaProvider,
    RateLimitExceededError,
    SuspiciousActivityError
)

# Initialize
provider = hCaptchaProvider.from_env()
bot_manager = BotProtectionManager(provider=provider, cache=cache)

@app.post("/login")
async def login(request: LoginRequest):
    # 1. Check rate limit first
    try:
        identifier = f"login:{request.username}"
        await bot_manager.check_rate_limit(identifier)
    except RateLimitExceededError as e:
        return JSONResponse(
            status_code=429,
            content={"error": "Too many attempts", "retry_after": e.retry_after}
        )
    
    # 2. Verify CAPTCHA
    captcha_result = await bot_manager.verify_captcha(
        token=request.captcha_token,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        action="login"
    )
    
    if not captcha_result.is_human:
        raise SuspiciousActivityError("Bot detected")
    
    if captcha_result.risk_level == RiskLevel.HIGH:
        # Require additional verification
        logger.warning(f"High risk login attempt: {request.username}")
    
    # 3. Proceed with authentication
    user = await auth_manager.login_user(...)
    return user
```

### Advanced Configuration

```python
from tessera.config import AuthConfig, BotProtectionConfig

config = AuthConfig(
    bot_protection=BotProtectionConfig(
        enabled=True,
        provider="hcaptcha",
        hcaptcha_secret_key="secret",
        hcaptcha_site_key="site_key",
        
        # Rate limiting
        enable_rate_limiting=True,
        max_requests_per_minute=10,
        max_requests_per_hour=100,
        
        # Behavioral analysis
        enable_behavioral_analysis=True,
        
        # Actions requiring CAPTCHA
        captcha_required_actions=["login", "register", "password_reset", "email_change"]
    )
)
```

### Custom Risk Thresholds

```python
bot_manager = BotProtectionManager(
    provider=provider,
    risk_threshold_medium=0.5,  # Adjust based on your needs
    risk_threshold_high=0.8
)

# In your auth flow
captcha_result = await bot_manager.verify_captcha(token, ip, user_agent)

if captcha_result.risk_score > 0.7:
    # Require MFA for high-risk logins
    require_mfa = True
elif captcha_result.risk_score > 0.4:
    # Log suspicious activity
    logger.warning(f"Medium risk: {captcha_result}")
```

---

## 3. Breached Password Detection

### Overview
Check passwords against the Have I Been Pwned database using k-anonymity (privacy-preserving). Never allows users to set compromised passwords.

### Quick Setup

**Step 1: Get HIBP API key (optional but recommended)**
- Sign up at https://haveibeenpwned.com/API/v3
- Get your API key (free, higher rate limits)

**Step 2: Configure environment variables**
```bash
export HIBP_API_KEY=your_api_key
export TESSERA_CHECK_BREACHED_PASSWORDS=true
export TESSERA_PASSWORD_MIN_LENGTH=12
```

**Step 3: Initialize**
```python
from tessera.password_security import (
    PasswordSecurityManager,
    HibpProvider,
    PasswordPolicy
)

# Initialize HIBP provider
hibp_provider = HibpProvider.from_env()  # Works without API key too

# Create password policy
policy = PasswordPolicy(
    min_length=12,
    require_uppercase=True,
    require_lowercase=True,
    require_numbers=True,
    require_special_chars=True,
    check_breached=True,
    disallow_common_passwords=True,
    disallow_sequential_chars=True,
    disallow_repeated_chars=True
)

# Create manager
password_manager = PasswordSecurityManager(
    hibp_provider=hibp_provider,
    policy=policy,
    cache=redis_cache_instance  # For caching breach checks
)
```

### Password Validation

```python
# Simple validation
is_valid, errors = await password_manager.validate_password(
    password="MySecureP@ss123",
    username="john_doe"
)

if not is_valid:
    return {"error": "Weak password", "details": errors}

# Detailed strength assessment
result = await password_manager.assess_password_strength(
    password="MySecureP@ss123",
    username="john_doe"
)

print(f"Strength: {result.strength_level} ({result.strength_score:.2f})")
print(f"Valid: {result.is_valid}")
print(f"Breached: {result.is_breached} ({result.breach_count} times)")
print(f"Suggestions: {result.suggestions}")
```

### Integration with Registration

```python
from tessera.core.auth_manager import TraditionalAuthManager
from tessera.password_security import PasswordSecurityManager, HibpProvider

# Setup
hibp = HibpProvider.from_env()
password_mgr = PasswordSecurityManager(hibp_provider=hibp)
auth_mgr = TraditionalAuthManager(db=db, cache=cache)

@app.post("/register")
async def register(request: RegisterRequest):
    # 1. Validate password strength
    is_valid, errors = await password_mgr.validate_password(
        password=request.password,
        username=request.username
    )
    
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"error": "Password does not meet requirements", "details": errors}
        )
    
    # 2. Get detailed assessment (optional, for UI feedback)
    assessment = await password_mgr.assess_password_strength(
        password=request.password,
        username=request.username
    )
    
    # 3. If breached, reject immediately
    if assessment.is_breached:
        return JSONResponse(
            status_code=400,
            content={
                "error": "This password has been compromised in data breaches",
                "breach_count": assessment.breach_count,
                "suggestion": "Please choose a unique password"
            }
        )
    
    # 4. Proceed with registration
    user = await auth_mgr.register_user(
        username=request.username,
        email=request.email,
        password=request.password
    )
    
    return {"user": user, "password_strength": assessment.strength_level}
```

### Custom Password Policies

```python
# Enterprise policy (very strict)
enterprise_policy = PasswordPolicy(
    min_length=16,
    max_length=128,
    require_uppercase=True,
    require_lowercase=True,
    require_numbers=True,
    require_special_chars=True,
    special_chars="!@#$%^&*()_+-=[]{}|;:,.<>?/",
    check_breached=True,
    min_breach_count=1,  # Reject even if breached once
    disallow_common_passwords=True,
    disallow_sequential_chars=True,
    disallow_repeated_chars=True,
    max_repeated_chars=2,
    disallow_username_in_password=True
)

# Consumer policy (more lenient)
consumer_policy = PasswordPolicy(
    min_length=8,
    require_uppercase=True,
    require_lowercase=True,
    require_numbers=True,
    require_special_chars=False,
    check_breached=True,
    min_breach_count=100,  # Only reject if widely breached
    disallow_common_passwords=True,
    disallow_sequential_chars=False,
    disallow_repeated_chars=True,
    max_repeated_chars=4,
    disallow_username_in_password=True
)
```

### Privacy Note

This implementation uses **k-anonymity**:
1. Password is hashed with SHA1 locally
2. Only first 5 characters of hash are sent to HIBP API
3. Full password **never** leaves your server
4. Response contains all hashes starting with those 5 characters
5. Local comparison determines if password is breached

```python
# Example of what's sent to API:
# Password: "password123"
# SHA1: 40BD001563085FC35165329EA1FF5C5ECBDBBEEF
# Sent to API: "40BD0" (first 5 chars only)
# API returns ~500 hashes starting with "40BD0"
# We check locally if full hash is in response
```

---

## Complete Example: Secure Registration Flow

```python
from fastapi import FastAPI, HTTPException
from tessera.config import AuthConfig
from tessera.sms import SMSManager, TwilioProvider
from tessera.bot_protection import BotProtectionManager, hCaptchaProvider
from tessera.password_security import PasswordSecurityManager, HibpProvider
from tessera.core.auth_manager import TraditionalAuthManager

app = FastAPI()

# Initialize all components
config = AuthConfig.from_env()

# SMS
sms_provider = TwilioProvider.from_env()
sms_manager = SMSManager(provider=sms_provider, cache=redis_cache)

# Bot protection
captcha_provider = hCaptchaProvider.from_env()
bot_manager = BotProtectionManager(provider=captcha_provider, cache=redis_cache)

# Password security
hibp_provider = HibpProvider.from_env()
password_manager = PasswordSecurityManager(hibp_provider=hibp_provider)

# Auth
auth_manager = TraditionalAuthManager(db=db, cache=redis_cache)

@app.post("/register")
async def register(request: RegisterRequest):
    # 1. Rate limiting
    try:
        await bot_manager.check_rate_limit(f"register:{request.ip}")
    except RateLimitExceededError:
        raise HTTPException(status_code=429, detail="Too many attempts")
    
    # 2. CAPTCHA verification
    captcha_result = await bot_manager.verify_captcha(
        token=request.captcha_token,
        ip_address=request.ip,
        user_agent=request.user_agent,
        action="register"
    )
    
    if not captcha_result.is_human:
        raise HTTPException(status_code=400, detail="Bot detected")
    
    # 3. Password validation
    is_valid, errors = await password_manager.validate_password(
        password=request.password,
        username=request.username
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail={"error": "Weak password", "issues": errors}
        )
    
    # 4. Check if breached
    assessment = await password_manager.assess_password_strength(
        password=request.password,
        username=request.username
    )
    
    if assessment.is_breached:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Password has been compromised",
                "breach_count": assessment.breach_count
            }
        )
    
    # 5. Register user
    user = await auth_manager.register_user(
        username=request.username,
        email=request.email,
        phone=request.phone,
        password=request.password
    )
    
    # 6. Send phone verification (if phone provided)
    if request.phone:
        await sms_manager.send_verification_code(request.phone)
        user["requires_phone_verification"] = True
    
    return {
        "user": user,
        "password_strength": assessment.strength_level,
        "message": "Registration successful"
    }

@app.post("/verify-phone")
async def verify_phone(request: VerifyPhoneRequest):
    try:
        result = await sms_manager.verify_code(request.phone, request.code)
        return {"success": True, "message": "Phone verified"}
    except (InvalidVerificationCodeError, VerificationCodeExpiredError, TooManyAttemptsError) as e:
        raise HTTPException(status_code=400, detail=str(e))
```

---

## Environment Variables Reference

### SMS
```bash
TESSERA_SMS_ENABLED=true
TESSERA_SMS_PROVIDER=twilio  # or aws_sns

# Twilio
TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=+1234567890
TWILIO_MESSAGING_SERVICE_SID=MG...

# AWS SNS (credentials via IAM role / credential chain — see AWS_SECURITY_GUIDE.md)
AWS_REGION=us-east-1
AWS_SNS_SENDER_ID=MyApp

# Code settings
TESSERA_SMS_CODE_LENGTH=6
TESSERA_SMS_CODE_EXPIRATION=300
TESSERA_SMS_MAX_ATTEMPTS=3
```

### Bot Protection
```bash
TESSERA_BOT_PROTECTION_ENABLED=true
TESSERA_CAPTCHA_PROVIDER=hcaptcha  # or recaptcha

# hCaptcha
HCAPTCHA_SITE_KEY=...
HCAPTCHA_SECRET_KEY=...

# reCAPTCHA
RECAPTCHA_SITE_KEY=...
RECAPTCHA_SECRET_KEY=...
RECAPTCHA_VERSION=v3
RECAPTCHA_MIN_SCORE=0.5

# Rate limiting
TESSERA_RATE_LIMIT_ENABLED=true
TESSERA_MAX_REQUESTS_PER_MINUTE=10
TESSERA_MAX_REQUESTS_PER_HOUR=100
```

### Password Security
```bash
TESSERA_CHECK_BREACHED_PASSWORDS=true
HIBP_API_KEY=...  # Optional but recommended

TESSERA_PASSWORD_MIN_LENGTH=12
TESSERA_PASSWORD_REQUIRE_UPPERCASE=true
TESSERA_PASSWORD_REQUIRE_LOWERCASE=true
TESSERA_PASSWORD_REQUIRE_NUMBERS=true
TESSERA_PASSWORD_REQUIRE_SPECIAL_CHARS=true
TESSERA_PASSWORD_DISALLOW_COMMON=true
TESSERA_PASSWORD_DISALLOW_SEQUENTIAL=true
TESSERA_PASSWORD_DISALLOW_REPEATED=true
TESSERA_PASSWORD_MAX_REPEATED=3
TESSERA_PASSWORD_DISALLOW_USERNAME=true
```

---

## Best Practices

1. **Always use HTTPS** - Never transmit credentials or tokens over HTTP
2. **Cache breach checks** - Use Redis to avoid repeated API calls for same password
3. **Rate limit aggressively** - Prevent brute force attacks on all endpoints
4. **Log suspicious activity** - Monitor for patterns indicating attacks
5. **Update provider keys regularly** - Rotate API keys periodically
6. **Test in staging** - Always test CAPTCHA flows before production
7. **Provide clear error messages** - Help users understand why password was rejected
8. **Consider UX** - Don't make security so strict it frustrates legitimate users
