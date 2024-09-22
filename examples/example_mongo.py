import asyncio
import os
from authy_package.core.auth_manager import TraditionalAuthManager
from authy_package.cache.redis_cache import RedisCaching
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.db.mongodb import MongoDB
from authy_package.utils.security import SecurityManager  

# Configuration
REDIS_URL = "redis://localhost:6379"
MONGO_URL = "mongodb://localhost:27017"
DB_NAME = "your_db_name"
COLLECTION_NAME = "users"
MAILJET_API_KEY = os.getenv('MAILJET_API_KEY', 'your_mailjet_api_key')  # Set your API key or get from env
MAILJET_API_SECRET = os.getenv('MAILJET_API_SECRET', 'your_mailjet_api_secret')  # Set your API secret or get from env

# Initialize MongoDB and Redis Managers
mongo_db = MongoDB(MONGO_URL, DB_NAME, COLLECTION_NAME)
redis_cache = RedisCaching(REDIS_URL)
mfa_auth_manager = MFAAuthManager(db=mongo_db)

# Initialize SecurityManager with MongoDB, Redis, and Mailjet API credentials
security_manager = SecurityManager(
    db=mongo_db, 
    cache=redis_cache, 
    api_key=MAILJET_API_KEY, 
    api_secret=MAILJET_API_SECRET
)

# Initialize AuthManager with SecurityManager, MongoDB, Redis, MFA, and SecurityManager
auth_manager = TraditionalAuthManager(
    db=mongo_db, 
    cache=redis_cache, 
    mfa_manager=mfa_auth_manager, 
    security_manager=security_manager  
)

async def main():
    # 1. Register a user
    try:
        response = await auth_manager.register_user(
            username="janedoe", 
            password="securepassword", 
            email="jane@example.com"
        )
        print("MongoDB Registration Response:", response)
    except ValueError as e:
        print("MongoDB Registration Error:", str(e))

    # 2. Log in the user
    try:
        login_response = await auth_manager.login_user(
            username="janedoe", 
            password="securepassword"
        )
        print("MongoDB Login Response:", login_response)
    except ValueError as e:
        print("MongoDB Login Error:", str(e))

    # 3. Refresh the token
    try:
        refresh_response = await auth_manager.refresh_token(
            refresh_token=login_response['refresh_token']
        )
        print("MongoDB Token Refresh Response:", refresh_response)
    except ValueError as e:
        print("MongoDB Refresh Error:", str(e))

    # 4. Log out the user
    try:
        await auth_manager.logout_user(
            access_token=login_response['access_token'],
            username="janedoe"
        )
        print("MongoDB User logged out successfully.")
    except ValueError as e:
        print("MongoDB Logout Error:", str(e))

    # 5. Enable MFA
    try:
        mfa_response = await auth_manager.enable_mfa(username="janedoe")
        print("MFA Enable Response:", mfa_response)
    except ValueError as e:
        print("MFA Enable Error:", str(e))

    # 6. Reconfigure MFA
    try:
        reconfigure_mfa_response = await auth_manager.reconfigure_mfa(username="janedoe")
        print("MFA Reconfigure Response:", reconfigure_mfa_response)
    except ValueError as e:
        print("MFA Reconfigure Error:", str(e))

    # 7. Generate and send password reset link
    try:
        reset_link_response = await auth_manager.request_password_reset(
            email="jane@example.com", 
            sender_email="noreply@example.com", 
            sender_name="Support"
        )
        print("Password Reset Link Response:", reset_link_response)
    except ValueError as e:
        print("Password Reset Link Error:", str(e))

    # 8. Validate reset token (assume we get this token from the user's email)
    try:
        # Replace 'token' with the actual token received from email
        token = "dummy_reset_token"
        user_identifier = await auth_manager.security_manager.validate_reset_token(token)
        print("Reset Token Validation Response:", user_identifier)
    except ValueError as e:
        print("Reset Token Validation Error:", str(e))

    # 9. Update password
    try:
        new_password_response = await auth_manager.reset_password(
            email="jane@example.com", 
            token="dummy_reset_token", 
            new_password="newsecurepassword"
        )
        print("Password Update Response:", new_password_response)
    except ValueError as e:
        print("Password Update Error:", str(e))

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())
