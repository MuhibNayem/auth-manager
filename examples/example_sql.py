import asyncio
import os
from auth_package.core.auth_manager import TraditionalAuthManager
from auth_package.cache.redis_cache import RedisCaching
from auth_package.mfa.mfa_setup import MFAAuthManager
from auth_package.db.sql import SQLDatabase
from auth_package.utils.security import SecurityManager  

# Configuration
REDIS_URL = "redis://localhost:6379"
SQL_URL = "postgresql+asyncpg://user:password@localhost/dbname"
MAILJET_API_KEY = os.getenv('MAILJET_API_KEY', 'your_mailjet_api_key')  # Set your API key or get from env
MAILJET_API_SECRET = os.getenv('MAILJET_API_SECRET', 'your_mailjet_api_secret')  # Set your API secret or get from env

# Replace 'YourORMModel' with the actual ORM model class you're using for SQL database.
class YourORMModel:
    pass  # Example ORM Model - replace with actual model

# Initialize SQL and Redis Managers
sql_db = SQLDatabase(SQL_URL, orm_model=YourORMModel)
redis_cache = RedisCaching(REDIS_URL)
mfa_auth_manager = MFAAuthManager(db=sql_db)

# Initialize SecurityManager with SQL, Redis, and Mailjet API credentials
security_manager = SecurityManager(
    db=sql_db, 
    cache=redis_cache, 
    api_key=MAILJET_API_KEY, 
    api_secret=MAILJET_API_SECRET
)

# Initialize AuthManager with SecurityManager, SQL, Redis, MFA & Security_Manager
auth_manager = TraditionalAuthManager(
    db=sql_db, 
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
        print("SQL Registration Response:", response)
    except ValueError as e:
        print("SQL Registration Error:", str(e))

    # 2. Log in the user
    try:
        login_response = await auth_manager.login_user(
            username="janedoe", 
            password="securepassword"
        )
        print("SQL Login Response:", login_response)
    except ValueError as e:
        print("SQL Login Error:", str(e))

    # 3. Refresh the token
    try:
        refresh_response = await auth_manager.refresh_token(
            refresh_token=login_response['refresh_token']
        )
        print("SQL Token Refresh Response:", refresh_response)
    except ValueError as e:
        print("SQL Refresh Error:", str(e))

    # 4. Log out the user
    try:
        await auth_manager.logout_user(
            access_token=login_response['access_token'],
            username="janedoe"
        )
        print("SQL User logged out successfully.")
    except ValueError as e:
        print("SQL Logout Error:", str(e))

    # 5. Enable MFA (if applicable)
    try:
        mfa_response = await auth_manager.enable_mfa(username="janedoe")
        print("MFA Enable Response:", mfa_response)
    except ValueError as e:
        print("MFA Enable Error:", str(e))

    # 6. Reconfigure MFA (if applicable)
    try:
        reconfigure_mfa_response = await auth_manager.reconfigure_mfa(username="janedoe")
        print("MFA Reconfigure Response:", reconfigure_mfa_response)
    except ValueError as e:
        print("MFA Reconfigure Error:", str(e))

    # 7. Generate and send password reset link (if applicable)
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
