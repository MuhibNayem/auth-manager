import asyncio
from auth_package.core.auth_manager import SocialAuthManager
from auth_package.cache.redis_cache import RedisCaching
from auth_package.db.mongodb import MongoDB
from auth_package.social.facebook import FacebookManager
from auth_package.social.github import GitHubManager
from auth_package.social.apple import AppleManager
from auth_package.social.google import GoogleManager
import os

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "your_db_name")
COLLECTION_NAME = "users"

# Social OAuth Manager Configurations
FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID", "your_facebook_app_id")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET", "your_facebook_app_secret")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "your_github_client_id")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "your_github_client_secret")
APPLE_TEAM_ID = os.getenv("APPLE_TEAM_ID", "your_apple_team_id")
APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID", "your_apple_client_id")
APPLE_KEY_ID = os.getenv("APPLE_KEY_ID", "your_apple_key_id")
APPLE_PRIVATE_KEY_PATH = os.getenv("APPLE_PRIVATE_KEY_PATH", "path_to_your_apple_private_key.p8")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your_google_client_id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your_google_client_secret")

# Initialize MongoDB, Redis, and Social Managers
mongo_db = MongoDB(MONGO_URL, DB_NAME, COLLECTION_NAME)
redis_cache = RedisCaching(REDIS_URL)
facebook_manager = FacebookManager(FACEBOOK_APP_ID, FACEBOOK_APP_SECRET)
github_manager = GitHubManager(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
apple_manager = AppleManager(APPLE_TEAM_ID, APPLE_CLIENT_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY_PATH)
google_manager = GoogleManager(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)

# Initialize AuthManager for MongoDB, Redis, and social login providers
auth_manager = SocialAuthManager(
    db=mongo_db,
    cache=redis_cache,
    facebook_manager=facebook_manager,
    github_manager=github_manager,
    apple_manager=apple_manager,
    google_manager=google_manager
)

async def social_login_facebook():
    try:
        facebook_code = "facebook_oauth_code_from_frontend"
        response = await auth_manager.facebook_social_login(facebook_code)
        print("Facebook Login Response:", response)
    except Exception as e:
        print("Facebook Login Error:", str(e))

async def social_login_github():
    try:
        github_code = "github_oauth_code_from_frontend"
        response = await auth_manager.github_social_login(github_code)
        print("GitHub Login Response:", response)
    except Exception as e:
        print("GitHub Login Error:", str(e))

async def social_login_apple():
    try:
        apple_code = "apple_oauth_code_from_frontend"
        response = await auth_manager.apple_social_login(apple_code)
        print("Apple Login Response:", response)
    except Exception as e:
        print("Apple Login Error:", str(e))

async def social_login_google():
    try:
        google_code = "google_oauth_code_from_frontend"
        response = await auth_manager.google_social_login(google_code)
        print("Google Login Response:", response)
    except Exception as e:
        print("Google Login Error:", str(e))

async def refresh_access_token(user_identifier):
    try:
        new_token = await auth_manager.refresh_access_token(user_identifier)
        print("New Access Token:", new_token)
    except Exception as e:
        print("Refresh Access Token Error:", str(e))

async def logout_user(user_identifier):
    try:
        await auth_manager.logout(provider="google", user_identifier=user_identifier)
        print("User logged out successfully.")
    except Exception as e:
        print("Logout Error:", str(e))

async def enable_mfa(user_identifier):
    try:
        mfa_response = await auth_manager.enable_mfa(user_identifier)
        print("MFA Enabled Response:", mfa_response)
    except Exception as e:
        print("Enable MFA Error:", str(e))

async def reconfigure_mfa(user_identifier):
    try:
        mfa_reconfigure_response = await auth_manager.reconfigure_mfa(user_identifier)
        print("MFA Reconfigured Response:", mfa_reconfigure_response)
    except Exception as e:
        print("Reconfigure MFA Error:", str(e))

async def main():
    await social_login_facebook()
    await social_login_github()
    await social_login_apple()
    await social_login_google()

    user_identifier = 'email' or 'username' or 'phone'
    await refresh_access_token(user_identifier)
    await logout_user(user_identifier)
    await enable_mfa(user_identifier)
    await reconfigure_mfa(user_identifier)

# Run the async main function
if __name__ == "__main__":
    asyncio.run(main())
