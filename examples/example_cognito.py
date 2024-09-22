import asyncio
from authy_package.core.auth_manager import CognitoAuthManager
from authy_package.cognito.cognito_manager import CognitoManager

# Configuration for Cognito
USER_POOL_ID = "your_user_pool_id"
APP_CLIENT_ID = "your_app_client_id"
REGION_NAME = "your_region"

# Initialize Cognito Manager
cognito_manager = CognitoManager(region_name=REGION_NAME, user_pool_id=USER_POOL_ID, app_client_id=APP_CLIENT_ID)

async def main():
    # Initialize AuthManager with CognitoManager
    auth_manager = CognitoAuthManager(cognito_manager=cognito_manager)

    # Register a user with Cognito
    await handle_registration(auth_manager)

    # Log in the user with Cognito
    login_response = await handle_login(auth_manager)

    # Refresh the access token using a refresh token
    await handle_token_refresh(auth_manager, login_response)

    # Logout the user from Cognito
    await handle_logout(auth_manager, login_response)

    # Initiate Social Login with Cognito
    await handle_social_login(auth_manager)

    # Exchange authorization code for tokens (Social login with Cognito)
    await handle_code_exchange(auth_manager)

    # Reset password
    await handle_password_reset(auth_manager)

    # Confirm new password
    await handle_password_confirmation(auth_manager)

    # Confirm user account
    await handle_account_confirmation(auth_manager)

    # Update user attributes
    await handle_attribute_update(auth_manager, login_response)

    # Enable MFA
    await handle_enable_mfa(auth_manager)

    # Disable MFA
    await handle_disable_mfa(auth_manager)

    # Verify MFA
    await handle_mfa_verification(auth_manager, login_response)

async def handle_registration(auth_manager):
    try:
        response = await auth_manager.register_user(username="johndoe", email="john@example.com", password="securepassword")
        print("Cognito Registration Response:", response)
    except Exception as e:
        print("Cognito Registration Error:", str(e))

async def handle_login(auth_manager):
    try:
        return await auth_manager.login_user(username="johndoe", password="securepassword")
    except Exception as e:
        print("Cognito Login Error:", str(e))

async def handle_token_refresh(auth_manager, login_response):
    try:
        refreshed_tokens = await auth_manager.refresh_token(refresh_token=login_response["RefreshToken"])
        print("Refreshed Tokens:", refreshed_tokens)
    except Exception as e:
        print("Refresh Token Error:", str(e))

async def handle_logout(auth_manager, login_response):
    try:
        await auth_manager.logout_user(access_token=login_response["AccessToken"])
        print("Cognito User logged out successfully.")
    except Exception as e:
        print("Cognito Logout Error:", str(e))

async def handle_social_login(auth_manager):
    try:
        social_login_url = await auth_manager.initiate_social_login(provider="google", redirect_uri="https://your-app.com/callback")
        print("Social Login URL:", social_login_url)
    except Exception as e:
        print("Social Login Error:", str(e))

async def handle_code_exchange(auth_manager):
    try:
        tokens = await auth_manager.exchange_code_for_tokens(code="auth_code_from_provider", redirect_uri="https://your-app.com/callback")
        print("Tokens received after exchanging code:", tokens)
    except Exception as e:
        print("Exchange Code for Tokens Error:", str(e))

async def handle_password_reset(auth_manager):
    try:
        await auth_manager.reset_password(username="johndoe")
        print("Password reset initiated for johndoe.")
    except Exception as e:
        print("Password Reset Error:", str(e))

async def handle_password_confirmation(auth_manager):
    try:
        confirmation_code = "your_confirmation_code"  # Replace with the actual code
        new_password = "new_secure_password"
        confirm_response = await auth_manager.confirm_password(username="johndoe", confirmation_code=confirmation_code, new_password=new_password)
        print("Password Confirmation Response:", confirm_response)
    except Exception as e:
        print("Password Confirmation Error:", str(e))

async def handle_account_confirmation(auth_manager):
    try:
        confirmation_code = "your_confirmation_code"  # Replace with the actual code
        confirm_account_response = await auth_manager.confirm_user_account(username="johndoe", confirmation_code=confirmation_code)
        print("Account Confirmation Response:", confirm_account_response)
    except Exception as e:
        print("Account Confirmation Error:", str(e))

async def handle_attribute_update(auth_manager, login_response):
    try:
        attributes = [{"Name": "email", "Value": "john.doe@example.com"}]
        update_response = await auth_manager.update_user_attributes(access_token=login_response["AccessToken"], attributes=attributes)
        print("User Attributes Update Response:", update_response)
    except Exception as e:
        print("Update User Attributes Error:", str(e))

async def handle_enable_mfa(auth_manager):
    try:
        await auth_manager.enable_mfa(username="johndoe")
        print("MFA enabled for johndoe.")
    except Exception as e:
        print("Enable MFA Error:", str(e))

async def handle_disable_mfa(auth_manager):
    try:
        await auth_manager.disable_mfa(username="johndoe")
        print("MFA disabled for johndoe.")
    except Exception as e:
        print("Disable MFA Error:", str(e))

async def handle_mfa_verification(auth_manager, login_response):
    try:
        access_token = login_response["AccessToken"]
        mfa_code = "your_mfa_code"  # Replace with the actual MFA code
        verify_response = await auth_manager.verify_mfa(access_token=access_token, code=mfa_code)
        print("MFA Verification Response:", verify_response)
    except Exception as e:
        print("MFA Verification Error:", str(e))

# Run the async main function
if __name__ == "__main__":
    asyncio.run(main())
