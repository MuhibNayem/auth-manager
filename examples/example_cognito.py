"""AWS Cognito flows: register, login, refresh, social, MFA, attributes.

Requires an AWS Cognito user pool and the `authy-package[dynamodb]` or
`authy-package[sms]` extra for boto3 (any extra that provides boto3, or
`pip install boto3`). AWS credentials come from the standard provider
chain — prefer IAM roles/SSO; never hardcode keys
(see AWS_SECURITY_GUIDE.md).

Environment variables:

    AWS_REGION              e.g. us-east-1
    COGNITO_USER_POOL_ID    e.g. us-east-1_xxxxxxxxx
    COGNITO_APP_CLIENT_ID   app client id
    COGNITO_REDIRECT_URI    e.g. https://app.example.com/callback
    AUTHY_COGNITO_USERNAME  demo username (default: johndoe)
    AUTHY_COGNITO_EMAIL     demo email   (default: john@example.com)

Interactive values (confirmation codes, MFA codes) are read from env
vars so the script contains no fake placeholder flow:

    AUTHY_COGNITO_CONFIRMATION_CODE / AUTHY_COGNITO_MFA_CODE

Token payloads use lowercase keys consistently:
    {"access_token": ..., "refresh_token": ..., "id_token": ...}
"""

import asyncio
import os

from authy_package.cognito.cognito_manager import CognitoManager
from authy_package.core.auth_manager import CognitoAuthManager

REGION = os.environ["AWS_REGION"]
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
APP_CLIENT_ID = os.environ["COGNITO_APP_CLIENT_ID"]
REDIRECT_URI = os.environ.get("COGNITO_REDIRECT_URI", "https://app.example.com/callback")

USERNAME = os.environ.get("AUTHY_COGNITO_USERNAME", "johndoe")
EMAIL = os.environ.get("AUTHY_COGNITO_EMAIL", "john@example.com")


async def main() -> None:
    cognito_manager = CognitoManager(
        region_name=REGION,
        user_pool_id=USER_POOL_ID,
        app_client_id=APP_CLIENT_ID,
    )
    auth_manager = CognitoAuthManager(cognito_manager=cognito_manager)

    # A strong per-run password for the demo account (never hardcode one).
    import secrets

    password = secrets.token_urlsafe(16)

    # 1. Register.
    try:
        response = await auth_manager.register_user(
            username=USERNAME, password=password, email=EMAIL
        )
        print("Cognito registration:", response)
    except Exception as exc:  # Cognito raises botocore ClientError variants
        print("Cognito registration error:", exc)

    # 2. Confirm the account if a code was provided (from the email/SMS).
    confirmation_code = os.environ.get("AUTHY_COGNITO_CONFIRMATION_CODE")
    if confirmation_code:
        try:
            await auth_manager.confirm_user_account(
                username=USERNAME, confirmation_code=confirmation_code
            )
            print("Account confirmed")
        except Exception as exc:
            print("Account confirmation error:", exc)
    else:
        print("[skip] account confirmation (set AUTHY_COGNITO_CONFIRMATION_CODE)")

    # 3. Login -> {"access_token", "refresh_token", ...}.
    login_response = None
    try:
        login_response = await auth_manager.login_user(
            username=USERNAME, password=password
        )
        print("Cognito login: received", sorted(login_response.keys()))
    except Exception as exc:
        print("Cognito login error:", exc)

    if not login_response:
        print("No session established; remaining steps skipped.")
        return

    access_token = login_response["access_token"]

    # 4. Refresh tokens.
    try:
        refreshed = await auth_manager.refresh_token(
            refresh_token=login_response["refresh_token"]
        )
        access_token = refreshed.get("access_token", access_token)
        print("Tokens refreshed:", sorted(refreshed.keys()))
    except Exception as exc:
        print("Refresh error:", exc)

    # 5. Social login via the hosted UI.
    try:
        social_url = await auth_manager.initiate_social_login(
            provider="google", redirect_uri=REDIRECT_URI
        )
        print("Social login URL:", social_url)
        # After the browser callback, exchange the code:
        code = os.environ.get("AUTHY_COGNITO_SOCIAL_CODE")
        if code:
            tokens = await auth_manager.exchange_code_for_tokens(
                code=code, redirect_uri=REDIRECT_URI
            )
            print("Social tokens:", sorted(tokens.keys()))
    except Exception as exc:
        print("Social login error:", exc)

    # 6. User info + attribute update (lowercase access_token key).
    try:
        user_info = await auth_manager.get_user_info(access_token=access_token)
        print("User info retrieved:", sorted(user_info.keys()) if isinstance(user_info, dict) else user_info)
        await auth_manager.update_user_attributes(
            access_token=access_token,
            attributes=[{"Name": "custom:department", "Value": "Engineering"}],
        )
        print("User attributes updated")
    except Exception as exc:
        print("Attribute update error:", exc)

    # 7. MFA: TOTP setup, optional verification with a real code.
    try:
        totp_setup = await auth_manager.associate_software_token(access_token=access_token)
        print("TOTP association:", sorted(totp_setup.keys()) if isinstance(totp_setup, dict) else totp_setup)
        await auth_manager.enable_TOTP_mfa(username=USERNAME)
        print("TOTP MFA enabled")
        mfa_code = os.environ.get("AUTHY_COGNITO_MFA_CODE")
        if mfa_code:
            verify = await auth_manager.verify_mfa(access_token=access_token, code=mfa_code)
            print("MFA verified:", verify)
        else:
            print("[skip] MFA verification (set AUTHY_COGNITO_MFA_CODE)")
    except Exception as exc:
        print("MFA error:", exc)

    # 8. Password reset flow (code comes from the email/SMS Cognito sends).
    try:
        await auth_manager.reset_password(username=USERNAME)
        print("Password reset initiated")
        reset_code = os.environ.get("AUTHY_COGNITO_RESET_CODE")
        if reset_code:
            await auth_manager.confirm_password(
                username=USERNAME,
                confirmation_code=reset_code,
                new_password=secrets.token_urlsafe(16),
            )
            print("Password reset completed")
    except Exception as exc:
        print("Password reset error:", exc)

    # 9. Logout (hosted-UI logout URL; requires redirect_uri).
    try:
        logout_url = await auth_manager.logout_user(
            redirect_uri=REDIRECT_URI, access_token=access_token
        )
        print("Logout URL:", logout_url)
    except Exception as exc:
        print("Logout error:", exc)


if __name__ == "__main__":
    asyncio.run(main())
