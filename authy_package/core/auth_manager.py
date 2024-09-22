from authy_package.utils.security import hash_password, verify_password
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.db.sql import SQLDatabase 
from authy_package.cache.abstract_cache import AbstractCache
from authy_package.cognito.cognito_manager import CognitoManager
from authy_package.social.apple import AppleManager
from authy_package.social.github import GitHubManager
from authy_package.social.facebook import FacebookManager
from authy_package.social.google import GoogleManager
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.utils.security import SecurityManager

## for Traditional Auth Flow
class TraditionalAuthManager:
    def __init__(self, db: AbstractDatabase, cache: AbstractCache = None, mfa_manager: MFAAuthManager = None, security_manager: SecurityManager = None):
        """
        Initializes the TraditionalAuthManager with database, cache, MFA manager, and Security manager.

        :param db: The database instance for user operations.
        :param cache: The cache instance for storing temporary data.
        :param mfa_manager: An instance of MFAAuthManager for managing multi-factor authentication.
        :param security_manager: An instance of SecurityManager for managing password resets.
        """
        self.db = db
        self.cache = cache
        self.mfa_manager = mfa_manager 
        self.security_manager = security_manager

    async def register_user(self, username=None, email=None, phone=None, password=None):
        """
        Registers a new user.

        :param username: The username of the user.
        :param email: The email of the user.
        :param phone: The phone number of the user.
        :param password: The password for the user account.
        :return: A message indicating the result of the registration.
        """
        existing_user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if existing_user:
            raise ValueError("User already exists.")
        
        hashed_password = hash_password(password)
        user_data = {
            "username": username,
            "email": email,
            "phone": phone,
            "hashed_password": hashed_password,
            "mfa_enabled": False 
        }
        
        await self.db.create_user(user_data)

        return {
            "message": "User registered successfully.",
            "user": user_data
        }

    async def login_user(self, username=None, email=None, phone=None, password=None, mfa_code=None):
        """
        Logs a user into the application.

        :param username: The username of the user.
        :param email: The email of the user.
        :param phone: The phone number of the user.
        :param password: The password for the user account.
        :param mfa_code: The MFA code for verification, if MFA is enabled.
        :return: A message indicating the result of the login operation, along with tokens if successful.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user or not verify_password(password, user['hashed_password']):
            raise ValueError("Invalid credentials.")
        
        if user.get('mfa_enabled'):
            if not mfa_code or not await self.mfa_manager.verify_mfa_code(mfa_code, username, email, phone):
                raise ValueError("Invalid MFA code.")
        
        if self.cache:
            access_token, refresh_token = self.cache.create_token_pair(user['username'] or user['email'] or user['phone'])
            return {"access_token": access_token, "refresh_token": refresh_token}
        
        return {"message": "Login successful.", "user": user}

    async def logout_user(self, access_token, username=None, pk=None):
        """
        Logs a user out of the application.

        :param access_token: The access token to invalidate.
        :param username: The username of the user (optional).
        :param pk: The primary key of the user (optional).
        :return: A message indicating the result of the logout operation.
        """
        if self.cache:
            self.cache.delete_access_token(access_token)
            if username or pk:
                self.cache.delete_refresh_token(username or pk)

        return {"message": "User logged out successfully."}

    async def refresh_token(self, refresh_token):
        """
        Refreshes the access token using the provided refresh token.

        :param refresh_token: The refresh token to validate and use for generating a new access token.
        :return: A new access token and refresh token.
        """
        if self.cache:
            user_identifier = self.cache.validate_refresh_token(refresh_token)
            if not user_identifier:
                raise ValueError("Invalid refresh token.")

            new_access_token, new_refresh_token = self.cache.create_token_pair(refresh_token)
            return {"access_token": new_access_token, "refresh_token": new_refresh_token}
        
        raise ValueError("Caching not enabled.")

    async def enable_mfa(self, username=None, email=None, phone=None):
        """
        Enables multi-factor authentication for a user.

        :param username: The username of the user.
        :param email: The email of the user.
        :param phone: The phone number of the user.
        
        Any of username or email or phone must be provided. the user identifier must be consistent throughout the app
        
        :return: A message indicating the result of the MFA enabling operation.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")

        if user.get('mfa_enabled'):
            return {"message": "MFA is already enabled for this user."}
        
        mfa_setup_response = await self.mfa_manager.setup_mfa(username or email or phone)
        return {
            "message": "MFA has been enabled successfully.",
            "mfa_secret": mfa_setup_response['mfa_secret']
        }

    async def reconfigure_mfa(self, username=None, email=None, phone=None):
        """
        Reconfigures multi-factor authentication for a user.

        :param username: The username of the user.
        :param email: The email of the user.
        :param phone: The phone number of the user.
        
        Any of username or email or phone must be provided. the user identifier must be consistent throughout the app
        
        :return: A message indicating the result of the MFA reconfiguration operation.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")
        
        if not user.get('mfa_enabled'):
            raise ValueError("MFA is not enabled for this user.")

        mfa_reconfig_response = await self.mfa_manager.reconfigure_mfa(username=username, email=email, phone=phone)
        return {
            "message": "MFA has been reconfigured successfully.",
            "mfa_secret": mfa_reconfig_response['mfa_secret']
        }

    # Password Reset Functionality
    async def request_password_reset(self, username=None, email=None, phone=None, sender_email: str = '', sender_name: str = '') -> dict:
        """
        Handles a password reset request by generating and sending the reset link.

        :param username: The username of the user requesting a password reset.
        :param email: The email of the user requesting a password reset.
        :param phone: The phone number of the user requesting a password reset.
        :param sender_email: The email address of the sender.
        :param sender_name: The name of the sender.
        :return: A message indicating the result of the operation.
        """
        return await self.security_manager.generate_and_send_reset_link(username=username, email=email, phone=phone, sender_email=sender_email, sender_name=sender_name)

    async def reset_password(self, email: str, token: str, new_password: str):
        """
        Resets the user's password after validating the reset token.

        :param email: The email of the user whose password is to be reset.
        :param token: The reset token sent to the user's email.
        :param new_password: The new password to set.
        :return: A message indicating the result of the password reset.
        """
        return await self.security_manager.update_password(email=email, new_password=new_password, token=token)

## For Cognito Related Auth Flow
class CognitoAuthManager:
    def __init__(self, cognito_manager: CognitoManager):
        """
        Initializes the CognitoAuthManager with a CognitoManager instance.

        :param cognito_manager: An instance of the CognitoManager for interacting with AWS Cognito.
        """
        self.cognito_manager = cognito_manager

    async def register_user(self, username: str, email: str, password: str):
        """Registers a new user asynchronously.

        :param username: The username for the new user.
        :param email: The email address of the new user.
        :param password: The password for the new user.
        :return: The response from the Cognito registration process.
        """
        return await self.cognito_manager.register_user(username, password, email)

    async def login_user(self, username: str, password: str):
        """Authenticates a user asynchronously.

        :param username: The username of the user attempting to log in.
        :param password: The password of the user.
        :return: The response from the Cognito authentication process.
        """
        return await self.cognito_manager.authenticate_user(username, password)

    async def logout_user(self, access_token: str):
        """Logs out the user asynchronously.

        :param access_token: The access token of the user to be logged out.
        :return: The response from the Cognito logout process.
        """
        return await self.cognito_manager.logout_user(access_token)

    async def refresh_token(self, refresh_token: str):
        """Refreshes the user's tokens asynchronously.

        :param refresh_token: The refresh token used to obtain new tokens.
        :return: The new access and ID tokens.
        """
        return await self.cognito_manager.refresh_token(refresh_token)

    async def initiate_social_login(self, provider: str, redirect_uri: str):
        """Initiates social login asynchronously.

        :param provider: The social provider (e.g., Google, Facebook).
        :param redirect_uri: The URI to redirect to after login.
        :return: The authorization URL for the social login.
        """
        return await self.cognito_manager.initiate_social_login(provider, redirect_uri)

    async def exchange_code_for_tokens(self, code: str, redirect_uri: str):
        """Exchanges an authorization code for tokens asynchronously.

        :param code: The authorization code received after social login.
        :param redirect_uri: The URI to redirect to after obtaining tokens.
        :return: The access and ID tokens.
        """
        return await self.cognito_manager.exchange_code_for_tokens(code, redirect_uri)

    async def reset_password(self, username: str):
        """Initiates the password reset process asynchronously.

        :param username: The username of the user requesting a password reset.
        :return: The response from the Cognito password reset process.
        """
        return await self.cognito_manager.reset_password(username)

    async def confirm_password(self, username: str, confirmation_code: str, new_password: str):
        """Confirms the new password asynchronously.

        :param username: The username of the user resetting their password.
        :param confirmation_code: The confirmation code received via email or SMS.
        :param new_password: The new password to set for the user.
        :return: The response from the Cognito confirm password process.
        """
        return await self.cognito_manager.confirm_password(username, confirmation_code, new_password)

    async def confirm_user_account(self, username: str, confirmation_code: str):
        """Confirms a user account asynchronously.

        :param username: The username of the user confirming their account.
        :param confirmation_code: The confirmation code received via email or SMS.
        :return: The response from the Cognito account confirmation process.
        """
        return await self.cognito_manager.confirm_user_account(username, confirmation_code)

    async def update_user_attributes(self, access_token: str, attributes: list):
        """Updates user attributes asynchronously.

        :param access_token: The access token of the user whose attributes are to be updated.
        :param attributes: A list of attributes to update.
        :return: The response from the Cognito update attributes process.
        """
        return await self.cognito_manager.update_user_attributes(access_token, attributes)

    async def get_user_info(self, access_token: str):
        """Retrieves the information of a user using their access token asynchronously.

        :param access_token: The access token of the user.
        :return: The user's information from Cognito.
        """
        return await self.cognito_manager.get_user_info(access_token)

    async def enable_mfa(self, username: str):
        """Enables MFA for a user asynchronously.

        :param username: The username of the user for whom MFA is to be enabled.
        :return: The response from the Cognito MFA enabling process.
        """
        return await self.cognito_manager.enable_mfa(username)

    async def disable_mfa(self, username: str):
        """Disables MFA for a user asynchronously.

        :param username: The username of the user for whom MFA is to be disabled.
        :return: The response from the Cognito MFA disabling process.
        """
        return await self.cognito_manager.disable_mfa(username)

    async def verify_mfa(self, access_token: str, code: str):
        """Verifies the MFA code asynchronously.

        :param access_token: The access token of the user for whom to verify the MFA code.
        :param code: The MFA code to verify.
        :return: The response from the Cognito MFA verification process.
        """
        return await self.cognito_manager.verify_mfa(access_token, code)

## for manual Social Auth Flow
class SocialAuthManager:
    def __init__(self, 
    db: AbstractDatabase, 
    cache: AbstractCache = None, 
    github_manager: GitHubManager = None, 
    apple_manager: AppleManager = None, 
    facebook_manager: FacebookManager = None, 
    google_manager: GoogleManager = None,
    mfa_manager: MFAAuthManager = None
    ):
        
        """
        Initializes the authentication service with the necessary components.

        Args:
            db (AbstractDatabase): The database interface for user data operations.
            cache (AbstractCache, optional): The caching mechanism for storing tokens and other data.
            github_manager (GitHubManager, optional): Manager for GitHub authentication and API interactions.
            apple_manager (AppleManager, optional): Manager for Apple authentication and API interactions.
            facebook_manager (FacebookManager, optional): Manager for Facebook authentication and API interactions.
            google_manager (GoogleManager, optional): Manager for Google authentication and API interactions.
            mfa_manager (MFAAuthManager, optional): Manager for multi-factor authentication processes.

        Attributes:
            db: The database interface for user operations.
            cache: The caching mechanism used in the service.
            github_manager: The manager for GitHub-related operations.
            apple_manager: The manager for Apple-related operations.
            facebook_manager: The manager for Facebook-related operations.
            google_manager: The manager for Google-related operations.
            mfa_manager: The manager for handling multi-factor authentication.
        """
        
        self.db = db
        self.cache = cache
        self.github_manager = github_manager
        self.apple_manager = apple_manager
        self.facebook_manager = facebook_manager
        self.google_manager = google_manager
        self.mfa_manager = mfa_manager

    async def facebook_social_login(self, code: str):
        """
        Handles Facebook social login by exchanging the code for a short-lived access token, then exchanges
        it for a long-lived token, retrieves user info, and stores tokens in the cache.
        
        Args:
            code (str): The authorization code obtained from Facebook's login redirect.
        
        Returns:
            dict: User information and token details.
        """
        
        short_lived_token_info = self.facebook_manager.get_access_token(code)
        short_lived_token = short_lived_token_info['access_token']

        long_lived_token_info = self.facebook_manager.get_long_lived_access_token(short_lived_token)
        access_token = long_lived_token_info['access_token']
        
        expires_at = long_lived_token_info.get('expires_at', None)

        user_info = self.facebook_manager.get_user_info(access_token)
            
        token_info = {
            'access_token': access_token,
            'refresh_token': self.cache.generate_refresh_token_for_access_token(access_token),
            'expires_at': expires_at
        }
        
        return await self._handle_social_login(self, "facebook", user_info, token_info)

    async def github_social_login(self, code: str):
        
        """
        Handles GitHub social login by exchanging the authorization code for an access token 
        and retrieving user information.

        :param code: The authorization code received from the GitHub OAuth 2.0 flow.
        
        :return: A dictionary containing a message about the login status, 
                user information, and access token information.
        """
        
        access_token_info = self.github_manager.get_access_token(code)
        token_info = {
            'access_token': access_token_info['access_token'],
            'refresh_token': self.cache.generate_refresh_token_for_access_token(access_token_info['access_token']),
        }
        user_info = self.github_manager.get_user_info(access_token_info['access_token'])
        return await self._handle_social_login(self, "github", user_info, token_info)

    async def apple_social_login(self, redirect_uri: str, code: str = None):
        """
        Handles Apple social login.

        Args:
            redirect_uri (str): The redirect URI for the application.
            code (str, optional): The authorization code from Apple.

        Returns:
            dict: A dictionary containing the authorization URL if no code is provided, or the login response.
        """

        if code is None:
            # If no code is provided, return the authorization URL
            authorization_url = await self.apple_manager.get_authorization_url(redirect_uri)
            return {"authorization_url": authorization_url}

        # Exchange code for access token and user information
        access_token_info = await self.apple_manager.get_access_token(code)
        user_info = await self.apple_manager.get_user_info(access_token_info['id_token'])

        # Handle user login or registration
        return await self._handle_social_login("apple", user_info, access_token_info)

    async def google_social_login(self, code: str):
        """
        Handles Google social login by exchanging the authorization code for access tokens 
        and retrieving user information.

        :param code: The authorization code received from the Google OAuth 2.0 flow.
        
        :return: A dictionary containing a message about the login status, 
                user information, and access token information.
        """
        
        credentials = self.google_manager.exchange_code_for_tokens(code)
        
        user_info = self.google_manager.get_user_info(credentials)
        
        access_token_info = {
            'access_token': credentials.token,
            'refresh_token': credentials.refresh_token
        }

        return await self._handle_social_login(self, "google", user_info, access_token_info)

    async def _handle_social_login(self, provider: str, user_info: dict, access_token_info: dict):
        
        """
        Handles social login for a user by checking for an existing account or creating a new one.

        :param provider: The social provider (e.g., 'google', 'facebook') used for authentication.
        :param user_info: A dictionary containing user information retrieved from the social provider.
            Expected keys include 'name' and 'email'.
        :param access_token_info: A dictionary containing access token information.
            Expected keys may include 'access_token', 'refresh_token', 'id_token', 'expires_at', and 'expires_in'.
        
        :return: A dictionary containing a success message, the user data, and access token information.
        """
        
        username = user_info.get("name") or user_info.get("email")
        email = user_info.get("email")

        existing_user = await self.db.get_user_by_identifier(username=username, email=email)
        
        if not existing_user:
            user_data = {
                "username": username,
                "email": email,
                "provider": provider,
                'mfa_enabled': False,
                'mfa_secret': ''
            }

            if isinstance(self.db, SQLDatabase) and self.db.orm_model:
                user_instance = self.db.orm_model(**user_data)
                await self.db.create_user(user_instance)  
            else:
                await self.db.create_user(user_data)

            user = user_data 
        else:
            user = existing_user

        if self.cache:
            access_token = access_token_info.get('access_token')
            refresh_token = access_token_info.get('refresh_token')
            id_token = access_token_info.get('id_token') or None
            exp = access_token_info.get('expires_at') or access_token_info.get('expires_in')
            self.cache.store_social_token(user["username"] or user["email"], access_token, refresh_token, id_token , exp or None)

        return {"message": "Login successful.", "user": user, "access_token": access_token_info}
    
    # refreshing tokens and storing it in redis
    async def refresh_access_token(self, provider: str, refresh_token: str, user: dict):
        """
        Refreshes the access token using the refresh token for a specific provider and stores it in the cache.

        Args:
            provider (str): The social provider name (e.g., "google", "facebook", "apple", "github").
            refresh_token (str): The refresh token for the user.
            user (dict): A dictionary containing the user's information (e.g., username, email).

        Returns:
            dict: A dictionary containing the updated access token and refresh token.
        """
        
        user_identifier = user.get("username") or user.get("email")

        if provider == "google" and self.google_manager:
            # Refresh access token using GoogleManager
            updated_credentials = await self.google_manager.refresh_access_token(refresh_token)
            updated_access_token = updated_credentials.token
            updated_refresh_token = updated_credentials.refresh_token
            await self.cache.update_social_token(user_identifier, updated_access_token, updated_refresh_token)
            return updated_credentials

        elif provider == "apple" and self.apple_manager:
            # Refresh access token using AppleManager
            updated_access_token_info = await self.apple_manager.refresh_access_token(refresh_token)
            access_token = updated_access_token_info.get("access_token")
            expires_in = updated_access_token_info.get("expires_in")
            refresh_token = updated_access_token_info.get("refresh_token")
            id_token = updated_access_token_info.get("id_token")

            await self.cache.update_social_token(user_identifier, access_token, refresh_token, id_token, expires_in)
            return updated_access_token_info

        elif provider == "github" and self.github_manager:
            # Retrieve the current access token for the user
            access_token = await self.cache.retrieve_access_token(user_identifier)
            if access_token:
                # Generate a new refresh token for the retrieved access token
                refresh_token = await self.cache.generate_refresh_token_for_access_token(access_token)
                
                # Delete the old access token
                await self.cache.delete_access_token(access_token)
                
                # Update the stored social token with new access and refresh tokens
                updated_access_token_info = await self.cache.update_social_token(
                    user_identifier,
                    new_access_token=access_token,  # Optionally generate a new access token
                    new_refresh_token=refresh_token
                )
                return updated_access_token_info

        elif provider == "facebook" and self.facebook_manager:
            # Similar process for Facebook
            access_token = await self.cache.retrieve_access_token(user_identifier)
            if access_token:
                refresh_token = await self.cache.generate_refresh_token_for_access_token(access_token)
                await self.cache.delete_access_token(access_token)
                
                updated_access_token_info = await self.cache.update_social_token(
                    user_identifier,
                    new_access_token=access_token,
                    new_refresh_token=refresh_token
                )
                return updated_access_token_info


        else:
            raise ValueError(f"Refresh token functionality is not implemented for provider: {provider}")

    async def logout(self, provider: str, user_identifier: str):
        """
        Handles user logout by revoking the user's access token from the social provider,
        and then deleting the tokens from the cache.

        Args:
            provider (str): The social provider name (e.g., "google", "facebook", "apple", "github").
            user_identifier (str): The user's unique identifier (e.g., email, username).
        
        Returns:
            dict: A message indicating the result of the logout operation.
        """
        access_token = await self.cache.retrieve_access_token(user_identifier)
        
        if provider == "facebook" and self.facebook_manager:
            self.facebook_manager.logout(access_token)

        elif provider == "apple" and self.apple_manager:
            self.apple_manager.logout(access_token)

        # Delete tokens from cache
        if self.cache:
            await self.cache.delete_access_token(user_identifier)
            await self.cache.delete_refresh_token(user_identifier)

        return {"message": "Logout successful."}
    
    async def enable_mfa(self, username=None, email=None, phone=None):
        """
        Enables Multi-Factor Authentication (MFA) for the specified user.

        Args:
            username (str, optional): The username of the user.
            email (str, optional): The email of the user.
            phone (str, optional): The phone number of the user.
            
            But any of username or email or phone must be provided. the user identifier must be consistent throughout the app

        Raises:
            ValueError: If the user is not found or if MFA is already enabled.

        Returns:
            dict: A message confirming the MFA has been enabled and the MFA secret.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")

        if user.get('mfa_enabled'):
            return {"message": "MFA is already enabled for this user."}
        
        mfa_setup_response = await self.mfa_manager.setup_mfa(username or email or phone)
        return {
            "message": "MFA has been enabled successfully.",
            "mfa_secret": mfa_setup_response['mfa_secret']
        }

    async def reconfigure_mfa(self, username=None, email=None, phone=None):
        """
        Reconfigures Multi-Factor Authentication (MFA) for the specified user.

        Args:
            username (str, optional): The username of the user.
            email (str, optional): The email of the user.
            phone (str, optional): The phone number of the user.
            
            But any of username or email or phone must be provided. the user identifier must be consistent throughout the app

        Raises:
            ValueError: If the user is not found or if MFA is not enabled.

        Returns:
            dict: A message confirming the MFA has been reconfigured and the new MFA secret.
        Note:
            User o 
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")
        
        if not user.get('mfa_enabled'):
            raise ValueError("MFA is not enabled for this user.")

        mfa_reconfig_response = await self.mfa_manager.reconfigure_mfa(username=username, email=email, phone=phone)
        return {
            "message": "MFA has been reconfigured successfully.",
            "mfa_secret": mfa_reconfig_response['mfa_secret']
        }
