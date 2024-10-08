import boto3
from botocore.exceptions import ClientError

class CognitoManager:
    def __init__(self, region_name, user_pool_id, app_client_id):
        """
        Initializes the CognitoManager with the necessary configurations.
        """
        self.cognito_client = boto3.client('cognito-idp', region_name=region_name)
        self.user_pool_id = user_pool_id
        self.app_client_id = app_client_id

    def register_user(self, username, password, email, phone_number=None):
        """
        Registers a new user in the Cognito user pool.
        """
        user_attributes = [{'Name': 'email', 'Value': email}]
        
        if phone_number:
            user_attributes.append({'Name': 'phone_number', 'Value': phone_number})

        try:
            response = self.cognito_client.sign_up(
                ClientId=self.app_client_id,
                Username=username,
                Password=password,
                UserAttributes=user_attributes
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def confirm_user_account(self, username, confirmation_code):
        """
        Confirms a user account using a confirmation code.
        """
        try:
            response = self.cognito_client.confirm_sign_up(
                ClientId=self.app_client_id,
                Username=username,
                ConfirmationCode=confirmation_code
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def authenticate_user(self, username, password):
        """
        Authenticates a user with a username and password.
        """
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            return response['AuthenticationResult']
        except ClientError as e:
            return {"Error": str(e)}

    def get_user_info(self, access_token):
        """
        Retrieves the information of a user using their access token.
        """
        try:
            response = self.cognito_client.get_user(AccessToken=access_token)
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def initiate_social_login(self, provider, redirect_uri):
        """
        Generates a URL for social login through a specified identity provider.
        """
        auth_url = f"https://{self.user_pool_id}.auth.{self.cognito_client.meta.region_name}.amazoncognito.com/oauth2/authorize"
        params = {
            "response_type": "code",
            "client_id": self.app_client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "identity_provider": provider
        }
        return f"{auth_url}?" + "&".join(f"{key}={value}" for key, value in params.items())

    def exchange_code_for_tokens(self, code, redirect_uri):
        """
        Exchanges an authorization code for authentication tokens.
        """
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow="AUTHORIZATION_CODE",
                AuthParameters={
                    "CODE": code,
                    "REDIRECT_URI": redirect_uri
                }
            )
            return response['AuthenticationResult']
        except ClientError as e:
            return {"Error": str(e)}

    def refresh_token(self, refresh_token):
        """
        Refreshes the user's tokens using a refresh token.
        """
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token
                }
            )
            return response['AuthenticationResult']
        except ClientError as e:
            return {"Error": str(e)}

    def logout_user(self, redirect_uri, access_token=None, provider=None):
        """
        Logs out the user by invalidating their access token or through social login.
        """
        if provider:
            if not redirect_uri:
                raise ValueError("Redirect URI must be provided for social logout.")

            # Redirect to Cognito Hosted UI's logout endpoint
            logout_url = f"https://{self.user_pool_id}.auth.{self.cognito_client.meta.region_name}.amazoncognito.com/logout"
            params = {
                "client_id": self.app_client_id,
                "logout_uri": redirect_uri
            }
            return f"{logout_url}?" + "&".join(f"{key}={value}" for key, value in params.items())

        if access_token:
            # Traditional login logout by invalidating the token
            try:
                self.cognito_client.global_sign_out(AccessToken=access_token)
                return {"Message": "User successfully logged out."}
            except ClientError as e:
                return {"Error": str(e)}

        return {"Error": "Invalid logout method. Provide an access_token or provider for social logout."}

    def reset_password(self, username):
        """
        Initiates the password reset process for the user.
        """
        try:
            response = self.cognito_client.forgot_password(
                ClientId=self.app_client_id,
                Username=username
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def confirm_password(self, username, confirmation_code, new_password):
        """
        Confirms the new password after a password reset.
        """
        try:
            response = self.cognito_client.confirm_forgot_password(
                ClientId=self.app_client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=new_password
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def enable_totp_mfa(self, username):
        """
        Enables TOTP-based MFA for a user.
        """
        try:
            response = self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SoftwareTokenMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': True
                }
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def enable_sms_mfa(self, username):
        """
        Enables SMS-based MFA for a user.
        Requires a verified phone number.
        """
        try:
            response = self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SMSMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': True
                }
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def disable_mfa(self, username):
        """
        Disables all MFA options for the user.
        """
        try:
            response = self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SMSMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
                SoftwareTokenMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                }
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def verify_mfa(self, access_token, code):
        """
        Verifies the MFA code (for TOTP or SMS MFA).
        """
        try:
            response = self.cognito_client.verify_software_token(
                AccessToken=access_token,
                UserCode=code,
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def associate_software_token(self, access_token):
        """
        Associates a software token for MFA (generates a secret key for TOTP).
        """
        try:
            response = self.cognito_client.associate_software_token(AccessToken=access_token)
            return response['SecretCode']
        except ClientError as e:
            return {"Error": str(e)}

    def update_user_attributes(self, username, attributes):
        """
        Updates user attributes (such as phone number, email).
        """
        try:
            response = self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=attributes
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def update_user_phone_number(self, username, phone_number):
        """
        Updates the user's phone number.
        """
        try:
            response = self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=[
                    {'Name': 'phone_number', 'Value': phone_number}
                ]
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}

    def update_user_email(self, username, email):
        """
        Updates the user's email address.
        """
        try:
            response = self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=[
                    {'Name': 'email', 'Value': email}
                ]
            )
            return response
        except ClientError as e:
            return {"Error": str(e)}