import requests
import jwt
import time

class AppleManager:
    def __init__(self, client_id, team_id, key_id, private_key):
        self.client_id = client_id
        self.team_id = team_id
        self.key_id = key_id
        self.private_key = private_key

    def get_authorization_url(self, redirect_uri, scope="openid email profile"):
        """
        Generates the authorization URL for Apple Sign-In.

        Args:
            redirect_uri (str): The redirect URI for your application.
            scope (str, optional): Requested scopes (default: openid email profile).

        Returns:
            str: The authorization URL.
        """
        url = "https://appleid.apple.com/auth/oauth2/v2/authorize"
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'response_type': 'code',
        }
        return url + "?" + requests.utils.urlencode(params)

    def get_access_token(self, code):
        """
        Exchanges the authorization code for an access token and ID token.

        Args:
            code (str): The authorization code received in the redirect URI.

        Returns:
            dict: The dictionary containing access token, ID token, refresh token (optional), etc.
        """
        url = "https://appleid.apple.com/auth/token"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'code': code,
            'grant_type': 'authorization_code'
        }
        response = requests.post(url, headers=headers, data=data)
        return response.json()

    def generate_client_secret(self):
        """
        Generates a client secret using your private key.
        """
        now = int(time.time())
        exp = now + 3600  # Token expiration time
        header = {
            "alg": "ES256",
            "kid": self.key_id
        }
        payload = {
            "iss": self.team_id,
            "iat": now,
            "exp": exp,
            "aud": "https://appleid.apple.com",
            "sub": self.client_id
        }
        client_secret = jwt.encode(payload, self.private_key, algorithm='ES256', headers=header)
        return client_secret.decode()  # Decode to string for requests

    def get_user_info(self, id_token):
        """
        Decodes the ID token to get user information.

        Args:
            id_token (str): The ID token obtained from the access token response.

        Returns:
            dict: The user information decoded from the ID token.
        """
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        return decoded_token

    def refresh_access_token(self, refresh_token):
        """
        Refreshes the access token using the refresh token.

        Args:
            refresh_token (str): The refresh token obtained from the access token response.

        Returns:
            dict (optional): The refreshed access token information or None if refresh fails.
        """
        url = "https://appleid.apple.com/auth/token"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    def logout(self, access_token):
        """
        Revokes the user's access token, effectively logging them out.

        Args:
            access_token (str): The user's access token.

        Returns:
            None
        """
        url = "https://appleid.apple.com/auth/oauth2/v2/revoke"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'token': access_token
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            raise ValueError(f"Failed to log out: {response.text}")