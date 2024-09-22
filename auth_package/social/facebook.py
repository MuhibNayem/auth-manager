import requests
import time

class FacebookManager:
    def __init__(self, app_id, app_secret, redirect_uri):
        self.app_id = app_id
        self.app_secret = app_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        """
        Generates the URL for Facebook login authorization.

        Returns:
            str: The authorization URL where the user needs to log in.
        """
        url = "https://www.facebook.com/v10.0/dialog/oauth"
        params = {
            'client_id': self.app_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'email,public_profile',  # Request required permissions
            'response_type': 'code',
            'state': 'your_custom_state_parameter'  # For CSRF protection
        }
        return url + "?" + requests.utils.urlencode(params)

    def get_access_token(self, code):
        """
        Exchanges the authorization code for a short-lived access token.

        Args:
            code (str): The authorization code obtained from Facebook's login redirect.

        Returns:
            dict: The access token information including access token, expiration time, etc.

        Raises:
            ValueError: If the access token request fails.
        """
        url = f"https://graph.facebook.com/v10.0/oauth/access_token"
        params = {
            'client_id': self.app_id,
            'client_secret': self.app_secret,
            'redirect_uri': self.redirect_uri,
            'code': code
        }
        response = requests.get(url, params=params)
        if response.status_code != 200:
            raise ValueError(f"Failed to get access token: {response.text}")
        access_info = response.json()

        # Set expiration time for short-lived token (typically 1-2 hours)
        access_info['expires_at'] = time.time() + 3600  # Adjust this based on Facebook's expiration
        return access_info

    def get_long_lived_access_token(self, short_lived_token):
        """
        Exchanges the short-lived access token for a long-lived access token.

        Args:
            short_lived_token (str): The short-lived access token obtained from `get_access_token`.

        Returns:
            dict: The long-lived access token information.

        Raises:
            ValueError: If the long-lived token request fails.
        """
        url = f"https://graph.facebook.com/v10.0/oauth/access_token"
        params = {
            'grant_type': 'fb_exchange_token',
            'client_id': self.app_id,
            'client_secret': self.app_secret,
            'fb_exchange_token': short_lived_token
        }
        response = requests.get(url, params=params)
        if response.status_code != 200:
            raise ValueError(f"Failed to get long-lived access token: {response.text}")
        access_info = response.json()

        # Set expiration time for long-lived token (typically up to 60 days)
        access_info['expires_at'] = time.time() + (60 * 24 * 3600)  # 60 days
        return access_info

    def get_user_info(self, access_token):
        """
        Retrieves user information using the access token.

        Args:
            access_token (str): The user's access token.

        Returns:
            dict: The user information retrieved from Facebook's Graph API.

        Raises:
            ValueError: If the user information request fails.
        """
        url = f"https://graph.facebook.com/me?fields=id,name,email&access_token={access_token}"
        response = requests.get(url)
        if response.status_code != 200:
            raise ValueError(f"Failed to get user info: {response.text}")
        return response.json()

    def logout(self, access_token):
        """
        Revokes the user's access token, effectively logging them out.

        Args:
            access_token (str): The user's access token.

        Raises:
            ValueError: If the logout request fails.
        """
        url = f"https://graph.facebook.com/me/permissions?access_token={access_token}"
        response = requests.delete(url)
        if response.status_code != 200:
            raise ValueError(f"Failed to log out: {response.text}")

    def is_token_expired(self, access_info):
        """
        Checks if the access token has expired.

        Args:
            access_info (dict): The access token information.

        Returns:
            bool: True if the token has expired, False otherwise.
        """
        return time.time() >= access_info['expires_at']