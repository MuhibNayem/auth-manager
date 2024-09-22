import requests
from google_auth_oauthlib.flow import InstalledAppFlow
import datetime


class GoogleManager:
    def __init__(self, client_secrets_file, redirect_uri, scopes):
        """
        Initializes the GoogleManager with client secrets, redirect URI, and OAuth scopes.

        :param client_secrets_file: Path to the client secrets JSON file.
        :param redirect_uri: The URI to which the user will be redirected after authorization.
        :param scopes: A list of scopes that the application requests access to.
        """
        self.client_secrets_file = client_secrets_file
        self.redirect_uri = redirect_uri
        self.scopes = scopes

    def authorize(self):
        """
        Initiates the OAuth authorization flow and retrieves the authorization code.

        This method prints the authorization URL and prompts the user to visit it to authorize the application.
        
        :return: The authorization code obtained after user authorization.
        """
        flow = InstalledAppFlow.from_client_secrets_file(
            self.client_secrets_file, scopes=self.scopes)
        authorization_url, _ = flow.authorization_url(redirect_uri=self.redirect_uri)
        print(f"Please visit this URL to authorize the application: {authorization_url}")
        code = input("Enter the code from the authorization page: ")
        return code

    def exchange_code_for_tokens(self, code):
        """
        Exchanges the authorization code for access and refresh tokens.

        :param code: The authorization code obtained from the user.
        :return: Credentials containing the access and refresh tokens.
        """
        flow = InstalledAppFlow.from_client_secrets_file(
            self.client_secrets_file, scopes=self.scopes)
        credentials = flow.exchange(code=code)
        return credentials

    def refresh_access_token(self, credentials):
        """
        Refreshes the access token using the refresh token.

        This method checks if the credentials are expired and attempts to refresh the access token.
        
        :param credentials: The credentials containing the refresh token.
        :return: Updated credentials with the new access token, or None if refreshing failed.
        """
        if credentials.expired and credentials.refresh_token:
            refresh_token = credentials.refresh_token
            url = "https://www.googleapis.com/oauth2/v4/token"
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = {
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }

            try:
                response = requests.post(url, headers=headers, data=data)
                response.raise_for_status()  # Raise an HTTPError if the response was unsuccessful
            except requests.exceptions.RequestException as e:
                print(f"Error refreshing access token: {e}")
                return None

            response_data = response.json()

            # Ensure the response contains the required tokens
            if 'access_token' in response_data and 'expires_in' in response_data:
                updated_credentials = credentials.with_subject(response_data.get('id_token'))
                updated_credentials.token = response_data['access_token']

                # Set the expiration time using datetime
                updated_credentials.expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=response_data['expires_in'])
                return updated_credentials
            else:
                print("Error: Token refresh failed, missing access_token or expires_in.")
                return None
        else:
            print("Credentials are not expired or refresh token is not available.")
            return None
    
    def get_user_info(self, credentials):
        """
        Retrieves user information using the access token.

        This method sends a request to the Google User Info API to get details about the user.

        :param credentials: The credentials containing the access token.
        :return: A JSON object containing user information.
        """
        url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {'Authorization': f'Bearer {credentials.token}'}
        response = requests.get(url, headers=headers)
        return response.json()
