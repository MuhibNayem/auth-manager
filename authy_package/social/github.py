import requests

class GitHubManager:
    def __init__(self, client_id, client_secret, redirect_uri):
        """
        Initializes the GitHubManager with client ID, client secret, and redirect URI.

        :param client_id: The client ID of the GitHub OAuth application.
        :param client_secret: The client secret of the GitHub OAuth application.
        :param redirect_uri: The URI to which the user will be redirected after authorization.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        """
        Constructs the authorization URL for GitHub's OAuth flow.

        This method generates the URL that the user needs to visit to authorize the application.

        :return: The URL for the user to authorize the application.
        """
        url = "https://github.com/login/oauth/authorize"
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'user:email,user:public_profile'
        }
        return url + "?" + requests.utils.urlencode(params)

    def get_access_token(self, code):
        """
        Exchanges the authorization code for an access token.

        This method sends a request to GitHub to exchange the provided authorization code for an access token.

        :param code: The authorization code obtained from the user.
        :return: A JSON object containing the access token and other relevant information.
        """
        url = "https://github.com/login/oauth/access_token"
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        response = requests.post(url, data=params, headers={'Accept': 'application/json'})
        return response.json()

    def get_user_info(self, access_token):
        """
        Retrieves user information using the access token.

        This method sends a request to the GitHub API to get details about the authenticated user.

        :param access_token: The access token obtained from the OAuth flow.
        :return: A JSON object containing user information.
        """
        url = "https://api.github.com/user"
        headers = {'Authorization': f'token {access_token}'}
        response = requests.get(url, headers=headers)
        return response.json()
