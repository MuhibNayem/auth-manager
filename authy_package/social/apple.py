import aiohttp
import jwt
import time
import json
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwt.algorithms import RSAAlgorithm


class AppleManager:
    """
    Apple Sign-In manager with proper security measures.
    
    Features:
    - ES256 client secret generation
    - ID token signature verification using Apple's JWKS
    - Async HTTP requests
    
    Usage:
        apple_mgr = AppleManager(client_id="...", team_id="...", key_id="...", private_key="...")
        url = apple_mgr.get_authorization_url(redirect_uri="https://example.com/callback")
        tokens = await apple_mgr.get_access_token(code="auth_code")
        user_info = await apple_mgr.get_user_info(id_token=tokens['id_token'])
    """
    
    def __init__(self, client_id: str, team_id: str, key_id: str, private_key: str):
        self.client_id = client_id
        self.team_id = team_id
        self.key_id = key_id
        self.private_key = private_key
        self._jwks_cache = None
        self._jwks_cache_time = 0

    def get_authorization_url(self, redirect_uri: str, scope: str = "openid email profile", state: Optional[str] = None) -> str:
        """Generates the authorization URL for Apple Sign-In."""
        import urllib.parse
        url = "https://appleid.apple.com/auth/oauth2/v2/authorize"
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'response_type': 'code',
            'response_mode': 'form_post',
        }
        if state:
            params['state'] = state
        return url + "?" + urllib.parse.urlencode(params)

    async def get_access_token(self, code: str) -> Dict[str, Any]:
        """Exchanges the authorization code for tokens."""
        url = "https://appleid.apple.com/auth/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'code': code,
            'grant_type': 'authorization_code'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    raise ValueError(f"Failed to get access token: {response.status}")
                return await response.json()

    def generate_client_secret(self) -> str:
        """Generates a client secret using ES256."""
        now = int(time.time())
        exp = now + 3600
        
        header = {"alg": "ES256", "kid": self.key_id}
        payload = {
            "iss": self.team_id,
            "iat": now,
            "exp": exp,
            "aud": "https://appleid.apple.com",
            "sub": self.client_id
        }
        
        # Load private key
        if isinstance(self.private_key, str):
            key = serialization.load_pem_private_key(
                self.private_key.encode(),
                password=None,
                backend=default_backend()
            )
        else:
            key = self.private_key
        
        return jwt.encode(payload, key, algorithm='ES256', headers=header)

    async def _get_apple_jwks(self) -> Dict:
        """Fetch Apple's JWKS for token verification."""
        now = time.time()
        # Cache JWKS for 1 hour
        if self._jwks_cache and (now - self._jwks_cache_time) < 3600:
            return self._jwks_cache
        
        async with aiohttp.ClientSession() as session:
            async with session.get("https://appleid.apple.com/auth/keys") as response:
                if response.status != 200:
                    raise ValueError("Failed to fetch Apple JWKS")
                self._jwks_cache = await response.json()
                self._jwks_cache_time = now
                return self._jwks_cache

    async def get_user_info(self, id_token: str) -> Dict[str, Any]:
        """
        Decodes and verifies the ID token signature.
        
        SECURITY FIX: Now properly verifies Apple's signature using JWKS
        """
        # Fetch Apple's public keys
        jwks = await self._get_apple_jwks()
        
        # Find the key that matches the token's kid
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        
        if not kid:
            raise ValueError("ID token missing kid header")
        
        # Find matching key in JWKS
        matching_key = None
        for key in jwks['keys']:
            if key['kid'] == kid:
                matching_key = key
                break
        
        if not matching_key:
            raise ValueError("No matching public key found for token")
        
        # Convert JWK to a public key using PyJWT's JWK support (handles base64url correctly)
        public_key = RSAAlgorithm.from_jwk(json.dumps(matching_key))
        
        # Verify and decode token
        try:
            decoded_token = jwt.decode(
                id_token,
                key=public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer='https://appleid.apple.com'
            )
            return decoded_token
        except jwt.ExpiredSignatureError:
            raise ValueError("ID token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid ID token: {str(e)}")

    async def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refreshes the access token."""
        url = "https://appleid.apple.com/auth/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status == 200:
                    return await response.json()
                return None

    async def logout(self, access_token: str) -> None:
        """Revokes the access token."""
        url = "https://appleid.apple.com/auth/oauth2/v2/revoke"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.generate_client_secret(),
            'token': access_token
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status != 200:
                    raise ValueError(f"Failed to revoke token: {response.status}")