import aioredis
import time
import hashlib

from authy_package.cache.abstract_cache import AbstractCache

class RedisCaching(AbstractCache):
    def __init__(self, cache_url: str, token_expiration_time: int = 3600, refresh_token_expiration_time: int = 604800, ID_TOKEN_EXPIRATION_TIME:int = 3600):
        self.redis = aioredis.from_url(cache_url)
        self.TOKEN_EXPIRATION_TIME = token_expiration_time
        self.REFRESH_TOKEN_EXPIRATION_TIME = refresh_token_expiration_time
        self.ID_TOKEN_EXPIRATION_TIME = ID_TOKEN_EXPIRATION_TIME

    async def create_token_pair(self, identifier: str):
        access_token = self._generate_token(identifier)
        refresh_token = self._generate_token(identifier)
        await self.redis.set(access_token, identifier, ex=self.TOKEN_EXPIRATION_TIME)
        await self.redis.set(refresh_token, identifier, ex=self.REFRESH_TOKEN_EXPIRATION_TIME)
        return access_token, refresh_token

    def _generate_token(self, identifier: str) -> str:
        return hashlib.sha256(f"{identifier}_{time.time()}".encode()).hexdigest()

    async def delete_access_token(self, access_token: str):
        await self.redis.delete(access_token)

    async def delete_refresh_token(self, identifier: str):
        refresh_token = f"refresh_{identifier}"
        await self.redis.delete(refresh_token)

    async def store_social_token(self, identifier: str, access_token: str, refresh_token: str = None, id_token: str = None, exp: int = None):
        await self.redis.set(f"{identifier}_access_token", access_token, ex=exp or self.TOKEN_EXPIRATION_TIME)
        if refresh_token:
            await self.redis.set(f"{identifier}_refresh_token", refresh_token, ex=self.REFRESH_TOKEN_EXPIRATION_TIME)
        if id_token:
            await self.redis.set(f"{identifier}_id_token", id_token, ex=exp or self.ID_TOKEN_EXPIRATION_TIME)

    async def update_social_token(self, identifier: str, new_access_token: str, new_refresh_token: str = None, id_token: str = None, exp: int = None):
        await self.redis.set(f"{identifier}_access_token", new_access_token, ex=self.TOKEN_EXPIRATION_TIME)
        if new_refresh_token:
            await self.redis.set(f"{identifier}_refresh_token", new_refresh_token, ex=self.REFRESH_TOKEN_EXPIRATION_TIME)
        if id_token:
            await self.redis.set(f"{identifier}_id_token", id_token, ex=exp or self.REFRESH_TOKEN_EXPIRATION_TIME)
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expires_in": self.TOKEN_EXPIRATION_TIME,
            "refresh_expires_in": self.REFRESH_TOKEN_EXPIRATION_TIME if new_refresh_token else None
        }

    async def validate_access_token(self, access_token: str):
        identifier = await self.redis.get(access_token)
        if identifier:
            return identifier.decode('utf-8')
        return None

    async def validate_refresh_token(self, refresh_token: str):
        identifier = await self.redis.get(refresh_token)
        if identifier:
            # Ensure token has not expired
            token_creation_time = int(refresh_token.split("_")[-1])
            if time.time() - token_creation_time > self.REFRESH_TOKEN_EXPIRATION_TIME:
                await self.delete_refresh_token(identifier.decode('utf-8'))
                return None
            return identifier.decode('utf-8')
        return None
    
    async def retrieve_access_token(self, identifier: str):
        access_token = await self.redis.get(f"{identifier}_access_token")
        if access_token:
            return access_token.decode('utf-8')
        return None
    
    # New function to generate a refresh token for an existing access token
    async def generate_refresh_token_for_access_token(self, access_token: str):
        identifier = await self.validate_access_token(access_token)
        if not identifier:
            raise ValueError("Invalid or expired access token.")

        refresh_token = self._generate_token(identifier)
        await self.redis.set(refresh_token, identifier, ex=self.REFRESH_TOKEN_EXPIRATION_TIME)

        return refresh_token
    
    # Store a reset change password token with an expiration time
    async def store_reset_token(self, email: str, reset_token: str, expiration: int = 900):
        """Store the password reset token for the user."""
        await self.redis.set(f"reset_token_{email}", reset_token, ex=expiration)

    # Retrieve the reset change password token from Redis
    async def get_reset_token(self, email: str) -> str:
        """Retrieve the reset token for the user."""
        token = await self.redis.get(f"reset_token_{email}")
        return token.decode('utf-8') if token else None

    # Delete the reset change password token after successful password update
    async def delete_reset_token(self, email: str):
        """Delete the reset token after the password has been reset."""
        await self.redis.delete(f"reset_token_{email}")
