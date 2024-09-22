from abc import ABC, abstractmethod

class AbstractCache(ABC):
    @abstractmethod
    def create_token_pair(self, identifier: str):
        """Creates a pair of access and refresh tokens for the given identifier."""
        pass

    @abstractmethod
    def delete_access_token(self, access_token: str):
        """Deletes the specified access token from the cache."""
        pass

    @abstractmethod
    def delete_refresh_token(self, identifier: str):
        """Deletes the refresh token associated with the given identifier from the cache."""
        pass 

    @abstractmethod
    def validate_access_token(self, access_token: str):
        """Validates the specified access token and returns the associated identifier if valid."""
        pass

    @abstractmethod
    def validate_refresh_token(self, refresh_token: str):
        """Validates the specified refresh token and returns the associated identifier if valid."""
        pass

    @abstractmethod
    def store_social_token(self, identifier: str, access_token: str, refresh_token: str = None):
        """Stores social login tokens in the cache."""
        pass

    @abstractmethod
    def update_social_token(self, identifier: str, new_access_token: str, new_refresh_token: str = None):
        """Updates social login tokens in the cache."""
        pass
    
    @abstractmethod
    async def get_reset_token(self, email: str) -> str:
        """Retrieve token for update password in the cache."""
        pass
    
    @abstractmethod
    async def delete_reset_token(self, email: str):
        """Delete token for update password in the cache."""
        pass
    
    @abstractmethod
    async def store_reset_token(self, email: str, reset_token: str, expiration: int = 900):
        """ Store reset Token for update password in the cache."""
        pass
