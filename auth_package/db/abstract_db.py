from abc import ABC, abstractmethod

class AbstractDatabase(ABC):
    @abstractmethod
    async def create_user(self, user_data: dict):
        """
        Creates a new user in the database.

        :param user_data: A dictionary containing user information (e.g., username, email, password).
        :return: None
        """
        pass

    @abstractmethod
    async def get_user_by_identifier(self, username=None, email=None, phone=None):
        """
        Retrieves a user from the database based on their identifier.

        :param username: The username of the user (optional).
        :param email: The email of the user (optional).
        :param phone: The phone number of the user (optional).
        :return: The user object if found, otherwise None.
        """
        pass

    @abstractmethod
    async def update_user_with_mfa(self, identifier, mfa_secret, mfa_enabled=False):
        """
        Updates the Multi-Factor Authentication (MFA) settings for a user.

        :param identifier: The email, username, or phone of the user.
        :param mfa_secret: The secret key for MFA.
        :param mfa_enabled: Boolean indicating whether MFA is enabled (default is False).
        :return: A dictionary with a message indicating the success of the operation.
        """
        pass
    
    @abstractmethod
    async def update_user_password(self, identifier: str, new_password: str):
        """
        Update the user's password based on their identifier (email, username, or phone).

        :param identifier: The email, username, or phone of the user
        :param new_password: The new hashed password to set
        :return: A dict with a message indicating success
        """
        pass
