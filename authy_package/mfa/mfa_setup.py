import pyotp
from authy_package.db.abstract_db import AbstractDatabase

class MFAAuthManager:
    def __init__(self, db: AbstractDatabase):
        """
        Initializes the MFAAuthManager with a database instance.

        :param db: An instance of AbstractDatabase for user operations.
        """
        self.db = db

    async def setup_mfa(self, username=None, email=None, phone=None):
        """
        Sets up multi-factor authentication (MFA) for a user.

        This method generates a new MFA secret for the user and updates the user's record in the database.

        :param username: The username of the user for whom MFA is being set up.
        :param email: The email of the user for whom MFA is being set up.
        :param phone: The phone number of the user for whom MFA is being set up.
        :return: A dictionary containing the generated MFA secret.
        :raises ValueError: If the user is not found.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")
        mfa_secret = pyotp.random_base32()
        user_identifier = username or email or phone
        await self.db.update_user_with_mfa(user_identifier, mfa_secret, mfa_enabled=True)
        return {"mfa_secret": mfa_secret}

    async def verify_mfa_code(self, mfa_code, username=None, email=None, phone=None):
        """
        Verifies the provided MFA code against the user's stored MFA secret.

        :param mfa_code: The MFA code provided by the user.
        :param username: The username of the user to verify the MFA code for.
        :param email: The email of the user to verify the MFA code for.
        :param phone: The phone number of the user to verify the MFA code for.
        :raises ValueError: If the user is not found or if the MFA code is invalid.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")
        totp = pyotp.TOTP(user['mfa_secret'])
        if not totp.verify(mfa_code):
            raise ValueError("Invalid MFA code.")

    async def reconfigure_mfa(self, username=None, email=None, phone=None):
        """
        Reconfigures the MFA for a user by generating a new MFA secret.

        This method updates the user's MFA secret and enables MFA.

        :param username: The username of the user for whom MFA is being reconfigured.
        :param email: The email of the user for whom MFA is being reconfigured.
        :param phone: The phone number of the user for whom MFA is being reconfigured.
        :return: A dictionary containing the new MFA secret.
        :raises ValueError: If the user is not found.
        """
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")
        mfa_secret = pyotp.random_base32()
        user_identifier = username or email or phone
        await self.db.update_user_with_mfa(user_identifier, mfa_secret, mfa_enabled=True)

        return {"mfa_secret": mfa_secret}
