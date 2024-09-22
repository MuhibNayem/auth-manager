from motor.motor_asyncio import AsyncIOMotorClient
from auth_package.db.abstract_db import AbstractDatabase

class MongoDB(AbstractDatabase):
    def __init__(self, db_url: str, db_name: str, collection_name: str):
        """
        Initializes the MongoDB client and sets up the database and collection.

        :param db_url: The URL of the MongoDB database.
        :param db_name: The name of the database to use.
        :param collection_name: The name of the collection to use.
        """
        self.client = AsyncIOMotorClient(db_url)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    async def create_user(self, user_data: dict):
        """
        Inserts a new user into the collection.

        :param user_data: A dictionary containing user information (e.g., username, email, password).
        :return: None
        """
        await self.collection.insert_one(user_data)

    async def get_user_by_identifier(self, username=None, email=None, phone=None):
        """
        Retrieves a user from the collection based on their identifier.

        :param username: The username of the user (optional).
        :param email: The email of the user (optional).
        :param phone: The phone number of the user (optional).
        :return: The user document if found, otherwise None.
        """
        query = {}
        if username:
            query["username"] = username
        elif email:
            query["email"] = email
        elif phone:
            query["phone"] = phone
        return await self.collection.find_one(query)

    async def update_user_with_mfa(self, identifier, mfa_secret, mfa_enabled=False):
        """
        Updates the Multi-Factor Authentication (MFA) settings for a user.

        :param identifier: The email, username, or phone of the user.
        :param mfa_secret: The secret key for MFA.
        :param mfa_enabled: Boolean indicating whether MFA is enabled (default is False).
        :return: A dictionary with a message indicating the success of the operation.
        """
        query = {}
        if "@" in identifier: 
            query["email"] = identifier
        elif identifier.isdigit():  
            query["phone"] = identifier
        else:
            query["username"] = identifier

        update_query = {
            "$set": {
                "mfa_secret": mfa_secret,
                "mfa_enabled": mfa_enabled
            }
        }
        result = await self.collection.update_one(query, update_query)

        if result.modified_count == 0:
            raise ValueError("User not found or MFA information not updated.")
        
        return {"message": "MFA information updated successfully."}
    
    async def update_user_password(self, identifier: str, new_password: str):
        """
        Updates the user's password based on their identifier.

        :param identifier: The email, username, or phone of the user.
        :param new_password: The new password to set for the user.
        :return: A dictionary with a message indicating the success of the operation.
        :raises ValueError: If the user is not found.
        """
        query = {}
        if "@" in identifier:  # Email
            query["email"] = identifier
        elif identifier.isdigit():  # Phone number
            query["phone"] = identifier
        else:  # Username
            query["username"] = identifier

        result = await self.collection.update_one(
            query,
            {"$set": {"password": new_password}}
        )

        if result.matched_count == 0:
            raise ValueError("User not found.")

        return {"message": "Password updated successfully."}
