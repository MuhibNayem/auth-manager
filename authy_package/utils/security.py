import os
import time
import secrets
from typing import Optional, Dict, Any
import jwt
from mailjet_rest import Client
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.cache.abstract_cache import AbstractCache
from passlib.context import CryptContext
from authy_package.config import JWTConfig

# Password hashing context supporting bcrypt and argon2
pwd_context = CryptContext(schemes=["bcrypt", "argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hashes the given password using bcrypt or argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies if the plain password matches the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def generate_reset_token() -> str:
    """Generates a secure random reset token using secrets module."""
    return secrets.token_urlsafe(32)


class JWTTokenManager:
    """
    Secure JWT token generation and validation.
    
    Usage:
        jwt_manager = JWTTokenManager(secret_key="your-secret-key")
        token = jwt_manager.create_access_token(user_identifier="user123")
        payload = jwt_manager.validate_token(token)
    """
    
    def __init__(self, config: Optional[JWTConfig] = None, secret_key: Optional[str] = None, warn_only: bool = True):
        if config:
            self.secret_key = config.secret_key
            self.algorithm = config.algorithm
            self.access_token_expiration = config.access_token_expiration
            self.refresh_token_expiration = config.refresh_token_expiration
        else:
            self.secret_key = secret_key or os.getenv("AUTHY_JWT_SECRET", "your-secret-key-change-in-production")
            self.algorithm = "HS256"
            self.access_token_expiration = 3600
            self.refresh_token_expiration = 604800
        
        if self.secret_key == "your-secret-key-change-in-production":
            if os.getenv("AUTHY_ENV") == "production" and not warn_only:
                raise ValueError("JWT secret key must be changed from default in production!")
            else:
                import warnings
                warnings.warn("Using default JWT secret key. Set AUTHY_JWT_SECRET in production.")
    
    def create_access_token(self, user_identifier: str, additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """Create a JWT access token."""
        now = int(time.time())
        payload = {
            "sub": user_identifier,
            "iat": now,
            "exp": now + self.access_token_expiration,
            "type": "access",
        }
        if additional_claims:
            payload.update(additional_claims)
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_identifier: str) -> str:
        """Create a JWT refresh token."""
        now = int(time.time())
        payload = {
            "sub": user_identifier,
            "iat": now,
            "exp": now + self.refresh_token_expiration,
            "type": "refresh",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate a JWT token and return its payload if valid."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def create_token_pair(self, user_identifier: str) -> Dict[str, str]:
        """Create both access and refresh tokens."""
        return {
            "access_token": self.create_access_token(user_identifier),
            "refresh_token": self.create_refresh_token(user_identifier),
        }


class SecurityManager:
    def __init__(self, db: AbstractDatabase, cache: AbstractCache = None, api_key: str = None, api_secret: str = None):
        """
        Initializes the SecurityManager with database, cache, and Mailjet client credentials.

        :param db: The database instance for user operations.
        :param cache: The cache instance for storing temporary data (e.g., reset tokens).
        :param api_key: Mailjet API key.
        :param api_secret: Mailjet API secret.
        """
        self.db = db
        self.cache = cache
        self.mailjet_client = Client(
            auth=(api_key or os.getenv('MAILJET_API_KEY'), api_secret or os.getenv('MAILJET_API_SECRET')),
            version='v3.1'
        )

    async def send_password_reset_email(self, user_email: str, reset_link: str, sender_email: str, sender_name: str, reset_token) -> dict:
        """Sends a password reset email using Mailjet.

        :param user_email: The email address of the user to send the reset email to.
        :param reset_link: The link for the user to reset their password.
        :param sender_email: The email address of the sender.
        :param sender_name: The name of the sender.
        :return: A message indicating the result of the email sending operation.
        """
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #333;">Password Reset Request</h2>
                    <p style="font-size: 16px; color: #555;">
                        Hi there,
                    </p>
                    <p style="font-size: 16px; color: #555;">
                        We received a request to reset your password. Click the link below to reset it:
                    </p>
                    <a href="{reset_link}" style="display: inline-block; margin: 20px 0; padding: 12px 20px; background-color: #007bff; color: #FFFFFFFF; text-decoration: none; border-radius: 5px;">
                        Reset Password
                    </a>
                    <p style="font-size: 14px; color: #555;">here is the reset token for updating the password: <span style="font-size: 16px; color: #3D78D6FF;">"{reset_token}"</span>
                    </p>
                    <p style="font-size: 14px; color: #777;">
                        If you didn't request this, you can ignore this email. Your password won't change until you create a new one.
                    </p>
                    <p style="font-size: 14px; color: #777;">
                        Thanks,<br>
                        {sender_name}
                    </p>
                </div>
            </body>
        </html>
        """

        data = {
            'Messages': [
                {
                    'From': {
                        'Email': sender_email,
                        'Name': sender_name
                    },
                    'To': [
                        {
                            'Email': user_email,
                            'Name': 'User'
                        }
                    ],
                    'Subject': 'Password Reset Request',
                    'TextPart': f'Click the link to reset your password: {reset_link}',
                    'HTMLPart': html_content
                }
            ]
        }

        try:
            response = self.mailjet_client.send(data=data)
            if response.status_code == 200:
                return {"message": "Password reset email sent successfully."}
            else:
                raise ValueError(f"Failed to send email: {response.status_code}, {response.json()}")
        except Exception as e:
            raise ValueError(f"Error sending email: {str(e)}")

    
    async def generate_and_send_reset_link(self, username=None, email=None, phone=None, sender_email: str = '', sender_name: str = '') -> dict:
        """Generates a reset token, stores it, and sends the password reset email.

        :param username: Username of the user requesting a password reset.
        :param email: Email of the user requesting a password reset.
        :param phone: Phone number of the user requesting a password reset.
        :param sender_email: The email address of the sender.
        :param sender_name: The name of the sender.
        :return: A message indicating the result of the operation.
        """
        # Find user by identifier
        user = await self.db.get_user_by_identifier(username=username, email=email, phone=phone)
        if not user:
            raise ValueError("User not found.")

        # Generate a reset token and store it in cache (expires in 15 minutes)
        reset_token = generate_reset_token()
        if self.cache:
            self.cache.store_reset_token(user['email'], reset_token, expiration=900)

        # Generate the reset link (in production, this should point to the real reset page)
        reset_link = f"http://example.com/reset-password?token={reset_token}&email={user['email']}"

        # Send the password reset email
        await self.send_password_reset_email(user_email=user['email'], reset_link=reset_link, sender_email=sender_email, sender_name=sender_name, reset_token=reset_token)

        return {"message": "Password reset link sent."}

    async def validate_reset_token(self, email: str, token: str) -> bool:
        """Validates the reset token by checking against the stored value in cache.

        :param email: The email of the user to validate the token for.
        :param token: The reset token to validate.
        :return: True if the token is valid, otherwise raises a ValueError.
        """
        stored_token = self.cache.get_reset_token(email) if self.cache else None
        if stored_token and stored_token == token:
            return True
        raise ValueError("Invalid or expired reset token.")

    async def update_password(self, email: str, new_password: str, token: str) -> dict:
        """Validates the reset token and updates the user's password.

        :param email: The email of the user whose password is to be updated.
        :param new_password: The new password to set.
        :param token: The reset token to validate.
        :return: A message indicating the result of the password update operation.
        """
        await self.validate_reset_token(email=email, token=token)
        hashed_password = hash_password(new_password)
        await self.db.update_user_password(email=email, new_password=hashed_password)
        if self.cache:
            self.cache.delete_reset_token(email)

        return {"message": "Password updated successfully."}
