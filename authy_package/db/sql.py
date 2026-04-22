from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from authy_package.db.abstract_db import AbstractDatabase

class SQLDatabase(AbstractDatabase):
    def __init__(self, db_url: str, orm_model):
        """
        Initializes the SQLDatabase instance.

        :param db_url: The database URL for connecting to the SQL database.
        :param orm_model: The ORM model class used for interacting with the database.
        """
        self.orm_model = orm_model
        self.engine = create_async_engine(db_url, echo=True)
        self.session_factory = sessionmaker(bind=self.engine, class_=AsyncSession, expire_on_commit=False)

    async def create_user(self, user_data: dict):
        """
        Creates a new user in the database.

        :param user_data: A dictionary containing user data.
        """
        async with self.session_factory() as session:
            async with session.begin():
                user = self.orm_model(**user_data)
                session.add(user)

    async def get_user_by_identifier(self, username=None, email=None, phone=None):
        """
        Retrieves a user from the database using a unique identifier (username, email, or phone).

        :param username: The username of the user to retrieve.
        :param email: The email of the user to retrieve.
        :param phone: The phone number of the user to retrieve.
        :return: The user object if found, otherwise None.
        """
        async with self.session_factory() as session:
            if username:
                query = select(self.orm_model).where(self.orm_model.username == username)
            elif email:
                query = select(self.orm_model).where(self.orm_model.email == email)
            elif phone:
                query = select(self.orm_model).where(self.orm_model.phone == phone)
            else:
                return None 
            
            result = await session.execute(query)
            return result.scalars().first()

    async def update_user_with_mfa(self, identifier, mfa_secret=None, mfa_enabled=None):
        """
        Updates the multi-factor authentication (MFA) settings for a user.

        :param identifier: The unique identifier of the user (email, username, or phone).
        :param mfa_secret: The new MFA secret to set.
        :param mfa_enabled: A boolean indicating whether MFA is enabled.
        :return: A message indicating the update status.
        """
        async with self.session_factory() as session:
            async with session.begin():
                # Determine the query based on the identifier type
                query = None
                if "@" in identifier:
                    query = select(self.orm_model).where(self.orm_model.email == identifier)
                elif identifier.isdigit():
                    query = select(self.orm_model).where(self.orm_model.phone == identifier)
                else:
                    query = select(self.orm_model).where(self.orm_model.username == identifier)

                result = await session.execute(query)
                user = result.scalars().first()

                if not user:
                    raise ValueError("User not found.")

                # Update MFA information
                if mfa_secret is not None:
                    user.mfa_secret = mfa_secret
                if mfa_enabled is not None:
                    user.mfa_enabled = mfa_enabled

                session.add(user)  # Make sure to add the updated user to the session

        return {"message": "MFA information updated successfully."}

    async def update_user_password(self, identifier: str, new_password: str):
        """
        Updates the password for a user identified by email, username, or phone.

        :param identifier: The unique identifier of the user (email, username, or phone).
        :param new_password: The new password to set for the user.
        :return: A message indicating the update status.
        """
        async with self.session_factory() as session:
            async with session.begin():
                # Determine the query based on the identifier type
                query = None
                if "@" in identifier:  # Email
                    query = select(self.orm_model).where(self.orm_model.email == identifier)
                elif identifier.isdigit():  # Phone number
                    query = select(self.orm_model).where(self.orm_model.phone == identifier)
                else:  # Username
                    query = select(self.orm_model).where(self.orm_model.username == identifier)

                result = await session.execute(query)
                user = result.scalars().first()

                if not user:
                    raise ValueError("User not found.")

                # Update the user's password
                user.password = new_password
                session.add(user) 

        return {"message": "Password updated successfully."}

    async def create_saml_provider(self, provider_data: dict) -> str:
        """Create a SAML provider configuration."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("""
                        INSERT INTO saml_providers (entity_id, metadata_xml, sso_url, slo_url, certificate, created_at)
                        VALUES (:entity_id, :metadata_xml, :sso_url, :slo_url, :certificate, NOW())
                        RETURNING id
                    """),
                    provider_data
                )
                row = result.fetchone()
                return str(row[0]) if row else None

    async def get_saml_provider_by_entity_id(self, entity_id: str):
        """Get a SAML provider by Entity ID."""
        async with self.session_factory() as session:
            from sqlalchemy import text
            result = await session.execute(
                text("SELECT * FROM saml_providers WHERE entity_id = :entity_id"),
                {"entity_id": entity_id}
            )
            row = result.fetchone()
            return dict(row._mapping) if row else None

    async def create_saml_session(self, session_data: dict) -> str:
        """Create a SAML session."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("""
                        INSERT INTO saml_sessions (session_id, request_id, name_id, session_index, created_at)
                        VALUES (:session_id, :request_id, :name_id, :session_index, NOW())
                        RETURNING session_id
                    """),
                    session_data
                )
                row = result.fetchone()
                return str(row[0]) if row else None

    async def get_saml_session(self, request_id: str):
        """Get a SAML session by request ID."""
        async with self.session_factory() as session:
            from sqlalchemy import text
            result = await session.execute(
                text("SELECT * FROM saml_sessions WHERE request_id = :request_id"),
                {"request_id": request_id}
            )
            row = result.fetchone()
            return dict(row._mapping) if row else None

    async def delete_saml_session(self, request_id: str) -> bool:
        """Delete a SAML session."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("DELETE FROM saml_sessions WHERE request_id = :request_id"),
                    {"request_id": request_id}
                )
                return result.rowcount > 0

    async def delete_saml_provider(self, entity_id: str) -> bool:
        """Delete a SAML provider."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("DELETE FROM saml_providers WHERE entity_id = :entity_id"),
                    {"entity_id": entity_id}
                )
                return result.rowcount > 0

    async def create_oidc_provider(self, provider_data: dict) -> str:
        """Create an OIDC provider configuration."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("""
                        INSERT INTO oidc_providers (provider_id, issuer, client_id, client_secret, config_json, created_at)
                        VALUES (:provider_id, :issuer, :client_id, :client_secret, :config_json, NOW())
                        RETURNING provider_id
                    """),
                    provider_data
                )
                row = result.fetchone()
                return str(row[0]) if row else None

    async def get_oidc_provider(self, provider_id: str):
        """Get an OIDC provider by ID."""
        async with self.session_factory() as session:
            from sqlalchemy import text
            result = await session.execute(
                text("SELECT * FROM oidc_providers WHERE provider_id = :provider_id"),
                {"provider_id": provider_id}
            )
            row = result.fetchone()
            return dict(row._mapping) if row else None

    async def update_oidc_provider(self, provider_id: str, update_data: dict) -> bool:
        """Update an OIDC provider."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                set_clause = ", ".join([f"{k} = :{k}" for k in update_data.keys()])
                query = text(f"UPDATE oidc_providers SET {set_clause}, updated_at = NOW() WHERE provider_id = :provider_id")
                update_data['provider_id'] = provider_id
                result = await session.execute(query, update_data)
                return result.rowcount > 0

    async def delete_oidc_provider(self, provider_id: str) -> bool:
        """Delete an OIDC provider."""
        async with self.session_factory() as session:
            async with session.begin():
                from sqlalchemy import text
                result = await session.execute(
                    text("DELETE FROM oidc_providers WHERE provider_id = :provider_id"),
                    {"provider_id": provider_id}
                )
                return result.rowcount > 0
