"""
Passwordless Authentication - Passkeys (WebAuthn)

Features:
- FIDO2/WebAuthn support
- Biometric authentication
- Platform authenticator support
- Cross-device authentication
- Phishing-resistant
"""

import uuid
import json
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class PasskeyCredential:
    """Represents a passkey credential"""
    id: str
    user_id: str
    credential_id: str
    public_key: str
    counter: int
    created_at: datetime
    last_used: Optional[datetime] = None
    device_name: Optional[str] = None
    transports: Optional[list] = None


class PasskeyManager:
    """
    Passkey (WebAuthn/FIDO2) authentication manager
    
    Usage:
        passkey_mgr = PasskeyManager(config, db)
        options = await passkey_mgr.register_start(user_id, email)
        credential = await passkey_mgr.register_complete(user_id, response)
        options = await passkey_mgr.authenticate_start()
        user = await passkey_mgr.authenticate_complete(response)
    """
    
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self._rp_name = config.app_name or "Authy App"
        self._rp_id = config.rp_id or config.base_url.split("//")[-1].split("/")[0]
        self._origin = config.base_url
    
    async def register_start(
        self,
        user_id: str,
        email: str,
        display_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Start passkey registration process
        
        Returns challenge options for client-side WebAuthn
        """
        from webauthn import generate_registration_options
        
        user = await self.db.get_user(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Get existing credentials
        existing_credentials = await self.db.get_user_passkeys(user_id)
        
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self._rp_name,
            user_name=email,
            user_id=user_id.encode(),
            user_display_name=display_name or email,
            exclude_credentials=[
                {"id": cred["credential_id"]} 
                for cred in existing_credentials
            ] if existing_credentials else None,
            authenticator_selection={
                "resident_key": "preferred",
                "user_verification": "preferred"
            }
        )
        
        # Store challenge in cache
        await self.db.cache.set(
            f"passkey_challenge:{user_id}",
            {
                "challenge": options.challenge,
                "email": email,
                "type": "registration"
            },
            ttl=300  # 5 minutes
        )
        
        return {
            "challenge": options.challenge,
            "rp": {"id": self._rp_id, "name": self._rp_name},
            "user": {
                "id": user_id,
                "name": email,
                "displayName": display_name or email
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "excludeCredentials": options.exclude_credentials or [],
            "authenticatorSelection": options.authenticator_selection,
            "timeout": 60000
        }
    
    async def register_complete(
        self,
        user_id: str,
        response: Dict[str, Any],
        device_name: Optional[str] = None
    ) -> PasskeyCredential:
        """
        Complete passkey registration
        
        Verifies the attestation and stores the credential
        """
        from webauthn import verify_registration_response
        
        # Retrieve challenge
        challenge_data = await self.db.cache.get(f"passkey_challenge:{user_id}")
        if not challenge_data or challenge_data.get("type") != "registration":
            raise ValueError("Invalid or expired challenge")
        
        expected_challenge = challenge_data["challenge"]
        
        # Verify registration response
        verification = verify_registration_response(
            response=response,
            expected_challenge=expected_challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._origin
        )
        
        if not verification.is_valid:
            raise ValueError("Registration verification failed")
        
        # Store credential
        credential = PasskeyCredential(
            id=str(uuid.uuid4()),
            user_id=user_id,
            credential_id=verification.credential_id,
            public_key=verification.public_key,
            counter=verification.sign_count,
            created_at=datetime.utcnow(),
            device_name=device_name,
            transports=response.get("transports")
        )
        
        await self.db.save_passkey({
            "id": credential.id,
            "user_id": credential.user_id,
            "credential_id": credential.credential_id,
            "public_key": credential.public_key,
            "counter": credential.counter,
            "created_at": credential.created_at.isoformat(),
            "device_name": credential.device_name,
            "transports": credential.transports
        })
        
        # Clear challenge
        await self.db.cache.delete(f"passkey_challenge:{user_id}")
        
        return credential
    
    async def authenticate_start(self) -> Dict[str, Any]:
        """
        Start passkey authentication
        
        Returns challenge options for client-side WebAuthn
        """
        from webauthn import generate_authentication_options
        
        # Generate random challenge
        import secrets
        challenge = secrets.token_bytes(32)
        
        # Store challenge temporarily
        await self.db.cache.set(
            "passkey_auth_challenge",
            {"challenge": challenge.hex(), "type": "authentication"},
            ttl=300
        )
        
        options = generate_authentication_options(
            rp_id=self._rp_id,
            allow_credentials=None,  # Allow all credentials, filter server-side
            user_verification="preferred"
        )
        
        return {
            "challenge": challenge.hex(),
            "rpId": self._rp_id,
            "allowCredentials": options.allow_credentials or [],
            "userVerification": "preferred",
            "timeout": 60000
        }
    
    async def authenticate_complete(
        self,
        response: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Complete passkey authentication
        
        Verifies the assertion and returns user data
        """
        from webauthn import verify_authentication_response
        
        # Retrieve challenge
        challenge_data = await self.db.cache.get("passkey_auth_challenge")
        if not challenge_data or challenge_data.get("type") != "authentication":
            raise ValueError("Invalid or expired challenge")
        
        credential_id = response.get("id")
        if not credential_id:
            raise ValueError("Missing credential ID")
        
        # Find credential in database
        credential = await self.db.get_passkey_by_credential_id(credential_id)
        if not credential:
            raise ValueError("Credential not found")
        
        # Verify authentication response
        verification = verify_authentication_response(
            response=response,
            expected_challenge=challenge_data["challenge"],
            expected_rp_id=self._rp_id,
            expected_origin=self._origin,
            credential_public_key=credential["public_key"],
            credential_current_sign_count=credential["counter"]
        )
        
        if not verification.is_valid:
            raise ValueError("Authentication verification failed")
        
        # Update counter
        await self.db.update_passkey_counter(
            credential["id"],
            verification.new_sign_count
        )
        
        # Update last used
        await self.db.update_passkey_last_used(credential["id"])
        
        # Clear challenge
        await self.db.cache.delete("passkey_auth_challenge")
        
        # Get user data
        user = await self.db.get_user(credential["user_id"])
        
        return {
            "user": user,
            "credential_id": credential_id,
            "authenticated_at": datetime.utcnow().isoformat()
        }
    
    async def list_passkeys(self, user_id: str) -> list:
        """List all passkeys for a user"""
        return await self.db.get_user_passkeys(user_id)
    
    async def delete_passkey(self, user_id: str, credential_id: str) -> bool:
        """Delete a specific passkey"""
        credential = await self.db.get_passkey_by_credential_id(credential_id)
        if not credential or credential["user_id"] != user_id:
            return False
        
        await self.db.delete_passkey(credential["id"])
        return True
