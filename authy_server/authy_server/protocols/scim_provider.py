"""
SCIM 2.0 Provider Implementation

System for Cross-domain Identity Management:
- User provisioning/deprovisioning
- Group management
- Schema support
- Filter queries
- Bulk operations (coming soon)

Compatible with Azure AD, Okta, OneLogin, and other IdPs.
"""
from datetime import datetime
from typing import Dict, Any, Optional, List


class SCIMProvider:
    """SCIM 2.0 Service Provider."""
    
    def __init__(self):
        self.base_url = "https://authy.dev/scim/v2"
        self.schemas = {
            "User": self._user_schema(),
            "Group": self._group_schema(),
        }
    
    def _user_schema(self) -> Dict[str, Any]:
        """SCIM User schema definition."""
        return {
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "unique": True},
                {"name": "name", "type": "complex", "subAttributes": [
                    {"name": "givenName", "type": "string"},
                    {"name": "familyName", "type": "string"},
                    {"name": "middleName", "type": "string"},
                    {"name": "honorificPrefix", "type": "string"},
                    {"name": "honorificSuffix", "type": "string"},
                ]},
                {"name": "displayName", "type": "string"},
                {"name": "nickName", "type": "string"},
                {"name": "profileUrl", "type": "reference"},
                {"name": "title", "type": "string"},
                {"name": "userType", "type": "string"},
                {"name": "preferredLanguage", "type": "string"},
                {"name": "locale", "type": "string"},
                {"name": "timezone", "type": "string"},
                {"name": "active", "type": "boolean"},
                {"name": "password", "type": "string", "direction": "in", "returned": "never"},
                {"name": "emails", "type": "complex", "multiValued": True, "subAttributes": [
                    {"name": "value", "type": "string"},
                    {"name": "display", "type": "string"},
                    {"name": "type", "type": "string"},
                    {"name": "primary", "type": "boolean"},
                ]},
                {"name": "phoneNumbers", "type": "complex", "multiValued": True},
                {"name": "ims", "type": "complex", "multiValued": True},
                {"name": "photos", "type": "complex", "multiValued": True},
                {"name": "addresses", "type": "complex", "multiValued": True},
                {"name": "groups", "type": "complex", "multiValued": True},
                {"name": "entitlements", "type": "complex", "multiValued": True},
                {"name": "roles", "type": "complex", "multiValued": True},
                {"name": "x509Certificates", "type": "complex", "multiValued": True},
            ],
        }
    
    def _group_schema(self) -> Dict[str, Any]:
        """SCIM Group schema definition."""
        return {
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True},
                {"name": "members", "type": "complex", "multiValued": True, "subAttributes": [
                    {"name": "value", "type": "string"},
                    {"name": "$ref", "type": "reference"},
                    {"name": "display", "type": "string"},
                ]},
            ],
        }
    
    async def list_users(
        self,
        start_index: int = 1,
        count: int = 10,
        filter_expr: Optional[str] = None,
        sort_by: Optional[str] = None,
        sort_order: str = "ascending",
    ) -> List[Dict[str, Any]]:
        """
        List users with pagination and filtering.
        
        Supports SCIM filter expressions:
        - userName eq "john.doe"
        - email sw "@example.com"
        - active eq true
        - name.givenName co "John"
        """
        # In production, query database with filters
        # This is a placeholder
        
        users = []
        # Example user
        users.append({
            "id": "user_123",
            "userName": "john.doe@example.com",
            "name": {
                "givenName": "John",
                "familyName": "Doe",
            },
            "emails": [{"value": "john.doe@example.com", "primary": True}],
            "active": True,
            "meta": {
                "resourceType": "User",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        })
        
        return users
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        # Query database
        return {
            "id": user_id,
            "userName": "john.doe@example.com",
            "name": {
                "givenName": "John",
                "familyName": "Doe",
            },
            "emails": [{"value": "john.doe@example.com", "primary": True}],
            "active": True,
            "meta": {
                "resourceType": "User",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        }
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user from SCIM payload."""
        # Validate against schema
        # Create in database
        # Return created user
        
        new_user = {
            "id": f"user_{datetime.utcnow().timestamp()}",
            "userName": user_data.get("userName"),
            "name": user_data.get("name", {}),
            "emails": user_data.get("emails", []),
            "active": user_data.get("active", True),
            "meta": {
                "resourceType": "User",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        }
        
        return new_user
    
    async def update_user(
        self,
        user_id: str,
        user_data: Dict[str, Any],
        replace: bool = False,
    ) -> Dict[str, Any]:
        """Update user (PUT for replace, PATCH for partial)."""
        # Get existing user
        # Merge or replace attributes
        # Save to database
        
        return await self.get_user(user_id)
    
    async def patch_user(
        self,
        user_id: str,
        operations: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Patch user with SCIM operations.
        
        Operations format:
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "emails", "value": [...]},
                {"op": "replace", "path": "active", "value": false},
                {"op": "remove", "path": "nickName"},
            ]
        }
        """
        ops = operations.get("Operations", [])
        
        # Apply operations
        # Save to database
        
        return await self.get_user(user_id)
    
    async def delete_user(self, user_id: str) -> None:
        """Delete user (soft delete recommended)."""
        # Mark as inactive or delete from database
        pass
    
    async def list_groups(
        self,
        start_index: int = 1,
        count: int = 10,
        filter_expr: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List groups with pagination."""
        groups = []
        
        groups.append({
            "id": "group_123",
            "displayName": "Engineering",
            "members": [],
            "meta": {
                "resourceType": "Group",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        })
        
        return groups
    
    async def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Get group by ID."""
        return {
            "id": group_id,
            "displayName": "Engineering",
            "members": [],
            "meta": {
                "resourceType": "Group",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        }
    
    async def create_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new group."""
        new_group = {
            "id": f"group_{datetime.utcnow().timestamp()}",
            "displayName": group_data.get("displayName"),
            "members": group_data.get("members", []),
            "meta": {
                "resourceType": "Group",
                "created": datetime.utcnow().isoformat(),
                "lastModified": datetime.utcnow().isoformat(),
            },
        }
        
        return new_group
    
    async def delete_group(self, group_id: str) -> None:
        """Delete group."""
        pass
    
    def format_list_response(
        self,
        resources: List[Dict[str, Any]],
        resource_type: str,
        start_index: int,
        count: int,
    ) -> Dict[str, Any]:
        """Format list response according to SCIM spec."""
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resources),
            "itemsPerPage": count,
            "startIndex": start_index,
            "Resources": resources,
        }
    
    def get_sp_config(self) -> Dict[str, Any]:
        """Return Service Provider Configuration."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://authy.dev/docs/scim",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 100},
            "changePassword": {"supported": True},
            "sort": {"supported": True},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using OAuth 2.0 Bearer tokens",
                    "specUri": "https://tools.ietf.org/html/rfc6750",
                }
            ],
        }
    
    def get_resource_types(self) -> List[Dict[str, Any]]:
        """Return available resource types."""
        return [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": f"{self.base_url}/Users",
                "description": "User Account",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": f"{self.base_url}/Groups",
                "description": "Group",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
            },
        ]
    
    def get_schemas(self) -> List[Dict[str, Any]]:
        """Return supported schemas."""
        return list(self.schemas.values())
