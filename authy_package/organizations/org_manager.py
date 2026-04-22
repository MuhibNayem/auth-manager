"""
Organization & Multi-Tenancy Management

Features:
- Multi-tenant support
- Organization hierarchy
- Role-based access control (RBAC)
- Team management
- Invitation system
- Billing integration ready
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum


class OrgRole(Enum):
    """Organization roles"""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class InvitationStatus(Enum):
    """Invitation statuses"""
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"


@dataclass
class Organization:
    """Represents an organization/tenant"""
    id: str
    name: str
    slug: str
    created_at: datetime
    updated_at: datetime
    owner_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    plan: str = "free"
    max_members: int = 10


@dataclass
class OrgMember:
    """Organization member"""
    id: str
    org_id: str
    user_id: str
    role: OrgRole
    joined_at: datetime
    invited_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Invitation:
    """Organization invitation"""
    id: str
    org_id: str
    email: str
    role: OrgRole
    status: InvitationStatus
    invited_by: str
    created_at: datetime
    expires_at: datetime
    token: str


class OrganizationManager:
    """
    Multi-tenancy and organization management
    
    Usage:
        org_mgr = OrganizationManager(config, db, cache)
        org = await org_mgr.create_organization("Acme Corp", user_id)
        await org_mgr.add_member(org.id, user_id, OrgRole.MEMBER)
        await org_mgr.send_invitation(org.id, "new@example.com", OrgRole.GUEST)
    """
    
    def __init__(self, config, db, cache):
        self.config = config
        self.db = db
        self.cache = cache
        self._invitation_ttl = 604800  # 7 days
    
    async def create_organization(
        self,
        name: str,
        owner_id: str,
        slug: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Organization:
        """Create a new organization"""
        org_id = str(uuid.uuid4())
        
        if not slug:
            slug = self._generate_slug(name)
        
        # Check slug uniqueness
        existing = await self.db.get_organization_by_slug(slug)
        if existing:
            slug = f"{slug}-{uuid.uuid4().hex[:6]}"
        
        now = datetime.utcnow()
        org = Organization(
            id=org_id,
            name=name,
            slug=slug,
            created_at=now,
            updated_at=now,
            owner_id=owner_id,
            metadata=metadata or {},
            plan="free",
            max_members=self.config.default_org_max_members
        )
        
        # Save organization
        await self.db.save_organization({
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "created_at": org.created_at.isoformat(),
            "updated_at": org.updated_at.isoformat(),
            "owner_id": org.owner_id,
            "metadata": org.metadata,
            "is_active": org.is_active,
            "plan": org.plan,
            "max_members": org.max_members
        })
        
        # Add owner as member
        await self._add_member_internal(
            org.id,
            owner_id,
            OrgRole.OWNER,
            invited_by=None
        )
        
        return org
    
    async def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID"""
        data = await self.db.get_organization(org_id)
        if not data:
            return None
        
        return self._deserialize_org(data)
    
    async def get_organization_by_slug(self, slug: str) -> Optional[Organization]:
        """Get organization by slug"""
        data = await self.db.get_organization_by_slug(slug)
        if not data:
            return None
        
        return self._deserialize_org(data)
    
    async def get_user_organizations(self, user_id: str) -> List[Organization]:
        """Get all organizations a user belongs to"""
        org_ids = await self.db.get_user_org_ids(user_id)
        orgs = []
        
        for org_id in org_ids:
            org = await self.get_organization(org_id)
            if org and org.is_active:
                orgs.append(org)
        
        return orgs
    
    async def get_member_role(self, org_id: str, user_id: str) -> Optional[OrgRole]:
        """Get a user's role in an organization"""
        member = await self.db.get_org_member(org_id, user_id)
        if not member:
            return None
        
        return OrgRole(member["role"])
    
    async def add_member(
        self,
        org_id: str,
        user_id: str,
        role: OrgRole,
        invited_by: Optional[str] = None
    ) -> OrgMember:
        """Add a member to an organization"""
        org = await self.get_organization(org_id)
        if not org:
            raise ValueError("Organization not found")
        
        # Check member limit
        members = await self.get_members(org_id)
        if len(members) >= org.max_members:
            raise ValueError("Organization member limit reached")
        
        # Check if already member
        existing = await self.db.get_org_member(org_id, user_id)
        if existing:
            raise ValueError("User is already a member")
        
        return await self._add_member_internal(org_id, user_id, role, invited_by)
    
    async def _add_member_internal(
        self,
        org_id: str,
        user_id: str,
        role: OrgRole,
        invited_by: Optional[str]
    ) -> OrgMember:
        """Internal method to add member"""
        member_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        member = OrgMember(
            id=member_id,
            org_id=org_id,
            user_id=user_id,
            role=role,
            joined_at=now,
            invited_by=invited_by
        )
        
        await self.db.save_org_member({
            "id": member.id,
            "org_id": member.org_id,
            "user_id": member.user_id,
            "role": member.role.value,
            "joined_at": member.joined_at.isoformat(),
            "invited_by": member.invited_by
        })
        
        return member
    
    async def remove_member(self, org_id: str, user_id: str) -> bool:
        """Remove a member from an organization"""
        member = await self.db.get_org_member(org_id, user_id)
        if not member:
            return False
        
        # Prevent removing last owner
        if member["role"] == OrgRole.OWNER.value:
            owners = await self._get_members_by_role(org_id, OrgRole.OWNER)
            if len(owners) <= 1:
                raise ValueError("Cannot remove the last owner")
        
        await self.db.delete_org_member(org_id, user_id)
        return True
    
    async def update_member_role(
        self,
        org_id: str,
        user_id: str,
        new_role: OrgRole
    ) -> bool:
        """Update a member's role"""
        member = await self.db.get_org_member(org_id, user_id)
        if not member:
            return False
        
        await self.db.update_org_member_role(org_id, user_id, new_role.value)
        return True
    
    async def get_members(self, org_id: str) -> List[OrgMember]:
        """Get all members of an organization"""
        members_data = await self.db.get_org_members(org_id)
        return [self._deserialize_member(m) for m in members_data]
    
    async def _get_members_by_role(self, org_id: str, role: OrgRole) -> List[OrgMember]:
        """Get members with specific role"""
        members = await self.get_members(org_id)
        return [m for m in members if m.role == role]
    
    async def send_invitation(
        self,
        org_id: str,
        email: str,
        role: OrgRole,
        invited_by: str
    ) -> Invitation:
        """Send an invitation to join an organization"""
        org = await self.get_organization(org_id)
        if not org:
            raise ValueError("Organization not found")
        
        # Check if already invited
        existing = await self.db.get_pending_invitation(org_id, email)
        if existing:
            raise ValueError("Invitation already sent")
        
        invitation_id = str(uuid.uuid4())
        token = str(uuid.uuid4())
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self._invitation_ttl)
        
        invitation = Invitation(
            id=invitation_id,
            org_id=org_id,
            email=email,
            role=role,
            status=InvitationStatus.PENDING,
            invited_by=invited_by,
            created_at=now,
            expires_at=expires_at,
            token=token
        )
        
        await self.db.save_invitation({
            "id": invitation.id,
            "org_id": invitation.org_id,
            "email": invitation.email,
            "role": invitation.role.value,
            "status": invitation.status.value,
            "invited_by": invitation.invited_by,
            "created_at": invitation.created_at.isoformat(),
            "expires_at": invitation.expires_at.isoformat(),
            "token": invitation.token
        })
        
        # Send invitation email
        invite_link = f"{self.config.base_url}/auth/invite?token={token}"
        await self.email_service.send_invitation_email(
            to=email,
            org_name=org.name,
            invite_link=invite_link,
            role=role.value
        )
        
        return invitation
    
    async def accept_invitation(self, token: str, user_id: str) -> Optional[OrgMember]:
        """Accept an invitation"""
        invitation = await self.db.get_invitation_by_token(token)
        if not invitation:
            return None
        
        # Validate invitation
        if invitation["status"] != InvitationStatus.PENDING.value:
            raise ValueError("Invitation is no longer valid")
        
        expires_at = datetime.fromisoformat(invitation["expires_at"])
        if datetime.utcnow() > expires_at:
            await self.db.update_invitation_status(invitation["id"], InvitationStatus.EXPIRED.value)
            raise ValueError("Invitation has expired")
        
        # Check email matches
        user = await self.db.get_user(user_id)
        if user["email"] != invitation["email"]:
            raise ValueError("Email does not match invitation")
        
        # Add member
        member = await self._add_member_internal(
            invitation["org_id"],
            user_id,
            OrgRole(invitation["role"]),
            invited_by=invitation["invited_by"]
        )
        
        # Update invitation status
        await self.db.update_invitation_status(invitation["id"], InvitationStatus.ACCEPTED.value)
        
        return member
    
    async def decline_invitation(self, token: str) -> bool:
        """Decline an invitation"""
        invitation = await self.db.get_invitation_by_token(token)
        if not invitation:
            return False
        
        await self.db.update_invitation_status(invitation["id"], InvitationStatus.DECLINED.value)
        return True
    
    def _deserialize_org(self, data: Dict) -> Organization:
        """Convert dict to Organization"""
        return Organization(
            id=data["id"],
            name=data["name"],
            slug=data["slug"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            owner_id=data["owner_id"],
            metadata=data.get("metadata", {}),
            is_active=data.get("is_active", True),
            plan=data.get("plan", "free"),
            max_members=data.get("max_members", 10)
        )
    
    def _deserialize_member(self, data: Dict) -> OrgMember:
        """Convert dict to OrgMember"""
        return OrgMember(
            id=data["id"],
            org_id=data["org_id"],
            user_id=data["user_id"],
            role=OrgRole(data["role"]),
            joined_at=datetime.fromisoformat(data["joined_at"]),
            invited_by=data.get("invited_by")
        )
    
    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from name"""
        import re
        slug = name.lower().strip()
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        slug = slug.strip('-')
        return slug or "org"


# Import timedelta
from datetime import timedelta
