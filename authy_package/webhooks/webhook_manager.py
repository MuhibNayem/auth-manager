"""
Real-time Webhooks System

Features:
- Event-driven architecture
- Automatic retries with exponential backoff
- Signature verification for security
- Multiple endpoint support
- Event filtering
- Delivery tracking and analytics
"""

import uuid
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio


class WebhookEventType(Enum):
    """Supported webhook event types"""
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_LOGGED_IN = "user.logged_in"
    USER_LOGGED_OUT = "user.logged_out"
    PASSWORD_RESET_REQUESTED = "password.reset_requested"
    PASSWORD_RESET_COMPLETED = "password.reset_completed"
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"
    MEMBER_ADDED = "member.added"
    MEMBER_REMOVED = "member.removed"
    INVITATION_SENT = "invitation.sent"
    INVITATION_ACCEPTED = "invitation.accepted"


@dataclass
class WebhookEvent:
    """Represents a webhook event"""
    id: str
    event_type: WebhookEventType
    payload: Dict[str, Any]
    created_at: datetime
    delivered: bool = False
    delivery_attempts: int = 0
    last_attempt_at: Optional[datetime] = None
    last_response_status: Optional[int] = None
    next_retry_at: Optional[datetime] = None


@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration"""
    id: str
    url: str
    secret: str
    events: List[WebhookEventType]
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


class WebhookManager:
    """
    Real-time webhook system for auth events
    
    Usage:
        webhook_mgr = WebhookManager(config, db, cache, http_client)
        await webhook_mgr.register_endpoint("https://api.example.com/webhooks", ["user.created"])
        await webhook_mgr.dispatch_event(WebhookEventType.USER_CREATED, {"user_id": "123"})
    """
    
    def __init__(self, config, db, cache, http_client):
        self.config = config
        self.db = db
        self.cache = cache
        self.http_client = http_client
        self._max_retries = 5
        self._retry_delays = [60, 300, 900, 3600, 14400]  # 1min, 5min, 15min, 1hr, 4hr
        self._event_queue_key = "webhook:pending_events"
    
    async def register_endpoint(
        self,
        url: str,
        events: List[WebhookEventType],
        secret: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> WebhookEndpoint:
        """Register a new webhook endpoint"""
        import secrets
        
        endpoint_id = str(uuid.uuid4())
        webhook_secret = secret or secrets.token_hex(32)
        
        endpoint = WebhookEndpoint(
            id=endpoint_id,
            url=url,
            secret=webhook_secret,
            events=events,
            metadata=metadata or {}
        )
        
        await self.db.save_webhook_endpoint({
            "id": endpoint.id,
            "url": endpoint.url,
            "secret": endpoint.secret,
            "events": [e.value for e in endpoint.events],
            "is_active": endpoint.is_active,
            "created_at": endpoint.created_at.isoformat(),
            "metadata": endpoint.metadata
        })
        
        return endpoint
    
    async def list_endpoints(self) -> List[WebhookEndpoint]:
        """List all registered webhook endpoints"""
        endpoints_data = await self.db.get_webhook_endpoints()
        return [self._deserialize_endpoint(e) for e in endpoints_data]
    
    async def delete_endpoint(self, endpoint_id: str) -> bool:
        """Delete a webhook endpoint"""
        return await self.db.delete_webhook_endpoint(endpoint_id)
    
    async def dispatch_event(
        self,
        event_type: WebhookEventType,
        payload: Dict[str, Any],
        sync: bool = False
    ):
        """
        Dispatch a webhook event to all subscribed endpoints
        
        Args:
            event_type: Type of event
            payload: Event data
            sync: If True, wait for all deliveries to complete
        """
        event = WebhookEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            payload=payload,
            created_at=datetime.utcnow()
        )
        
        # Store event
        await self.db.save_webhook_event(self._serialize_event(event))
        
        # Get subscribed endpoints
        endpoints = await self.list_endpoints()
        subscribed = [
            e for e in endpoints
            if e.is_active and event_type in e.events
        ]
        
        if not subscribed:
            return
        
        # Queue for delivery
        for endpoint in subscribed:
            await self._queue_delivery(event, endpoint)
        
        # Add to pending queue for background processing
        await self.cache.lpush(self._event_queue_key, json.dumps({
            "event_id": event.id,
            "endpoint_ids": [e.id for e in subscribed]
        }))
        
        if sync:
            # Wait for all deliveries (not recommended for production)
            await self._process_pending_events()
    
    async def _queue_delivery(self, event: WebhookEvent, endpoint: WebhookEndpoint):
        """Queue event for delivery to an endpoint"""
        delivery_task = {
            "event_id": event.id,
            "endpoint_id": endpoint.id,
            "url": endpoint.url,
            "secret": endpoint.secret,
            "attempts": 0,
            "next_retry": datetime.utcnow().isoformat()
        }
        
        await self.cache.hset(
            f"webhook:delivery:{event.id}:{endpoint.id}",
            mapping=delivery_task
        )
    
    async def _process_pending_events(self):
        """Process pending webhook deliveries (background task)"""
        while True:
            item = await self.cache.rpop(self._event_queue_key)
            if not item:
                break
            
            try:
                data = json.loads(item)
                event = await self.db.get_webhook_event(data["event_id"])
                if not event:
                    continue
                
                for endpoint_id in data["endpoint_ids"]:
                    await self._deliver_to_endpoint(event, endpoint_id)
                    
            except Exception as e:
                # Log error but continue processing
                await self._log_error(f"Error processing webhook: {str(e)}")
    
    async def _deliver_to_endpoint(self, event: WebhookEvent, endpoint_id: str):
        """Deliver event to a specific endpoint"""
        endpoint_data = await self.db.get_webhook_endpoint(endpoint_id)
        if not endpoint_data or not endpoint_data.get("is_active"):
            return
        
        endpoint = self._deserialize_endpoint(endpoint_data)
        
        # Get delivery state
        delivery_key = f"webhook:delivery:{event.id}:{endpoint_id}"
        delivery_state = await self.cache.hgetall(delivery_key)
        
        attempts = int(delivery_state.get("attempts", 0)) if delivery_state else 0
        
        if attempts >= self._max_retries:
            # Max retries exceeded, mark as failed
            await self._mark_delivery_failed(event, endpoint_id, "Max retries exceeded")
            return
        
        # Prepare payload
        webhook_payload = {
            "id": event.id,
            "type": event.event_type.value,
            "created_at": event.created_at.isoformat(),
            "data": event.payload
        }
        
        # Generate signature
        signature = self._generate_signature(
            webhook_payload,
            endpoint.secret,
            event.created_at
        )
        
        # Make HTTP request
        try:
            response = await self.http_client.post(
                endpoint.url,
                json=webhook_payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": signature,
                    "X-Webhook-Timestamp": event.created_at.isoformat(),
                    "X-Webhook-ID": event.id,
                    "User-Agent": "Authy-Webhooks/2.0"
                },
                timeout=30
            )
            
            # Update delivery state
            await self._mark_delivery_success(
                event, endpoint_id, response.status_code
            )
            
        except Exception as e:
            # Schedule retry
            await self._schedule_retry(event, endpoint_id, attempts, str(e))
    
    def _generate_signature(self, payload: Dict, secret: str, timestamp: datetime) -> str:
        """Generate HMAC signature for webhook payload"""
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        message = f"{timestamp.isoformat()}.{payload_str}".encode()
        signature = hmac.new(
            secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"
    
    @staticmethod
    def verify_signature(
        payload: Dict,
        signature: str,
        secret: str,
        timestamp: str,
        tolerance_seconds: int = 300
    ) -> bool:
        """
        Verify webhook signature (for endpoint receivers)
        
        Usage:
            is_valid = WebhookManager.verify_signature(payload, sig, secret, timestamp)
        """
        try:
            # Check timestamp tolerance
            ts = datetime.fromisoformat(timestamp)
            if abs((datetime.utcnow() - ts).total_seconds()) > tolerance_seconds:
                return False
            
            # Verify signature
            expected_sig = f"sha256={hmac.new(secret.encode(), f'{timestamp}.{json.dumps(payload, sort_keys=True, separators=(',', ':'))}'.encode(), hashlib.sha256).hexdigest()}"
            return hmac.compare_digest(signature, expected_sig)
            
        except Exception:
            return False
    
    async def _mark_delivery_success(self, event: WebhookEvent, endpoint_id: str, status_code: int):
        """Mark delivery as successful"""
        await self.db.update_webhook_delivery(
            event.id,
            endpoint_id,
            success=True,
            status_code=status_code
        )
        await self.cache.delete(f"webhook:delivery:{event.id}:{endpoint_id}")
    
    async def _mark_delivery_failed(self, event: WebhookEvent, endpoint_id: str, reason: str):
        """Mark delivery as permanently failed"""
        await self.db.update_webhook_delivery(
            event.id,
            endpoint_id,
            success=False,
            error=reason
        )
        await self.cache.delete(f"webhook:delivery:{event.id}:{endpoint_id}")
    
    async def _schedule_retry(self, event: WebhookEvent, endpoint_id: str, attempts: int, error: str):
        """Schedule a retry for failed delivery"""
        next_retry = datetime.utcnow() + timedelta(seconds=self._retry_delays[min(attempts, len(self._retry_delays)-1)])
        
        await self.cache.hset(
            f"webhook:delivery:{event.id}:{endpoint_id}",
            mapping={
                "attempts": str(attempts + 1),
                "next_retry": next_retry.isoformat(),
                "last_error": error
            }
        )
        
        # Re-queue for later processing
        await self.cache.lpush(self._event_queue_key, json.dumps({
            "event_id": event.id,
            "endpoint_ids": [endpoint_id],
            "scheduled_for": next_retry.isoformat()
        }))
    
    def _serialize_event(self, event: WebhookEvent) -> Dict:
        """Serialize event for storage"""
        return {
            "id": event.id,
            "event_type": event.event_type.value,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
            "delivered": event.delivered,
            "delivery_attempts": event.delivery_attempts
        }
    
    def _deserialize_endpoint(self, data: Dict) -> WebhookEndpoint:
        """Deserialize endpoint from storage"""
        return WebhookEndpoint(
            id=data["id"],
            url=data["url"],
            secret=data["secret"],
            events=[WebhookEventType(e) for e in data["events"]],
            is_active=data.get("is_active", True),
            created_at=datetime.fromisoformat(data["created_at"]),
            metadata=data.get("metadata", {})
        )
    
    async def _log_error(self, message: str):
        """Log webhook errors"""
        error_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        }
        await self.db.save_webhook_error(error_log)
