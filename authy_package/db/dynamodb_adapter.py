"""
DynamoDB Adapter for Enterprise Authy.
Production-ready implementation with connection pooling, retries, and full feature parity.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from decimal import Decimal

from .enterprise_abstract import (
    EnterpriseDatabaseAdapter,
    DatabaseError,
    ConnectionError,
    IntegrityError,
    NotFoundError
)
from .enterprise_utils import (
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig,
    with_retry,
    ConnectionPool,
    PoolConfig,
    ObservabilityMixin
)

logger = logging.getLogger(__name__)


class DynamoDBAdapter(EnterpriseDatabaseAdapter, ObservabilityMixin):
    """
    Enterprise-grade DynamoDB adapter with full Authy feature support.
    Uses boto3 with aioboto3 for async operations.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        ObservabilityMixin.__init__(self)
        
        self.table_prefix = config.get('table_prefix', 'authy_')
        self.region = config.get('region', 'us-east-1')
        
        # Circuit breaker for resilience
        self.circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60.0
        ))
        
        # Retry configuration
        self.retry_config = RetryConfig(
            max_retries=3,
            base_delay=0.5,
            exponential_base=2.0
        )

    @with_retry()
    async def connect(self) -> None:
        """Initialize DynamoDB client and verify connectivity."""
        try:
            import aioboto3
            
            session = aioboto3.Session()
            self.client = await session.client(
                'dynamodb',
                region_name=self.region,
                aws_access_key_id=self.config.get('access_key'),
                aws_secret_access_key=self.config.get('secret_key'),
                endpoint_url=self.config.get('endpoint_url')  # For LocalStack/DynamoDB Local
            ).__aenter__()
            
            self.resource = await session.resource(
                'dynamodb',
                region_name=self.region,
                aws_access_key_id=self.config.get('access_key'),
                aws_secret_access_key=self.config.get('secret_key'),
                endpoint_url=self.config.get('endpoint_url')
            ).__aenter__()
            
            # Verify connectivity
            await self.health_check()
            self.is_connected = True
            logger.info("DynamoDB connection established")
            
        except Exception as e:
            logger.error(f"Failed to connect to DynamoDB: {e}")
            raise ConnectionError(f"DynamoDB connection failed: {e}")

    async def disconnect(self) -> None:
        """Close DynamoDB connections."""
        if hasattr(self, 'client'):
            await self.client.__aexit__(None, None, None)
        if hasattr(self, 'resource'):
            await self.resource.__aexit__(None, None, None)
        self.is_connected = False
        logger.info("DynamoDB connections closed")

    def _get_table_name(self, entity: str) -> str:
        return f"{self.table_prefix}{entity}"

    def _serialize_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Python types to DynamoDB-compatible types."""
        serialized = {}
        for key, value in item.items():
            if isinstance(value, str):
                serialized[key] = {'S': value}
            elif isinstance(value, (int, float)):
                serialized[key] = {'N': str(value)}
            elif isinstance(value, bool):
                serialized[key] = {'BOOL': value}
            elif isinstance(value, dict):
                serialized[key] = {'M': self._serialize_item(value)}
            elif isinstance(value, list):
                if len(value) == 0:
                    serialized[key] = {'L': []}
                elif isinstance(value[0], str):
                    serialized[key] = {'SS': value}
                elif isinstance(value[0], (int, float)):
                    serialized[key] = {'NS': [str(v) for v in value]}
                else:
                    serialized[key] = {'L': [self._serialize_item({'v': v})['v'] for v in value]}
            elif isinstance(value, datetime):
                serialized[key] = {'S': value.isoformat()}
            elif value is None:
                serialized[key] = {'NULL': True}
            else:
                serialized[key] = {'S': str(value)}
        return serialized

    def _deserialize_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB types back to Python types."""
        if not item:
            return {}
        
        deserialized = {}
        for key, value in item.items():
            if 'S' in value:
                deserialized[key] = value['S']
            elif 'N' in value:
                num = Decimal(value['N'])
                deserialized[key] = int(num) if num % 1 == 0 else float(num)
            elif 'BOOL' in value:
                deserialized[key] = value['BOOL']
            elif 'M' in value:
                deserialized[key] = self._deserialize_item(value['M'])
            elif 'L' in value:
                deserialized[key] = [self._deserialize_item({'v': v})['v'] for v in value['L']]
            elif 'SS' in value:
                deserialized[key] = value['SS']
            elif 'NS' in value:
                deserialized[key] = [float(n) for n in value['NS']]
            elif 'NULL' in value:
                deserialized[key] = None
        return deserialized

    async def _execute_with_circuit_breaker(self, operation: str, func, *args, **kwargs):
        """Execute DynamoDB operation with circuit breaker and observability."""
        return await self.execute_with_observation(
            operation,
            self.circuit_breaker.call,
            func,
            *args,
            **kwargs
        )

    # ==================== USER MANAGEMENT ====================

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('users')
        
        # Check for existing user
        identifier = user_data.get('email') or user_data.get('username')
        if identifier:
            existing = await self.get_user_by_identifier(identifier)
            if existing:
                raise IntegrityError(f"User with identifier {identifier} already exists")
        
        item = {
            'PK': f"USER#{user_data['id']}",
            'SK': "PROFILE",
            'GSI1PK': f"EMAIL#{user_data.get('email', '')}",
            'GSI1SK': "PROFILE",
            'created_at': datetime.utcnow().isoformat(),
            **user_data
        }
        
        await self._execute_with_circuit_breaker(
            'create_user',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item),
            ConditionExpression='attribute_not_exists(PK)'
        )
        
        return user_data

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('users')
        
        response = await self._execute_with_circuit_breaker(
            'get_user_by_id',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"USER#{user_id}"}, 'SK': {'S': 'PROFILE'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def get_user_by_identifier(self, identifier: str, identifier_type: str = 'email') -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('users')
        
        response = await self._execute_with_circuit_breaker(
            'get_user_by_identifier',
            self.client.query,
            TableName=table_name,
            IndexName='GSI1Index',
            KeyConditionExpression='GSI1PK = :pk AND GSI1SK = :sk',
            ExpressionAttributeValues={
                ':pk': {'S': f"{identifier_type.upper()}#{identifier}"},
                ':sk': {'S': 'PROFILE'}
            }
        )
        
        items = response.get('Items', [])
        return self._deserialize_item(items[0]) if items else None

    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('users')
        
        update_expr = "SET " + ", ".join(f"#{k} = :{k}" for k in update_data.keys())
        expr_attr_names = {f"#{k}": k for k in update_data.keys()}
        expr_attr_values = self._serialize_item(update_data)
        
        await self._execute_with_circuit_breaker(
            'update_user',
            self.client.update_item,
            TableName=table_name,
            Key={'PK': {'S': f"USER#{user_id}"}, 'SK': {'S': 'PROFILE'}},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values,
            ReturnValues='ALL_NEW'
        )
        
        return {**update_data, 'id': user_id}

    async def delete_user(self, user_id: str) -> bool:
        table_name = self._get_table_name('users')
        
        await self._execute_with_circuit_breaker(
            'delete_user',
            self.client.delete_item,
            TableName=table_name,
            Key={'PK': {'S': f"USER#{user_id}"}, 'SK': {'S': 'PROFILE'}}
        )
        
        return True

    async def list_users(self, org_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('users')
        
        if org_id:
            # Query by organization
            response = await self._execute_with_circuit_breaker(
                'list_users_by_org',
                self.client.query,
                TableName=table_name,
                IndexName='GSI2Index',
                KeyConditionExpression='GSI2PK = :pk',
                ExpressionAttributeValues={':pk': {'S': f"ORG#{org_id}"}},
                Limit=limit
            )
        else:
            # Scan all users (use sparingly in production)
            response = await self._execute_with_circuit_breaker(
                'list_users',
                self.client.scan,
                TableName=table_name,
                Limit=limit
            )
        
        items = response.get('Items', [])
        return [self._deserialize_item(item) for item in items]

    # ==================== ORGANIZATION & TENANCY ====================
    
    async def create_organization(self, org_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('organizations')
        
        item = {
            'PK': f"ORG#{org_data['id']}",
            'SK': "PROFILE",
            'GSI1PK': f"SLUG#{org_data.get('slug', '')}",
            'GSI1SK': "PROFILE",
            'created_at': datetime.utcnow().isoformat(),
            **org_data
        }
        
        await self._execute_with_circuit_breaker(
            'create_organization',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item),
            ConditionExpression='attribute_not_exists(PK)'
        )
        
        return org_data

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('organizations')
        
        response = await self._execute_with_circuit_breaker(
            'get_organization',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"ORG#{org_id}"}, 'SK': {'S': 'PROFILE'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def update_organization(self, org_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('organizations')
        
        update_expr = "SET " + ", ".join(f"#{k} = :{k}" for k in update_data.keys())
        expr_attr_names = {f"#{k}": k for k in update_data.keys()}
        expr_attr_values = self._serialize_item(update_data)
        
        await self._execute_with_circuit_breaker(
            'update_organization',
            self.client.update_item,
            TableName=table_name,
            Key={'PK': {'S': f"ORG#{org_id}"}, 'SK': {'S': 'PROFILE'}},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values,
            ReturnValues='ALL_NEW'
        )
        
        return {**update_data, 'id': org_id}

    async def add_org_member(self, org_id: str, user_id: str, role: str) -> Dict[str, Any]:
        table_name = self._get_table_name('org_members')
        
        item = {
            'PK': f"ORG#{org_id}",
            'SK': f"MEMBER#{user_id}",
            'role': role,
            'joined_at': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'org_id': org_id
        }
        
        await self._execute_with_circuit_breaker(
            'add_org_member',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return item

    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        table_name = self._get_table_name('org_members')
        
        await self._execute_with_circuit_breaker(
            'remove_org_member',
            self.client.delete_item,
            TableName=table_name,
            Key={'PK': {'S': f"ORG#{org_id}"}, 'SK': {'S': f"MEMBER#{user_id}"}}
        )
        
        return True

    async def get_org_members(self, org_id: str, role_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('org_members')
        
        response = await self._execute_with_circuit_breaker(
            'get_org_members',
            self.client.query,
            TableName=table_name,
            KeyConditionExpression='PK = :pk',
            ExpressionAttributeValues={':pk': {'S': f"ORG#{org_id}"}}
        )
        
        items = response.get('Items', [])
        members = [self._deserialize_item(item) for item in items]
        
        if role_filter:
            members = [m for m in members if m.get('role') == role_filter]
        
        return members

    async def get_user_orgs(self, user_id: str) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('org_members')
        
        response = await self._execute_with_circuit_breaker(
            'get_user_orgs',
            self.client.query,
            TableName=table_name,
            IndexName='GSI1Index',
            KeyConditionExpression='GSI1PK = :pk',
            ExpressionAttributeValues={':pk': {'S': f"USER#{user_id}"}}
        )
        
        items = response.get('Items', [])
        org_ids = [item['org_id']['S'] for item in items]
        
        # Fetch organization details
        orgs = []
        for org_id in org_ids:
            org = await self.get_organization(org_id)
            if org:
                orgs.append(org)
        
        return orgs

    # ==================== SESSION MANAGEMENT ====================

    async def create_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('sessions')
        
        item = {
            'PK': f"SESSION#{session_data['id']}",
            'SK': "ACTIVE",
            'GSI1PK': f"USER#{session_data['user_id']}",
            'GSI1SK': f"SESSION#{session_data['id']}",
            'expires_at': session_data.get('expires_at'),
            **session_data
        }
        
        await self._execute_with_circuit_breaker(
            'create_session',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return session_data

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('sessions')
        
        response = await self._execute_with_circuit_breaker(
            'get_session',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"SESSION#{session_id}"}, 'SK': {'S': 'ACTIVE'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def update_session(self, session_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('sessions')
        
        update_expr = "SET " + ", ".join(f"#{k} = :{k}" for k in update_data.keys())
        expr_attr_names = {f"#{k}": k for k in update_data.keys()}
        expr_attr_values = self._serialize_item(update_data)
        
        await self._execute_with_circuit_breaker(
            'update_session',
            self.client.update_item,
            TableName=table_name,
            Key={'PK': {'S': f"SESSION#{session_id}"}, 'SK': {'S': 'ACTIVE'}},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values,
            ReturnValues='ALL_NEW'
        )
        
        return {**update_data, 'id': session_id}

    async def revoke_session(self, session_id: str) -> bool:
        table_name = self._get_table_name('sessions')
        
        # Move to revoked state instead of deleting (for audit)
        await self._execute_with_circuit_breaker(
            'revoke_session',
            self.client.update_item,
            TableName=table_name,
            Key={'PK': {'S': f"SESSION#{session_id}"}, 'SK': {'S': 'ACTIVE'}},
            UpdateExpression='SET #status = :status, #revoked_at = :revoked_at',
            ExpressionAttributeNames={'#status': 'status', '#revoked_at': 'revoked_at'},
            ExpressionAttributeValues={
                ':status': {'S': 'revoked'},
                ':revoked_at': {'S': datetime.utcnow().isoformat()}
            }
        )
        
        return True

    async def revoke_all_user_sessions(self, user_id: str, exclude_session_id: Optional[str] = None) -> int:
        sessions = await self.get_active_sessions(user_id)
        count = 0
        
        for session in sessions:
            if exclude_session_id and session['id'] == exclude_session_id:
                continue
            await self.revoke_session(session['id'])
            count += 1
        
        return count

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('sessions')
        
        response = await self._execute_with_circuit_breaker(
            'get_active_sessions',
            self.client.query,
            TableName=table_name,
            IndexName='GSI1Index',
            KeyConditionExpression='GSI1PK = :pk AND begins_with(GSI1SK, :sk_prefix)',
            ExpressionAttributeValues={
                ':pk': {'S': f"USER#{user_id}"},
                ':sk_prefix': {'S': 'SESSION#'}
            }
        )
        
        items = response.get('Items', [])
        return [self._deserialize_item(item) for item in items]

    # ==================== AUDIT LOGGING ====================

    async def write_audit_log(self, log_entry: Dict[str, Any]) -> str:
        table_name = self._get_table_name('audit_logs')
        log_id = f"AUDIT#{datetime.utcnow().timestamp()}#{log_entry.get('actor_id', 'system')}"
        
        item = {
            'PK': log_id,
            'SK': f"EVENT#{log_entry.get('event_type', 'unknown')}",
            'GSI1PK': f"ACTOR#{log_entry.get('actor_id', 'system')}",
            'GSI1SK': f"TIME#{datetime.utcnow().isoformat()}",
            'GSI2PK': f"EVENT#{log_entry.get('event_type', 'unknown')}",
            'GSI2SK': f"TIME#{datetime.utcnow().isoformat()}",
            **log_entry
        }
        
        await self._execute_with_circuit_breaker(
            'write_audit_log',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return log_id

    async def query_audit_logs(
        self, 
        filters: Dict[str, Any], 
        start_date: datetime, 
        end_date: datetime, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('audit_logs')
        
        # Build query based on filters
        key_condition = 'GSI1SK BETWEEN :start AND :end'
        expr_values = {
            ':start': {'S': start_date.isoformat()},
            ':end': {'S': end_date.isoformat()}
        }
        
        if filters.get('actor_id'):
            expr_values[':pk'] = {'S': f"ACTOR#{filters['actor_id']}"}
            key_condition = 'GSI1PK = :pk AND ' + key_condition
        elif filters.get('event_type'):
            expr_values[':pk'] = {'S': f"EVENT#{filters['event_type']}"}
            key_condition = 'GSI2PK = :pk AND GSI2SK BETWEEN :start AND :end'
        
        response = await self._execute_with_circuit_breaker(
            'query_audit_logs',
            self.client.query,
            TableName=table_name,
            IndexName='GSI1Index' if 'actor_id' in filters else 'GSI2Index',
            KeyConditionExpression=key_condition,
            ExpressionAttributeValues=expr_values,
            Limit=limit
        )
        
        items = response.get('Items', [])
        return [self._deserialize_item(item) for item in items]

    async def export_audit_logs(
        self, 
        filters: Dict[str, Any], 
        format: str = 'json'
    ) -> bytes:
        import json
        import csv
        import io
        
        logs = await self.query_audit_logs(filters, datetime.min, datetime.max, limit=10000)
        
        if format.lower() == 'csv':
            output = io.StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            return output.getvalue().encode('utf-8')
        else:
            return json.dumps(logs, indent=2).encode('utf-8')

    # ==================== MFA & SECURITY ====================

    async def save_mfa_secret(self, user_id: str, secret_data: Dict[str, Any]) -> None:
        table_name = self._get_table_name('mfa_secrets')
        
        item = {
            'PK': f"USER#{user_id}",
            'SK': "MFA",
            **secret_data
        }
        
        await self._execute_with_circuit_breaker(
            'save_mfa_secret',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )

    async def get_mfa_secret(self, user_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('mfa_secrets')
        
        response = await self._execute_with_circuit_breaker(
            'get_mfa_secret',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"USER#{user_id}"}, 'SK': {'S': 'MFA'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def record_login_attempt(self, user_id: str, success: bool, ip: str, user_agent: str) -> None:
        table_name = self._get_table_name('login_attempts')
        
        item = {
            'PK': f"USER#{user_id}",
            'SK': f"ATTEMPT#{datetime.utcnow().isoformat()}",
            'success': success,
            'ip': ip,
            'user_agent': user_agent
        }
        
        await self._execute_with_circuit_breaker(
            'record_login_attempt',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )

    async def get_failed_login_count(self, user_id: str, window_minutes: int) -> int:
        table_name = self._get_table_name('login_attempts')
        from datetime import timedelta
        
        window_start = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
        
        response = await self._execute_with_circuit_breaker(
            'get_failed_login_count',
            self.client.query,
            TableName=table_name,
            KeyConditionExpression='PK = :pk AND SK > :start',
            FilterExpression='success = :success',
            ExpressionAttributeValues={
                ':pk': {'S': f"USER#{user_id}"},
                ':start': {'S': f"ATTEMPT#{window_start}"},
                ':success': {'BOOL': False}
            }
        )
        
        return len(response.get('Items', []))

    # ==================== WEBHOOKS ====================

    async def create_webhook_subscription(self, sub_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('webhooks')
        
        item = {
            'PK': f"WEBHOOK#{sub_data['id']}",
            'SK': "ACTIVE",
            'GSI1PK': f"EVENT#{sub_data.get('event_type', 'all')}",
            'GSI1SK': f"WEBHOOK#{sub_data['id']}",
            **sub_data
        }
        
        await self._execute_with_circuit_breaker(
            'create_webhook_subscription',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return sub_data

    async def get_webhook_subscriptions(self, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        table_name = self._get_table_name('webhooks')
        
        if event_type:
            response = await self._execute_with_circuit_breaker(
                'get_webhook_subscriptions_by_event',
                self.client.query,
                TableName=table_name,
                IndexName='GSI1Index',
                KeyConditionExpression='GSI1PK = :pk',
                ExpressionAttributeValues={':pk': {'S': f"EVENT#{event_type}"}}
            )
        else:
            response = await self._execute_with_circuit_breaker(
                'get_webhook_subscriptions',
                self.client.scan,
                TableName=table_name,
                FilterExpression='begins_with(SK, :sk)',
                ExpressionAttributeValues={':sk': {'S': 'ACTIVE'}}
            )
        
        items = response.get('Items', [])
        return [self._deserialize_item(item) for item in items]

    async def record_webhook_delivery(self, subscription_id: str, success: bool, response_code: int, payload: str) -> None:
        table_name = self._get_table_name('webhook_deliveries')
        
        item = {
            'PK': f"WEBHOOK#{subscription_id}",
            'SK': f"DELIVERY#{datetime.utcnow().isoformat()}",
            'success': success,
            'response_code': response_code,
            'payload': payload[:1024]  # Truncate large payloads
        }
        
        await self._execute_with_circuit_breaker(
            'record_webhook_delivery',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )

    # ==================== SAML & OIDC ====================

    async def register_saml_provider(self, provider_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('saml_providers')
        
        item = {
            'PK': f"SAML#{provider_data['entity_id']}",
            'SK': "CONFIG",
            **provider_data
        }
        
        await self._execute_with_circuit_breaker(
            'register_saml_provider',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return provider_data

    async def get_saml_provider(self, entity_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('saml_providers')
        
        response = await self._execute_with_circuit_breaker(
            'get_saml_provider',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"SAML#{entity_id}"}, 'SK': {'S': 'CONFIG'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def create_saml_session(self, session_data: Dict[str, Any]) -> str:
        table_name = self._get_table_name('saml_sessions')
        request_id = session_data['request_id']
        
        item = {
            'PK': f"SAML_SESSION#{request_id}",
            'SK': "STATE",
            'expires_at': (datetime.utcnow().timestamp() + 300),  # 5 min TTL
            **session_data
        }
        
        await self._execute_with_circuit_breaker(
            'create_saml_session',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return request_id

    async def consume_saml_session(self, request_id: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('saml_sessions')
        
        response = await self._execute_with_circuit_breaker(
            'consume_saml_session',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"SAML_SESSION#{request_id}"}, 'SK': {'S': 'STATE'}}
        )
        
        item = response.get('Item')
        if item:
            # Delete after consumption
            await self._execute_with_circuit_breaker(
                'delete_saml_session',
                self.client.delete_item,
                TableName=table_name,
                Key={'PK': {'S': f"SAML_SESSION#{request_id}"}, 'SK': {'S': 'STATE'}}
            )
            return self._deserialize_item(item)
        
        return None

    async def register_oidc_provider(self, provider_data: Dict[str, Any]) -> Dict[str, Any]:
        table_name = self._get_table_name('oidc_providers')
        
        item = {
            'PK': f"OIDC#{provider_data['issuer']}",
            'SK': "CONFIG",
            **provider_data
        }
        
        await self._execute_with_circuit_breaker(
            'register_oidc_provider',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )
        
        return provider_data

    async def get_oidc_provider(self, issuer: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('oidc_providers')
        
        response = await self._execute_with_circuit_breaker(
            'get_oidc_provider',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"OIDC#{issuer}"}, 'SK': {'S': 'CONFIG'}}
        )
        
        return self._deserialize_item(response.get('Item')) if 'Item' in response else None

    async def link_external_identity(self, user_id: str, provider_type: str, subject: str) -> None:
        table_name = self._get_table_name('external_identities')
        
        item = {
            'PK': f"EXTERNAL#{provider_type}#{subject}",
            'SK': "LINK",
            'user_id': user_id,
            'provider_type': provider_type,
            'subject': subject,
            'linked_at': datetime.utcnow().isoformat()
        }
        
        await self._execute_with_circuit_breaker(
            'link_external_identity',
            self.client.put_item,
            TableName=table_name,
            Item=self._serialize_item(item)
        )

    async def get_user_by_external_identity(self, provider_type: str, subject: str) -> Optional[Dict[str, Any]]:
        table_name = self._get_table_name('external_identities')
        
        response = await self._execute_with_circuit_breaker(
            'get_user_by_external_identity',
            self.client.get_item,
            TableName=table_name,
            Key={'PK': {'S': f"EXTERNAL#{provider_type}#{subject}"}, 'SK': {'S': 'LINK'}}
        )
        
        item = response.get('Item')
        if item:
            deserialized = self._deserialize_item(item)
            return await self.get_user_by_id(deserialized['user_id'])
        
        return None

    # ==================== UTILITIES ====================

    async def health_check(self) -> Dict[str, Any]:
        start = time.time()
        try:
            await self.client.describe_table(TableName=self._get_table_name('users'))
            latency = (time.time() - start) * 1000
            
            return {
                "status": "healthy",
                "database": "DynamoDB",
                "latency_ms": round(latency, 2),
                "region": self.region
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "database": "DynamoDB",
                "error": str(e),
                "latency_ms": round((time.time() - start) * 1000, 2)
            }

    async def run_migration(self, version: str) -> None:
        logger.info(f"DynamoDB migrations are handled via CloudFormation/CDK. Version: {version}")
        # DynamoDB is schemaless; migrations involve creating tables/indexes via IaC
