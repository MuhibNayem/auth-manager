"""
Enterprise Database Adapters for Authy Package.
Supports SQL, MongoDB, DynamoDB, Cassandra, Redis, and Neo4j.
"""

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

# Built-in adapters
try:
    from .sql import SQLDatabase
except ImportError:
    pass

try:
    from .mongodb import MongoDBDatabase
except ImportError:
    pass

try:
    from .dynamodb_adapter import DynamoDBAdapter
except ImportError:
    pass

try:
    from .cassandra_adapter import CassandraAdapter
except ImportError:
    pass

try:
    from .redis_adapter import RedisAdapter
except ImportError:
    pass

try:
    from .neo4j_adapter import Neo4jAdapter
except ImportError:
    pass

__all__ = [
    # Abstract & Utils
    'EnterpriseDatabaseAdapter',
    'DatabaseError',
    'ConnectionError',
    'IntegrityError',
    'NotFoundError',
    'CircuitBreaker',
    'CircuitBreakerConfig',
    'RetryConfig',
    'with_retry',
    'ConnectionPool',
    'PoolConfig',
    'ObservabilityMixin',
    # Adapters
    'SQLDatabase',
    'MongoDBDatabase',
    'DynamoDBAdapter',
    'CassandraAdapter',
    'RedisAdapter',
    'Neo4jAdapter'
]
