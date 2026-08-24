"""
Production-Ready Database Utilities for Enterprise Authy.
Provides connection pooling, retry logic, circuit breakers, and observability.
"""
import asyncio
import logging
import random
import time
from typing import Any, Dict, Callable, TypeVar, Optional
from functools import wraps
from dataclasses import dataclass
from enum import Enum

from authy_package.errors import DatabaseError

logger = logging.getLogger("authy.db.enterprise_utils")

T = TypeVar('T')

#: Cryptographic RNG for retry jitter (never used for secrets).
_JITTER_RNG = random.SystemRandom()


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    expected_exceptions: tuple = (Exception,)


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures.
    Automatically opens circuit after repeated failures, then attempts recovery.
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        async with self._lock:
            if self.state == CircuitState.OPEN:
                if time.monotonic() - self.last_failure_time > self.config.recovery_timeout:
                    logger.info("Circuit breaker entering HALF_OPEN state")
                    self.state = CircuitState.HALF_OPEN
                else:
                    raise DatabaseError(
                        "Circuit breaker is OPEN - service unavailable",
                        code="circuit_open",
                    )

        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                if self.state == CircuitState.HALF_OPEN:
                    logger.info("Circuit breaker recovered - entering CLOSED state")
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
            return result
        except self.config.expected_exceptions as e:
            async with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.monotonic()
                if self.failure_count >= self.config.failure_threshold:
                    logger.warning(f"Circuit breaker OPENING after {self.failure_count} failures")
                    self.state = CircuitState.OPEN
            raise


@dataclass
class RetryConfig:
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_exceptions: tuple = (DatabaseError, TimeoutError)


def with_retry(config: RetryConfig = RetryConfig()):
    """
    Decorator that adds exponential backoff retry logic to async functions.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            for attempt in range(config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except config.retryable_exceptions as e:
                    last_exception = e
                    if attempt == config.max_retries:
                        break
                    
                    delay = min(
                        config.base_delay * (config.exponential_base ** attempt),
                        config.max_delay
                    )
                    if config.jitter:
                        delay += _JITTER_RNG.uniform(0, delay * 0.2)
                    
                    logger.warning(
                        f"Retry {attempt + 1}/{config.max_retries} for {func.__name__} "
                        f"after {delay:.2f}s due to {type(e).__name__}"
                    )
                    await asyncio.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator


@dataclass
class PoolConfig:
    min_size: int = 5
    max_size: int = 20
    max_overflow: int = 10
    pool_timeout: float = 30.0
    pool_recycle: float = 3600.0
    pool_pre_ping: bool = True


class ConnectionPool:
    """
    Generic async connection pool with health checks and recycling.
    Adapts to SQLAlchemy, Motor, or custom pool implementations.
    """
    
    def __init__(self, create_conn_func: Callable, close_conn_func: Callable, config: PoolConfig):
        self.create_conn = create_conn_func
        self.close_conn = close_conn_func
        self.config = config
        self.pool = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the underlying connection pool."""
        if self._initialized:
            return
        
        logger.info(f"Initializing connection pool (min={self.config.min_size}, max={self.config.max_size})")
        self.pool = await self.create_conn(
            min_size=self.config.min_size,
            max_size=self.config.max_size,
            max_overflow=self.config.max_overflow,
            timeout=self.config.pool_timeout,
            recycle=self.config.pool_recycle,
            pre_ping=self.config.pool_pre_ping
        )
        self._initialized = True
        logger.info("Connection pool initialized successfully")

    async def get_connection(self):
        """Acquire a connection from the pool."""
        if not self._initialized:
            await self.initialize()
        return await self.pool.acquire()

    async def release_connection(self, conn) -> None:
        """Return a connection to the pool."""
        if self.pool:
            await self.pool.release(conn)

    async def health_check(self) -> Dict[str, Any]:
        """Verify pool health and connectivity."""
        start = time.time()
        try:
            conn = await self.get_connection()
            latency = (time.time() - start) * 1000
            
            # Run a lightweight query/ping. SQLAlchemy 2.x requires text().
            if hasattr(conn, 'execute'):
                try:
                    from sqlalchemy import text
                    await conn.execute(text("SELECT 1"))
                except ImportError:
                    await conn.execute("SELECT 1")
            elif hasattr(conn, 'command'):
                await conn.command('ping')
            
            await self.release_connection(conn)
            
            return {
                "status": "healthy",
                "latency_ms": round(latency, 2),
                "pool_size": self.pool.size if hasattr(self.pool, 'size') else "unknown",
                "available": self.pool.qsize() if hasattr(self.pool, 'qsize') else "unknown"
            }
        except Exception as e:
            logger.error(f"Pool health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": round((time.time() - start) * 1000, 2)
            }

    async def close(self) -> None:
        """Gracefully shutdown the pool."""
        if self.pool:
            logger.info("Closing connection pool...")
            await self.pool.close()
            self._initialized = False


class ObservabilityMixin:
    """
    Mixin providing metrics, logging, and tracing for database operations.
    """
    
    def __init__(self):
        self.metrics = {
            "total_operations": 0,
            "failed_operations": 0,
            "slow_operations": 0,
            "latency_sum": 0.0
        }
        self.slow_query_threshold = 1.0  # seconds

    async def execute_with_observation(
        self, 
        operation_name: str, 
        func: Callable[..., T], 
        *args, 
        **kwargs
    ) -> T:
        """Execute a database operation with full observability."""
        start_time = time.time()
        self.metrics["total_operations"] += 1
        
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            self.metrics["latency_sum"] += duration
            if duration > self.slow_query_threshold:
                self.metrics["slow_operations"] += 1
                logger.warning(
                    f"SLOW_QUERY: {operation_name} took {duration:.3f}s",
                    extra={"operation": operation_name, "duration": duration}
                )
            
            logger.debug(
                f"DB_OP: {operation_name} completed in {duration*1000:.2f}ms",
                extra={"operation": operation_name, "duration_ms": duration*1000}
            )
            
            return result
            
        except Exception as e:
            self.metrics["failed_operations"] += 1
            duration = time.time() - start_time
            
            logger.error(
                f"DB_ERROR: {operation_name} failed after {duration:.3f}s - {type(e).__name__}: {e}",
                extra={"operation": operation_name, "error": str(e)},
                exc_info=True
            )
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Return current performance metrics."""
        total = self.metrics["total_operations"]
        failed = self.metrics["failed_operations"]
        return {
            **self.metrics,
            "avg_latency_ms": round((self.metrics["latency_sum"] / total * 1000) if total > 0 else 0, 2),
            "success_rate": round(((total - failed) / total * 100) if total > 0 else 100, 2),
            "failure_rate": round((failed / total * 100) if total > 0 else 0, 2)
        }
