"""AWS SNS SMS provider (CONTRACTS.md §0/§1).

Async wrapper over boto3's synchronous SNS client (executed in a thread
pool). Credentials follow the standard AWS credential chain — environment
variables, IAM role, or ``~/.aws/credentials`` — and are never hardcoded
(§0.8).

Upstream failures raise :class:`SMSProviderError` (§1 ``ProviderError``)
after the retry budget is exhausted.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    BOTO3_AVAILABLE = True
except ImportError:  # §0.9 — module imports cleanly without boto3
    boto3 = None  # type: ignore[assignment]
    BOTO3_AVAILABLE = False
    ClientError = None  # type: ignore[assignment,misc]
    BotoCoreError = None  # type: ignore[assignment,misc]

from .abstract_provider import AbstractSMSProvider, SMSProviderError, SMSResponse

logger = logging.getLogger("authy.sms.aws_sns")

__all__ = ["AWSSNSConfig", "AWSSNSProvider", "BOTO3_AVAILABLE"]

#: Client-side AWS error codes that do not benefit from retries.
_NON_RETRYABLE_CODES = frozenset(
    {"InvalidParameter", "InvalidParameterValue", "AuthorizationError"}
)


@dataclass
class AWSSNSConfig:
    """AWS SNS configuration."""

    region_name: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    sender_id: Optional[str] = None  # alphanumeric sender id (region-dependent)

    @classmethod
    def from_env(cls) -> "AWSSNSConfig":
        """Load configuration from environment variables."""
        region_name = os.getenv("AWS_REGION", "us-east-1")
        aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        sender_id = os.getenv("AWS_SNS_SENDER_ID")

        if not region_name:
            raise ValueError("AWS_REGION is required")

        return cls(
            region_name=region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            sender_id=sender_id,
        )


class AWSSNSProvider(AbstractSMSProvider):
    """AWS SNS provider with retries and typed error mapping."""

    def __init__(
        self,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        sender_id: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize the provider.

        Args:
            region_name: AWS region; when omitted ``AWS_REGION`` is used.
            aws_access_key_id/aws_secret_access_key: Optional explicit
                credentials; otherwise the default AWS credential chain applies.
            sender_id: Optional alphanumeric sender id.
            max_retries: Retry attempts for transient failures.
            retry_delay: Base delay (seconds) for exponential backoff.

        Raises:
            ImportError: When ``boto3`` is not installed.
        """
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 library not installed. Install with: pip install boto3"
            )

        if region_name:
            self.config = AWSSNSConfig(
                region_name=region_name,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                sender_id=sender_id,
            )
        else:
            self.config = AWSSNSConfig.from_env()

        self._client: Optional[Any] = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    @property
    def client(self) -> Any:
        """Lazily constructed boto3 SNS client."""
        if self._client is None:
            kwargs: Dict[str, Any] = {"region_name": self.config.region_name}
            if self.config.aws_access_key_id and self.config.aws_secret_access_key:
                kwargs["aws_access_key_id"] = self.config.aws_access_key_id
                kwargs["aws_secret_access_key"] = self.config.aws_secret_access_key
            self._client = boto3.client("sns", **kwargs)
        return self._client

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "AWS SNS"

    async def send_sms(
        self, to: str, body: str, from_number: Optional[str] = None
    ) -> SMSResponse:
        """Send an SMS via AWS SNS.

        ``from_number`` is not supported by SNS; configure ``sender_id``
        instead.

        Raises:
            SMSProviderError: On upstream failure after retries (§1).
        """
        last_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            try:
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None, self._send_sms_sync, to, body
                )
                return SMSResponse(
                    success=True,
                    message_id=response.get("MessageId"),
                    status="sent",
                    raw_response=response,
                )
            except ClientError as exc:
                error_info = (exc.response or {}).get("Error", {})
                error_code = error_info.get("Code", "Unknown")
                error_message = error_info.get("Message", str(exc))
                last_error = f"AWS SNS error ({error_code}): {error_message}"
                if error_code in _NON_RETRYABLE_CODES:
                    break
            except BotoCoreError as exc:
                last_error = f"AWS SDK error: {exc}"
            except Exception as exc:  # unexpected SDK/network failure
                last_error = f"Unexpected error: {exc}"

            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_delay * (2**attempt))

        raise SMSProviderError(
            f"AWS SNS send failed: {last_error or 'unknown error'}"
        )

    def _send_sms_sync(self, to: str, body: str) -> Dict[str, Any]:
        """Synchronous SNS publish (runs in the executor)."""
        params: Dict[str, Any] = {
            "PhoneNumber": to,
            "Message": body,
            "MessageAttributes": {
                "AWS.SNS.SMS.SMSType": {
                    "DataType": "String",
                    "StringValue": "Transactional",
                }
            },
        }
        if self.config.sender_id:
            params["MessageAttributes"]["AWS.SNS.SMS.SenderID"] = {
                "DataType": "String",
                "StringValue": self.config.sender_id,
            }
        return self.client.publish(**params)

    async def check_delivery_status(self, message_id: str) -> str:
        """Return the delivery status for ``message_id``.

        SNS has no direct per-message status API; delivery status is only
        available through CloudWatch/SNS delivery logs. This method is
        honest about that limitation and returns ``"unknown"``.
        """
        return "unknown"

    @classmethod
    def from_env(cls, **kwargs: Any) -> "AWSSNSProvider":
        """Create a provider from environment variables."""
        config = AWSSNSConfig.from_env()
        return cls(
            region_name=kwargs.get("region_name", config.region_name),
            aws_access_key_id=kwargs.get(
                "aws_access_key_id", config.aws_access_key_id
            ),
            aws_secret_access_key=kwargs.get(
                "aws_secret_access_key", config.aws_secret_access_key
            ),
            sender_id=kwargs.get("sender_id", config.sender_id),
            max_retries=kwargs.get("max_retries", 3),
            retry_delay=kwargs.get("retry_delay", 1.0),
        )
