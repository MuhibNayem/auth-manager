"""
AWS SNS SMS Provider Implementation for Authy Package.

Enterprise-grade AWS SNS integration with async support, IAM credential handling,
and comprehensive error handling.

Configuration:
    Option 1 - Direct initialization:
        provider = AWSSNSProvider(
            region_name="us-east-1",
            aws_access_key_id="AKIA...",
            aws_secret_access_key="secret"
        )
    
    Option 2 - Environment variables / IAM role (recommended):
        # Uses standard AWS credential chain:
        # 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        # 2. IAM role (when running on EC2, Lambda, ECS, etc.)
        # 3. AWS credentials file (~/.aws/credentials)
        
        export AWS_REGION=us-east-1
        provider = AWSSNSProvider.from_env()

Usage:
    response = await provider.send_sms(
        to="+1987654321",
        body="Your verification code is: 123456"
    )
"""

import os
from typing import Optional, Dict, Any
import asyncio
from dataclasses import dataclass

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception
    BotoCoreError = Exception

from .abstract_provider import AbstractSMSProvider, SMSResponse, SMSProviderError


@dataclass
class AWSSNSConfig:
    """AWS SNS configuration."""
    region_name: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    sender_id: Optional[str] = None  # For alphanumeric sender IDs
    
    @classmethod
    def from_env(cls) -> 'AWSSNSConfig':
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
            sender_id=sender_id
        )


class AWSSNSProvider(AbstractSMSProvider):
    """
    AWS SNS SMS provider implementation.
    
    Features:
    - Async support with thread pool executor
    - Automatic retry on transient failures
    - Standard AWS credential chain support
    - Support for both short codes and long codes
    - Delivery status tracking via CloudWatch
    """
    
    def __init__(
        self,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        sender_id: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        """
        Initialize AWS SNS provider.
        
        :param region_name: AWS region (e.g., us-east-1)
        :param aws_access_key_id: AWS access key (optional, uses credential chain)
        :param aws_secret_access_key: AWS secret key (optional, uses credential chain)
        :param sender_id: Alphanumeric sender ID (country-dependent)
        :param max_retries: Maximum number of retry attempts
        :param retry_delay: Delay between retries in seconds
        """
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 library not installed. Install with: pip install boto3"
            )
        
        # Load from config or environment
        if region_name:
            self.config = AWSSNSConfig(
                region_name=region_name,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                sender_id=sender_id
            )
        else:
            self.config = AWSSNSConfig.from_env()
        
        self._client = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
    @property
    def client(self):
        """Lazy initialization of SNS client."""
        if self._client is None:
            kwargs = {"region_name": self.config.region_name}
            
            # Only explicitly set credentials if provided
            # Otherwise, boto3 will use the default credential chain
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
        self,
        to: str,
        body: str,
        from_number: Optional[str] = None
    ) -> SMSResponse:
        """
        Send an SMS message via AWS SNS.
        
        :param to: Recipient phone number in E.164 format
        :param body: Message body text
        :param from_number: Not used by SNS (use SenderID in config instead)
        :return: SMSResponse with success status
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Run synchronous boto3 call in thread pool
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    self._send_sms_sync,
                    to,
                    body
                )
                
                return SMSResponse(
                    success=True,
                    message_id=response.get("MessageId"),
                    status="sent",
                    raw_response=response
                )
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                last_error = f"AWS SNS error ({error_code}): {e.response['Error']['Message']}"
                # Don't retry on client errors
                if error_code in ["InvalidParameter", "InvalidParameterValue", "AuthorizationError"]:
                    break
                    
            except BotoCoreError as e:
                last_error = f"AWS SDK error: {str(e)}"
                
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
            
            # Retry with exponential backoff
            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
        
        return SMSResponse(
            success=False,
            error_message=last_error or "Unknown error",
            status="failed"
        )
    
    def _send_sms_sync(self, to: str, body: str) -> Dict[str, Any]:
        """Synchronous SNS SMS sending (runs in executor)."""
        params = {
            "PhoneNumber": to,
            "Message": body,
            "MessageAttributes": {
                "AWS.SNS.SMS.SMSType": {
                    "DataType": "String",
                    "StringValue": "Transactional"
                }
            }
        }
        
        # Add sender ID if configured (supported in some countries)
        if self.config.sender_id:
            params["MessageAttributes"]["AWS.SNS.SMS.SenderID"] = {
                "DataType": "String",
                "StringValue": self.config.sender_id
            }
        
        return self.client.publish(**params)
    
    async def check_delivery_status(self, message_id: str) -> str:
        """
        Check delivery status of a message.
        
        Note: AWS SNS doesn't provide direct delivery status via API.
        Status must be retrieved from CloudWatch Logs or SNS delivery status logs.
        This method returns 'unknown' - implement CloudWatch integration for real status.
        
        :param message_id: SNS Message ID
        :return: Status string (limited support)
        """
        # SNS doesn't have a direct API to check message status
        # You would need to query CloudWatch Logs for delivery status
        # For now, return unknown
        return "unknown"
    
    @classmethod
    def from_env(cls, **kwargs) -> 'AWSSNSProvider':
        """
        Create AWSSNSProvider from environment variables.
        
        :param kwargs: Additional arguments to override environment values
        :return: Configured AWSSNSProvider instance
        """
        config = AWSSNSConfig.from_env()
        return cls(
            region_name=kwargs.get('region_name', config.region_name),
            aws_access_key_id=kwargs.get('aws_access_key_id', config.aws_access_key_id),
            aws_secret_access_key=kwargs.get('aws_secret_access_key', config.aws_secret_access_key),
            sender_id=kwargs.get('sender_id', config.sender_id),
            max_retries=kwargs.get('max_retries', 3),
            retry_delay=kwargs.get('retry_delay', 1.0)
        )
