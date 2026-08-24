# auth_package/core/__init__.py
"""Core authentication managers (traditional, Cognito facade, social)."""

from .auth_manager import CognitoAuthManager, SocialAuthManager, TraditionalAuthManager

__all__ = ["TraditionalAuthManager", "CognitoAuthManager", "SocialAuthManager"]
