"""Passwordless module initialization"""
from .magic_link import MagicLinkManager
from .passkey import PasskeyManager

__all__ = ["MagicLinkManager", "PasskeyManager"]
