# auth_package/social/__init__.py

from .apple import AppleManager
from .github import GitHubManager
from .facebook import FacebookManager
from .google import GoogleManager

__all__ = ["AppleManager", "GitHubManager", "FacebookManager", "GoogleManager"]
