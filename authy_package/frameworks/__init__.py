"""Frameworks module initialization."""
from .fastapi_adapter import FastAPIAuth
from .flask_adapter import FlaskAuth
from .django_adapter import (
    DjangoAuth,
    DjangoAuthMiddleware,
    get_auth_manager,
    set_auth_manager,
)

__all__ = [
    "FastAPIAuth",
    "FlaskAuth",
    "DjangoAuth",
    "DjangoAuthMiddleware",
    "set_auth_manager",
    "get_auth_manager",
]
