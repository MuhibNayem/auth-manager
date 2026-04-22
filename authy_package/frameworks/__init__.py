"""Frameworks module initialization"""
from .fastapi_adapter import FastAPIAuth
from .flask_adapter import FlaskAuth
from .django_adapter import DjangoAuth

__all__ = ["FastAPIAuth", "FlaskAuth", "DjangoAuth"]
