"""Database backends for the Tessera package (CONTRACTS.md §4).

Exports the unified :class:`AbstractDatabase` contract, the in-memory
reference implementation, and a :func:`get_database` factory keyed on
``DatabaseConfig.db_type`` (``sql | mongodb | dynamodb | memory``).

The heavy adapters (:class:`SQLDatabase`, :class:`MongoDB`,
:class:`DynamoDBAdapter`) are imported lazily and defensively: import
failures in those modules must never break ``import tessera.db``.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Dict

from tessera.db.abstract_db import AbstractDatabase
from tessera.db.memory import InMemoryDatabase
from tessera.errors import ConfigError

logger = logging.getLogger("tessera.db")

__all__ = [
    "AbstractDatabase",
    "InMemoryDatabase",
    "SQLDatabase",
    "MongoDB",
    "DynamoDBAdapter",
    "get_database",
]

#: module path -> class name for lazily imported adapters.
_ADAPTERS: Dict[str, tuple] = {
    "SQLDatabase": (".sql", "SQLDatabase"),
    "MongoDB": (".mongodb", "MongoDB"),
    "DynamoDBAdapter": (".dynamodb_adapter", "DynamoDBAdapter"),
}

_ADAPTER_ALIASES: Dict[str, str] = {
    # Legacy name kept importable for one release.
    "MongoDBDatabase": "MongoDB",
}


def _load_adapter(name: str) -> Any:
    """Lazily import an adapter class; raise informative ImportError on failure."""
    module_path, class_name = _ADAPTERS[name]
    try:
        module = importlib.import_module(module_path, __name__)
    except Exception as exc:
        raise ImportError(
            f"Database adapter {name!r} is unavailable: failed to import "
            f"tessera.db{module_path}: {exc}"
        ) from exc
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise ImportError(
            f"Database adapter {name!r} is unavailable: "
            f"tessera.db{module_path} has no class {class_name!r}"
        ) from exc


def __getattr__(name: str) -> Any:
    """PEP 562 lazy, guarded adapter imports."""
    resolved = _ADAPTER_ALIASES.get(name, name)
    if resolved in _ADAPTERS:
        return _load_adapter(resolved)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_database(config: Any) -> AbstractDatabase:
    """Create a database backend from configuration.

    Args:
        config: An :class:`~tessera.config.AuthConfig` (its ``database``
            attribute is used) or a
            :class:`~tessera.config.DatabaseConfig` directly.

    Returns:
        An :class:`AbstractDatabase` implementation for ``db_type``.

    Raises:
        ConfigError: On an unsupported ``db_type``.
        ImportError: When the requested adapter module cannot be imported.
    """
    db_config = getattr(config, "database", config)
    db_type = getattr(db_config, "db_type", None)
    if db_type == "memory":
        return InMemoryDatabase()
    if db_type == "sql":
        return _load_adapter("SQLDatabase")(db_config)
    if db_type == "mongodb":
        return _load_adapter("MongoDB")(db_config)
    if db_type == "dynamodb":
        return _load_adapter("DynamoDBAdapter")(db_config)
    raise ConfigError(
        f"Unsupported database.db_type {db_type!r}; expected one of "
        "'sql', 'mongodb', 'dynamodb', 'memory'"
    )
