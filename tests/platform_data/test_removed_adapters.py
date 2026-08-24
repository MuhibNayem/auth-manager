"""Contract decision: Redis/Cassandra fake stubs are DELETED (§4).

Asserts the files are gone, their imports fail, and the factory rejects
the removed db_types with ConfigError.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tessera.config import DatabaseConfig
from tessera.db import get_database
from tessera.errors import ConfigError

_DB_DIR = Path(__file__).resolve().parents[2] / "tessera" / "db"


class TestRemovedAdapters:
    def test_adapter_files_deleted(self) -> None:
        assert not (_DB_DIR / "redis_adapter.py").exists()
        assert not (_DB_DIR / "cassandra_adapter.py").exists()

    def test_adapter_modules_not_importable(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("tessera.db.redis_adapter")
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("tessera.db.cassandra_adapter")

    @pytest.mark.parametrize("db_type", ["redis", "cassandra"])
    def test_factory_rejects_removed_db_types(self, db_type: str) -> None:
        with pytest.raises(ConfigError):
            get_database(DatabaseConfig(db_type=db_type))

    def test_factory_still_supports_contract_db_types(self) -> None:
        # memory constructs immediately; sql/mongodb/dynamodb resolve lazily.
        database = get_database(DatabaseConfig(db_type="memory"))
        assert database.__class__.__name__ == "InMemoryDatabase"
        import tessera.db as db_module

        for name in ("SQLDatabase", "MongoDB", "DynamoDBAdapter"):
            assert isinstance(getattr(db_module, name), type)
