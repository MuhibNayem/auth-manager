"""Tests for §6 password hashing: bcrypt direct, argon2, constant-time path."""

from __future__ import annotations

import pytest

from tessera.utils import security
from tessera.utils.security import (
    hash_password,
    verify_password,
    verify_password_constant_time,
)


class TestBcrypt:
    def test_hash_verify_roundtrip(self) -> None:
        hashed = hash_password("Correct-Horse-9!", bcrypt_rounds=4)
        assert hashed.startswith("$2b$04$")
        assert verify_password("Correct-Horse-9!", hashed) is True

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("Correct-Horse-9!", bcrypt_rounds=4)
        assert verify_password("wrong-password", hashed) is False

    def test_respects_configured_rounds(self) -> None:
        hashed = hash_password("abc123!ABC", bcrypt_rounds=5)
        assert hashed.startswith("$2b$05$")

    def test_empty_password_rejected(self) -> None:
        with pytest.raises(ValueError):
            hash_password("")

    def test_unknown_algorithm_rejected(self) -> None:
        with pytest.raises(ValueError):
            hash_password("abc", algorithm="md5")

    def test_long_password_truncated_to_72_bytes(self) -> None:
        base = "A" * 72
        long_a = base + "tail-of-a"
        long_b = base + "tail-of-b"
        hashed = hash_password(long_a, bcrypt_rounds=4)
        # bcrypt ignores bytes beyond 72: both verify against the same hash.
        assert verify_password(long_a, hashed) is True
        assert verify_password(long_b, hashed) is True
        assert verify_password("B" * 72, hashed) is False

    def test_unicode_password(self) -> None:
        hashed = hash_password("pässwörd-日本語-🔒", bcrypt_rounds=4)
        assert verify_password("pässwörd-日本語-🔒", hashed) is True
        assert verify_password("pässwörd-日本語-🔓", hashed) is False


class TestArgon2:
    def test_hash_verify_roundtrip(self) -> None:
        hashed = hash_password("Correct-Horse-9!", algorithm="argon2")
        assert hashed.startswith("$argon2")
        assert verify_password("Correct-Horse-9!", hashed) is True
        assert verify_password("nope", hashed) is False


class TestVerifyEdgeCases:
    def test_verify_none_or_garbage_returns_false(self) -> None:
        assert verify_password("x", None) is False
        assert verify_password("x", "") is False
        assert verify_password("x", "not-a-hash") is False
        assert verify_password("x", "$2b$garbage") is False

    def test_non_string_candidate_returns_false(self) -> None:
        hashed = hash_password("abc", bcrypt_rounds=4)
        assert verify_password(None, hashed) is False  # type: ignore[arg-type]


class TestConstantTimePath:
    def test_missing_hash_runs_dummy_compare_and_returns_false(self) -> None:
        # The dummy-hash path must never return True and must execute the
        # same verification machinery (bcrypt against a precomputed hash).
        assert verify_password_constant_time("anything", None) is False

    def test_dummy_hash_for_configured_rounds_is_cached(self) -> None:
        first = security._get_dummy_hash("bcrypt", 4)
        second = security._get_dummy_hash("bcrypt", 4)
        assert first == second
        assert first.startswith("$2b$04$")
        assert verify_password_constant_time("guess", None, bcrypt_rounds=4) is False

    def test_with_real_hash_matches_verify_password(self) -> None:
        hashed = hash_password("Real-Password-1", bcrypt_rounds=4)
        assert verify_password_constant_time("Real-Password-1", hashed) is True
        assert verify_password_constant_time("Real-Password-2", hashed) is False

    def test_constant_time_with_none_uses_dummy_of_same_cost(self) -> None:
        # A wrong password against a real hash and any password against a
        # missing hash both perform a full bcrypt verification at the same
        # cost factor.
        real = hash_password("Some-Password-1", bcrypt_rounds=4)
        assert verify_password_constant_time("bad", real, bcrypt_rounds=4) is False
        assert verify_password_constant_time("bad", None, bcrypt_rounds=4) is False
