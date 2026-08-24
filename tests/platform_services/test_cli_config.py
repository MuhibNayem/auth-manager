"""``tessera config`` CLI tests — roundtrip persistence with 0600 perms."""

from __future__ import annotations

import json
import stat

from tessera.cli import cli


def test_config_set_get_roundtrip(runner, tmp_path):
    config_file = tmp_path / "config.json"

    result = runner.invoke(
        cli, ["config", "set", "region", "eu-west-1", "--file", str(config_file)]
    )
    assert result.exit_code == 0, result.output
    assert config_file.exists()

    result = runner.invoke(cli, ["config", "get", "region", "--file", str(config_file)])
    assert result.exit_code == 0
    assert "eu-west-1" in result.output


def test_config_file_written_with_0600(runner, tmp_path):
    config_file = tmp_path / "config.json"
    result = runner.invoke(
        cli, ["config", "set", "api_key", "super-secret-value", "--file", str(config_file)]
    )
    assert result.exit_code == 0, result.output

    mode = stat.S_IMODE(config_file.stat().st_mode)
    assert mode == 0o600


def test_config_existing_file_chmodded_to_0600(runner, tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text("{}", encoding="utf-8")
    config_file.chmod(0o644)

    result = runner.invoke(
        cli, ["config", "set", "k", "v", "--file", str(config_file)]
    )
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(config_file.stat().st_mode) == 0o600


def test_config_show_masks_secrets(runner, tmp_path):
    config_file = tmp_path / "config.json"
    runner.invoke(
        cli, ["config", "set", "jwt_secret", "abcdef1234567890", "--file", str(config_file)]
    )
    runner.invoke(cli, ["config", "set", "region", "us-east-1", "--file", str(config_file)])

    result = runner.invoke(cli, ["config", "show", "--file", str(config_file)])
    assert result.exit_code == 0
    # Secret masked, plain value visible.
    assert "abcdef1234567890" not in result.output
    assert "us-east-1" in result.output


def test_config_get_missing_key_exits_nonzero(runner, tmp_path):
    result = runner.invoke(
        cli, ["config", "get", "nope", "--file", str(tmp_path / "config.json")]
    )
    assert result.exit_code == 1


def test_config_set_json_value(runner, tmp_path):
    config_file = tmp_path / "config.json"
    result = runner.invoke(
        cli,
        ["config", "set", "limits", '{"minute": 10}', "--json-value",
         "--file", str(config_file)],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(config_file.read_text(encoding="utf-8"))
    assert stored["limits"] == {"minute": 10}
