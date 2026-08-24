"""Packaging & CI metadata tests (docs/CONTRACTS.md §11, §12).

Guards the single-source-of-truth packaging config and the release
pipeline invariants:

- root ``pyproject.toml`` is the only packaging config (name/version/
  python range/extras), with ``passlib`` absent everywhere;
- ``authy_package/__init__.py:__version__`` stays in sync with it;
- every ``.github/workflows/*.yml`` parses as YAML;
- a pytest job exists in CI and gates the PyPI publish job.

Only stdlib ``tomllib`` + PyYAML are required; no package import.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
INIT_PATH = REPO_ROOT / "authy_package" / "__init__.py"

REQUIRED_EXTRAS = {
    "fastapi",
    "flask",
    "django",
    "postgresql",
    "mongodb",
    "dynamodb",
    "saml",
    "oidc",
    "sms",
    "captcha",
    "webauthn",
    "all",
    "dev",
}


def _load_pyproject() -> dict:
    with PYPROJECT_PATH.open("rb") as fh:
        return tomllib.load(fh)


# --- pyproject.toml: identity ------------------------------------------------


def test_pyproject_name_is_authy_package() -> None:
    meta = _load_pyproject()
    assert meta["tool"]["poetry"]["name"] == "authy-package"


def test_pyproject_version_is_2_0_0() -> None:
    meta = _load_pyproject()
    assert meta["tool"]["poetry"]["version"] == "2.0.0"


def test_pyproject_version_matches_package_init() -> None:
    meta = _load_pyproject()
    match = re.search(
        r'__version__\s*=\s*["\']([^"\']+)["\']', INIT_PATH.read_text(encoding="utf-8")
    )
    assert match, "__version__ not found in authy_package/__init__.py"
    assert meta["tool"]["poetry"]["version"] == match.group(1)


def test_python_range_supports_39_to_3x() -> None:
    meta = _load_pyproject()
    constraint = meta["tool"]["poetry"]["dependencies"]["python"]
    # Must allow 3.9+ and cap below 4.0 per CONTRACTS.md §11.
    assert ">=3.9" in constraint.replace(" ", "")
    assert "<4.0" in constraint.replace(" ", "")
    assert "^3.12" not in constraint  # legacy over-restriction is gone


def test_build_backend_is_poetry_core() -> None:
    meta = _load_pyproject()
    assert meta["build-system"]["build-backend"] == "poetry.core.masonry.api"


def test_no_inner_pyproject_remains() -> None:
    # One packaging config only (CONTRACTS.md §11).
    assert not (REPO_ROOT / "authy_package" / "pyproject.toml").exists()
    assert not (REPO_ROOT / "authy_package" / "requirements-enterprise.txt").exists()


# --- dependencies & extras ----------------------------------------------------


def _all_dependency_names(meta: dict) -> list[str]:
    names = [str(k).lower() for k in meta["tool"]["poetry"]["dependencies"]]
    for dep_list in meta["tool"]["poetry"]["extras"].values():
        names.extend(str(d).lower() for d in dep_list)
    return names


def test_passlib_is_gone_from_packaging() -> None:
    meta = _load_pyproject()
    assert not any("passlib" in name for name in _all_dependency_names(meta))
    # Belt and braces: no passlib anywhere in the file text.
    assert "passlib" not in PYPROJECT_PATH.read_text(encoding="utf-8")


def test_core_dependencies_present() -> None:
    meta = _load_pyproject()
    deps = {str(k).lower() for k in meta["tool"]["poetry"]["dependencies"]}
    required = {
        "pyjwt",
        "cryptography",
        "bcrypt",
        "httpx",
        "aiohttp",
        "requests",
        "click",
        "rich",
        "python-dotenv",
        "redis",
        "pyotp",
        "python-multipart",
    }
    missing = required - deps
    assert not missing, f"missing core dependencies: {sorted(missing)}"


def test_all_required_extras_exist() -> None:
    meta = _load_pyproject()
    extras = meta["tool"]["poetry"]["extras"]
    missing = REQUIRED_EXTRAS - set(extras)
    assert not missing, f"missing extras: {sorted(missing)}"


def test_extra_contents_match_contract() -> None:
    meta = _load_pyproject()
    extras = meta["tool"]["poetry"]["extras"]
    assert "sqlalchemy" in extras["postgresql"] and "asyncpg" in extras["postgresql"]
    assert "motor" in extras["mongodb"]
    assert "aioboto3" in extras["dynamodb"]
    for dep in ("lxml", "xmlsec", "python3-saml"):
        assert dep in extras["saml"]
    assert "twilio" in extras["sms"] and "boto3" in extras["sms"]
    assert "webauthn" in extras["webauthn"]


def test_dev_extra_tooling() -> None:
    meta = _load_pyproject()
    dev = {str(d).lower() for d in meta["tool"]["poetry"]["extras"]["dev"]}
    assert {"pytest", "pytest-asyncio", "pytest-cov", "ruff", "mypy"} <= dev


def test_all_extra_covers_feature_extras() -> None:
    meta = _load_pyproject()
    extras = meta["tool"]["poetry"]["extras"]
    everything = set(extras["all"])
    for extra_name in REQUIRED_EXTRAS - {"all", "dev", "oidc", "captcha"}:
        for dep in extras[extra_name]:
            assert dep in everything, f"{dep} ({extra_name}) missing from 'all'"


# --- workflows ----------------------------------------------------------------


def _load_workflow(name: str) -> dict:
    path = WORKFLOWS_DIR / name
    assert path.exists(), f"missing workflow: {path}"
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _job_steps(job: dict) -> list[dict]:
    return job.get("steps", []) or []


def _runs_pytest(job: dict) -> bool:
    return any("pytest" in str(step.get("run", "")) for step in _job_steps(job))


def _transitive_needs(jobs: dict, start: str) -> set[str]:
    seen: set[str] = set()
    frontier = [start]
    while frontier:
        current = frontier.pop()
        raw = jobs.get(current, {}).get("needs") or []
        needs = [raw] if isinstance(raw, str) else list(raw)
        for need in needs:
            if need not in seen:
                seen.add(need)
                frontier.append(need)
    return seen


def test_all_workflow_files_parse_as_yaml() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    assert workflows, "no workflow files found"
    for path in workflows:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, dict) and "jobs" in data, f"{path.name} has no jobs"


def test_ci_has_pytest_job_on_pr_and_main() -> None:
    ci = _load_workflow("ci.yml")
    triggers = ci.get("on") or ci.get(True)  # YAML parses bare `on:` as True
    assert "pull_request" in triggers
    assert "main" in (triggers.get("push") or {}).get("branches", [])
    assert any(_runs_pytest(job) for job in ci["jobs"].values())


def test_publish_only_on_semver_tags() -> None:
    publish = _load_workflow("publish.yml")
    triggers = publish.get("on") or publish.get(True)
    tag_patterns = triggers["push"]["tags"]
    assert any(p.startswith("v") for p in tag_patterns), tag_patterns
    assert "branches" not in triggers.get("push", {}), "publish must not run on branches"


def test_publish_is_gated_by_pytest() -> None:
    publish = _load_workflow("publish.yml")
    jobs = publish["jobs"]
    pytest_jobs = {name for name, job in jobs.items() if _runs_pytest(job)}
    assert pytest_jobs, "publish workflow has no pytest job"
    for publish_job in ("publish-pypi", "github-release"):
        assert publish_job in jobs, f"missing job {publish_job}"
        assert _transitive_needs(jobs, publish_job) & pytest_jobs, (
            f"{publish_job} is not gated by a pytest job"
        )


def test_publish_creates_tag_exactly_once_and_no_bot_guard() -> None:
    publish = _load_workflow("publish.yml")
    # No step may create tags (the tag arrives with the trigger ref), and
    # the broken bot-guard command (git log -1 author check) is gone.
    for job in publish["jobs"].values():
        for step in _job_steps(job):
            run = str(step.get("run", ""))
            assert "git tag" not in run, "workflow must not create tags itself"
            assert "git log -1" not in run, "bot guard must not exist"
    # OIDC trusted publishing retained.
    text = (WORKFLOWS_DIR / "publish.yml").read_text(encoding="utf-8")
    assert "id-token: write" in text
    assert "pypa/gh-action-pypi-publish" in text
