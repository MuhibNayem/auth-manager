"""Structural build-config tests for the React admin dashboard UI kit.

Node-free: these tests parse package.json / tsconfig files and assert that
every file referenced by the build actually exists and that scripts/deps are
coherent. They protect against the "cannot build" regression class (missing
tsconfig.node.json, missing index.html, tailwind without config, scripts
pointing at nothing).
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = REPO_ROOT / "authy_package" / "ui_kits" / "react" / "admin-dashboard"


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (string-aware) so JSONC parses as JSON."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def load_jsonc(path: Path):
    return json.loads(strip_jsonc(path.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def pkg():
    return json.loads((DASHBOARD / "package.json").read_text(encoding="utf-8"))


def test_dashboard_directory_exists():
    assert DASHBOARD.is_dir(), f"missing dashboard package at {DASHBOARD}"


def test_package_json_scripts_coherent(pkg):
    scripts = pkg.get("scripts", {})
    for name in ("dev", "build", "preview", "lint", "test"):
        assert name in scripts, f"package.json is missing script '{name}'"
    # build must typecheck then bundle
    assert "tsc" in scripts["build"] and "vite build" in scripts["build"]
    # test must be a single-run vitest invocation (watch mode would hang CI)
    assert re.fullmatch(r"vitest run", scripts["test"].strip()), (
        "test script must be 'vitest run' (non-watch)"
    )
    # every binary referenced by a script must come from a declared dependency
    binaries = {
        "vite": "vite",
        "tsc": "typescript",
        "eslint": "eslint",
        "vitest": "vitest",
    }
    dev_deps = pkg.get("devDependencies", {})
    deps = pkg.get("dependencies", {})
    for binary, package in binaries.items():
        used = any(re.search(rf"\b{binary}\b", s) for s in scripts.values())
        if used:
            assert package in dev_deps or package in deps, (
                f"script uses '{binary}' but package '{package}' is not declared"
            )


def test_runtime_dependencies_present(pkg):
    deps = pkg.get("dependencies", {})
    for required in ("react", "react-dom", "react-router-dom", "axios",
                     "@tanstack/react-query", "zustand"):
        assert required in deps, f"missing runtime dependency: {required}"


def test_tsconfig_project_references_resolve():
    tsconfig = load_jsonc(DASHBOARD / "tsconfig.json")
    refs = tsconfig.get("references", [])
    assert refs, "tsconfig.json lost its project references"
    for ref in refs:
        ref_path = DASHBOARD / ref["path"]
        assert ref_path.exists(), f"referenced project missing: {ref_path}"
        load_jsonc(ref_path)  # must parse
    node_cfg = load_jsonc(DASHBOARD / "tsconfig.node.json")
    assert "vite.config.ts" in node_cfg.get("include", []), (
        "tsconfig.node.json must cover vite.config.ts"
    )


def test_index_html_exists_and_references_entry():
    index_html = DASHBOARD / "index.html"
    assert index_html.is_file(), "index.html is missing (vite dev cannot start)"
    html = index_html.read_text(encoding="utf-8")
    match = re.search(r'src="(/src/[^"]+)"', html)
    assert match, "index.html must load a module entry under /src"
    entry_rel = match.group(1).lstrip("/")
    assert (DASHBOARD / entry_rel).is_file(), f"entry referenced by index.html missing: {entry_rel}"


def test_tailwind_deps_have_configs():
    pkg = json.loads((DASHBOARD / "package.json").read_text(encoding="utf-8"))
    dev_deps = pkg.get("devDependencies", {})
    if "tailwindcss" in dev_deps:
        tailwind_cfg = DASHBOARD / "tailwind.config.js"
        assert tailwind_cfg.is_file(), "tailwindcss declared but tailwind.config.js missing"
        cfg_text = tailwind_cfg.read_text(encoding="utf-8")
        assert "content" in cfg_text, "tailwind.config.js must declare content globs"

        postcss_cfg = DASHBOARD / "postcss.config.js"
        assert postcss_cfg.is_file(), "tailwindcss declared but postcss.config.js missing"
        postcss_text = postcss_cfg.read_text(encoding="utf-8")
        assert "tailwindcss" in postcss_text and "autoprefixer" in postcss_text

        index_css = DASHBOARD / "src" / "index.css"
        assert index_css.is_file(), "tailwindcss declared but src/index.css missing"
        css = index_css.read_text(encoding="utf-8")
        for directive in ("@tailwind base", "@tailwind components", "@tailwind utilities"):
            assert directive in css, f"src/index.css missing '{directive}'"


def test_lint_script_points_at_real_config():
    pkg = json.loads((DASHBOARD / "package.json").read_text(encoding="utf-8"))
    lint = pkg["scripts"]["lint"]
    assert "eslint" in lint
    candidates = [
        DASHBOARD / ".eslintrc.cjs",
        DASHBOARD / ".eslintrc.js",
        DASHBOARD / ".eslintrc.json",
        DASHBOARD / "eslint.config.js",
    ]
    assert any(c.is_file() for c in candidates), (
        "lint script runs eslint but no eslint config file exists"
    )
    if "typescript" in lint or "--ext ts" in lint:
        dev_deps = pkg.get("devDependencies", {})
        assert "@typescript-eslint/parser" in dev_deps


def test_test_script_has_at_least_one_test_file():
    tests = [
        p for p in (DASHBOARD / "src").rglob("*")
        if p.is_file() and re.search(r"\.(test|spec)\.[cm]?[jt]sx?$", p.name)
    ]
    assert tests, "vitest configured but no *.test.* files under src/"


def test_vite_config_exists_and_parses():
    vite_cfg = DASHBOARD / "vite.config.ts"
    assert vite_cfg.is_file()
    text = vite_cfg.read_text(encoding="utf-8")
    assert "defineConfig" in text
