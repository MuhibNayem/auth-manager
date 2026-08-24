"""Optional node-based build verification for the React admin dashboard.

Skipped by default so `pytest tests/ui` stays node-free and fast. Enable
with the environment variable TESSERA_UI_RUN_NODE=1. Requires `node` and
`npm` on PATH; runs `npm install --no-audit --no-fund` followed by
`npm run build` (tsc typecheck + vite build) in the dashboard directory.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = REPO_ROOT / "tessera" / "ui_kits" / "react" / "admin-dashboard"

pytestmark = pytest.mark.skipif(
    os.environ.get("TESSERA_UI_RUN_NODE") != "1",
    reason="node build tests are opt-in: set TESSERA_UI_RUN_NODE=1",
)


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not available in this environment")
    return path


def test_npm_install_and_build_pass():
    _require_tool("node")
    npm = _require_tool("npm")

    install = subprocess.run(
        [npm, "install", "--no-audit", "--no-fund"],
        cwd=DASHBOARD,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert install.returncode == 0, f"npm install failed:\n{install.stdout}\n{install.stderr}"

    build = subprocess.run(
        [npm, "run", "build"],
        cwd=DASHBOARD,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert build.returncode == 0, f"npm run build failed:\n{build.stdout}\n{build.stderr}"
    assert (DASHBOARD / "dist" / "index.es.js").is_file(), "library build output missing"
