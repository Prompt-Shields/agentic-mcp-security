"""Release metadata stays consistent: a mismatch would fail the release workflow or the registry."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
SERVER_JSON = json.loads((ROOT / "server.json").read_text())


def test_versions_agree():
    package = SERVER_JSON["packages"][0]
    assert PYPROJECT["version"] == SERVER_JSON["version"] == package["version"]


def test_registry_package_is_this_pypi_project():
    package = SERVER_JSON["packages"][0]
    assert package["registryType"] == "pypi" and package["identifier"] == PYPROJECT["name"]
    assert package["transport"] == {"type": "stdio"}
    # Registry clients start a PyPI server as `uvx <identifier>`, so a script must carry that name.
    assert PYPROJECT["name"] in PYPROJECT["scripts"]


def test_readme_proves_ownership():
    # The registry checks the PyPI description (this README) for `mcp-name: <server name>`,
    # followed by a boundary such as whitespace or the end of an HTML comment.
    readme = (ROOT / "README.md").read_text()
    assert re.search(rf"mcp-name: {re.escape(SERVER_JSON['name'])}(?=\s|-->)", readme)


def test_server_json_basics():
    assert re.fullmatch(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+", SERVER_JSON["name"])
    assert 1 <= len(SERVER_JSON["description"]) <= 100
    assert SERVER_JSON["$schema"].startswith("https://static.modelcontextprotocol.io/schemas/")
    assert SERVER_JSON["repository"] == {
        "url": PYPROJECT["urls"]["Repository"], "source": "github", "subfolder": "server",
    }
