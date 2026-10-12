import json
from pathlib import Path

import pytest

from mcp import Client

from awesome_mcp_security.catalog import Catalog
from awesome_mcp_security.config_review import parse_servers, review_config, review_server
from awesome_mcp_security.server import build_server

GITHUB_PAT = "ghp_" + "a" * 36
SECRETS = [GITHUB_PAT, "SUPERSECRET123", "hunter2hunter2", "plainpassword99", "dbpass42", "envdbpass7"]

RISKY = {
    "mcpServers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB_PAT, "LOG_LEVEL": "debug"},
        },
        "remote": {"command": "npx", "args": ["mcp-remote@0.1.10", "https://example.com/sse"]},
        "fs": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@2025.1.14", "/Users"]},
        "box": {"command": "docker", "args": ["run", "-i", "--privileged", "-v", "/:/host", "acme/mcp"]},
        "api": {"url": "http://mcp.example.com/mcp?api_key=SUPERSECRET123"},
        "wrapped": {"command": "bash", "args": ["-c", "node server.js --api-key hunter2hunter2"]},
        "flag": {"command": "node", "args": ["server.js", "--password", "plainpassword99"]},
        "pg": {
            "command": "npx",
            "args": ["@modelcontextprotocol/server-postgres@0.6.2", "postgresql://app:dbpass42@db.internal/prod"],
            "env": {"DATABASE_URL": "postgres://ro:envdbpass7@db/x"},
        },
        "safe": {
            "command": "uvx",
            "args": ["acme-mcp==1.2.3"],
            "env": {"ACME_TOKEN": "${ACME_TOKEN}", "AUTH_METHOD": "bearer"},
        },
    }
}

CATALOG_PAGE = """\
# Sample

| CVE | Affected component | Fixed in | Links |
| --- | --- | --- | --- |
| CVE-2025-6514 | mcp-remote (npm) | >= 0.1.16 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) |

- [Remote write-up](https://blog.example.org/mcp-remote) - How mcp-remote was exploited.
- [Not it](https://example.com/x) - Mentions mcp-remotely, a different word.
"""


@pytest.fixture
def catalog(tmp_path: Path) -> Catalog:
    (tmp_path / "mcp_sample.md").write_text(CATALOG_PAGE)
    return Catalog(tmp_path)


def rules(result: dict, server: str) -> list[str]:
    return [f["rule"] for s in result["servers"] if s["server"] == server for f in s["findings"]]


def test_findings_per_server(catalog: Catalog):
    r = review_config(json.dumps(RISKY), catalog)
    assert rules(r, "github") == ["plaintext-secret", "unpinned-package", "auto-install"]
    assert rules(r, "remote") == []  # pinned, though to a vulnerable version: see the catalog match
    assert rules(r, "fs") == ["broad-filesystem-access"]
    assert set(rules(r, "box")) == {"privileged-container", "broad-mount", "unpinned-image"}
    assert set(rules(r, "api")) == {"plaintext-transport", "secret-in-url"}
    assert set(rules(r, "wrapped")) == {"shell-wrapper", "secret-in-args"}
    assert rules(r, "flag") == ["secret-in-args"]
    assert set(rules(r, "pg")) == {"password-in-connection-string", "plaintext-secret"}
    assert rules(r, "safe") == []  # pinned; env references and "bearer" are not secrets
    assert r["summary"]["high"] == 9  # github 1, box 2, api 2, wrapped 1, flag 1, pg 2
    # High findings come first within a server.
    box = next(s for s in r["servers"] if s["server"] == "box")
    assert [f["severity"] for f in box["findings"]] == sorted(
        (f["severity"] for f in box["findings"]), key={"high": 0, "medium": 1, "low": 2}.get
    )


def test_secret_values_never_returned(catalog: Catalog):
    out = json.dumps(review_config(json.dumps(RISKY), catalog))
    for secret in SECRETS:
        assert secret not in out
    wrapped = next(s for s in review_config(json.dumps(RISKY), catalog)["servers"] if s["server"] == "wrapped")
    assert wrapped["launches"] == "bash -c node server.js --api-key [redacted]"
    pg = next(s for s in review_config(json.dumps(RISKY), catalog)["servers"] if s["server"] == "pg")
    assert pg["launches"].endswith("postgresql://app:[redacted]@db.internal/prod")


def test_catalog_matches_exact_package_names(catalog: Catalog):
    r = review_config(json.dumps(RISKY), catalog)
    remote = next(s for s in r["servers"] if s["server"] == "remote")
    titles = [e["title"] for e in remote["catalog"]]
    assert titles[0] == "CVE-2025-6514"  # the CVE record ranks first
    assert "Remote write-up" in titles and "Not it" not in titles  # whole-word match only


@pytest.mark.parametrize(
    "wrapper",
    [
        lambda s: {"mcpServers": s},
        lambda s: {"servers": s},  # .vscode/mcp.json
        lambda s: {"mcp": {"servers": s}},  # VS Code settings.json
        lambda s: s,  # just the table
    ],
)
def test_config_shapes(wrapper):
    servers = {"a": {"command": "node", "args": ["a.js"]}}
    assert list(parse_servers(json.dumps(wrapper(servers)))) == ["a"]


@pytest.mark.parametrize(
    ("text", "message"),
    [("{not json", "not valid JSON"), ("[]", "JSON object"), ('{"mcpServers": {}}', "no MCP servers"),
     ("x" * 200_001, "over")],
)
def test_bad_input(text: str, message: str):
    with pytest.raises(ValueError, match=message):
        parse_servers(text)


def test_pinning_rules():
    def rule_names(args):
        return [f.rule for f in review_server("s", {"command": "npx", "args": args}).findings]

    assert "unpinned-package" in rule_names(["pkg"])
    assert "unpinned-package" in rule_names(["pkg@latest"])
    assert "unpinned-package" not in rule_names(["pkg@1.0.0"])
    assert "unpinned-package" not in rule_names(["@scope/pkg@1.0.0"])
    assert "unpinned-package" in rule_names(["@scope/pkg"])
    digest = review_server("d", {"command": "docker", "args": ["run", "acme/mcp@sha256:" + "0" * 64]})
    assert "unpinned-image" not in [f.rule for f in digest.findings]


def test_localhost_http_is_fine():
    review = review_server("local", {"url": "http://localhost:3000/mcp"})
    assert review.findings == []


def test_password_from_environment_is_fine():
    review = review_server("pg", {"command": "node", "args": ["s.js", "postgresql://app:${DB_PASS}@db/x"],
                                  "env": {"DATABASE_URL": "postgres://ro:$PASS@db/x"}})
    assert review.findings == []


@pytest.mark.anyio
async def test_tool(catalog: Catalog):
    async with Client(build_server(catalog), raise_exceptions=True) as c:
        result = (await c.call_tool("review_client_config", {"config": json.dumps(RISKY)})).structured_content
        assert result["summary"]["high"] == 9 and "not instructions" in result["note"]
        bad = await c.call_tool("review_client_config", {"config": "{nope"})
        assert bad.is_error and "not valid JSON" in bad.content[0].text


# Regression cases from the code review of review_client_config.

def review(spec: dict, name: str = "s"):
    return review_server(name, spec)


def leaks(r, *secrets: str) -> list[str]:
    text = json.dumps({"launches": r.launches, "findings": [f.to_dict() for f in r.findings], "pk": r.packages})
    return [s for s in secrets if s in text]


def test_docker_env_literal_flagged_and_redacted():
    r = review({"command": "docker", "args": ["run", "-i", "--rm", "-e", "BRAVE_API_KEY=BSAabcdef123456",
                                               "-e", "LOG_LEVEL", "mcp/brave-search"]})
    assert "secret-in-args" in [f.rule for f in r.findings]
    assert leaks(r, "BSAabcdef123456") == [] and "BRAVE_API_KEY=[redacted]" in r.launches
    assert r.packages == ["mcp/brave-search"]


def test_auth_header_in_args_flagged_and_redacted():
    r = review({"command": "npx", "args": ["mcp-remote@0.1.16", "https://x.com/sse", "--header",
                                            "Authorization: Bearer abcdef1234567890"]})
    assert "secret-in-args" in [f.rule for f in r.findings]
    assert leaks(r, "abcdef1234567890") == [] and "Authorization: Bearer [redacted]" in r.launches


@pytest.mark.parametrize("dsn,secret", [("redis://:supersecretpw@cache:6379", "supersecretpw"),
                                        ("postgresql://app:pa/ss42word@db/x", "pa/ss42word")])
def test_connection_string_variants(dsn: str, secret: str):
    r = review({"command": "node", "args": ["s.js", dsn]})
    assert "password-in-connection-string" in [f.rule for f in r.findings]
    assert leaks(r, secret) == []


def test_url_fragment_credential():
    r = review({"url": "https://x.com/mcp#token=abcdefsecret"})
    assert "secret-in-url" in [f.rule for f in r.findings]
    assert leaks(r, "abcdefsecret") == [] and r.launches == "url https://x.com/mcp"


@pytest.mark.parametrize("spec", [
    {"command": "cmd", "args": ["/c", "npx", "-y", "mcp-remote"]},
    {"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "mcp-remote"]},
    {"command": "bash", "args": ["-c", "npx -y mcp-remote"]},
])
def test_wrapped_and_windows_runners_are_reviewed(spec: dict):
    r = review(spec)
    rules = [f.rule for f in r.findings]
    assert "unpinned-package" in rules and "auto-install" in rules and r.packages == ["mcp-remote"]


def test_docker_image_found_after_flags_and_args():
    r = review({"command": "docker", "args": ["run", "-i", "--rm", "--mount", "type=bind,src=/,dst=/projects",
                                               "mcp/filesystem", "/projects"]})
    assert r.packages == ["mcp/filesystem"]
    rules = [f.rule for f in r.findings]
    assert "broad-mount" in rules  # --mount src=/
    assert any("mcp/filesystem" in f.detail for f in r.findings if f.rule == "unpinned-image")
    assert review({"command": "docker", "args": ["run", "alpine"]}).packages == ["alpine"]


@pytest.mark.parametrize("path", ["/Users/alice", "/home/bob/", "C:\\Users\\alice", "~"])
def test_home_directory_is_broad(path: str):
    r = review({"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", path]})
    assert [f.rule for f in r.findings] == ["broad-filesystem-access"]


def test_project_folder_is_not_broad():
    r = review({"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/Users/alice/code"]})
    assert r.findings == []


@pytest.mark.parametrize("args,package", [
    (["--python", "3.12", "mcp-server-fetch"], "mcp-server-fetch"),
    (["--from", "mcp-server-git==0.6.2", "mcp-server-git"], "mcp-server-git"),
    (["--registry", "https://r.example", "-y", "pkg@1.0.0"], "pkg"),
])
def test_runner_flag_values_are_not_the_package(args: list[str], package: str):
    command = "uvx" if args[0] in {"--python", "--from"} else "npx"
    assert review({"command": command, "args": args}).packages == [package]


@pytest.mark.parametrize("bad", [5, True, None, {"a": 1}])
def test_odd_args_do_not_crash(bad):
    assert review({"command": "node", "args": bad}).findings == []


def test_jsonc_comments_and_trailing_commas():
    text = '{\n  // my servers\n  "mcpServers": {\n    "a": {"command": "node", "args": ["a.js // not a comment"],},\n  },\n}'
    servers = parse_servers(text)
    assert servers["a"]["args"] == ["a.js // not a comment"]


@pytest.mark.parametrize("spec", [
    {"command": "node", "args": ["s.js", "--token-file", "/run/secrets/token"]},
    {"command": "node", "args": ["s.js"], "env": {"OAUTH_PROVIDER": "github-oauth", "API_KEY_PATH": "/etc/k"}},
])
def test_pointers_to_secrets_are_not_secrets(spec: dict):
    assert review(spec).findings == []
