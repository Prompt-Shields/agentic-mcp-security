"""Combinatorial no-leak test for review_client_config.

Every secret shape below is placed in every position a client config can carry a
credential (env, headers, args in each flag form, docker -e, connection strings,
URLs, shell scripts, Windows launchers). Whatever the reviewer makes of the
config, the secret must not appear anywhere in what it returns.
"""

import json

import pytest

from awesome_mcp_security.config_review import review_config
from awesome_mcp_security.catalog import Catalog

SECRETS = {
    "github": "ghp_" + "Q" * 36,
    "anthropic": "sk-ant-" + "q" * 32,
    "slack": "xoxb-" + "1" * 12 + "-qwerty",
    "aws": "AKIA" + "Q" * 16,
    "opaque": "h7Kq9ZpL2vXw4MnB",  # no known shape: caught only by where it appears
}

# Each placement turns a secret into one server spec. Every slot is one a reviewer can
# recognise by position (a secret-named key or flag, an auth header, a URL's userinfo),
# so even the opaque secret, which has no known shape, must be caught.
PLACEMENTS = {
    "env-named": lambda s: {"command": "node", "args": ["s.js"], "env": {"API_TOKEN": s}},
    "header-auth": lambda s: {"url": "https://x.example/mcp", "headers": {"Authorization": f"Bearer {s}"}},
    "header-key": lambda s: {"url": "https://x.example/mcp", "headers": {"X-API-Key": s}},
    "flag-space": lambda s: {"command": "node", "args": ["s.js", "--api-key", s]},
    "flag-equals": lambda s: {"command": "node", "args": ["s.js", f"--token={s}"]},
    "header-arg": lambda s: {"command": "npx", "args": ["mcp-remote@0.1.16", "https://x.example/sse", "--header",
                                                        f"Authorization: Bearer {s}"]},
    "docker-e": lambda s: {"command": "docker", "args": ["run", "-i", "-e", f"API_KEY={s}", "acme/mcp:1"]},
    "docker-env-eq": lambda s: {"command": "docker", "args": ["run", "-i", f"--env=SECRET_TOKEN={s}", "acme/mcp:1"]},
    "dsn": lambda s: {"command": "node", "args": ["s.js", f"postgresql://app:{s}@db.internal/prod"]},
    "dsn-nouser": lambda s: {"command": "node", "args": ["s.js", f"redis://:{s}@cache:6379"]},
    "env-dsn": lambda s: {"command": "node", "args": ["s.js"], "env": {"DATABASE_URL": f"postgres://u:{s}@db/x"}},
    "url-query": lambda s: {"url": f"https://x.example/mcp?api_key={s}"},
    "url-fragment": lambda s: {"url": f"https://x.example/mcp#access_token={s}"},
    "url-userinfo": lambda s: {"url": f"https://user:{s}@x.example/mcp"},
    "sh-flag": lambda s: {"command": "bash", "args": ["-c", f"node s.js --api-key {s}"]},
    "sh-prefix": lambda s: {"command": "sh", "args": ["-c", f"GITHUB_TOKEN={s} npx -y srv@1.0.0"]},
    "sh-trailing": lambda s: {"command": "bash", "args": ["-c", f"npx -y srv@1.0.0 --token {s}", "--", "x"]},
    "cmd-c": lambda s: {"command": "cmd", "args": ["/c", "npx", "-y", "srv@1.0.0", "--password", s]},
    "pwsh": lambda s: {"command": "pwsh", "args": ["-Command", f"node s.js --secret {s}"]},
}


@pytest.fixture(scope="module")
def catalog(tmp_path_factory) -> Catalog:
    d = tmp_path_factory.mktemp("pages")
    (d / "mcp_x.md").write_text("# X\n\n- [srv](https://example.com/srv) - a server\n")
    return Catalog(d)


@pytest.mark.parametrize("placement", sorted(PLACEMENTS))
@pytest.mark.parametrize("kind", sorted(SECRETS))
def test_secret_never_returned(catalog: Catalog, placement: str, kind: str):
    secret = SECRETS[kind]
    config = {"mcpServers": {"s": PLACEMENTS[placement](secret)}}
    out = json.dumps(review_config(json.dumps(config), catalog))
    assert secret not in out, f"{kind} secret leaked via {placement}: {out[:400]}"


@pytest.mark.parametrize("placement", sorted(PLACEMENTS))
def test_secret_is_reported(catalog: Catalog, placement: str):
    """Not leaking is not enough: the reviewer must also tell the user the secret is there."""
    config = {"mcpServers": {"s": PLACEMENTS[placement](SECRETS["opaque"])}}
    result = review_config(json.dumps(config), catalog)
    high = [f for s in result["servers"] for f in s["findings"] if f["severity"] == "high"]
    assert high, f"no high finding for a credential placed via {placement}"
