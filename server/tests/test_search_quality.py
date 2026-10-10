"""Search regression tests against the real topic pages.

Each case is a query a model might send and a URL that a good answer must rank
near the top. When the list changes these may need updating; when ranking code
changes they catch regressions. Point AWESOME_MCP_SECURITY_CONTENT_DIR at another
copy of the pages (say, an upstream export) to check ranking against it first.
"""

from pathlib import Path

import pytest

from awesome_mcp_security.catalog import Catalog
from awesome_mcp_security.server import resolve_content_dir

CASES = [
    # (query, URL expected in the top results -- or a tuple of acceptable ones, for
    # questions with many right answers -- and how many results to look at)
    ("Burp Suite", "github.com/PortSwigger/mcp-server", 1),
    ("damn vulnerable mcp server", "github.com/harishsg993010/damn-vulnerable-MCP-server", 1),
    ("OWASP MCP top 10", "owasp.org/www-project-mcp-top-10", 1),
    ("tool poisoning", "invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", 5),
    ("mcp-remote RCE", "jfrog.com", 3),
    ("Ghidra reverse engineering", "github.com/LaurieWired/GhidraMCP", 3),
    (
        "what scanners detect tool poisoning",
        ("github.com/snyk/agent-scan", "github.com/gensecaihq/mcpscc", "secure-hulk", "github.com/antgroup/MCP-Security"),
        5,
    ),
    ("how to secure OAuth tokens for MCP servers", "modelcontextprotocol.io", 5),
    ("Snyk agent scan", "github.com/snyk/agent-scan", 1),
    ("SIEM", "github.com/panther-labs/mcp-panther", 5),
]


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog(resolve_content_dir())  # honours AWESOME_MCP_SECURITY_CONTENT_DIR


@pytest.mark.parametrize(("query", "expected", "top"), CASES, ids=[c[0] for c in CASES])
def test_expected_result_ranks_high(catalog: Catalog, query: str, expected: str | tuple[str, ...], top: int):
    urls = [(e.url or "").lower() for e in catalog.search(query, limit=top)]
    wanted = (expected,) if isinstance(expected, str) else expected
    assert any(w.lower() in u for w in wanted for u in urls), f"none of {wanted!r} in top {top}: {urls}"


def test_no_duplicate_urls_in_results(catalog: Catalog):
    for query, _, _ in CASES:
        urls = [e.url.rstrip("/").lower() for e in catalog.search(query, limit=20) if e.url]
        assert len(urls) == len(set(urls)), query


def test_linked_entries_outrank_cross_references(catalog: Catalog):
    hits = catalog.search("damn vulnerable mcp server", limit=3)
    assert all(e.url for e in hits[:2])
