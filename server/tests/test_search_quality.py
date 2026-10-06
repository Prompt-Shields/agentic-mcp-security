"""Search regression tests against the real topic pages.

Each case is a query a model might send and a URL that a good answer must rank
near the top. When the list changes these may need updating; when ranking code
changes they catch regressions.
"""

from pathlib import Path

import pytest

from awesome_mcp_security.catalog import Catalog
from awesome_mcp_security.server import default_content_dir

CASES = [
    # (query, URL expected in the top results, how many results to look at)
    ("Burp Suite", "github.com/PortSwigger/mcp-server", 1),
    ("damn vulnerable mcp server", "github.com/harishsg993010/damn-vulnerable-MCP-server", 1),
    ("OWASP MCP top 10", "owasp.org/www-project-mcp-top-10", 1),
    ("tool poisoning", "invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", 5),
    ("mcp-remote RCE", "jfrog.com", 3),
    ("Ghidra reverse engineering", "github.com/LaurieWired/GhidraMCP", 3),
    ("what scanners detect tool poisoning", "github.com/snyk/agent-scan", 5),
    ("how to secure OAuth tokens for MCP servers", "modelcontextprotocol.io", 5),
    ("Snyk agent scan", "github.com/snyk/agent-scan", 1),
    ("SIEM", "github.com/panther-labs/mcp-panther", 5),
]


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog(default_content_dir())


@pytest.mark.parametrize(("query", "expected", "top"), CASES, ids=[c[0] for c in CASES])
def test_expected_result_ranks_high(catalog: Catalog, query: str, expected: str, top: int):
    urls = [e.url or "" for e in catalog.search(query, limit=top)]
    assert any(expected.lower() in u.lower() for u in urls), f"{expected!r} not in top {top}: {urls}"


def test_no_duplicate_urls_in_results(catalog: Catalog):
    for query, _, _ in CASES:
        urls = [e.url.rstrip("/").lower() for e in catalog.search(query, limit=20) if e.url]
        assert len(urls) == len(set(urls)), query


def test_linked_entries_outrank_cross_references(catalog: Catalog):
    hits = catalog.search("damn vulnerable mcp server", limit=3)
    assert all(e.url for e in hits[:2])
