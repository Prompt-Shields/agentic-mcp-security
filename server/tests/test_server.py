from pathlib import Path

import pytest

from mcp import Client

from awesome_mcp_security.catalog import Catalog, clean, parse_topic
from awesome_mcp_security.server import build_server, default_content_dir

FIXTURE = """\
# Sample Topic

## Contents

- [Tables](#tables)

## Tables

| Tool | Summary | Last updated |
| --- | --- | --- |
| [Scanner][ref_scanner] | Finds **tool poisoning** in configs | [![last commit](https://badgen.net/github/last-commit/acme/scanner)][ref_commits] |
| [Inline](https://example.com/inline) | Mentions CVE-2025-6514 and cve-2024-12345 | ![](https://badgen.net/github/last-commit/acme/inline) |

### Nested

- [Bullet link](https://example.com/bullet) - A bulleted entry.

[Bare link][ref_scanner]

## Podcasts

<table>
<thead>
<tr><th>Date</th><th>Episode</th><th>Summary</th></tr>
</thead>
<tbody>
<tr><td>2026-01-01</td><td><a href="https://example.com/ep1">Episode &amp; One</a> : Show</td><td>About gateways.</td></tr>
</tbody>
</table>

# Second H1

| Name | Notes |
| --- | --- |
| [Under second H1](https://example.com/h1) | x |

[ref_scanner]: https://example.com/scanner
[ref_commits]: https://example.com/scanner/commits
"""


@pytest.fixture
def sample_dir(tmp_path: Path) -> Path:
    (tmp_path / "mcp_sample.md").write_text(FIXTURE)
    return tmp_path


def test_parse_fixture(sample_dir: Path):
    topic = parse_topic(sample_dir / "mcp_sample.md")
    assert topic.slug == "sample"
    assert topic.title == "Sample Topic"
    titles = {e.title: e for e in topic.entries}
    assert set(titles) == {"Scanner", "Inline", "Bullet link", "Bare link", "Episode & One : Show", "Under second H1"}

    scanner = titles["Scanner"]
    assert scanner.url == "https://example.com/scanner"  # reference-style link resolved
    assert scanner.section == "Tables"
    assert scanner.github_repo == "acme/scanner"
    assert scanner.fields == {"Summary": "Finds tool poisoning in configs"}  # badge column dropped

    assert titles["Inline"].cves == ["CVE-2024-12345", "CVE-2025-6514"]
    assert titles["Bullet link"].section == "Tables > Nested"
    assert titles["Bullet link"].fields == {"Summary": "A bulleted entry."}
    episode = titles["Episode & One : Show"]
    assert episode.url == "https://example.com/ep1"
    assert episode.fields == {"Date": "2026-01-01", "Summary": "About gateways."}
    assert titles["Under second H1"].section == "Second H1"
    assert "Contents" not in " ".join(topic.sections)


def test_clean():
    assert clean("[a][b] **bold** `code` ![](x) <br> tail") == "a bold code tail"


def test_search_ranks_title_matches(sample_dir: Path):
    catalog = Catalog(sample_dir)
    assert [e.title for e in catalog.search("scanner")][0] == "Scanner"
    assert [e.title for e in catalog.search("poison")] == ["Scanner"]  # substring match
    assert catalog.search("poisoning nonexistentword") == []  # all terms must match
    assert catalog.search("   ") == []


def test_missing_content_dir(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        Catalog(tmp_path)


def test_real_pages_parse():
    catalog = Catalog(default_content_dir())
    assert len(catalog.topics) >= 10
    assert len(catalog.entries) > 300
    with_url = sum(1 for e in catalog.entries.values() if e.url)
    assert with_url / len(catalog.entries) > 0.95
    assert catalog.by_cve("CVE-2025-6514")


@pytest.fixture
async def client(sample_dir: Path):
    async with Client(build_server(Catalog(sample_dir)), raise_exceptions=True) as c:
        yield c


@pytest.mark.anyio
async def test_tools_listed_read_only(client: Client):
    tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == {"list_topics", "search", "list_entries", "get_entry", "find_cve"}
    assert all(t.annotations.read_only_hint for t in tools.values())


@pytest.mark.anyio
async def test_search_and_get_entry(client: Client):
    result = await client.call_tool("search", {"query": "tool poisoning"})
    assert not result.is_error
    hits = result.structured_content["result"]
    assert hits[0]["title"] == "Scanner"

    entry = await client.call_tool("get_entry", {"entry_id": hits[0]["id"]})
    assert entry.structured_content["url"] == "https://example.com/scanner"

    missing = await client.call_tool("get_entry", {"entry_id": "sample:999"})
    assert missing.is_error


@pytest.mark.anyio
async def test_list_entries_paging(client: Client):
    first = (await client.call_tool("list_entries", {"topic": "sample", "limit": 2})).structured_content
    assert first["total"] == 6 and len(first["entries"]) == 2 and first["next_offset"] == 2
    last = (await client.call_tool("list_entries", {"topic": "sample", "offset": 4})).structured_content
    assert last["next_offset"] is None
    bad = await client.call_tool("list_entries", {"topic": "../etc"})
    assert bad.is_error


@pytest.mark.anyio
async def test_find_cve(client: Client):
    found = (await client.call_tool("find_cve", {"cve_id": "cve-2025-6514"})).structured_content
    assert [e["title"] for e in found["entries"]] == ["Inline"]
    assert (await client.call_tool("find_cve", {"cve_id": "not-a-cve"})).is_error


@pytest.mark.anyio
async def test_topic_resources(client: Client):
    uris = [str(r.uri) for r in (await client.list_resources()).resources]
    assert uris == ["awesome-mcp-security://topics/sample"]
    page = await client.read_resource("awesome-mcp-security://topics/sample")
    assert page.contents[0].text.startswith("# Sample Topic")
