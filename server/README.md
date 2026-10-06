# Awesome MCP Security server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server that makes this list searchable from any MCP client (Claude Code, Claude Desktop, Cursor, and others).

At startup it parses the `mcp_*.md` topic pages in the repository root into structured entries. Each entry has a title, URL, section, summary columns, GitHub repo and cited CVE ids. It then serves those entries as tools and serves the pages themselves as resources. The pages stay the single source of truth: edit the Markdown and restart the server.

## Tools

| Tool | What it does |
| --- | --- |
| `list_topics` | Topic pages with their sections, entry counts and resource URIs. |
| `search` | Keyword search across titles, sections and summaries. All keywords must match, and title hits rank first. Optional `topic` and `section` filters. |
| `list_entries` | Pages through one topic (`limit` / `offset`), optionally filtered to a section. |
| `get_entry` | One entry by the id that `search` or `list_entries` returned, for example `security_tools:3`. |
| `lookup_project` | What the list says about a specific repo or link: entries about it, and entries that link to it. Use it to check a server before installing it. |
| `find_cve` | Entries citing a CVE id, plus the CVE catalogs the list links to. |

Every tool is annotated `readOnlyHint` and `openWorldHint: false`.

## Prompts

| Prompt | Argument | What it sets up |
| --- | --- | --- |
| `vet_mcp_server` | `server`: a GitHub repo or URL | A pre-install review covering what the list says about the server, each key risk area, which listed scanners fit, and a go/no-go checklist. |
| `threat_model` | `deployment`: a plain description | A threat model of that deployment against the list's risk areas and security principles. |

Both prompts embed the relevant catalog text inside `<catalog_data>` tags, trimmed to keep the prompt short. They tell the model to treat that text as data. Angle brackets in it are replaced so that text can't close the tag early.

## Resources

`awesome-mcp-security://topics/<slug>` holds the raw Markdown of each topic page. For example, `awesome-mcp-security://topics/security_tools` is `mcp_security_tools.md`.

## Run it

You need Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```sh
cd server
uv run awesome-mcp-security                 # stdio
uv run awesome-mcp-security --transport streamable-http --port 8000
```

Add it to Claude Code:

```sh
claude mcp add awesome-mcp-security -- uv run --directory /path/to/agentic-mcp-security/server awesome-mcp-security
```

Or add it to a client's JSON config:

```json
{
  "mcpServers": {
    "awesome-mcp-security": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agentic-mcp-security/server", "awesome-mcp-security"]
    }
  }
}
```

The server reads the pages from the repository root of the checkout it runs from. To point it elsewhere, use `--content-dir DIR` or set `AWESOME_MCP_SECURITY_CONTENT_DIR`.

## Security notes

- **No side effects.** The server never fetches the URLs it returns, never writes files and never opens outbound connections.
- **Fixed resource set.** Only the topic pages found at startup are registered as resources, so a resource URI cannot name any other file.
- **Third-party text.** Entry titles and summaries describe other people's projects. The server's instructions tell clients to treat them as data rather than instructions, and to review a project before running it.
- **Local binding.** The HTTP transport binds to `127.0.0.1` by default and has no authentication. Put it behind an authenticating proxy or gateway before exposing it beyond localhost.

## Develop

```sh
cd server
uv run --group dev pytest
```

The parser handles pipe tables, HTML `<table>` rows, bulleted links and bare link lines, with both inline and reference-style links. If you add a page in a new layout, add a case to `tests/test_server.py`.
