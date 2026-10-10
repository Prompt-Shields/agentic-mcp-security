# Awesome MCP Security server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server that makes this list searchable from any MCP client (Claude Code, Claude Desktop, Cursor, and others).

At startup it parses the `mcp_*.md` topic pages in the repository root into structured entries. Each entry has a title, URL, section, summary columns, GitHub repo and cited CVE ids. It then serves those entries as tools and serves the pages themselves as resources. The pages stay the single source of truth: edit the Markdown, and a running server picks up the change on its next call.

## Tools

| Tool | What it does |
| --- | --- |
| `list_topics` | Topic pages with their sections, entry counts and resource URIs. |
| `search` | Relevance-ranked (BM25) search across titles, sections and summaries. Takes keywords or a plain question: filler words are ignored, simple word forms match, entries covering more of the query rank first, and a project listed in several sections appears once. Optional `topic` and `section` filters. |
| `list_entries` | Pages through one topic (`limit` / `offset`), optionally filtered to a section. |
| `get_entry` | The full record for one entry (every column and link), by the id another tool returned. |
| `lookup_project` | What the list says about one named server or tool, before you install it. Give a repo or URL for exact matches (entries about it, and entries that link to it), or a plain name such as `Burp Suite MCP` for ranked candidates. |
| `find_cve` | One CVE: the CVE page's own record for it (`advisories`: affected component, issue, fixed version, advisory links), the blogs, talks, labs and videos that cite it (`writeups`), and the MCP CVE catalogs to look in further (`cve_catalogs`). |

Every tool is annotated `readOnlyHint` and `openWorldHint: false`.

Result lists use a compact form: `id`, `title`, `url`, `where` (topic and section), and a `summary` trimmed to 300 characters. `github_repo` and `cves` are added when present. Every response carries a `note` saying that the text is third-party content to treat as data, not instructions.

Entry ids look like `security_tools:1a2b3c4d`. They're derived from the entry's link (or its title when it has none), not its position, so they stay valid when rows are added above them. If an entry is removed, its id fails with an error rather than pointing to another entry.

## Prompts

| Prompt | Argument | What it sets up |
| --- | --- | --- |
| `vet_mcp_server` | `server`: a name, GitHub repo or URL | A pre-install review covering what the list says about the server, each key risk area, which listed scanners fit, and a go/no-go checklist. |
| `threat_model` | `deployment`: a plain description | A threat model of that deployment against the list's risk areas and security principles. |

Both prompts embed the relevant catalog text inside `<catalog_data>` tags, trimmed to keep the prompt short. They tell the model to treat that text as data. Angle brackets in it are replaced so that text can't close the tag early.

## Resources

`awesome-mcp-security://topics/<slug>` holds the raw Markdown of each topic page. For example, `awesome-mcp-security://topics/security_tools` is `mcp_security_tools.md`. Pages present at startup are listed, and a URI template also serves pages added while the server runs. Every read comes from the same snapshot the tools use.

## Run it

You need [uv](https://docs.astral.sh/uv/), which installs Python 3.10+ for you if needed.

Without cloning anything (the topic pages are bundled into the package when it builds):

```sh
uvx --from "git+https://github.com/Prompt-Shields/agentic-mcp-security#subdirectory=server" awesome-mcp-security
```

To add it to Claude Code:

```sh
claude mcp add --scope user awesome-mcp-security -- uvx --from "git+https://github.com/Prompt-Shields/agentic-mcp-security#subdirectory=server" awesome-mcp-security
```

Or add it to a client's JSON config:

```json
{
  "mcpServers": {
    "awesome-mcp-security": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Prompt-Shields/agentic-mcp-security#subdirectory=server", "awesome-mcp-security"]
    }
  }
}
```

From a checkout, so that the server follows your edits to the pages:

```sh
cd server
uv run awesome-mcp-security                 # stdio
uv run awesome-mcp-security --transport streamable-http --port 8000
```

An installed package reads its bundled copy of the pages, and a checkout reads the pages in the repository root. To point either one somewhere else, use `--content-dir DIR` or set `AWESOME_MCP_SECURITY_CONTENT_DIR`.

While it runs, the server checks the pages for changes at most every two seconds, on the next tool or prompt call. Edited, added and removed pages show up in the tools, prompts and resource reads without a restart. If a reload fails, for example on a half-saved file, the server keeps the previous version and tries again later. The resource list itself is fixed at startup, so a page added later can be read through the URI template but isn't listed until a restart.

## Security notes

- **No side effects.** The server never fetches the URLs it returns, never writes files and never opens outbound connections.
- **No path access.** Resource URIs resolve only to known topic slugs, served from memory, so a URI can't name any other file. The SDK's own path check also rejects traversal attempts before they reach the server.
- **Third-party text.** Entry titles and summaries describe other people's projects. Every tool response, as well as the server's instructions, tells the model to treat them as data rather than instructions, and to review a project before running it. Result lists are trimmed, so one long entry can't flood the context.
- **Local binding and DNS rebinding.** The HTTP transport binds to `127.0.0.1` by default, where the SDK rejects requests whose `Host` or `Origin` header isn't loopback. That stops a web page in your browser reaching the server through a hostname it controls. The SDK switches those checks off for any other bind address, so the server refuses to start on one unless you name the hostnames clients use: `--host 0.0.0.0 --allowed-host mcp.example.com:8000`. Use `--allowed-origin` to allow a browser app as well. It still has no authentication of its own, and it warns when not on loopback, so put an authenticating proxy or gateway in front before exposing it.

## Develop

```sh
cd server
uv run --group dev pytest
```

The parser handles pipe tables, HTML `<table>` rows, bulleted links and bare link lines, with both inline and reference-style links. If you add a page in a new layout, add a case to `tests/test_server.py`. `tests/test_search_quality.py` holds queries a model might send and the URL each must rank near the top. Run it after changing ranking code, and update it when the list itself changes.

### Does a model pick the right tool?

`evals/tool_selection.py` runs everyday tasks through `claude -p`, with only this server connected, web search and file tools switched off, and no tool named in the task. It checks which tool the model reaches for first. One case is off-topic and must not call the server at all. It makes real model calls, so it isn't part of `pytest`. You need the Claude Code CLI, signed in.

```sh
cd server
uv run python evals/tool_selection.py              # all cases
uv run python evals/tool_selection.py --only 1 2 --show-answers
```

Run it after changing tool descriptions or the server instructions. Before those were rewritten, the model answered "what should I know before installing the Burp Suite MCP server?" from memory and never called the server. It now passes all 6 cases.
