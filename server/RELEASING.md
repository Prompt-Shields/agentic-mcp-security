# Releasing the server

A release publishes the package to PyPI as `awesome-mcp-security-server`, then lists it in the
[MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.Prompt-Shields/awesome-mcp-security`. `.github/workflows/release-server.yml` does both
when a `server-v*` tag is pushed. No API tokens are stored: PyPI and the registry both accept the
workflow's GitHub OIDC identity.

## One-time setup

1. **PyPI trusted publisher.** In PyPI, go to *Your account → Publishing → Add a new pending publisher*.
   Use project `awesome-mcp-security-server`, owner `Prompt-Shields`, repository `agentic-mcp-security`,
   workflow `release-server.yml`, and environment `pypi`.
2. **GitHub environment.** In the repo's *Settings → Environments*, create `pypi`. You can require a
   reviewer there, so each publish waits for a person to approve it.
3. **Registry namespace.** `io.github.Prompt-Shields/*` belongs to the GitHub organization. Publishing
   into it needs an organization owner's authority. Check on the first release that the workflow's OIDC
   login is granted that namespace. If it isn't, see the registry's authentication docs.

## Each release

1. Set the same version in `pyproject.toml`, and in both `version` fields of `server.json`.
   `tests/test_release.py` fails if they differ.
2. Merge to `main`, then tag: `git tag server-v0.1.0 && git push origin server-v0.1.0`.
3. The workflow checks that the tag matches the files, runs the tests, builds, publishes to PyPI, and then
   publishes to the registry. The registry checks ownership by finding `mcp-name:` in the README PyPI
   shows, so the README must keep that line.

## After the first release

Users can then run the server without git:

```sh
uvx awesome-mcp-security-server
```
