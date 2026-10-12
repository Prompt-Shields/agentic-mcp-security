"""Review an MCP client config (claude_desktop_config.json, .mcp.json, ...) for risky settings.

Pure functions over the pasted text: nothing is executed, installed, fetched or
read from disk. Secret values are never returned; findings name the key only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .catalog import Catalog, Entry, github_repo

MAX_CONFIG_CHARS = 200_000
MAX_SERVERS = 50

_SECRET_KEY = re.compile(r"(token|secret|passw(or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)", re.I)
# Shapes of common live credentials, matched in values (env, args, headers).
_SECRET_VALUE = re.compile(
    r"(ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"
    r"|sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
# A flag named for a secret, and "--api-key VALUE" / "--token=VALUE" anywhere in a string (a shell
# command line, say). Narrower than _SECRET_KEY: "--auth-method bearer" is not a secret.
_SECRET_WORDS = r"(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
_SECRET_FLAG = re.compile(rf"--?[\w-]*{_SECRET_WORDS}[\w-]*", re.I)
_SECRET_FLAG_VALUE = re.compile(rf"(--?[\w-]*{_SECRET_WORDS}[\w-]*)(=|\s+)(?![$-])(\S+)", re.I)
# A password in a URL's userinfo: postgresql://user:password@host/db, https://user:pass@host.
_URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@$][^/\s@]*)(@)", re.I)  # "$VAR" is fine
# A reference to the environment or a secret store, not a literal secret.
_INDIRECT = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\{\{.*\}\}$|^op://|^<.*>$|^$")
_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm"}
_SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
_LOCAL_HOSTS = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", re.I)
_BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "/home", "/Users", "C:\\", "C:/", "/root"}


@dataclass
class Finding:
    severity: str  # "high", "medium" or "low"
    rule: str
    detail: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "rule": self.rule, "detail": self.detail}


@dataclass
class ServerReview:
    name: str
    launches: str  # what starts it, secrets removed: "npx -y @scope/pkg", "url https://...", ...
    packages: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def parse_servers(text: str) -> dict[str, dict]:
    """The server table from a client config: {"mcpServers": {...}}, {"servers": {...}} or the table itself."""
    if len(text) > MAX_CONFIG_CHARS:
        raise ValueError(f"config is over {MAX_CONFIG_CHARS} characters; paste just the MCP servers section")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}") from None
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(data.get(key), dict):
            data = data[key]
            break
    else:
        if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
            data = data["mcp"]["servers"]  # VS Code settings.json
    servers = {k: v for k, v in data.items() if isinstance(v, dict)}
    if not servers:
        raise ValueError("found no MCP servers; expected an object such as {\"mcpServers\": {\"name\": {...}}}")
    return dict(list(servers.items())[:MAX_SERVERS])


def _redact(value: str) -> str:
    value = _SECRET_VALUE.sub("[redacted]", value)
    value = _URL_PASSWORD.sub(lambda m: f"{m.group(1)}[redacted]{m.group(3)}", value)
    return _SECRET_FLAG_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", value)


def _redacted_command(command: str, args: list[str]) -> str:
    """The command line with credential-shaped values and values of secret-named flags removed."""
    out, hide_next = [], False
    for arg in args:
        if hide_next:
            out.append("[redacted]")
            hide_next = False
            continue
        flag, eq, _ = arg.partition("=")
        if _SECRET_FLAG.fullmatch(flag):
            if eq:
                out.append(f"{flag}=[redacted]")
            else:
                out.append(arg)
                hide_next = True
            continue
        out.append(_redact(arg))
    return " ".join([command, *out]).strip()


def _package_of(arg: str) -> tuple[str, bool]:
    """(package name without version, whether a version is pinned) for a runner argument."""
    if arg.startswith("@"):
        scope, _, rest = arg.partition("/")
        name, at, version = rest.partition("@")
        return f"{scope}/{name}", bool(at and version and version != "latest")
    for sep in ("==", "@"):
        if sep in arg:
            name, _, version = arg.partition(sep)
            return name, bool(version and version != "latest")
    return arg, False


def review_server(name: str, spec: dict) -> ServerReview:
    command = str(spec.get("command") or "")
    args = [str(a) for a in spec.get("args") or [] if isinstance(a, (str, int, float))]
    env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
    headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
    url = str(spec.get("url") or spec.get("serverUrl") or "")
    findings: list[Finding] = []
    packages: list[str] = []

    # Secrets written into the config in plain text. Name the key, never the value.
    for where, table in (("env", env), ("headers", headers)):
        for key, value in table.items():
            value = str(value)
            if _INDIRECT.match(value.strip()):
                continue
            if (
                _SECRET_VALUE.search(value)
                or _URL_PASSWORD.search(value)
                or (_SECRET_KEY.search(str(key)) and len(value) >= 8)
            ):
                findings.append(Finding(
                    "high", "plaintext-secret",
                    f"{where}.{key} holds what looks like a credential in plain text. Load it from the OS "
                    "keychain, a secret manager or an environment variable set outside this file, and "
                    "rotate it if this file was ever shared or synced.",
                ))
    for i, arg in enumerate(args):
        literal_after_flag = (
            _SECRET_FLAG.fullmatch(arg) is not None
            and i + 1 < len(args)
            and not args[i + 1].startswith(("-", "$"))
        )
        if _URL_PASSWORD.search(arg):
            findings.append(Finding(
                "high", "password-in-connection-string",
                f"args[{i}] is a connection string with the password written into it. Give the server a "
                "least-privilege (ideally read-only) account and supply the password through the environment.",
            ))
        elif _SECRET_VALUE.search(arg) or _SECRET_FLAG_VALUE.search(arg) or literal_after_flag:
            findings.append(Finding(
                "high", "secret-in-args",
                f"args[{i}] passes what looks like a credential on the command line, where other local processes "
                "(e.g. `ps`) and logs can see it. Pass it through the environment instead.",
            ))

    base = command.rsplit("/", 1)[-1].lower()
    if base in _RUNNERS:
        positional = [a for a in args if not a.startswith("-") and a not in {"dlx", "exec", "run", "x", "tool"}]
        if positional:
            package, pinned = _package_of(positional[0])
            packages.append(package)
            if not pinned:
                findings.append(Finding(
                    "medium", "unpinned-package",
                    f"`{base}` fetches {package} at its latest version on each start, so a compromised or "
                    "hijacked release runs without review. Pin an exact version you have reviewed.",
                ))
        if base in {"npx", "bunx", "pnpx"} and any(a in {"-y", "--yes"} for a in args):
            findings.append(Finding(
                "low", "auto-install",
                "`-y` installs the package without a prompt; combined with an unpinned version, there's no point at "
                "which you see what code is about to run.",
            ))
    elif base in _SHELLS and any(a in {"-c", "/c", "-Command", "-command"} for a in args):
        findings.append(Finding(
            "medium", "shell-wrapper",
            "The server is started through a shell command string, which hides what actually runs and makes "
            "injection through interpolated values possible. Call the program directly with an args list.",
        ))
    elif base in {"docker", "podman"}:
        joined = " ".join(args)
        if "--privileged" in args:
            findings.append(Finding("high", "privileged-container",
                                    "The container runs with --privileged, which gives it near-host access."))
        if re.search(r"--network[= ]host|--net[= ]host", joined):
            findings.append(Finding("medium", "host-network",
                                    "--network host lets the container reach every local service, including ones "
                                    "bound to localhost."))
        if "docker.sock" in joined:
            findings.append(Finding("high", "docker-socket",
                                    "The Docker socket is mounted into the container, which is equivalent to root "
                                    "on the host."))
        for mount in re.findall(r"(?:-v|--volume|--mount)[= ](\S+)", joined):
            source = mount.split(":")[0].removeprefix("type=bind,source=").removeprefix("source=")
            if source.rstrip("/") in {p.rstrip("/") for p in _BROAD_PATHS} or source in _BROAD_PATHS:
                findings.append(Finding("high", "broad-mount",
                                        f"A broad host path ({source}) is mounted into the container."))
        image = next((a for a in reversed(args) if not a.startswith("-") and ("/" in a or ":" in a)), "")
        if image:
            packages.append(image.split("@")[0].rsplit(":", 1)[0] if "@sha256" not in image else image.split("@")[0])
            if "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                findings.append(Finding("medium", "unpinned-image",
                                        f"Image {image} isn't pinned to a version or digest."))

    if "filesystem" in (name + " " + " ".join(args)).lower():
        broad = [a for a in args if a in _BROAD_PATHS or a.rstrip("/") in {"/home", "/Users"}]
        if broad:
            findings.append(Finding(
                "medium", "broad-filesystem-access",
                f"The filesystem server is given {', '.join(broad)}. Limit it to the project folders it needs; a "
                "broad root exposes SSH keys, browser profiles and other credentials to tool calls.",
            ))

    if url:
        if _URL_PASSWORD.search(url):
            findings.append(Finding("high", "secret-in-url", "The server URL has a password written into it."))
        if url.lower().startswith("http://") and not _LOCAL_HOSTS.match(url):
            findings.append(Finding(
                "high", "plaintext-transport",
                "This remote server is reached over plain HTTP, so requests, responses and any tokens can be read "
                "or changed in transit. Use https.",
            ))
        if re.search(r"[?&](token|key|api[_-]?key|access_token|secret)=", url, re.I):
            findings.append(Finding(
                "high", "secret-in-url",
                "The server URL carries a credential in its query string, which ends up in logs and history. "
                "Use an Authorization header or the client's OAuth flow.",
            ))
        packages.append(url.split("?")[0])

    launches = f"url {_redact(url.split('?')[0])}" if url else _redacted_command(command, args)
    return ServerReview(name=name, launches=launches[:300], packages=packages, findings=findings)


def catalog_matches(catalog: Catalog, package: str, limit: int = 5) -> list[Entry]:
    """Entries that name this package or link to it, CVE rows first. Exact names only, to avoid false alarms."""
    if package.startswith(("http://", "https://")):
        _, about, mentions = catalog.find_project(package, limit=limit)
        return (about + mentions)[:limit]
    if github_repo(package):
        about, mentions = catalog.lookup(package)
        return (about + mentions)[:limit]
    name = package.lower().rsplit("/", 1)[-1] if package.startswith("@") else package.lower()
    full = package.lower()
    if len(name) < 5:
        return []
    pattern = re.compile(rf"(?<![\w@/.-]){re.escape(full)}(?![\w-])" if full != name else
                         rf"(?<![\w.-]){re.escape(name)}(?![\w-])")
    hits = [e for e in catalog.entries.values() if pattern.search(e.text().lower())]
    hits.sort(key=lambda e: (e.topic != "cve", not e.cves, e.topic, e.line))
    return hits[:limit]


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def review_config(text: str, catalog: Catalog) -> dict[str, Any]:
    servers = parse_servers(text)
    out = []
    for name, spec in servers.items():
        review = review_server(str(name)[:100], spec)
        seen: set[str] = set()
        matches = []
        for package in review.packages:
            for entry in catalog_matches(catalog, package):
                if entry.id not in seen:
                    seen.add(entry.id)
                    matches.append(entry.to_brief())
        review.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
        out.append({
            "server": review.name,
            "launches": review.launches,
            "findings": [f.to_dict() for f in review.findings],
            "catalog": matches,
        })
    counts = {s: sum(f["severity"] == s for r in out for f in r["findings"]) for s in SEVERITY_ORDER}
    return {"servers": out, "summary": counts}
