"""Review an MCP client config (claude_desktop_config.json, .mcp.json, ...) for risky settings.

Pure functions over the pasted text: nothing is executed, installed, fetched or
read from disk. Secret values are never returned; findings name the key only.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from .catalog import Catalog, Entry, github_repo

MAX_CONFIG_CHARS = 200_000
MAX_SERVERS = 50

_SECRET_WORDS = r"(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?token)"
# Names that point *at* a secret rather than holding one: --token-file, API_KEY_PATH, AUTH_PROVIDER.
_POINTER_SUFFIX = r"(?:[_-](?:file|path|dir|env|name|id|url|provider|method|type|mode|header))"
# An env var or header name that holds a secret.
_SECRET_KEY = re.compile(
    rf"^(?!.*{_POINTER_SUFFIX}$).*(?:{_SECRET_WORDS}|authorization|cookie|(?:^|[_-])auth(?:$|[_-]))", re.I
)
# A command-line flag named for a secret: --api-key, --password (not --token-file).
_SECRET_FLAG = re.compile(rf"--?(?![\w-]*{_POINTER_SUFFIX}$)[\w-]*{_SECRET_WORDS}[\w-]*", re.I)
# "--api-key VALUE" / "--token=VALUE" inside a string (a shell command line, say).
_SECRET_FLAG_VALUE = re.compile(
    rf"(--?(?![\w-]*{_POINTER_SUFFIX}[=\s])[\w-]*{_SECRET_WORDS}[\w-]*)(=|\s+)(?![$-])(\S+)", re.I
)
# Shapes of common live credentials, matched in any value.
_SECRET_VALUE = re.compile(
    r"(ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"
    r"|sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
# A password in a URL's userinfo, user optional: postgresql://u:pw@h, redis://:pw@h. "$VAR" is fine.
_URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:@/]*:)((?![$\d]+(?:/|$))(?!\$)[^\s@?#]+)(@)", re.I)
# An HTTP auth header written into a string: "Authorization: Bearer abc", "X-API-Key: abc".
_HEADER_SECRET = re.compile(
    r"((?:proxy-)?authorization\s*:\s*(?:(?:bearer|basic|token|apikey)\s+)?|"
    r"(?:x-[\w-]*(?:key|token|secret)|api[_-]?key|cookie)\s*:\s*)"
    r"(?!(?:bearer|basic|token|apikey)\b)((?![$%{])[^\s\"']+)",
    re.I,
)
# NAME=value with a secret-named NAME anywhere in a string (a shell script's env prefix, say).
_ASSIGNMENT_SECRET = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:token|secret|passw(?:or)?d|api_?key|access_?key|private_?key|credential)s?"
    r"[A-Za-z0-9_]*)=(?![$%{])([^\s\"']+)",
    re.I,
)
# A reference to the environment or a secret store, not a literal secret.
_INDIRECT = re.compile(
    r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{(?:input|env|config):[^}]+\}$|^\{\{.*\}\}$|^op://|^<.*>$"
    r"|^%[A-Za-z_]+%$|^$"
)
_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm", "bun"}
_SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"}
_SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-c:"}
_RUNNER_SUBCOMMANDS = {"dlx", "exec", "run", "x", "tool"}
# Runner flags that name the package to fetch, and flags that just take a value.
_PACKAGE_FLAGS = {
    "npx": {"-p", "--package"}, "pnpx": {"-p", "--package"}, "bunx": {"-p", "--package"},
    "pnpm": {"--package"}, "yarn": {"-p", "--package"}, "uvx": {"--from"}, "pipx": {"--spec"},
}
_VALUE_FLAGS = {"--python", "-p", "--with", "--index-url", "--extra-index-url", "--index", "--registry", "--cache",
                "--prefix", "--python-preference", "--userconfig", "-c", "--call", "--pip-args"}
# A local script or path rather than a package name: bun run ./srv.ts, npx /abs/server.js.
_LOCAL_TARGET = re.compile(r"^(?:\.{0,2}/|[A-Za-z]:[\\/]|~/)|[\\]|\.(?:m?[jt]s|cjs|py|sh)$", re.I)
_DOCKER_VALUE_FLAGS = {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "--network", "--net", "-p",
                       "--publish", "--name", "-w", "--workdir", "-u", "--user", "--entrypoint", "-l", "--label",
                       "--platform", "--add-host", "--cap-add", "--cap-drop", "--device", "-m", "--memory", "--cpus",
                       "--pull", "--restart", "--hostname", "-h", "--dns", "--ipc", "--pid", "--security-opt",
                       "--tmpfs", "--ulimit", "--runtime", "--gpus", "--log-driver", "--log-opt", "--shm-size",
                       "-a", "--attach", "--cidfile", "--sysctl", "--group-add", "--link", "--volumes-from",
                       "--expose", "--health-cmd", "--health-interval", "--health-retries", "--health-timeout",
                       "--stop-signal", "--stop-timeout", "--oom-score-adj", "--cgroupns", "--cgroup-parent",
                       "--userns", "--uts", "--isolation", "--storage-opt", "--label-file", "--mac-address",
                       "--ip", "--ip6", "--network-alias", "--dns-search", "--dns-option", "--device-cgroup-rule",
                       "--blkio-weight", "--cpu-shares", "-c", "--cpuset-cpus", "--cpuset-mems", "--memory-swap",
                       "--memory-reservation", "--pids-limit", "--domainname", "--annotation"}
_LOCAL_HOSTS = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", re.I)
# A filesystem root or a whole home directory, on any OS.
_BROAD_PATH = re.compile(
    r"^(?:/|~|~/|\$\{?HOME\}?|%USERPROFILE%|/root|/home(?:/[^/]+)?|/Users(?:/[^/]+)?|/var/home/[^/]+"
    r"|[A-Za-z]:[\\/]?|[A-Za-z]:[\\/]Users(?:[\\/][^\\/]+)?)[\\/]?$",
    re.I,
)


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


def _strip_jsonc(text: str) -> str:
    """Drop // and /* */ comments and trailing commas, as in VS Code settings, leaving strings intact."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue  # trailing comma
            out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def parse_servers(text: str) -> dict[str, dict]:
    """The server table from a client config: {"mcpServers": {...}}, {"servers": {...}} or the table itself."""
    if len(text) > MAX_CONFIG_CHARS:
        raise ValueError(f"config is over {MAX_CONFIG_CHARS} characters; paste just the MCP servers section")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = json.loads(_strip_jsonc(text))  # VS Code and Cursor allow comments
        except json.JSONDecodeError as exc:
            # Stripping keeps every newline, so the line number matches what the user pasted.
            raise ValueError(f"not valid JSON (line {exc.lineno}): {exc.msg}") from None
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
    """Remove every credential-shaped part of a string that will be echoed back."""
    value = _SECRET_VALUE.sub("[redacted]", value)
    value = _URL_PASSWORD.sub(lambda m: f"{m.group(1)}[redacted]{m.group(3)}", value)
    value = _HEADER_SECRET.sub(lambda m: f"{m.group(1)}[redacted]", value)
    value = _ASSIGNMENT_SECRET.sub(lambda m: f"{m.group(1)}=[redacted]", value)
    return _SECRET_FLAG_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", value)


def _is_secret_assignment(text: str) -> bool:
    """NAME=value with a secret-named NAME or a credential-shaped value (docker -e, env strings)."""
    name, eq, value = text.partition("=")
    if not eq or _INDIRECT.match(value.strip()):
        return False
    return bool(_SECRET_VALUE.search(value) or _URL_PASSWORD.search(value)
                or (_SECRET_KEY.search(name) and len(value) >= 8))


def _program(command: str) -> str:
    """The bare program name: /usr/bin/npx, C:\\...\\npx.cmd and npx.exe are all "npx"."""
    base = re.split(r"[\\/]", command.strip())[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        base = base.removesuffix(suffix)
    return base


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


def _runner_package(runner: str, args: list[str]) -> str | None:
    """The package a runner (npx, uvx, ...) fetches, skipping its own flags and their values.

    None when it runs a local file (bun run ./srv.ts) rather than fetching a package.
    """
    explicit, i = None, 0
    package_flags = _PACKAGE_FLAGS.get(runner, set())
    while i < len(args):
        arg = args[i]
        flag, eq, value = arg.partition("=")
        if flag in package_flags:
            explicit = value if eq else (args[i + 1] if i + 1 < len(args) else None)
            i += 1 if eq else 2
            continue
        if flag in _VALUE_FLAGS:
            i += 1 if eq else 2
            continue
        if arg.startswith("-") or arg in _RUNNER_SUBCOMMANDS:
            i += 1
            continue
        if explicit:
            return explicit
        return None if _LOCAL_TARGET.search(arg) and not arg.startswith("@") else arg
    return explicit


def _mount_source(value: str, long_form: bool) -> str:
    if long_form:  # --mount type=bind,src=/,dst=/data
        fields = dict(p.split("=", 1) for p in value.split(",") if "=" in p)
        return fields.get("source") or fields.get("src") or ""
    m = re.match(r"([A-Za-z]:[\\/][^:]*|[^:]*)", value)  # -v SRC:DST[:opts], SRC may be C:\...
    return m.group(1) if m else value


def _review_docker(args: list[str], findings: list[Finding], packages: list[str]) -> None:
    joined = " ".join(args)
    if "--privileged" in args:
        findings.append(Finding("high", "privileged-container",
                                "The container runs with --privileged, which gives it near-host access."))
    if re.search(r"--(?:network|net)[= ]host\b", joined):
        findings.append(Finding("medium", "host-network",
                                "--network host lets the container reach every local service, including ones "
                                "bound to localhost."))
    if "docker.sock" in joined:
        findings.append(Finding("high", "docker-socket",
                                "The Docker socket is mounted into the container, which is equivalent to root "
                                "on the host."))
    run = next((i for i, a in enumerate(args) if a in {"run", "create"}), None)
    i, image = (run + 1 if run is not None else 0), ""
    while i < len(args):
        flag, eq, value = args[i].partition("=")
        if flag in _DOCKER_VALUE_FLAGS:
            value = value if eq else (args[i + 1] if i + 1 < len(args) else "")
            if flag in {"-v", "--volume", "--mount"}:
                source = _mount_source(value, flag == "--mount")
                if source and _BROAD_PATH.match(source):
                    findings.append(Finding("high", "broad-mount",
                                            f"A broad host path ({source}) is mounted into the container."))
            if flag in {"-e", "--env"} and _is_secret_assignment(value):
                findings.append(Finding(
                    "high", "secret-in-args",
                    f"The container is given {value.partition('=')[0]} as a literal `-e` value, which shows in "
                    "`docker inspect`, `ps` and logs. Use `-e NAME` to pass it through from the environment.",
                ))
            i += 1 if eq else 2
            continue
        if args[i].startswith("-") or re.fullmatch(r"\d+(?:\.\d+)?[bkmgt]?", args[i], re.I):
            i += 1  # a flag, or the value of a flag not in the list above (sizes, counts)
            continue
        image = args[i]
        break
    if image:
        packages.append(image.split("@")[0].rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else
                        image.split("@")[0])
        last = image.split("@")[0].rsplit("/", 1)[-1]
        if "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
            findings.append(Finding("medium", "unpinned-image", f"Image {image} isn't pinned to a version or digest."))


def _review_command(command: str, args: list[str], findings: list[Finding], packages: list[str],
                    depth: int = 0) -> str:
    """Review a command line; return it redacted. Shell wrappers are unwrapped and the inner command reviewed."""
    base = _program(command)
    flag_at = next((i for i, a in enumerate(args) if a.lower() in _SHELL_FLAGS), None)
    if base in _SHELLS and flag_at is not None:
        findings.append(Finding(
            "medium", "shell-wrapper",
            "The server is started through a shell, which hides what actually runs and makes injection through "
            "interpolated values possible. Call the program directly with an args list.",
        ))
        inner = args[flag_at + 1:]
        if base in {"cmd", "powershell", "pwsh"} and len(inner) > 1:
            pass  # cmd /c npx -y pkg: the remaining args are already the command line
        elif inner and (len(inner) == 1 or re.search(r"\s", inner[0])):
            # sh -c 'script' [$0 args...]: the script is one string; what follows are its arguments.
            try:
                inner = shlex.split(inner[0], posix=base not in {"cmd", "powershell", "pwsh"})
            except ValueError:
                inner = inner[0].split()
        # Leading NAME=value words set the environment for the command that follows.
        while inner and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", inner[0]):
            if _is_secret_assignment(inner[0]):
                findings.append(Finding(
                    "high", "secret-in-args",
                    f"The shell command sets {inner[0].partition('=')[0]} to a literal value, which is visible to "
                    "other local processes and logs. Set it outside this file instead.",
                ))
            inner = inner[1:]
        prefix = _redact(" ".join([command, *args[: flag_at + 1]]))
        if inner and depth < 2:
            return f"{prefix} " + _review_command(inner[0], inner[1:], findings, packages, depth + 1)
        return _redact(" ".join([prefix, *inner]))

    for i, arg in enumerate(args):
        literal_after_flag = (_SECRET_FLAG.fullmatch(arg) is not None and i + 1 < len(args)
                              and not args[i + 1].startswith(("-", "$", "%")))
        if _URL_PASSWORD.search(arg):
            findings.append(Finding(
                "high", "password-in-connection-string",
                f"Argument {i + 1} of `{base}` is a connection string with the password written into it. Give the "
                "server a least-privilege (ideally read-only) account and supply the password through the "
                "environment.",
            ))
        elif (_SECRET_VALUE.search(arg) or _SECRET_FLAG_VALUE.search(arg) or _HEADER_SECRET.search(arg)
              or literal_after_flag):
            findings.append(Finding(
                "high", "secret-in-args",
                f"Argument {i + 1} of `{base}` passes what looks like a credential on the command line, where "
                "other local processes (e.g. `ps`) and logs can see it. Pass it through the environment instead.",
            ))

    if base in _RUNNERS:
        package = _runner_package(base, args)
        if package:
            name, pinned = _package_of(package)
            packages.append(name)
            if not pinned:
                findings.append(Finding(
                    "medium", "unpinned-package",
                    f"`{base}` fetches {name} at its latest version on each start, so a compromised or "
                    "hijacked release runs without review. Pin an exact version you have reviewed.",
                ))
        if base in {"npx", "bunx", "pnpx"} and any(a in {"-y", "--yes"} for a in args):
            findings.append(Finding(
                "low", "auto-install",
                "`-y` installs the package without a prompt; combined with an unpinned version, there's no point at "
                "which you see what code is about to run.",
            ))
    elif base in {"docker", "podman"}:
        _review_docker(args, findings, packages)

    if any("filesystem" in p.lower() for p in packages) or "filesystem" in " ".join(args).lower():
        broad = [a for a in args if _BROAD_PATH.match(a)]
        if broad:
            findings.append(Finding(
                "medium", "broad-filesystem-access",
                f"The filesystem server is given {', '.join(broad)}. Limit it to the project folders it needs; a "
                "root or home directory exposes SSH keys, browser profiles and other credentials to tool calls.",
            ))

    out, hide_next = [], False
    for arg in args:
        if hide_next:
            out.append("[redacted]")
            hide_next = False
            continue
        flag, eq, rest = arg.partition("=")
        if _SECRET_FLAG.fullmatch(flag):
            out.append(f"{flag}=[redacted]" if eq else arg)
            hide_next = not eq
            continue
        if flag in {"-e", "--env"} and eq and _is_secret_assignment(rest):
            out.append(f"{flag}={rest.partition('=')[0]}=[redacted]")
            continue
        if _is_secret_assignment(arg):
            out.append(f"{flag}=[redacted]")
            continue
        out.append(_redact(arg))
    return _redact(" ".join([command, *out]).strip())


def review_server(name: str, spec: dict) -> ServerReview:
    command = str(spec.get("command") or "")
    raw_args = spec.get("args")
    if isinstance(raw_args, str):
        raw_args = [raw_args]
    args = [str(a) for a in raw_args if isinstance(a, (str, int, float))] if isinstance(raw_args, list) else []
    env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
    headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
    url = str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or "")
    findings: list[Finding] = []
    packages: list[str] = []

    # Secrets written into the config in plain text. Name the key, never the value.
    for where, table in (("env", env), ("headers", headers)):
        for key, value in table.items():
            value = str(value)
            # "Bearer ${TOKEN}" is a reference too: look past an auth scheme word.
            core = re.sub(r"^(?:bearer|basic|token|apikey)\s+", "", value.strip(), flags=re.I)
            if _INDIRECT.match(core):
                continue
            if (_SECRET_VALUE.search(value) or _URL_PASSWORD.search(value) or _HEADER_SECRET.search(f"{key}: {value}")
                    or (_SECRET_KEY.search(str(key)) and len(value) >= 8)):
                findings.append(Finding(
                    "high", "plaintext-secret",
                    f"{where}.{key} holds what looks like a credential in plain text. Load it from the OS "
                    "keychain, a secret manager or an environment variable set outside this file, and "
                    "rotate it if this file was ever shared or synced.",
                ))

    launches = _review_command(command, args, findings, packages) if command else ""

    if url:
        bare = re.split(r"[?#]", url, maxsplit=1)[0]
        query = url[len(bare):]
        if _URL_PASSWORD.search(url):
            findings.append(Finding("high", "secret-in-url", "The server URL has a password written into it."))
        names = re.findall(r"[?&#;]([\w.-]+)=", query)
        secret_param = re.compile(
            r"(?:^|[_.-])(?:token|key|secret|signature|sig|auth|password|pass|apikey|api[_-]key|code)(?:$|[_.-])"
            r"|^(?:access|refresh|id)_?token$", re.I,
        )
        if any(secret_param.search(name) for name in names):
            findings.append(Finding(
                "high", "secret-in-url",
                "The server URL carries a credential in its query string or fragment, which ends up in logs and "
                "history. Use an Authorization header or the client's OAuth flow.",
            ))
        if url.lower().startswith("http://") and not _LOCAL_HOSTS.match(url):
            findings.append(Finding(
                "high", "plaintext-transport",
                "This remote server is reached over plain HTTP, so requests, responses and any tokens can be read "
                "or changed in transit. Use https.",
            ))
        packages.append(_URL_PASSWORD.sub(r"\1[redacted]\3", bare))
        launches = f"url {_redact(bare)}" + (f" ({launches})" if launches else "")

    # Backstop: whatever path built it, `launches` gets a last redaction pass before it leaves.
    return ServerReview(name=name, launches=_redact(launches)[:300], packages=packages, findings=findings)


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
