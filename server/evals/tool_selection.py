"""Does a real model reach for the right tool on its own?

Runs each task below through `claude -p` with only this server connected
(--strict-mcp-config), web search and local file tools switched off, and the
task worded the way a user would ask, without naming any tool. A case passes when
the first of this server's tools the model calls is one of the expected ones and the run finishes
without an error.

Needs the Claude Code CLI, signed in. Uses real model calls, so it is not part of
the pytest suite:

    cd server && uv run python evals/tool_selection.py [--model MODEL] [--only N ...]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
SERVER_NAME = "awesome-mcp-security"
TOOL_PREFIX = f"mcp__{SERVER_NAME}__"
# Everything that would let the model answer without this server.
DISALLOWED = "WebSearch,WebFetch,Bash,Read,Grep,Glob,Edit,Write,NotebookEdit,Agent,Task"


@dataclass
class Case:
    task: str
    # Tool names without the mcp__ prefix; the first call must be one of these.
    # An empty set means the task is off-topic and the model must not call the server at all.
    expected: set[str]


CASES = [
    Case(
        "I'm about to install the PortSwigger Burp Suite MCP server. What should I know about it from a "
        "security standpoint? Keep it to 5 bullets.",
        {"lookup_project"},
    ),
    Case("What's known about CVE-2025-6514, and where can I read the write-ups?", {"find_cve"}),
    Case(
        "I want to practise attacking MCP servers hands-on. Recommend two labs for tool poisoning and say why.",
        {"search"},
    ),
    Case("Which tools can scan my MCP server configs for tool poisoning? Give me three.", {"search"}),
    Case(
        "Is github.com/semgrep/mcp covered anywhere, and what does the coverage say about using it safely?",
        {"lookup_project"},
    ),
    Case("Write a two-line rhyme about autumn leaves.", set()),
]


@dataclass
class Outcome:
    case: Case
    tools: list[str]
    ok: bool
    answer: str
    error: str = ""

    @property
    def passed(self) -> bool:
        if not self.case.expected:
            return self.ok and not self.tools
        return self.ok and bool(self.tools) and self.tools[0] in self.case.expected


def run_case(case: Case, config: Path, model: str | None, timeout: int) -> Outcome:
    cmd = [
        "claude", "-p", case.task,
        "--mcp-config", str(config), "--strict-mcp-config",
        "--disallowedTools", DISALLOWED,
        "--allowedTools", f"mcp__{SERVER_NAME}",
        "--output-format", "stream-json", "--verbose",
    ]
    if model:
        cmd += ["--model", model]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, cwd=tempfile.gettempdir()
        )
    except subprocess.TimeoutExpired:
        return Outcome(case, [], False, "", f"timed out after {timeout}s")

    tools, answer, ok, error = [], "", False, ""
    for line in proc.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "assistant":
            for block in event["message"].get("content", []):
                # Count only this server's tools: the CLI may first call ToolSearch to load
                # tool schemas, which is plumbing rather than the model choosing a tool.
                if block.get("type") == "tool_use" and block["name"].startswith(TOOL_PREFIX):
                    tools.append(block["name"].removeprefix(TOOL_PREFIX))
        elif event.get("type") == "result":
            ok = event.get("subtype") == "success" and not event.get("is_error")
            answer = str(event.get("result") or "")
            if not ok:
                error = answer[:300]
    if not answer and proc.returncode:
        error = (proc.stderr or proc.stdout)[-300:]
    return Outcome(case, tools, ok, answer, error)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", help="Model to test (default: the CLI's default).")
    parser.add_argument("--only", type=int, nargs="*", help="Run only these case numbers (1-based).")
    parser.add_argument("--timeout", type=int, default=300, help="Seconds per case.")
    parser.add_argument("--show-answers", action="store_true")
    args = parser.parse_args()

    numbered = [(i, c) for i, c in enumerate(CASES, 1) if not args.only or i in args.only]
    cases = [c for _, c in numbered]
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "mcp.json"
        config.write_text(json.dumps({
            "mcpServers": {SERVER_NAME: {"command": "uv", "args": ["run", "--directory", str(SERVER_DIR), SERVER_NAME]}}
        }))
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda c: run_case(c, config, args.model, args.timeout), cases))

    for (i, _), o in zip(numbered, outcomes):
        mark = "PASS" if o.passed else "FAIL"
        print(f"{mark}  {i}. {o.case.task[:70]}")
        expected = " or ".join(sorted(o.case.expected)) or "no tool"
        print(f"      expected first tool: {expected}; called: {', '.join(o.tools) or 'none'}")
        if o.error:
            print(f"      error: {o.error}")
        if args.show_answers or not o.passed:
            print("      answer: " + o.answer[:600].replace("\n", "\n              "))
    passed = sum(o.passed for o in outcomes)
    print(f"\n{passed}/{len(outcomes)} passed")
    return 0 if passed == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
