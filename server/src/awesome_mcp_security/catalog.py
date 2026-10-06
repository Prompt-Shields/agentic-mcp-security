"""Parse the list's topic pages into structured, searchable entries.

The pages are hand-written Markdown: mostly tables, plus some bulleted lists and
bare link lines. Links are either inline (`[text](url)`) or reference-style
(`[text][ref]` with `[ref]: url` at the bottom of the page). Badge images
(`![](https://badgen.net/...)`) carry no text but name the GitHub repo.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from pathlib import Path

TOPIC_GLOB = "mcp_*.md"

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_REF_DEF = re.compile(r"^\s*\[([^\]]+)\]:\s*(\S+)")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
# A link that is not an image; group 1 is the text, 2 an inline URL, 3 a ref label.
_LINK = re.compile(r"(?<!!)\[([^\]\[]+)\](?:\(([^)\s]+)[^)]*\)|\[([^\]]+)\])")
_BADGE_REPO = re.compile(r"badgen\.net/github/last-commit/([\w.-]+/[\w.-]+)")
_BULLET = re.compile(r"^\s*[-*+]\s+(.*)$")
_TABLE_SEPARATOR = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_HTML_CELL = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.IGNORECASE | re.DOTALL)
_HTML_LINK = re.compile(r'<a\s[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")


@dataclass
class Entry:
    id: str
    topic: str
    section: str
    title: str
    url: str | None
    fields: dict[str, str]
    github_repo: str | None = None
    cves: list[str] = field(default_factory=list)
    line: int = 0

    def text(self) -> str:
        return " ".join([self.title, self.section, *self.fields.values()])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "topic": self.topic,
            "section": self.section,
            "title": self.title,
            "url": self.url,
            "fields": self.fields,
            "github_repo": self.github_repo,
            "cves": self.cves,
            "source": f"{self.topic}:{self.line}",
        }


@dataclass
class Topic:
    slug: str
    title: str
    path: Path
    sections: list[str]
    entries: list[Entry]


def slug_for(path: Path) -> str:
    return path.stem.removeprefix("mcp_")


def clean(text: str) -> str:
    """Render inline Markdown as plain text."""
    text = _IMAGE.sub("", text)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = _LINK.sub(lambda m: m.group(1), text)
    text = re.sub(r"\[\]\[[^\]]*\]|\[\]\([^)]*\)", "", text)  # leftover badge wrappers
    text = re.sub(r"(\*\*|__|`)", "", text)
    text = text.replace("\\|", "|")
    return re.sub(r"\s+", " ", text).strip(" -–—:·")


def _first_link(text: str, refs: dict[str, str]) -> str | None:
    for m in _LINK.finditer(text):
        if m.group(1).startswith("!"):
            continue
        if m.group(2):
            return m.group(2)
        url = refs.get((m.group(3) or "").lower())
        if url:
            return url
    return None


def _html_to_markdown(cell: str) -> str:
    cell = _HTML_LINK.sub(lambda m: f"[{m.group(2)}]({m.group(1)})", cell)
    return html.unescape(re.sub(r"<[^>]+>", "", cell)).strip()


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)]


def parse_topic(path: Path) -> Topic:
    slug = slug_for(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    refs = {}
    for line in lines:
        m = _REF_DEF.match(line)
        if m:
            refs[m.group(1).lower()] = m.group(2)

    title: str | None = None
    headings: dict[int, str] = {}
    sections: list[str] = []
    entries: list[Entry] = []
    header: list[str] | None = None
    in_contents = False

    def section() -> str:
        return " > ".join(headings[k] for k in sorted(headings))

    def add(row_title: str, url: str | None, fields: dict[str, str], raw: str, lineno: int) -> None:
        if not row_title:
            return
        repo = _BADGE_REPO.search(raw)
        cves = sorted({c.upper() for c in _CVE.findall(raw)})
        entries.append(
            Entry(
                id=f"{slug}:{len(entries) + 1}",
                topic=slug,
                section=section(),
                title=row_title,
                url=url,
                fields=fields,
                github_repo=repo.group(1) if repo else None,
                cves=cves,
                line=lineno,
            )
        )

    for lineno, line in enumerate(lines, start=1):
        if _REF_DEF.match(line):
            continue
        h = _HEADING.match(line)
        if h:
            level, text = len(h.group(1)), clean(h.group(2))
            header = None
            if level == 1 and title is None:
                title = text  # the page title; later H1s (some pages have several) are sections
                continue
            headings = {k: v for k, v in headings.items() if k < level}
            headings[level] = text
            in_contents = text.lower() == "contents"
            if not in_contents and section() not in sections:
                sections.append(section())
            continue
        if in_contents:
            continue

        stripped = line.strip()
        html_cells = _HTML_CELL.findall(stripped) if stripped.lower().startswith("<tr") else []
        if stripped.startswith("|") or html_cells:
            if _TABLE_SEPARATOR.match(stripped):
                continue
            if html_cells:
                if "<th" in stripped.lower():
                    header = None
                cells = [_html_to_markdown(c) for c in html_cells]
                stripped = " | ".join(cells)
            else:
                cells = _split_row(stripped)
            if header is None:
                header = [clean(c) or f"column {i + 1}" for i, c in enumerate(cells)]
                continue
            fields = {}
            for name, cell in zip(header, cells):
                value = clean(cell)
                if value:
                    fields[name] = value
            # The first column naming a resource is the title (a leading date column is not).
            first = next((c for c in cells if _first_link(c, refs)), cells[0] if cells else "")
            url = _first_link(first, refs) or _first_link(stripped, refs)
            row_title = clean(first)
            fields = {k: v for k, v in fields.items() if v != row_title}
            add(row_title, url, fields, stripped, lineno)
            continue
        if not stripped.lower().startswith(("<", "</")):
            header = None

        b = _BULLET.match(line)
        body = b.group(1) if b else stripped
        if not b and not re.fullmatch(r"\[[^\]]+\](\([^)]+\)|\[[^\]]+\])", stripped):
            continue  # only bullets and bare link lines are entries outside tables
        url = _first_link(body, refs)
        if not url:
            continue
        m = _LINK.search(body)
        link_title = clean(m.group(1)) if m else clean(body)
        rest = clean(body[m.end():]) if m else ""
        add(link_title, url, {"Summary": rest} if rest else {}, body, lineno)

    return Topic(slug=slug, title=title or slug, path=path, sections=sections, entries=entries)


def tokenize(text: str) -> list[str]:
    return _WORD.findall(text.lower())


class Catalog:
    def __init__(self, content_dir: Path):
        self.content_dir = content_dir
        paths = sorted(content_dir.glob(TOPIC_GLOB))
        if not paths:
            raise FileNotFoundError(f"no {TOPIC_GLOB} topic pages in {content_dir}")
        self.topics = {slug_for(p): parse_topic(p) for p in paths}
        self.entries = {e.id: e for t in self.topics.values() for e in t.entries}
        self._index = {
            eid: (set(tokenize(e.title)), set(tokenize(e.text())), e.text().lower())
            for eid, e in self.entries.items()
        }

    def search(
        self, query: str, topic: str | None = None, section: str | None = None, limit: int = 10
    ) -> list[Entry]:
        terms = tokenize(query)
        if not terms:
            return []
        phrase = query.lower().strip()
        section = section.lower() if section else None
        scored = []
        for eid, (title_words, all_words, text) in self._index.items():
            entry = self.entries[eid]
            if topic and entry.topic != topic:
                continue
            if section and section not in entry.section.lower():
                continue
            score = 0
            for term in terms:
                if term in title_words:
                    score += 3
                elif term in all_words:
                    score += 1
                elif term in text:  # prefix / substring, e.g. "poison" in "poisoning"
                    score += 0.5
                else:
                    break
            else:
                if len(terms) > 1 and phrase in text:
                    score += 2
                scored.append((score, eid))
        scored.sort(key=lambda s: (-s[0], self.entries[s[1]].line, s[1]))
        return [self.entries[eid] for _, eid in scored[:limit]]

    def by_cve(self, cve_id: str) -> list[Entry]:
        cve_id = cve_id.upper()
        return [e for e in self.entries.values() if cve_id in e.cves]
