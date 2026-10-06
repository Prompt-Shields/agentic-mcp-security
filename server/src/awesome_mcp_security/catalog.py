"""Parse the list's topic pages into structured, searchable entries.

The pages are hand-written Markdown: mostly tables, plus some bulleted lists and
bare link lines. Links are either inline (`[text](url)`) or reference-style
(`[text][ref]` with `[ref]: url` at the bottom of the page). Badge images
(`![](https://badgen.net/...)`) carry no text but name the GitHub repo.
"""

from __future__ import annotations

import html
import logging
import math
import re
import time
from collections import Counter
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
_GITHUB_REPO = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)", re.IGNORECASE)
_BARE_REPO = re.compile(r"^([\w.-]+)/([\w.-]+)$")
# github.com/<first segment> values that are site pages, not repository owners.
_GITHUB_NON_OWNERS = {"orgs", "apps", "topics", "search", "features", "marketplace", "sponsors", "settings", "advisories"}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")


SUMMARY_CHARS = 300
TITLE_CHARS = 160


def trim(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


@dataclass
class Entry:
    id: str
    topic: str
    section: str
    title: str
    url: str | None
    fields: dict[str, str]
    github_repo: str | None = None
    links: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    line: int = 0

    def text(self) -> str:
        return " ".join([self.title, self.section, *self.fields.values()])

    def summary(self) -> str:
        return " · ".join(self.fields.values())

    def to_brief(self, max_chars: int = SUMMARY_CHARS) -> dict:
        """The compact form for result lists: what is needed to choose an entry and cite it."""
        brief = {
            "id": self.id,
            "title": trim(self.title, TITLE_CHARS),
            "url": self.url,
            "where": f"{self.topic} > {self.section}" if self.section else self.topic,
            "summary": trim(self.summary(), max_chars),
        }
        if self.github_repo:
            brief["github_repo"] = self.github_repo
        if self.cves:
            brief["cves"] = self.cves
        return {k: v for k, v in brief.items() if v}

    def to_dict(self) -> dict:
        """The full record, for get_entry."""
        return {
            "id": self.id,
            "topic": self.topic,
            "section": self.section,
            "title": self.title,
            "url": self.url,
            "fields": self.fields,
            "github_repo": self.github_repo,
            "links": self.links,
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


def github_repo(url: str) -> str | None:
    """`owner/repo` (lower-cased) for a GitHub repository URL or bare `owner/repo`, else None."""
    url = url.strip()
    m = _GITHUB_REPO.match(url) or (None if "://" in url or "." in url.split("/")[0] else _BARE_REPO.match(url))
    if not m or m.group(1).lower() in _GITHUB_NON_OWNERS:
        return None
    return f"{m.group(1)}/{m.group(2).removesuffix('.git')}".lower()


def normalize_url(url: str) -> str:
    """Scheme-, www-, query- and trailing-slash-insensitive form of a URL, for comparison."""
    url = re.sub(r"^[a-z]+://", "", url.strip().lower())
    url = re.sub(r"^www\.", "", url)
    return re.split(r"[?#]", url, maxsplit=1)[0].rstrip("/")


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


def _all_links(text: str, refs: dict[str, str]) -> list[str]:
    links = []
    for m in _LINK.finditer(text):
        url = m.group(2) or refs.get((m.group(3) or "").lower())
        if url and url not in links:
            links.append(url)
    return links


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
        badge = _BADGE_REPO.search(raw)
        repo = badge.group(1) if badge else (github_repo(url) if url else None)
        links = _all_links(raw, refs)
        cves = sorted({c.upper() for c in _CVE.findall(raw)})
        entries.append(
            Entry(
                id=f"{slug}:{len(entries) + 1}",
                topic=slug,
                section=section(),
                title=row_title,
                url=url,
                fields=fields,
                github_repo=repo,
                links=links,
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


# Words that carry no meaning in a search over this list.
_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it of on or that the this to "
    "what when where which who why with about any are some me my you your".split()
)
TITLE_WEIGHT = 3  # a title word counts as this many body words
_BM25_K1, _BM25_B = 1.2, 0.75


def stem(word: str) -> str:
    """Very light stemming, so "scanners", "scanning" and "scanner" meet."""
    if word.isdigit() or len(word) <= 3:
        return word
    for suffix, keep in (("ies", "y"), ("ing", ""), ("ers", "er"), ("ed", ""), ("es", "e"), ("s", "")):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3 and not word.endswith("ss"):
            return word[: -len(suffix)] + keep
    return word


def tokenize(text: str) -> list[str]:
    """Search terms: lower-cased stems, with hyphenated words also split into their parts."""
    terms = []
    for word in _WORD.findall(text.lower()):
        parts = [word, *re.split(r"[-.]", word)] if re.search(r"[-.]", word) else [word]
        terms.extend(stem(w) for w in parts if w and w not in _STOPWORDS)
    return terms


class Catalog:
    def __init__(self, content_dir: Path):
        self.content_dir = content_dir
        paths = sorted(content_dir.glob(TOPIC_GLOB))
        if not paths:
            raise FileNotFoundError(f"no {TOPIC_GLOB} topic pages in {content_dir}")
        self.topics = {slug_for(p): parse_topic(p) for p in paths}
        self.entries = {e.id: e for t in self.topics.values() for e in t.entries}
        # BM25 index: per-entry term counts (title words weighted up), lengths and document frequencies.
        self._tf: dict[str, Counter[str]] = {}
        for eid, e in self.entries.items():
            tf = Counter(tokenize(e.text()))
            for term in tokenize(e.title):
                tf[term] += TITLE_WEIGHT - 1
            self._tf[eid] = tf
        self._len = {eid: sum(tf.values()) for eid, tf in self._tf.items()}
        self._avg_len = sum(self._len.values()) / max(len(self._len), 1)
        self._df: Counter[str] = Counter(term for tf in self._tf.values() for term in tf)

    def search(
        self, query: str, topic: str | None = None, section: str | None = None, limit: int = 10
    ) -> list[Entry]:
        """BM25-ranked entries matching any of the query's terms; more matched terms rank higher."""
        terms = list(dict.fromkeys(tokenize(query)))
        if not terms:
            return []
        n = len(self._tf)
        idf = {t: math.log(1 + (n - self._df[t] + 0.5) / (self._df[t] + 0.5)) for t in terms}
        section = section.lower() if section else None
        scored = []
        for eid, tf in self._tf.items():
            entry = self.entries[eid]
            if topic and entry.topic != topic:
                continue
            if section and section not in entry.section.lower():
                continue
            matched = [t for t in terms if tf[t]]
            if not matched:
                continue
            norm = _BM25_K1 * (1 - _BM25_B + _BM25_B * self._len[eid] / self._avg_len)
            score = sum(idf[t] * tf[t] * (_BM25_K1 + 1) / (tf[t] + norm) for t in matched)
            # Prefer entries covering more of the query over ones that repeat a single word.
            score *= (len(matched) / len(terms)) ** 2
            if not entry.url:
                score *= 0.5  # link-less rows are cross-references to entries listed elsewhere
            scored.append((score, eid))
        scored.sort(key=lambda s: (-s[0], self.entries[s[1]].line, s[1]))
        results, seen = [], set()
        for _, eid in scored:
            entry = self.entries[eid]
            key = normalize_url(entry.url) if entry.url else eid
            if key in seen:
                continue  # pages list some projects in several sections; keep the best-ranked one
            if not entry.url:
                # A link-less "X (see ... above)" row adds nothing once X itself is in the results.
                stem_title = re.split(r"\s*\(see\b", entry.title, maxsplit=1, flags=re.IGNORECASE)[0].lower()
                if any(r.title.lower().startswith(stem_title) for r in results):
                    continue
            seen.add(key)
            results.append(entry)
            if len(results) == limit:
                break
        return results

    def section_text(self, slug: str, heading: str) -> str:
        """The Markdown under `heading` on a topic page, up to the next heading of the same or higher level."""
        lines = self.topics[slug].path.read_text(encoding="utf-8").splitlines()
        out: list[str] = []
        level = None
        for line in lines:
            h = _HEADING.match(line)
            if level is None:
                if h and clean(h.group(2)).lower() == heading.lower():
                    level = len(h.group(1))
                continue
            if h and len(h.group(1)) <= level:
                break
            if not _REF_DEF.match(line):
                out.append(line)
        if level is None:
            raise KeyError(f"no heading {heading!r} in {slug}")
        return "\n".join(out).strip().removesuffix("---").strip()

    def lookup(self, project: str) -> tuple[list[Entry], list[Entry]]:
        """Entries about a project (its main link), and entries that only link to it.

        `project` is a GitHub repo (`owner/repo` or any URL inside it) or any other URL.
        """
        repo = github_repo(project)
        target = normalize_url(project)

        def matches(url: str) -> bool:
            if repo:
                return github_repo(url) == repo
            u = normalize_url(url)
            return u == target or u.startswith(target + "/")

        about, mentions = [], []
        for e in self.entries.values():
            if (e.url and matches(e.url)) or (repo and (e.github_repo or "").lower() == repo):
                about.append(e)
            elif any(matches(link) for link in e.links):
                mentions.append(e)
        return about, mentions

    def by_cve(self, cve_id: str) -> list[Entry]:
        cve_id = cve_id.upper()
        return [e for e in self.entries.values() if cve_id in e.cves]


logger = logging.getLogger(__name__)


class LiveCatalog:
    """A Catalog that reloads itself when topic pages are edited, added or removed.

    Pages are checked at most every `interval` seconds, on access. If a reload
    fails (say, a page is caught half-written), the previous catalog is kept
    and the reload is retried on a later access.
    """

    def __init__(self, content_dir: Path, interval: float = 2.0, clock=time.monotonic):
        self.content_dir = content_dir
        self.interval = interval
        self._clock = clock
        self._catalog = Catalog(content_dir)
        self._stamp = self._fingerprint()
        self._checked = clock()

    def _fingerprint(self) -> tuple:
        stamp = []
        for p in sorted(self.content_dir.glob(TOPIC_GLOB)):
            st = p.stat()
            stamp.append((p.name, st.st_mtime_ns, st.st_size))
        return tuple(stamp)

    def get(self) -> Catalog:
        now = self._clock()
        if now - self._checked < self.interval:
            return self._catalog
        self._checked = now
        try:
            stamp = self._fingerprint()
            if stamp != self._stamp:
                self._catalog = Catalog(self.content_dir)
                self._stamp = stamp
                logger.info("reloaded %d topic pages from %s", len(self._catalog.topics), self.content_dir)
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("keeping the previous catalog; reload failed: %s", exc)
        return self._catalog
