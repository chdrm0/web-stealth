"""Document → text + links.

The plugin returns `WebFetchBody.kind = 'text'`, not `'html'`: `dsh-tool-web`
slices the body at its own fetchMaxOutputChars BEFORE rendering, so raw HTML
from a heavy page loses its tail before conversion even starts. Extracting here
keeps the budget on content.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

from bs4 import BeautifulSoup

log = logging.getLogger("fetchd.extract")

_DROP_TAGS = ("script", "style", "noscript", "svg", "template", "picture", "source", "iframe")
_DROP_SELECTORS = (
    "nav", "header", "footer", "aside", "form", "dialog",
    "[role=navigation]", "[role=banner]", "[role=contentinfo]", "[role=dialog]",
    ".cookie", ".cookie-banner", "#onetrust-consent-sdk",
)
_CONTENT_SELECTORS = ("article", "main", "[role=main]", "#content", ".content", "#main", ".main")
_BLOCK_TAGS = ("h1", "h2", "h3", "h4", "h5", "p", "li", "pre", "blockquote", "td", "th", "figcaption")


def strip_query(url: str) -> str:
    """Drop query and fragment — the same normalisation the existing tooling uses."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _pick_content_root(soup: BeautifulSoup):
    for selector in _CONTENT_SELECTORS:
        for node in soup.select(selector):
            if len(node.get_text(" ", strip=True)) > 400:
                return node
    return soup.body or soup


def collect_links(soup: BeautifulSoup, base_url: str, max_links: int) -> list[dict]:
    """Deduplicated absolute links, query-stripped, capped."""
    base = urlsplit(base_url)
    seen: dict[str, str] = {}
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.startswith(("javascript:", "mailto:", "#", "data:")):
            continue
        if href.startswith("//"):
            absolute = f"{base.scheme}:{href}"
        elif href.startswith(("http://", "https://")):
            absolute = href
        elif href.startswith("/"):
            absolute = urlunsplit((base.scheme, base.netloc, href, "", ""))
        else:
            absolute = urlunsplit((base.scheme, base.netloc, f"{base.path.rsplit('/', 1)[0]}/{href}", "", ""))
        key = strip_query(absolute)
        if not key.startswith(("http://", "https://")):
            continue
        text = " ".join(anchor.get_text(" ", strip=True).split())[:120]
        if key not in seen or (text and not seen[key]):
            seen[key] = text
        if len(seen) >= max_links:
            break
    return [{"url": url, "text": text} for url, text in seen.items()]


def extract(html: str, max_chars: int, base_url: str = "", max_links: int = 100) -> tuple[str, list[dict], bool]:
    """Return (text, links, truncated)."""
    text, links, truncated, _total = extract_measured(html, max_chars, base_url, max_links)
    return text, links, truncated


def extract_measured(
    html: str, max_chars: int, base_url: str = "", max_links: int = 100
) -> tuple[str, list[dict], bool, int]:
    """Return (text, links, truncated, total_chars): the length before the cut, too."""
    soup = BeautifulSoup(html, "html.parser")
    links = collect_links(soup, base_url, max_links) if base_url else []

    for tag in soup(_DROP_TAGS):
        tag.decompose()
    for selector in _DROP_SELECTORS:
        for node in soup.select(selector):
            node.decompose()

    root = _pick_content_root(soup)
    parts: list[str] = []
    seen_lines: set[str] = set()
    for block in root.find_all(_BLOCK_TAGS, recursive=True):
        text = " ".join(block.get_text(" ", strip=True).split())
        if len(text) < 2 or text in seen_lines:
            continue
        seen_lines.add(text)
        name = block.name
        if name in ("h1", "h2", "h3", "h4", "h5"):
            parts.append(f"{'#' * int(name[1])} {text}")
        elif name == "li":
            parts.append(f"- {text}")
        else:
            parts.append(text)

    body = "\n\n".join(parts) if parts else " ".join(root.get_text(" ", strip=True).split())
    truncated = len(body) > max_chars
    return body[:max_chars], links, truncated, len(body)


class PdfExtractionError(Exception):
    """The PDF cannot be parsed at all: corrupt, truncated, encrypted, page-less."""


class PdfPageRangeError(ValueError):
    """The `#page=` fragment asks for pages that cannot be served."""


@dataclass(frozen=True)
class PageRange:
    """1-based, inclusive. `end` is None for an open-ended `#page=N`."""

    start: int
    end: int | None

    def label(self) -> str:
        return f"{self.start}-{self.end}" if self.end is not None else str(self.start)


# `#page=N`, `#page=N-M`, `#page=N-` and a bare `#N` / `#N-M`. Anything else
# after `#` is an ordinary anchor and is ignored for a PDF, as a viewer would.
_PAGE_FRAGMENT = re.compile(r"^\s*(?:page\s*=\s*)?(\d+)\s*(?:-\s*(\d*))?\s*$", re.IGNORECASE)


def parse_page_fragment(fragment: str) -> PageRange | None:
    """`page=N-M` (or a bare `N`) -> PageRange; any other anchor -> None.

    A fragment that names `page=` but cannot be read is an error, not an anchor:
    the caller asked for a page and must hear why it did not get one.
    """
    fragment = unquote(fragment or "").strip()
    if not fragment:
        return None
    match = _PAGE_FRAGMENT.match(fragment)
    if match is None:
        if fragment.lower().startswith("page"):
            raise PdfPageRangeError(
                f"cannot read the page fragment #{fragment}; use #page=N or #page=N-M (1-based, inclusive)"
            )
        return None
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else None
    if start < 1:
        raise PdfPageRangeError(f"#{fragment}: page numbers start at 1")
    if end is not None and end < start:
        raise PdfPageRangeError(f"#{fragment}: the range ends (page {end}) before it starts (page {start})")
    return PageRange(start, end)


def extract_pdf(
    raw: bytes, max_chars: int, page_range: PageRange | None = None, max_range_pages: int = 50
) -> tuple[str, dict]:
    """PDF bytes -> (text, meta).

    meta: {pages, pagesParsed, pagesSkipped, pagesFailed, truncated, scanned,
    rangeRequested, rangeServed, firstPage, lastPage, cutInsideRange, nextFragment}.
    Only the requested pages are walked, one at a time, and the character cap
    cuts at or inside a page, so a shortened result names the page it stopped at
    and the exact fragment that continues it.
    """
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    if page_range is not None and page_range.end is not None:
        width = page_range.end - page_range.start + 1
        if width > max_range_pages:
            raise PdfPageRangeError(
                f"#page={page_range.label()} spans {width} pages; at most {max_range_pages} pages per request "
                f"(STEALTH_PDF_MAX_RANGE_PAGES={max_range_pages}). Ask for "
                f"#page={page_range.start}-{page_range.start + max_range_pages - 1} first."
            )

    try:
        reader = PdfReader(io.BytesIO(raw), strict=False)
        if reader.is_encrypted:
            # An empty owner password covers the common "permissions-only" case;
            # a real user password stays a named refusal, not an empty document.
            if not reader.decrypt(""):
                raise PdfExtractionError("PDF is password-protected; no password available")
        pages = len(reader.pages)
    except PdfReadError as error:
        raise PdfExtractionError(f"pypdf could not parse the PDF: {error}") from error
    except PdfExtractionError:
        raise
    except Exception as error:
        # pypdf raises bare OSError/ValueError on truncated xref tables.
        raise PdfExtractionError(f"PDF appears corrupt or truncated: {error}") from error

    if pages == 0:
        raise PdfExtractionError("PDF parsed but contains no pages")

    if page_range is None:
        first, last = 1, pages
        requested = None
    else:
        if page_range.start > pages:
            raise PdfPageRangeError(
                f"#page={page_range.label()} starts at page {page_range.start}, but this document has "
                f"{pages} page(s); ask for #page=1-{min(pages, max_range_pages)} or any start up to {pages}"
            )
        first = page_range.start
        wanted_end = page_range.end if page_range.end is not None else page_range.start + max_range_pages - 1
        last = min(wanted_end, pages)
        requested = f"{page_range.start}-{wanted_end}"

    chunks: list[str] = []
    used = 0
    parsed = 0
    failed = 0
    truncated = False
    cut_mid_page = False
    for number in range(first, last + 1):
        if used >= max_chars:
            truncated = True
            break
        try:
            page_text = (reader.pages[number - 1].extract_text() or "").strip()
        except Exception as error:
            # A broken content stream on one page must not lose the other pages,
            # but it is counted and logged, never dropped in silence.
            failed += 1
            log.warning("pypdf failed on page %d of %d: %s", number, pages, error)
            page_text = ""
        parsed += 1
        if not page_text:
            continue
        room = max_chars - used
        if len(page_text) > room:
            chunks.append(page_text[:room])
            used += room
            truncated = True
            cut_mid_page = True
            break
        chunks.append(page_text)
        used += len(page_text) + 2

    stop_at = first + parsed - 1 if parsed else first - 1
    skipped = (last - first + 1) - parsed
    # A page cut mid-way is served again by the next fragment, unless it is the
    # first page of this request: then re-asking would cut it at the same place.
    next_start = stop_at if cut_mid_page and stop_at > first else stop_at + 1
    next_fragment = None
    if (truncated or last < pages) and next_start <= pages:
        next_fragment = f"#page={next_start}-{min(pages, next_start + max_range_pages - 1)}"
    meta = {
        "pages": pages,
        "pagesParsed": parsed,
        "pagesSkipped": skipped,
        "pagesFailed": failed,
        "truncated": truncated,
        "scanned": False,
        "rangeRequested": requested,
        "rangeServed": f"{first}-{stop_at}" if parsed else None,
        "firstPage": first,
        "lastPage": stop_at,
        "cutInsideRange": truncated,
        "cutMidPage": cut_mid_page,
        "nextFragment": next_fragment,
    }

    if not used:
        # Every page yielded nothing: scanned/image-only pages, reported as
        # themselves rather than as an empty document.
        meta["scanned"] = True
        meta["pagesParsed"] = 0
        meta["pagesSkipped"] = 0
        where = f"Pages {first}-{last} of this {pages}-page PDF have" if page_range else f"This PDF has {pages} page(s) and"
        return (
            f"[{where} no extractable text: scanned or image-only. "
            "Text extraction (OCR) is not performed.]",
            meta,
        )

    covered = f"pages {first}-{stop_at} of {pages}"
    asked = f"requested #page={page_range.label()}" if page_range else "no page fragment, read from page 1"
    if truncated:
        status = f"the character cap ({max_chars}) cut inside the requested range at page {stop_at}"
    elif page_range is not None and page_range.end is not None and page_range.end > pages:
        status = f"the range was clamped to the document's last page, {pages}"
    elif page_range is not None and page_range.end is None and last < pages:
        status = f"an open range is limited to {max_range_pages} pages"
    else:
        status = "the requested range is complete"
    header = f"[PDF {covered}; {asked}; {status}]\n\n"

    text = header + "\n\n".join(chunks)
    if truncated:
        tail = f"\n\n[PDF text truncated at page {stop_at} of {pages}"
        if cut_mid_page:
            tail += " (that page only partly included)"
        if skipped:
            tail += f": {skipped} page(s) of the range not included"
        tail += f"; character cap {max_chars}"
        if next_fragment:
            tail += f". Continue with the same URL plus {next_fragment}"
            if next_start == stop_at and stop_at < pages:
                tail += (
                    f" (it repeats page {stop_at} in full; "
                    f"#page={stop_at + 1}-{min(pages, stop_at + max_range_pages)} skips the rest of that page)"
                )
        tail += "]"
        text += tail
    elif next_fragment:
        text += f"\n\n[End of the requested pages; page {stop_at} of {pages}. Continue with the same URL plus {next_fragment}]"
    return text, meta
