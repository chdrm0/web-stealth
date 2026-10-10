"""Search-result extraction: the SERP is read as structure, not as text.

The seam wants `sources[]` with url/title/snippet. Flattening the page first is
exactly what destroys the pairing between a heading and the lines under it, so
the results page is walked as a document instead.

The parser is deliberately structural rather than class-name based: search
engines reobfuscate their CSS classes every few weeks, while "an external link
that contains an <h3>" has stayed true far longer.
"""

from __future__ import annotations

import re
from base64 import b64encode
from urllib.parse import parse_qs, urlencode, urlparse

from bs4 import BeautifulSoup

from ..extract import strip_query

#: `num` is capped at 20: google silently ignores larger values and brave has no
#: equivalent parameter, so asking for more only produces a shorter page.
def _gs_lcrp(query: str) -> str:
    """The omnibox envelope that a search typed into the address bar carries.

    Measured: google checks that this parameter is present, not what it contains —
    a blob with its middle bytes changed returns the same results. It still varies
    with the query on purpose, because one constant token sent on every request is a
    fingerprint of its own. The leading bytes are the same ones every real token
    starts with.
    """
    envelope = b"\x12\x06chrome" + query.encode("utf-8", "ignore")[:64]
    return b64encode(envelope).decode("ascii")


def _google_url(query: str, limit: int) -> str:
    return (
        "https://www.google.com/search?"
        + urlencode(
            {
                "q": query,
                "oq": query,
                "gs_lcrp": _gs_lcrp(query),
                "sourceid": "chrome",
                "source": "chrome.ob",
                "ie": "UTF-8",
                "num": min(max(limit, 1), 20),
            }
        )
    )


def _brave_url(query: str, limit: int) -> str:
    return f"https://search.brave.com/search?{urlencode({'q': query})}"


def _ddg_url(query: str, limit: int) -> str:
    # The /html endpoint, not the main site: the main site is a script app. This
    # exit currently gets a JS proof from google and startpage and a captcha from
    # mojeek, while this endpoint answers a plain request with real links.
    return f"https://html.duckduckgo.com/html/?{urlencode({'q': query})}"


ENGINE_URLS = {"google": _google_url, "brave": _brave_url, "duckduckgo": _ddg_url}

#: Fallback order after the configured primary. google is the richest when it
#: answers a logged-in curl request, brave is anonymous but rate-limits fast,
#: duckduckgo's /html endpoint is the plainest and the most tolerant of a
#: datacenter exit.
ENGINE_ORDER = ("google", "brave", "duckduckgo")

#: Links belonging to the engine itself are navigation, never results.
SELF_HOST_SUFFIXES = {
    "google": ("google.com", "googleusercontent.com", "gstatic.com", "youtube.com"),
    "brave": ("brave.com",),
    "duckduckgo": ("duckduckgo.com",),
}

SNIPPET_MAX_CHARS = 240

#: A leading host inside a title ("commandline.microsoft.com Bringing local…").
_HOST_PREFIX = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\s+", re.IGNORECASE)

#: A soft wall, not a layout change: the engine answers 200 with a page whose
#: only content is a JavaScript redirect. Its follow-up link carries real tokens
#: (`sca_esv`, `sxsrf`), and following that link was measured to return the same
#: page — the proof needs a script engine, so no curl-side retry fixes it.
JS_PROOF_MARKERS = ("/httpservice/retry/enablejs", "if you are not redirected")


def demands_js_proof(html: str) -> bool:
    """True when the body is the engine's JS-proof interstitial."""
    window = html[:20_000].lower()
    return any(marker in window for marker in JS_PROOF_MARKERS)

_RELATIVE_DATE = re.compile(r"\b\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago\b", re.I)
_ISO_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_ABS_DATE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4}\b")
#: An anchor with no <h3> whose text runs this long is body copy, not a title.
MAX_TITLE_CHARS = 120


def page_text(html: str, limit: int = 4000) -> str:
    """Flat text of the results page, for classifying a zero-result answer."""
    return " ".join(BeautifulSoup(html, "html.parser").get_text(" ", strip=True).split())[:limit]


def build_search_url(engine: str, query: str, limit: int) -> str:
    builder = ENGINE_URLS.get(engine)
    if builder is None:
        raise ValueError(f"unknown search engine {engine!r}; expected one of {sorted(ENGINE_URLS)}")
    return builder(query, limit)


def _unwrap(href: str) -> str:
    """Result links arrive wrapped: google as /url?q=, duckduckgo as /l/?uddg=."""
    parsed = urlparse(href)
    if parsed.path.startswith("/url"):
        params = parse_qs(parsed.query)
        for key in ("q", "url"):
            if params.get(key):
                return params[key][0]
    if parsed.path.startswith("/l"):
        params = parse_qs(parsed.query)
        if params.get("uddg"):
            # parse_qs has already undone the percent-encoding.
            return params["uddg"][0]
    return href


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


#: Engines that serve the same sites under every country domain
#: (scholar.google.fi, news.google.co.uk, maps.google.com.au). The brand label
#: matches only when everything after it looks like a public suffix — one or two
#: short alphabetic labels — so google.blogspot.com or google-watchblog.de, which
#: are third-party sites about the engine, are not engine hosts.
SELF_HOST_BRANDS = {
    "google": ("google",),
}
_COUNTRY_SUFFIX_LABEL = re.compile(r"^[a-z]{2,3}$")


def _is_self_host(host: str, engine: str) -> bool:
    host = host.lower().rstrip(".")
    if any(host == suffix or host.endswith("." + suffix) for suffix in SELF_HOST_SUFFIXES.get(engine, ())):
        return True
    labels = host.split(".")
    for brand in SELF_HOST_BRANDS.get(engine, ()):
        for index, label in enumerate(labels):
            tail = labels[index + 1:]
            if label == brand and 1 <= len(tail) <= 2 and all(_COUNTRY_SUFFIX_LABEL.match(part) for part in tail):
                return True
    return False


def _block_text(anchor, key_of: dict[int, str]) -> str:
    """Text of the tightest ancestor that still belongs to this one result.

    Climbing blindly lands on a container holding several results, and the
    snippet then quotes its neighbours. Several anchors of the *same* URL inside
    one card are still one result, so the climb stops at the first ancestor that
    spans more than one distinct URL.
    """
    node = anchor.parent
    best = anchor
    while node is not None:
        keys = {key_of[id(other)] for other in node.find_all("a", href=True) if id(other) in key_of}
        if len(keys) > 1:
            break
        best = node
        node = node.parent
    return " ".join(best.get_text(" ", strip=True).split())


#: Breadcrumb runs ("Site https://host › path › slug"). Google renders the cite
#: twice — once for the desktop and once for the mobile layout — so the pattern
#: is removed everywhere, not just at the head. The start is pinned to a word
#: boundary: an unpinned `{0,60}` begins mid-word and leaves shreds behind
#: ("GitHub nodriver" arriving as "GitH nodriver").
_BREADCRUMB_RUN = re.compile(r"(?:(?<=\s)|^)[^›]{0,60}›\s*")
#: Google's own query UI leaking into a result block ("Missing: x | Show results
#: with: x").
_GOOGLE_QUERY_CHROME = re.compile(r"\bMissing:.*?Show results with:\s*\S+", re.I)
#: The same card rendered twice for desktop and mobile layouts. The minimum is
#: 12 characters, not 25: the duplicated chrome is often shorter than that
#: ("GitHub nodriver GitHub nodriver"), and below 12 the pattern starts eating
#: legitimate repetition.
_REPEATED_BLOCK = re.compile(r"(.{12,}?)\s+\1", re.I)
#: Engine chrome that leaks into the first block of the page.
_CHROME_PHRASES = ("web results", "people also ask", "images", "videos", "top stories")


#: `_REPEATED_BLOCK` backreferences an unbounded `.{25,}?`, which is superlinear
#: on long input (measured around 0.5 s on 10 KB). A snippet is capped at
#: SNIPPET_MAX_CHARS regardless, so the block is cut to a bounded window before
#: any substitution runs — the regex never sees more than this.
CLEAN_WINDOW_CHARS = 4 * SNIPPET_MAX_CHARS


def _clean_snippet(block: str, title: str) -> str:
    block = block[:CLEAN_WINDOW_CHARS]
    if title and title in block:
        block = block.replace(title, " ", 1)
    block = _GOOGLE_QUERY_CHROME.sub(" ", block)
    block = _BREADCRUMB_RUN.sub(" ", block)
    block = _REPEATED_BLOCK.sub(r"\1", block)
    block = " ".join(block.split())
    for phrase in _CHROME_PHRASES:
        if block.lower().startswith(phrase):
            block = block[len(phrase) :].strip()
            break
    return block[:SNIPPET_MAX_CHARS].strip()


def _wide_block_text(anchor, key_of: dict[int, str], other_titles: list[str]) -> str:
    """Fallback when the tight block is only the title.

    Some engines put the description one level up, in a container that also
    holds sibling results. Taking that text and subtracting the other candidates'
    titles is honest: if nothing is left, the card really has no description.
    """
    node = anchor.parent
    for _ in range(3):
        if node is None:
            break
        text = " ".join(node.get_text(" ", strip=True).split())
        if len(text) >= 60:
            for other in other_titles:
                if other and other in text:
                    text = text.replace(other, " ")
            return text
        node = node.parent
    return ""


#: Phrases that mean "the engine answered, and the answer is nothing". Words are
#: far more stable than the engines' class names, so an empty answer is claimed
#: only on positive evidence — a renamed CSS class must never turn a readable
#: SERP into a confident zero.
_EMPTY_PHRASES = (
    "did not match any documents",
    "no results found",
    "it looks like there aren't any great matches",
)

#: What each engine puts on the anchor of a real result, as a fallback for the
#: case where the heading inside the anchor is gone. Structural evidence is
#: tried first (see `_is_result_anchor`), classes only second.
_ANCHOR_CLASSES = {
    "google": ("zReHs",),
    "brave": ("title",),
    "duckduckgo": ("result__a",),
}

_HEADING = re.compile("^h[1-6]$")


def _brave_snippet(anchor):
    """Brave's organic result container: `div.snippet[data-type="web"]`.

    Brave ships no heading at all — measured: zero `<h3>` on a page with 68 result
    markers — so the generic rule "an external link that contains a heading" never
    fires there, and every brave anchor used to be read as a breadcrumb.

    The same `div.snippet` container also wraps brave's enrichment blocks under a
    different `data-type` (the news carousel was measured as one), and those cards
    carry a site name, a headline and a date but no description, so `data-type` is
    the discriminator, not the class.
    """
    block = anchor.find_parent("div", class_="snippet")
    return block if block is not None and block.get("data-type") == "web" else None


def _brave_title(anchor):
    """The title div inside a brave anchor, or None.

    One brave card holds several links — the site-name link, the title link, deep
    links — and only the last wraps the title. Taking any anchor of the card is
    what produced titles like "host.com Some headline": the site-name link reads
    as breadcrumb plus headline once its text is glued.
    """
    return anchor.find(class_="title") or anchor.find(class_="search-snippet-title")


def _is_result_anchor(anchor, engine: str) -> bool:
    """Is this anchor a result, or just navigation that happens to have a link?"""
    if engine == "brave":
        return _brave_snippet(anchor) is not None and _brave_title(anchor) is not None
    if anchor.find(_HEADING) is not None:
        return True
    classes = anchor.get("class") or ()
    return any(name in classes for name in _ANCHOR_CLASSES.get(engine, ()))


def _says_empty(soup) -> bool:
    text = soup.get_text(" ", strip=True).lower()
    return any(phrase in text for phrase in _EMPTY_PHRASES)


def parse_results(html: str, engine: str, limit: int) -> tuple[list[dict], str]:
    """The results, and a verdict on what the page actually was.

    The verdict is derived from the anchors that were seen, never from a
    substring of the raw bytes: a challenge page that ships the engine's own CSS
    must not read as a result set, and a page whose results our own filters
    removed must not be reported as a wall.

      links       — results were extracted
      opaque      — result anchors were there, their hrefs were unusable
                    (Google's `/goto?url=<blob>` is exactly this)
      filtered    — result anchors were there and readable, we dropped them
      empty       — the engine says in words that it found nothing
      unreadable  — no result anchors and no empty phrase: the shape changed
    """
    soup = BeautifulSoup(html, "html.parser")
    # A CSS rule or an inline script can contain the engine's own result class;
    # scanning the document for it would call a challenge page a result set.
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    candidates: list[tuple[object, str, str]] = []
    seen: set[str] = set()
    opaque = 0
    filtered = 0
    for anchor in soup.find_all("a", href=True):
        shaped = _is_result_anchor(anchor, engine)
        if engine == "brave" and not shaped:
            # Measured: brave's enrichment blocks (news carousel, discussion rail)
            # sit in the same `div.snippet` container under a `data-type` other than
            # "web", and their card is one anchor holding a site-name div, a
            # headline div and a date div. Read as a web result that anchor's own
            # text arrives glued as "host.com Headline" with no description under
            # it, which is exactly the defect this gate removes. The generic
            # text-fallback below must therefore never run for brave.
            continue
        href = _unwrap(anchor["href"].strip())
        if not href.startswith(("http://", "https://")):
            if shaped:
                opaque += 1
            continue
        host = _host_of(href)
        if not host or _is_self_host(host, engine):
            if shaped:
                filtered += 1
            continue
        heading = anchor.find(_HEADING)
        if heading is not None:
            title = " ".join(heading.get_text(" ", strip=True).split())
        elif engine == "brave" and (brave_title := _brave_title(anchor)) is not None:
            # Defensive: the web card's title div holds the headline alone (the host
            # lives in a sibling site-name div, measured), but if brave ever moves
            # the host inside it, cut the leading dotted token by shape.
            title = _HOST_PREFIX.sub("", " ".join(brave_title.get_text(" ", strip=True).split()), count=1)
        else:
            # Without an <h3> the anchor's own text is usually the breadcrumb
            # ("Site host.com › path"), not a title. Those are not results.
            title = " ".join(anchor.get_text(" ", strip=True).split())
            if "›" in title or "://" in title or len(title) > MAX_TITLE_CHARS:
                if shaped:
                    filtered += 1
                continue
        if len(title) < 3:
            if shaped:
                filtered += 1
            continue
        key = strip_query(href)
        if key in seen:
            continue
        seen.add(key)
        candidates.append((anchor, href, title))
        if len(candidates) >= limit:
            break

    key_of = {id(anchor): strip_query(href) for anchor, href, _ in candidates}
    titles = [title for _, _, title in candidates]
    results: list[dict] = []
    for anchor, href, title in candidates:
        snippet = _clean_snippet(_block_text(anchor, key_of), title)
        if not snippet:
            snippet = _clean_snippet(_wide_block_text(anchor, key_of, [t for t in titles if t != title]), title)
        entry = {"url": href, "title": title[:200], "snippet": snippet}
        published = _RELATIVE_DATE.search(snippet) or _ABS_DATE.search(snippet) or _ISO_DATE.search(snippet)
        if published is not None:
            entry["publishedAt"] = published.group(0)
        results.append(entry)
    if results:
        verdict = "links"
    elif opaque:
        verdict = "opaque"
    elif filtered:
        verdict = "filtered"
    elif _says_empty(soup):
        verdict = "empty"
    else:
        verdict = "unreadable"
    return results, verdict
