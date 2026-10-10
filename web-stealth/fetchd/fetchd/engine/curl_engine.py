"""Tier 1: curl_cffi with a Chrome TLS fingerprint, the shared jar, and the proxy.

This is the default path. The browser tier exists only for documents that
cannot be read without executing script.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from curl_cffi.curl import CurlError
from curl_cffi.requests import AsyncSession

from ..config import Settings
from ..extract import PdfExtractionError, PdfPageRangeError, extract_measured, extract_pdf, parse_page_fragment
from ..jar import group_for

log = logging.getLogger("fetchd.curl")


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()

#: 429 is handled apart from the others: a search endpoint that says "slow down"
#: does not change its mind after three fast retries, and hammering it is how a
#: healthy session gets blocked. One patient retry, then hand the 429 back.
RATE_LIMIT_STATUS = 429
RATE_LIMIT_RETRY_S = 12.0
RATE_LIMIT_MAX_WAIT_S = 30.0
RETRYABLE_STATUS = frozenset({408, 425, 500, 502, 503, 504})
#: curl error numbers that mean "the transport hiccuped", not "the site refused".
RETRYABLE_CURL_CODES = frozenset({7, 28, 35, 52, 55, 56, 92})
TEXT_CONTENT_TYPES = ("application/json", "application/xml", "text/plain", "text/csv")
PDF_CONTENT_TYPES = ("application/pdf", "application/x-pdf")
#: Servers that mislabel PDFs as octet-stream exist; the URL path ending in
#: `.pdf` is only trusted as a secondary signal when the stated type says nothing.
PDF_FALLBACK_CONTENT_TYPES = ("", "application/octet-stream")


def _retry_after_seconds(raw: str | None) -> float | None:
    """`Retry-After` as seconds — the header is either a number or an HTTP date."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.isdigit():
        return max(0.0, float(raw))
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


class FetchFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class CurlEngine:
    """One long-lived session per cookie group.

    Connection reuse is part of looking human, but a single shared session was a
    credential leak: curl keeps the cookies it was handed, and a session that has
    just carried a Google session to google.com also carries it to the next site
    it visits. Grouping sessions by jar group keeps the reuse (same origin, same
    connection) and makes cross-origin leakage structurally impossible.
    """

    def __init__(self, settings: Settings, jar) -> None:
        self.settings = settings
        self.jar = jar
        self._sessions: dict[str, AsyncSession] = {}
        # group -> monotonic time until which the origin is known to be rate
        # limiting us. Bounded by the closed set of groups.
        self.cooloff_until: dict[str, float] = {}

    def _new_session(self) -> AsyncSession:
        return AsyncSession(
            impersonate=self.settings.impersonate,
            proxy=self.settings.proxy,
            headers=self.settings.extra_headers,
            timeout=self.settings.fetch_timeout_ms / 1000,
            allow_redirects=True,
        )

    async def session(self, group: str = "") -> AsyncSession:
        """The session for this group, created on first use.

        Groups are a closed set (google, github, brave, other), so this map is
        bounded and needs no eviction.
        """
        session = self._sessions.get(group)
        if session is None:
            session = self._new_session()
            self._sessions[group] = session
        return session

    async def close(self) -> None:
        sessions, self._sessions = self._sessions, {}
        for session in sessions.values():
            await session.close()

    async def fetch(self, url: str, max_chars: int, timeout_ms: int, send_jar: bool = True) -> dict:
        """Fetch and reduce one URL to text + links.

        Returns a dict the supervisor can hand straight to the seam:
        {url, statusCode, text, links, truncated, contentType, outcome}.
        Raises FetchFailure for conditions the caller must classify.
        """
        # A fragment is a client-side address: it never goes on the wire. For a
        # PDF it is the page selector (`#page=N-M`), applied after the download.
        url, _, fragment = url.partition("#")
        deadline = time.monotonic() + timeout_ms / 1000
        group = group_for(url)
        attempt = 0
        jar_applied = 0
        last_error: str = "unknown"

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchFailure("timeout", f"deadline exceeded after {attempt} attempt(s): {last_error}")

            still = await self._await_cooloff(group, remaining)
            if still > 0:
                # Do not spend a request on an origin that just said no: answer
                # the 429 ourselves and let the caller back off.
                log.warning("group %s is still rate limiting us (%.1fs left); request not sent", group, still)
                return {
                    "url": url, "statusCode": RATE_LIMIT_STATUS, "text": "", "links": [], "truncated": False,
                    "contentType": "", "group": group, "jarApplied": 0, "attempts": attempt, "cooloffSeconds": round(still, 1),
                }

            session = await self.session(group)
            if group and send_jar:
                jar_applied = self.jar.apply_to_session(session, group)

            try:
                response = await session.get(url, timeout=min(remaining, self.settings.fetch_timeout_ms / 1000))
            except CurlError as error:
                last_error = f"curl {error.code}: {error.message if hasattr(error, 'message') else error}"
                if error.code not in RETRYABLE_CURL_CODES or attempt >= self.settings.max_retries:
                    raise FetchFailure("network", last_error) from error
                attempt += 1
                log.warning("fetch %s attempt %d failed: %s", url, attempt, last_error)
                await self._backoff(attempt, deadline)
                continue

            status = response.status_code
            if status == RATE_LIMIT_STATUS:
                delay = self._rate_limit_delay(response, deadline)
                self._note_rate_limit(group, delay)
                if delay is not None and attempt < 1:
                    attempt += 1
                    last_error = "HTTP 429"
                    log.warning("rate limited by %s; waiting %.1fs before one retry", url, delay)
                    await asyncio.sleep(delay)
                    continue
            if status != RATE_LIMIT_STATUS and status in RETRYABLE_STATUS and attempt < self.settings.max_retries:
                attempt += 1
                last_error = f"HTTP {status}"
                await self._backoff(attempt, deadline, retry_after=response.headers.get("Retry-After"))
                continue

            if group and send_jar:
                try:
                    self.jar.merge_from_session(group, session, host=_host_of(str(response.url or url)))
                except OSError as error:
                    log.warning("could not fold cookies back into %s: %s", group, error)

            result = await self._reduce(response, max_chars, url, fragment)
            result["group"] = group
            result["jarApplied"] = jar_applied
            result["attempts"] = attempt + 1
            return result

    async def fetch_raw(self, url: str, max_bytes: int, timeout_ms: int, send_jar: bool = True) -> dict:
        """Unextracted body, for when the model asked to see the source itself."""
        deadline = time.monotonic() + timeout_ms / 1000
        attempt = 0
        jar_applied = 0
        last_error = "unknown"
        group = group_for(url)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchFailure("timeout", f"deadline exceeded after {attempt} attempt(s): {last_error}")
            still = await self._await_cooloff(group, remaining)
            if still > 0:
                log.warning("group %s is still rate limiting us (%.1fs left); request not sent", group, still)
                return {
                    "url": url, "statusCode": RATE_LIMIT_STATUS, "contentType": "", "body": "", "bytes": 0,
                    "truncated": False, "group": group, "jarApplied": 0, "attempts": attempt, "cooloffSeconds": round(still, 1),
                }
            session = await self.session(group)
            if group and send_jar:
                jar_applied = self.jar.apply_to_session(session, group)
            try:
                response = await session.get(url, timeout=min(remaining, self.settings.fetch_timeout_ms / 1000))
            except CurlError as error:
                last_error = f"curl {error.code}: {error}"
                if error.code not in RETRYABLE_CURL_CODES or attempt >= self.settings.max_retries:
                    raise FetchFailure("network", last_error) from error
                attempt += 1
                await self._backoff(attempt, deadline)
                continue

            status = response.status_code
            if status == RATE_LIMIT_STATUS:
                delay = self._rate_limit_delay(response, deadline)
                self._note_rate_limit(group, delay)
                if delay is not None and attempt < 1:
                    attempt += 1
                    last_error = "HTTP 429"
                    log.warning("rate limited by %s; waiting %.1fs before one retry", url, delay)
                    await asyncio.sleep(delay)
                    continue
            if status != RATE_LIMIT_STATUS and status in RETRYABLE_STATUS and attempt < self.settings.max_retries:
                attempt += 1
                last_error = f"HTTP {response.status_code}"
                await self._backoff(attempt, deadline, retry_after=response.headers.get("Retry-After"))
                continue

            if group and send_jar:
                try:
                    self.jar.merge_from_session(group, session, host=_host_of(str(response.url or url)))
                except OSError as error:
                    log.warning("could not fold cookies back into %s: %s", group, error)

            body = response.content or b""
            content_type = (response.headers.get("Content-Type") or "").split(";")[0].lower()
            return {
                "url": str(response.url or url),
                "statusCode": response.status_code,
                "contentType": content_type,
                "body": body[:max_bytes].decode("utf-8", "replace"),
                "bytes": len(body),
                "truncated": len(body) > max_bytes,
                "group": group,
                "jarApplied": jar_applied,
                "attempts": attempt + 1,
            }

    def _rate_limit_delay(self, response, deadline: float) -> float | None:
        """Seconds to wait before the single allowed 429 retry, or None to give up."""
        advertised = _retry_after_seconds(response.headers.get("Retry-After"))
        # `Retry-After: 0` is not an invitation to retry immediately.
        delay = advertised if advertised is not None and advertised > 0 else RATE_LIMIT_RETRY_S
        delay += random.uniform(0, delay * 0.25)
        if delay > RATE_LIMIT_MAX_WAIT_S or delay > deadline - time.monotonic():
            return None
        return delay

    def _note_rate_limit(self, group: str, delay: float | None) -> None:
        """Record that this origin said no, so the *next* request waits too."""
        self.cooloff_until[group] = time.monotonic() + min(RATE_LIMIT_MAX_WAIT_S, RATE_LIMIT_RETRY_S if delay is None else delay)

    async def _await_cooloff(self, group: str, remaining: float) -> float:
        """Sleep out a known cooloff. Returns the seconds that were left but not slept."""
        left = self.cooloff_until.get(group, 0.0) - time.monotonic()
        if left <= 0:
            return 0.0
        if left > remaining:
            return left
        log.info("waiting %.1fs before %s: it is rate limiting us", left, group)
        await asyncio.sleep(left)
        return 0.0

    async def _backoff(self, attempt: int, deadline: float, retry_after: str | None = None) -> None:
        """Bounded exponential backoff with jitter; honours Retry-After."""
        delay = min(8.0, 0.5 * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
        if retry_after and retry_after.isdigit():
            delay = max(delay, min(30.0, float(retry_after)))
        delay = min(delay, max(0.0, deadline - time.monotonic()))
        await asyncio.sleep(delay)

    async def _reduce(self, response, max_chars: int, url: str, fragment: str = "") -> dict:
        content_type = (response.headers.get("Content-Type") or "").lower()

        # Checked before the text decode: a PDF body decoded as text is wasted
        # work and garbage either way.
        base_type = content_type.split(";")[0]
        stated_type = any(token in content_type for token in PDF_CONTENT_TYPES)
        path_says_pdf = urlsplit(str(response.url or url)).path.lower().endswith(".pdf")
        if stated_type or (path_says_pdf and base_type in PDF_FALLBACK_CONTENT_TYPES):
            return await self._reduce_pdf(response, max_chars, url, fragment)

        body = response.text or ""

        if any(token in content_type for token in TEXT_CONTENT_TYPES):
            truncated = len(body) > max_chars
            return {
                "url": str(response.url or url),
                "statusCode": response.status_code,
                "text": body[:max_chars],
                "links": [],
                "truncated": truncated,
                "textChars": len(body),
                "contentType": content_type.split(";")[0],
            }

        if "html" not in content_type and content_type:
            raise FetchFailure("unsupported-content", f"Content-Type {content_type.split(';')[0]!r} is not a document")

        # BeautifulSoup is pure CPU: on the event loop it would freeze every other
        # in-flight request for as long as the page takes to parse.
        text, links, truncated, total_chars = await asyncio.to_thread(
            extract_measured, body, max_chars, base_url=str(response.url or url), max_links=self.settings.max_links
        )
        return {
            "url": str(response.url or url),
            "statusCode": response.status_code,
            "text": text,
            "links": links,
            "truncated": truncated,
            # Extracted text length before the cut, so a truncation can be stated.
            "textChars": total_chars,
            # How much source produced this text. A heavy document that yields a
            # handful of lines is a script bootstrap, and the escalation policy
            # needs the ratio, not the text on its own.
            "htmlChars": len(body),
            "contentType": content_type.split(";")[0] or "text/html",
        }

    async def _reduce_pdf(self, response, max_chars: int, url: str, fragment: str = "") -> dict:
        """PDF body -> the same result shape the HTML path returns, plus `pdf` metadata."""
        try:
            page_range = parse_page_fragment(fragment)
        except PdfPageRangeError as error:
            log.warning("PDF at %s: rejected page fragment: %s", url, error)
            raise FetchFailure("pdf-page-range", str(error)) from error
        raw = response.content or b""
        if len(raw) > self.settings.pdf_max_bytes:
            log.warning("PDF at %s is %d bytes, over the %d-byte cap; not parsed", url, len(raw), self.settings.pdf_max_bytes)
            raise FetchFailure(
                "pdf-too-large",
                f"PDF body is {len(raw)} bytes, over the {self.settings.pdf_max_bytes}-byte cap (STEALTH_PDF_MAX_BYTES)",
            )
        # The caller's budget and the configured ceiling both bind; the smaller wins.
        cap = min(max_chars, self.settings.pdf_max_chars)
        try:
            # pypdf is pure CPU: keep it off the event loop like BeautifulSoup.
            text, meta = await asyncio.to_thread(
                extract_pdf, raw, cap, page_range, self.settings.pdf_max_range_pages
            )
        except PdfPageRangeError as error:
            log.warning("PDF at %s: rejected page range: %s", url, error)
            raise FetchFailure("pdf-page-range", str(error)) from error
        except PdfExtractionError as error:
            log.warning("PDF at %s (%d bytes) could not be read: %s", url, len(raw), error)
            raise FetchFailure("pdf-corrupt", f"{url}: {error}") from error
        return {
            "url": str(response.url or url),
            "statusCode": response.status_code,
            "text": text,
            "links": [],
            "truncated": meta["truncated"],
            "contentType": "application/pdf",
            "pdf": {**meta, "bytes": len(raw), "charCap": cap},
        }
