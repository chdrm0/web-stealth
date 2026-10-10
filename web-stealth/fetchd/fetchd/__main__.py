"""Sidecar entry point: line-delimited JSON over stdio.

stdout carries protocol frames only; every log line goes to stderr, where the JS
supervisor keeps a bounded ring buffer for diagnostics.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sys
import time

from .admission import RejectedUrl, admit
from .config import ConfigError, Settings
from .engine.browser_engine import BrowserEngine, BrowserUnavailable
from .engine.captcha import CaptchaFailure
from .engine.classifier import classify
from .engine.curl_engine import CurlEngine, FetchFailure
from .engine.routing import Policy, overrides_from_env, resolve
from .engine.search import ENGINE_ORDER, ENGINE_URLS, build_search_url, demands_js_proof, page_text, parse_results
from .jar import FALLBACK_GROUP, Jar, group_for
from .protocol import decode_request, handshake, response_error, response_ok

log = logging.getLogger("fetchd")

RAW_MAX_BYTES = 200_000
#: A results page is far heavier than an article: scripts and inline styles carry
#: most of it, and the parser only needs the head of the document.
SEARCH_HTML_MAX_BYTES = 400_000
MAX_QUERY_CHARS = 400
#: A script bootstrap: heavy source, almost no prose. Both halves are required,
#: or a genuinely short page would pay for a browser.
SHELL_HTML_MIN_CHARS = 20_000
SHELL_TEXT_MAX_CHARS = 900
#: Curl-tier google verdicts that send the same query to the browser tier.
GOOGLE_WALLS = ("js-proof", "rate-limited", "challenge", "interstitial", "unparsed")
#: Browser budget for that retry, and the time it must leave to the engines behind it.
BROWSER_SEARCH_MAX_MS = 30_000
BROWSER_MIN_MS = 8_000
BROWSER_RESERVE_MS = 8_000


class Supervisor:
    def __init__(self, settings: Settings, writer: asyncio.StreamWriter, policy_overrides: dict[str, dict] | None = None) -> None:
        self.settings = settings
        self.writer = writer
        self.policy_overrides = policy_overrides or {}
        self.jar = Jar(settings.jar_dir)
        self.curl = CurlEngine(settings, self.jar)
        # Constructed eagerly, started lazily: the process is cheap, the browser
        # inside it is not.
        self.browser = BrowserEngine(settings, self.jar)
        self.pending: dict[int, asyncio.Task] = {}
        self._write_lock = asyncio.Lock()

    async def send(self, frame: dict) -> None:
        payload = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        async with self._write_lock:
            self.writer.write(payload)
            await self.writer.drain()

    async def handle(self, frame: dict) -> None:
        op = frame["op"]
        request_id = frame["id"]
        try:
            url = admit(frame["url"]) if op in ("fetch", "raw", "browser.render", "browser.open") else None
        except RejectedUrl as error:
            await self.send(response_error(request_id, error.code, str(error)))
            return

        if op == "fetch":
            data = await self._fetch(request_id, url, frame)
        elif op == "raw":
            data = await self._raw(request_id, url, frame)
        elif op == "browser.render":
            render_policy = resolve(group_for(url), self.policy_overrides)
            data = await self._render(url, frame, render_policy.send_jar)
        elif op == "browser.open":
            open_policy = resolve(group_for(url), self.policy_overrides)
            data = await self._browser_call(
                self.browser.open(url, open_policy.send_jar, self._max_elements(frame), self._text_chars(frame), self._timeout_ms(frame))
            )
        elif op == "browser.state":
            data = await self._browser_call(
                self.browser.state(self._max_elements(frame), self._text_chars(frame), self._timeout_ms(frame))
            )
        elif op == "browser.act":
            data = await self._browser_call(
                self.browser.act(
                    frame["index"],
                    frame["action"],
                    frame.get("value", ""),
                    self._max_elements(frame),
                    self._text_chars(frame),
                    self._timeout_ms(frame),
                )
            )
        elif op == "browser.read":
            data = await self._browser_call(self.browser.read(self._max_chars(frame), self._timeout_ms(frame)))
        elif op == "browser.requests":
            # Summary only. The body is a separate call with its own cap, so reading
            # a listing can never pull a page's payloads into the conversation.
            data = await self._browser_call(
                self.browser.requests(int(frame.get("since", 0) or 0), int(frame.get("limit", 60) or 60))
            )
        elif op == "browser.body":
            # The handle travels as `requestId`, not `id`: the JS client stamps
            # its own integer correlation id onto every frame, and a CDP request
            # id sent as `id` was overwritten by that counter before it got here.
            data = await self._browser_call(
                self.browser.request_body(
                    str(frame.get("requestId", "")),
                    int(frame.get("maxBytes", 4000) or 4000),
                    bool(frame.get("headers")),
                    self._timeout_ms(frame),
                    # Strict: only a JSON true replays a document (see protocol.py).
                    frame.get("replayDocument") is True,
                )
            )
        elif op == "browser.captcha":
            # `solve` is what spends money: without it the call only reports what
            # the page carries.
            data = await self._browser_call(self.browser.captcha(bool(frame.get("solve")), self._timeout_ms(frame)))
        elif op == "browser.close":
            data = await self._browser_call(self.browser.close_session(self._timeout_ms(frame)))
        elif op == "search":
            data = await self._search(frame)
        elif op == "jar.status":
            data = {"groups": self.jar.status(), "proxy": self.settings.proxy.split("://")[0]}
        else:
            await self.send(response_error(request_id, "unknown-op", f"op {op!r} is not implemented yet"))
            return
        await self.send(response_ok(request_id, data))

    def _max_chars(self, frame: dict) -> int:
        return frame.get("maxChars") or self.settings.max_chars

    def _timeout_ms(self, frame: dict) -> int:
        return frame.get("timeoutMs") or self.settings.fetch_timeout_ms

    def _max_elements(self, frame: dict) -> int:
        # Absent means the configured cap, zero means "no listing". `or` would
        # turn a request for nothing into a request for everything.
        requested = frame.get("maxElements")
        if requested is None:
            return self.settings.browser_max_elements
        try:
            return max(0, int(requested))
        except (TypeError, ValueError) as error:
            raise FetchFailure("bad-request", f"maxElements must be an integer, got {requested!r}") from error

    def _text_chars(self, frame: dict) -> int:
        """The preview cap for open/state/act — not the read cap."""
        return frame.get("textChars") or self.settings.browser_text_chars

    async def _browser_call(self, operation):
        """Await one browser operation and name its failure.

        `BrowserUnavailable` covers everything from a refused start to a tab that
        stopped answering. The caller needs to know the browser tier is the part
        that failed, not that the sidecar hit an internal error.
        """
        try:
            return await operation
        except BrowserUnavailable as error:
            raise FetchFailure("browser-unavailable", error.message) from error
        except CaptchaFailure as error:
            # The solver's refusal, timeout or missing key: one code for the
            # caller to route on, the reason in the message, never the key.
            raise FetchFailure("captcha", f"[{error.code}] {error}") from error

    def _mark_staleness(self, group: str, policy: Policy, status: int, outcome: str, jar_applied: int) -> None:
        """Renewal on fact: a rejected set is marked, an accepted one clears it.

        Only origins that were actually shown the jar can go stale, and a later
        success clears the marker without any manual step. In a multi-engine
        search this has to run per engine: the engine that rejected the jar is
        usually not the one that finally answered.
        """
        # The catch-all group is a bucket of unrelated sites: one site's 403
        # would tell every other one to "re-run harvest", and an unrelated 200
        # would clear it. Only a named group has a set that can go stale.
        if group != FALLBACK_GROUP and policy.send_jar and jar_applied > 0:
            try:
                if status in (401, 403) or outcome in ("challenge", "consent"):
                    self.jar.mark_stale(group, f"{outcome}/{status}", status)
                elif outcome == "ok":
                    self.jar.clear_stale(group)
            except OSError as error:
                # The marker is bookkeeping. Losing it must not cost the caller a
                # response they already have in hand.
                log.warning("could not update the stale marker for %s: %s", group, error)

    def _note_outcome(self, data: dict, policy: Policy) -> dict:
        self._mark_staleness(
            data["group"], policy, data["statusCode"], data["outcome"], data.get("jarApplied", 0)
        )
        data["policy"] = policy.policy
        data["jarStale"] = self.jar.is_stale(data["group"])
        return data

    @staticmethod
    def _hint_for(data: dict) -> str | None:
        hints: list[str] = []
        if data["outcome"] in ("challenge", "consent"):
            hints.append("the response looks like an interstitial, not the document; do not treat it as content")
        elif data["outcome"] == "interstitial":
            hints.append(
                "the page is a gate demanding cookies or JavaScript, not the document; "
                "this is a refusal, not a thin or empty page"
            )
        elif data["outcome"] == "empty-shell":
            hints.append("the document needs script execution; the text above is a shell")
        elif data["outcome"] == "rate-limited":
            hints.append("this origin is rate limiting us; back off instead of re-issuing the request")
        elif data["outcome"] == "js-proof":
            hints.append("the engine demands a JavaScript proof from this exit; the results page is unreachable without a browser")
        if data.get("jarStale"):
            hints.append(f"the cookie set for {data['group']} was rejected ({data['jarStale'].get('reason')}); re-run harvest")
        return "; ".join(hints) or None

    async def _fetch(self, request_id: int, url: str, frame: dict) -> dict:
        policy = resolve(group_for(url), self.policy_overrides)
        if policy.policy == "browser_first":
            data = await self._render(url, frame, policy.send_jar)
            data["policy"] = policy.policy
            return data

        data = await self.curl.fetch(url, self._max_chars(frame), self._timeout_ms(frame), send_jar=policy.send_jar)
        data["outcome"] = classify(data["statusCode"], data["text"], data["contentType"], links=len(data["links"]))
        data = self._note_outcome(data, policy)

        # The browser tier answers one question only: is the document missing
        # because it needs script? A refusal is not that question, so a
        # challenge or a 403 is reported as itself and never re-attempted with a
        # second fingerprint.
        #
        # `empty-shell` catches the polite variant ("enable javascript"). The
        # common one is quieter: the page ships tens of kilobytes of source and
        # returns only its navigation — measured on github/settings, 48 KB of
        # HTML for 372 characters of headings. The ratio catches that.
        # The ratio half has to be gated on a successful status: a 403 page, a
        # 404 page and a challenge interstitial are all heavy HTML with thin
        # text, and they would otherwise be retried with a second fingerprint.
        # `interstitial` escalates too: the gate demands cookies or script, and
        # the browser tier has both — but if it cannot render, the caller still
        # sees the refusal named, never the gate's text as an article.
        looks_like_shell = data["statusCode"] // 100 == 2 and (
            data["outcome"] in ("empty-shell", "interstitial")
            or (data.get("htmlChars", 0) >= SHELL_HTML_MIN_CHARS and len(data["text"]) < SHELL_TEXT_MAX_CHARS)
        )
        if looks_like_shell and policy.policy == "curl_then_browser":
            rendered = await self._try_render(url, frame, policy.send_jar)
            if rendered is not None:
                # The curl tier's pre-cut length describes the curl text, not this one.
                data.pop("textChars", None)
                data.update(rendered)
                data["outcome"] = classify(data["statusCode"], data["text"], data["contentType"], links=len(data["links"]))
                data["escalated"] = True
            else:
                data["escalated"] = False

        hint = self._hint_for(data)
        if data.get("escalated") is False:
            note = "the page needs script and the browser tier could not render it"
            hint = f"{hint}; {note}" if hint else note
        if hint is not None:
            data["hint"] = hint
        return data

    async def _try_render(self, url: str, frame: dict, send_jar: bool) -> dict | None:
        """Render with the browser, or return None and keep the curl answer."""
        try:
            return await self.browser.render(url, self._max_chars(frame), self._timeout_ms(frame), send_jar=send_jar)
        except BrowserUnavailable as error:
            log.warning("browser tier unavailable for %s: %s", url, error.message)
            return None

    async def _render(self, url: str, frame: dict, send_jar: bool) -> dict:
        """Direct browser render, for the `browser.render` op and browser-first origins."""
        try:
            data = await self.browser.render(url, self._max_chars(frame), self._timeout_ms(frame), send_jar=send_jar)
        except BrowserUnavailable as error:
            raise FetchFailure("browser-unavailable", error.message) from error
        data["group"] = group_for(url)
        data["outcome"] = classify(data["statusCode"], data["text"], data["contentType"], links=len(data["links"]))
        return data

    async def _raw(self, request_id: int, url: str, frame: dict) -> dict:
        policy = resolve(group_for(url), self.policy_overrides)
        limit = min(frame.get("maxBytes") or RAW_MAX_BYTES, RAW_MAX_BYTES)
        data = await self.curl.fetch_raw(url, limit, self._timeout_ms(frame), send_jar=policy.send_jar)
        data["policy"] = policy.policy
        return data

    def _engine_chain(self, preferred: str) -> list[str]:
        """The configured engine first, then the rest in fallback order."""
        if preferred not in ENGINE_URLS:
            raise ValueError(f"unknown search engine {preferred!r}; expected one of {sorted(ENGINE_URLS)}")
        return [preferred] + [name for name in ENGINE_ORDER if name != preferred]

    @staticmethod
    async def _serp_outcome(status: int, body: str, content_type: str, name: str, limit: int) -> tuple[list[dict], str]:
        """The results of one SERP and the verdict on it, whichever tier fetched it."""
        if status // 100 != 2:
            # A 429 page parses into links too — an error page is not a
            # result set, so the status decides before anything else does.
            text = await asyncio.to_thread(page_text, body)
            outcome = classify(status, text, content_type, links=0)
            results = []
        else:
            # Parsing 400 KB of engine HTML is CPU work; on the event loop it
            # would stall every other in-flight request.
            results, verdict = await asyncio.to_thread(parse_results, body, name, limit)
            if verdict == "links":
                outcome = "ok"
            elif await asyncio.to_thread(demands_js_proof, body):
                # Named separately from "no results": this engine is reachable
                # and the query is fine, the exit just has no script engine.
                outcome = "js-proof"
            elif verdict == "opaque":
                # Result anchors were on the page and none of their hrefs could
                # be resolved: Google hands every result out as an opaque
                # /goto?url= redirect. A shape we cannot read, not an answer.
                outcome = "unparsed"
            elif verdict == "filtered":
                # The engine answered and we threw the answer away ourselves
                # (every link pointed back at the engine's own sites). Honest
                # label, and the next engine may still have something.
                outcome = "filtered-out"
            elif verdict == "empty":
                outcome = "no-results"
            else:
                # No result anchors and no words saying "nothing found": an
                # interstitial, or a layout we can no longer read. classify()
                # names the first; a plain 200 that produced nothing readable
                # is the second, and it must not be reported as an empty query.
                text = await asyncio.to_thread(page_text, body)
                outcome = classify(status, text, content_type, links=0)
                if outcome == "ok":
                    outcome = "unparsed"
        return results, outcome

    async def _google_via_browser(self, query: str, limit: int, timeout_ms: int) -> dict:
        """The same google query rendered by the browser tier.

        Measured: the browser tier gets organic results where the curl tier is
        walled, and with or without the omnibox set. It does not mint a `gs_lcrp`
        of its own, and it sends no `gs_lcrp` even when the URL asked for one, so
        there is no browser token to hand back to the curl tier.
        """
        url = build_search_url("google", query, limit)
        policy = resolve(group_for(url), self.policy_overrides)
        page = await self.browser.render_html(url, timeout_ms, send_jar=policy.send_jar)
        admit(page["url"])
        results, outcome = await self._serp_outcome(page["status"], page["html"], "text/html", "google", limit)
        return {"url": page["url"], "statusCode": page["status"], "results": results, "outcome": outcome, "group": group_for(url), "policy": policy}

    async def _search(self, frame: dict) -> dict:
        """One search: the engine URLs are built here, never supplied by the caller."""
        query = frame.get("query")
        if not isinstance(query, str) or not query.strip():
            raise FetchFailure("bad-request", "search requires a non-empty string `query`")
        query = query.strip()
        if len(query) > MAX_QUERY_CHARS:
            raise FetchFailure("bad-request", f"query is too long ({MAX_QUERY_CHARS} characters max)")
        try:
            limit = max(1, min(int(frame.get("maxResults") or 10), 25))
            chain = self._engine_chain(frame.get("engine") or self.settings.search_engine)
        except (TypeError, ValueError) as error:
            raise FetchFailure("bad-request", f"malformed search request: {error}") from error

        # One deadline for the whole search: the caller agreed to wait `timeoutMs`
        # for an answer, not for each engine. Parsing is CPU work on top of the
        # network time, so the split covers the network only and the deadline is
        # what actually bounds the call.
        total_ms = self._timeout_ms(frame)
        deadline = time.monotonic() + total_ms / 1000
        per_engine_ms = min(total_ms, max(5_000, total_ms // len(chain)))
        tried: list[dict] = []
        data: dict = {}
        policy = None
        for name in chain:
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms < 1_000:
                # No usable time left. Say so per engine rather than starting a
                # request that is certain to be cut off.
                tried.append({"engine": name, "tier": "none", "statusCode": 0, "outcome": "no-budget"})
                continue
            url = build_search_url(name, query, limit)
            # The URL is ours, but it still passes the same gate: a future engine
            # definition must not become a way around the private-network block.
            admit(url)
            policy = resolve(group_for(url), self.policy_overrides)
            try:
                raw = await self.curl.fetch_raw(
                    url, SEARCH_HTML_MAX_BYTES, min(per_engine_ms, remaining_ms), send_jar=policy.send_jar
                )
            except FetchFailure as error:
                # One engine running out of its slice is not the search failing.
                # A walled engine can spend most of the budget before it says so,
                # and the engine behind it may still answer inside what is left —
                # so this is recorded per engine, next to the `no-budget` entries,
                # and the chain moves on. Any other failure is the caller's to see.
                if error.code != "timeout":
                    raise
                tried.append({"engine": name, "tier": "curl", "statusCode": 0, "outcome": "timeout"})
                continue
            status = raw["statusCode"]
            results, outcome = await self._serp_outcome(status, raw["body"], raw["contentType"], name, limit)
            self._mark_staleness(raw["group"], policy, status, outcome, raw["jarApplied"])
            tried.append({"engine": name, "tier": "curl", "statusCode": raw["statusCode"], "outcome": outcome})
            data = {
                "query": query,
                "engine": name,
                "url": raw["url"],
                "statusCode": raw["statusCode"],
                "results": results,
                "outcome": outcome,
                "group": raw["group"],
                "jarApplied": raw["jarApplied"],
                "attempts": raw["attempts"],
                "tier": "curl",
            }
            if name == "google" and outcome in GOOGLE_WALLS:
                browser_ms = int((deadline - time.monotonic()) * 1000) - BROWSER_RESERVE_MS
                if browser_ms < BROWSER_MIN_MS:
                    tried.append({"engine": name, "tier": "browser", "statusCode": 0, "outcome": "no-budget"})
                else:
                    try:
                        page = await self._google_via_browser(query, limit, min(browser_ms, BROWSER_SEARCH_MAX_MS))
                    except (BrowserUnavailable, RejectedUrl) as error:
                        # Recorded in the trail the caller sees, and the chain moves
                        # on to the next engine: the curl wall is still the answer.
                        log.warning("browser tier could not carry the google search: %s", error)
                        tried.append({"engine": name, "tier": "browser", "statusCode": 0, "outcome": "browser-unavailable"})
                    else:
                        tried.append({"engine": name, "tier": "browser", "statusCode": page["statusCode"], "outcome": page["outcome"]})
                        if page["outcome"] in ("ok", "no-results"):
                            policy = page.pop("policy")
                            data = {"query": query, "engine": name, **page, "jarApplied": 0, "attempts": 1, "tier": "browser"}
            # A wall moves on to the next engine. An empty answer does not: it is
            # an answer, and re-asking three engines for it is noise.
            if data["outcome"] in ("ok", "no-results"):
                break

        if not data:
            # No engine produced an answer to describe: every one was skipped for
            # lack of time or ran out of its slice. There is no page whose outcome
            # could be reported, so this is a failure, named by who was tried.
            raise FetchFailure(
                "timeout",
                "no search engine was given usable time: "
                + ", ".join(f"{entry['engine']}={entry['outcome']}" for entry in tried),
            )

        data["enginesTried"] = tried
        data = self._note_outcome(data, policy)
        hint = self._hint_for(data)
        note = None
        if data["outcome"] == "no-results":
            # Appended, not replaced: a stale jar and a changed layout can be true
            # at once, and dropping either one loses the only clue the caller has.
            note = "the engine found nothing for this query and said so in words"
        elif data["outcome"] == "unparsed":
            # Named from the engines that actually walled, not from the last one
            # visited: the caller cannot open a results page it was never shown,
            # and a wrong engine name sends it looking in the wrong place.
            walled = [entry["engine"] for entry in tried if entry["outcome"] == "unparsed"] or [data["engine"]]
            note = (
                f"{' and '.join(walled)} answered 200 but their result links could not be read "
                "(Google hands them out as opaque redirects) — the browser tier can open that results page"
            )
        elif data["outcome"] == "filtered-out":
            note = "the engine's results all pointed back at the engine's own sites and were dropped as navigation"
        if note is not None:
            hint = f"{hint}; {note}" if hint else note
        if len(tried) > 1:
            # Every attempt, in order: naming only the first and the answering engine
            # hid every engine in between (brave's 429 never reached the caller).
            trail = ", ".join(f"{entry['engine']}/{entry['tier']}={entry['outcome']}" for entry in tried)
            note = f"engines tried: {trail}; answered by {data['engine']} via the {data['tier']} tier"
            hint = f"{hint}; {note}" if hint else note
        if hint is not None:
            data["hint"] = hint
        return data

    async def _idle_watchdog(self) -> None:
        """Retire the process when nothing is in flight for `idle_timeout_s`.

        A long-lived process is what makes connection reuse work, but it must not
        outlive a code change. The watchdog — not the read loop — owns the
        decision, because the read loop cannot tell idle from a slow request.
        """
        idle_s = self.settings.idle_timeout_s
        if idle_s <= 0:
            return
        while True:
            await asyncio.sleep(idle_s)
            if not self.pending:
                log.info("idle for %ss; exiting so the supervisor can start a fresh generation", idle_s)
                self.reader.feed_eof()
                return

    async def run(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader
        watchdog = asyncio.create_task(self._idle_watchdog())
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError) as error:
                    log.error("frame too large: %s", error)
                    continue
                if not line:
                    break
                try:
                    frame = decode_request(line.decode("utf-8", "replace").strip())
                except (ValueError, json.JSONDecodeError) as error:
                    log.error("bad frame rejected: %s", error)
                    # A rejected frame that carries an id still gets an answer.
                    # Silence makes the caller wait out its own timeout and report
                    # a timeout instead of the validation error that actually
                    # happened — and a misconfigured `browserTimeoutMs` above the
                    # protocol ceiling fails every browser call that way.
                    try:
                        parsed = json.loads(line.decode("utf-8", "replace"))
                        frame_id = parsed.get("id") if isinstance(parsed, dict) else None
                    except (ValueError, UnicodeDecodeError):
                        frame_id = None
                    if isinstance(frame_id, int) and not isinstance(frame_id, bool):
                        await self.send(response_error(frame_id, "bad-request", str(error)))
                    continue

                op = frame["op"]
                if op == "shutdown":
                    break
                if op == "cancel":
                    task = self.pending.get(frame["id"])
                    if task is not None:
                        task.cancel()
                    continue

                task = asyncio.create_task(self._guarded(frame))
                self.pending[frame["id"]] = task
                task.add_done_callback(lambda finished, rid=frame["id"]: self.pending.pop(rid, None))
        finally:
            watchdog.cancel()

    async def _guarded(self, frame: dict) -> None:
        request_id = frame["id"]
        try:
            await self.handle(frame)
        except asyncio.CancelledError:
            await self.send(response_error(request_id, "cancelled", "request cancelled"))
            raise
        except FetchFailure as error:
            await self.send(response_error(request_id, error.code, error.message))
        except TimeoutError:
            await self.send(response_error(request_id, "timeout", "request timed out"))
        except Exception as error:  # noqa: BLE001 - a crash must not take the process down
            log.exception("unhandled error while processing op=%s", frame.get("op"))
            await self.send(response_error(request_id, "internal", f"{type(error).__name__}: {error}"))

    async def shutdown(self) -> None:
        for task in list(self.pending.values()):
            task.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*self.pending.values(), return_exceptions=True)
        await self.browser.close()
        await self.curl.close()


async def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="fetchd %(levelname)s %(message)s")
    try:
        settings = Settings.from_env()
    except ConfigError as error:
        print(f"fetchd: bad configuration: {error}", file=sys.stderr)
        return 2

    reader = asyncio.StreamReader(limit=4_194_304)
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    write_transport, write_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(write_transport, write_protocol, reader, loop)

    try:
        overrides = overrides_from_env()
    except ValueError as error:
        print(f"fetchd: bad origin policy: {error}", file=sys.stderr)
        return 2

    try:
        build_search_url(settings.search_engine, "probe", 1)
    except ValueError as error:
        print(f"fetchd: {error}", file=sys.stderr)
        return 2

    supervisor = Supervisor(settings, writer, overrides)
    await supervisor.send(handshake(["curl", "browser"]))
    log.info("ready: proxy=%s impersonate=%s jar=%s idle=%ss search=%s browser=%s", settings.proxy, settings.impersonate, settings.jar_dir, settings.idle_timeout_s, settings.search_engine, settings.browser_executable)

    try:
        await supervisor.run(reader)
    finally:
        await supervisor.shutdown()
    log.info("shutdown complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
