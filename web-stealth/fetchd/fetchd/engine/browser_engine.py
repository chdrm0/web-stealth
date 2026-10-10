"""Tier 2: a real browser, used passively.

One job only: documents that do not exist until script has run. It is not a
fallback for "curl was refused" — that is a policy question, not a rendering
one, and sending a second fingerprint at a refusal is how a session gets burned.

One browser, one tab, started on demand and released when idle. The browser
profile is *not* logged in: the harvest signs in inside a context it creates for
the run, so that session never reaches the profile on disk. The jar is therefore
the only credential store, and the browser is handed the same set the curl tier
uses (see Jar.to_cdp_cookies).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import codecs
import contextlib
import json
import logging
import time
from pathlib import Path
from urllib.parse import urlsplit

from ..admission import RejectedUrl, admit
from ..config import Settings
from ..extract import extract
from ..jar import FALLBACK_GROUP, group_for
from .browser_dom import EMBEDDED_TAGS, act_script, box_script, captcha_inject_script, captcha_script, snapshot_script
from .captcha import AntiCaptcha, CaptchaFailure, SolveBudget, captcha_identity

log = logging.getLogger("fetchd.browser")

#: Bounds on the captured request log. A page like google's results fires well over
#: a hundred requests; the description of each is cheap, the body is not, so the two
#: get separate caps and the body is only ever fetched by id.
MAX_TRACKED_REQUESTS = 200
MAX_REQUEST_PAGE = 80
MAX_REQUEST_URL_CHARS = 300
#: The replay path needs the exact URL, so it keeps its own, much longer copy;
#: only a URL longer than this is refused for replay.
MAX_REPLAY_URL_CHARS = 8192
#: Extra-info events that arrived before their RequestWillBeSent, held until the
#: request is noted. Bounded: an id that never gets noted must not accumulate.
MAX_EARLY_HEADERS = 200
MAX_REQUEST_BODY_BYTES = 20_000

#: Hard ceiling on the window in which the Fetch domain is armed to re-fetch one
#: body. A silent page must never leave interception standing: the domain is
#: disabled in a finally, and this bounds every await inside the window.
FETCH_BODY_WINDOW_S = 12.0
#: Time held back from the operation budget for releasing paused requests and
#: `Fetch.disable`, so cleanup still fits after the window is spent.
FETCH_CLEANUP_RESERVE_S = 3.0
#: Ceiling on one `Network.getResponseBody` round trip.
NETWORK_BODY_TIMEOUT_S = 10.0


def _initiator_of(event) -> str:
    """Who asked for this request, in as few characters as still answers the question."""
    initiator = getattr(event, "initiator", None)
    if initiator is None:
        return ""
    kind = str(getattr(initiator, "type", "") or "")
    url = str(getattr(initiator, "url", "") or "")
    if kind == "script" and url:
        return f"script:{url.rsplit('/', 1)[-1][:40]}"
    return kind


def _redact_headers(headers: dict) -> dict:
    """Header names and shapes, never values that are credentials.

    Capturing request headers answers what the browser sends that the curl tier
    does not — a question of names, order and form. A cookie value answers none of
    that and is a secret by the project's rules, so it is replaced by its size.
    """
    redacted: dict[str, str] = {}
    for name, value in (headers or {}).items():
        lowered = str(name).lower()
        text = str(value)
        if lowered == "cookie":
            redacted[lowered] = f"<{len(text)} bytes, {text.count(';') + 1} pairs>"
        elif lowered in ("authorization", "proxy-authorization", "set-cookie", "x-csrftoken"):
            redacted[lowered] = "<redacted>"
        else:
            redacted[lowered] = text[:200]
    return redacted

#: A React shell fires the load event and paints afterwards, so readyState alone
#: catches an empty skeleton. The page is watched until its requests go quiet and
#: its rendered text stops growing: poll intervals, how many equal polls count as
#: settled, and the ceiling on that waiting.
SETTLE_POLL_S = 0.6
SETTLE_STABLE_POLLS = 2
SETTLE_MAX_S = 8.0
READY_POLL_S = 0.25
NETWORK_POLL_S = 0.25
#: How long the request set must stay empty before the page counts as loaded.
NETWORK_QUIET_S = 1.0
#: Consecutive CDP failures before a waiting loop gives up on the tab instead of
#: spinning until the deadline with a dead target.
TAB_ERROR_LIMIT = 3
#: Anything the browser tier reports about itself, so the caller can tell a
#: rendered document from a curl one.
ENGINE = "browser"

#: The serialized DOM is parsed in memory, and a pathological page is tens of
#: megabytes. The text that comes out is capped far below that, so the DOM is cut
#: before parsing — the parser tolerates a truncated tail, and the caller is told
#: the document was cut rather than shown a shorter page than there was.
HTML_PARSE_MAX_CHARS = 1_500_000


def _bounded_html(raw: str | None) -> tuple[str, bool]:
    html = raw or ""
    if len(html) <= HTML_PARSE_MAX_CHARS:
        return html, False
    log.info("page DOM cut for parsing: %d characters", len(html))
    return html[:HTML_PARSE_MAX_CHARS], True


class BrowserUnavailable(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _resource_type(event) -> str:
    """Resource type of a Network event, lower-cased.

    nodriver names the field `type_` because `type` is a builtin, and its value
    is an enum whose str() reads "ResourceType.Document". A handler that gets
    this wrong raises inside nodriver's event dispatch, which logs and swallows
    it — the symptom is a field that silently never fills in.
    """
    value = getattr(event, "type_", None)
    if value is None:
        value = getattr(event, "type", None)
    return str(getattr(value, "value", value)).lower()


def _is_main_frame(event, main_frame: str | None) -> bool:
    """Whether a Network event belongs to the page itself, not to one of its frames.

    An iframe's 200 must not be reported as the page's status: a page that was
    refused can embed a captcha or a consent frame that answered fine.
    """
    if main_frame is None:
        return True
    return str(getattr(event, "frame_id", "") or "") in ("", main_frame)


def _bounded_fetch_body(body: str, base64_encoded: bool, limit: int) -> tuple[str, bool, int, bool]:
    """Decode no more of a Fetch body than `limit` characters can need.

    Returns `(content, is_base64, total_bytes, truncated)`. `total_bytes` is the
    size of the whole body, computed from its length without decoding it.
    """
    if not base64_encoded:
        return body[:limit], False, len(body), len(body) > limit
    total = len(body) // 4 * 3 - body[-2:].count("=")
    # UTF-8 spends at most 4 bytes per character and base64 4 characters per 3
    # bytes, so this window always holds `limit` characters; a multiple of 4
    # keeps the slice valid base64.
    window = 4 * -(-4 * limit // 3)
    head = body[:window]
    cut = len(body) > window
    try:
        raw = base64.b64decode(head, validate=True)
    except (binascii.Error, ValueError) as error:
        log.warning("Fetch body is not valid base64 (%d chars); returning it undecoded: %s", len(body), error)
        return head[:limit], True, len(body), len(body) > limit
    try:
        # Incremental, so a multi-byte character split by the window is held
        # back instead of failing the decode.
        text = codecs.getincrementaldecoder("utf-8")().decode(raw, final=not cut)
    except UnicodeDecodeError:
        return head[:limit], True, total, cut or len(head) > limit
    return text[:limit], False, total, cut or len(text) > limit


class BrowserEngine:
    def __init__(self, settings: Settings, jar=None) -> None:
        self.settings = settings
        # The jar is the single credential store; the browser is handed the same
        # set the curl tier uses (see Jar.to_cdp_cookies for why the profile is
        # not enough).
        self.jar = jar
        # Every browser operation is serialized: one tab, one page at a time.
        self._lock = asyncio.Lock()
        self._browser = None
        self._tab = None
        # A browser whose teardown was interrupted. `stop()` only signals, and a
        # cancelled teardown leaves the process running with the profile locked;
        # the handle is parked here so the next start can find and reap it.
        self._dying = None
        # The browser's self-reported identity is written once per session, not per
        # tab: the engine does not change version under itself.
        self._fingerprint_recorded = False
        # What the page asked for, oldest-first, bounded. A normal page fires
        # hundreds of requests; the last few dozen are worth more to the agent than
        # the whole log, and an unbounded list is how a context overflows.
        self._requests: dict[str, dict] = {}
        self._seen_requests = 0
        # Session generations: `_session_gen` ticks on every browser start, and
        # `_capture_gen` records which generation last filled the captured set.
        # A body call that misses while the two disagree means the caller is
        # holding ids from a session that was released and recreated — a
        # different answer from "that id was evicted from this navigation".
        self._session_gen = 0
        self._capture_gen = 0
        # Ticks on every main-frame navigation: the captured set is keyed on it,
        # not on the browser start, so a session that inherits a browser from a
        # render never lists the render's requests as its own.
        self._nav_gen = 0
        # The page that opened the window we are driving. A sign-in popup posts
        # its result to `window.opener` and closes itself, so the opener has to
        # stay alive for the hand-off to finish, and to take the session back.
        self._opener = None
        # Set by a click that pressed into a frame: the window it opens is the
        # site's own login, not a stray tab, so it is adopted rather than closed.
        self._expect_handoff = False
        # Which groups this session put into the browser. Only those are folded
        # back on teardown: the profile is shared with the harvester, and cookies
        # that were sitting in it from elsewhere are not this session's to keep.
        self._injected: set[str] = set()
        # The solver is a paid third party and is only ever asked explicitly.
        self.anticaptcha = AntiCaptcha(settings.anticaptcha_key, settings.anticaptcha_timeout_ms / 1000)
        # Lives on the engine, not the browser session: closing and reopening a
        # session must not reset the spend cap.
        self.solve_budget = SolveBudget()
        self._early_headers: dict[str, dict] = {}
        self._last_used = 0.0
        self._watchdog: asyncio.Task | None = None
        # Request ids the browser is still waiting on, fed by the CDP handlers.
        self._inflight: set[str] = set()
        # Status of the last Document response, and the reason a navigation
        # produced no document at all. Both come from the Network handlers.
        self._main_status: int | None = None
        self._nav_error: str = ""
        # The frame the page target itself owns. Network events from iframes carry
        # another id, and their status is not the status of the page.
        self._main_frame: str | None = None
        # True between a successful open and close/teardown: the tab belongs to a
        # session, and a one-shot render must not walk in and take it.
        self._session_open = False
        # Claimed synchronously by `request_body` before it queues for the lock:
        # a second body call fails fast instead of arming a second Fetch window.
        self._body_in_flight = False

    @property
    def is_up(self) -> bool:
        return self._browser is not None

    @staticmethod
    def _tolerate_private_events(cdp) -> None:
        """Teach the CDP parser to drop the events Brave invents.

        Brave emits `Network.requestAdblock*` events, which are not part of the
        protocol and have no parser in nodriver. Each one arrives as a KeyError
        and is logged as an error with a traceback — on a real page that is one
        error block per blocked request, which is the kind of noise that hides a
        real one. They are parsed into a stand-in type that has no handlers, so
        they are dropped where they arrive rather than silenced in the log: a
        genuinely unknown event is still a KeyError and still reported.
        """

        class _IgnoredEvent:
            @staticmethod
            def from_json(_params: dict) -> "_IgnoredEvent":
                return _IgnoredEvent()

        for method in (
            "Network.requestAdblockInfoReceived",
            "Network.requestAdblockRuleIdentifiersReceived",
        ):
            cdp.util._event_parsers.setdefault(method, _IgnoredEvent)

    async def _start(self) -> None:
        import nodriver as uc
        from nodriver import cdp

        self._tolerate_private_events(cdp)
        # Before a new process is spawned: a Brave left behind by an interrupted
        # teardown still holds the profile's single-instance lock, and the new
        # start would fail on it with a message that blames the sandbox.
        await self._reap_dying()

        launch_args = [
            "--no-first-run",
            "--no-default-browser-check",
            # Brave starts a crashpad handler that uploads to cr.brave.com even
            # with --disable-breakpad present. A browser carrying a live session
            # has no business reporting its crashes — and a crash report is a
            # request that does not go through our address gate.
            "--disable-crash-reporter",
            # The locale is set, not inherited: the curl tier says en-US, and two
            # tiers answering with different Accept-Language is a fingerprint
            # difference for the same session.
            "--lang=en-US",
            # Memory, not stealth. A headed Chromium tree costs ~510 MB at rest
            # on a machine with a few gigabytes free: fewer renderer processes
            # lowers the fixed base, and a V8 heap ceiling turns an
            # out-of-memory kill of the whole session into one page failing to
            # allocate. Neither flag is visible to page script.
            "--renderer-process-limit=2",
            "--js-flags=--max-old-space-size=512",
        ]
        if self.settings.browser_proxy:
            launch_args.append(f"--proxy-server={self.settings.browser_proxy}")
            # Chrome routes loopback around the proxy by default. Without this a
            # page can point the browser at 127.0.0.1 — the harness GUI, the CDP
            # port — and the proxy never sees a request it could refuse.
            launch_args.append("--proxy-bypass-list=<-loopback>")
        else:
            # No exit, so the flag above would guard nothing. Loopback names go to a
            # blackhole at resolution time, and the address ranges are refused per
            # tab by Settings.blocked_patterns.
            launch_args.append(
                "--host-resolver-rules=MAP localhost 0.0.0.0, MAP *.localhost 0.0.0.0"
            )

        config = uc.Config(
            user_data_dir=Path(self.settings.browser_profile).expanduser(),
            headless=False,
            browser_executable_path=self.settings.browser_executable,
            # The proxy belongs to the process, not to a private context. A
            # context made by create_context() has its own cookie store, and
            # Storage.setCookies over the page session does not reach it: with
            # the proxy on the context, every render came back logged out even
            # though the cookies read back fine.
            browser_args=launch_args,
            # The browser sandbox stays on. It was off because an early start
            # failure was read as a machine limit; the setuid helper
            # (/opt/brave-bin/chrome-sandbox) and unprivileged user namespaces are
            # both present, so there is nothing to work around — and a browser that
            # is fed cookies from a live session should not run with its own
            # isolation switched off.
            sandbox=True,
        )
        # Built here instead of through `uc.start()`: that helper spawns the process
        # and only then attaches, so a cancel or a failed attach leaves a headed
        # Brave holding the profile's single-instance lock with no handle of ours to
        # terminate it. Assigning first means there is always something to stop.
        browser = uc.Browser(config)
        self._browser = browser
        try:
            await browser.start()
        except asyncio.CancelledError:
            # No awaits: the task is being cancelled. The process is stopped and
            # parked in `_dying` — `stop()` only signals, so the next start waits
            # for it there instead of racing a Brave that is still going down.
            self._terminate(browser)
            self._browser, self._tab = None, None
            self._dying = browser
            raise
        except Exception as error:  # nodriver raises a dozen shapes here
            # A fast teardown, not `_stop_locked`: this browser never loaded a
            # page and never had cookies injected, so the cookie work there would
            # spend the caller's whole budget on nothing. The profile being held
            # by another session lands exactly here, and it must fail fast. The
            # handle still goes to `_dying` first, so a cancel during the reap
            # cannot orphan the process.
            self._browser, self._tab = None, None
            self._dying = browser
            await self._reap_dying()
            raise BrowserUnavailable(f"could not start {self.settings.browser_executable}: {error}") from error

        try:
            self._tab = browser.main_tab
            if self._tab is None:
                raise RuntimeError("the browser started without a tab")
            # For the main frame of a page target, CDP reports frameId == targetId.
            # Network events from iframes carry a different one, and their status
            # must not be reported as the status of the page.
            self._main_frame = self._tab.target_id
            await self._apply_tab_policy(self._tab)
            self._track_network()
            # The profile lives on disk, so a run that died before its cleanup can
            # leave cookies behind. A new session must not inherit them.
            await self._clear_cookies()
        except asyncio.CancelledError:
            await self._stop_locked()
            raise
        except Exception as error:
            await self._stop_locked()
            raise BrowserUnavailable(f"browser started but its tab failed: {error}") from error

        self._session_gen += 1
        log.info("browser up: executable=%s proxy=%s", self.settings.browser_executable, self.settings.browser_proxy)

    async def _reap_dying(self) -> None:
        """Finish tearing down a browser an interrupted teardown left behind.

        `stop()` only signals, and the process is what holds the profile's
        single-instance lock, so the wait is what makes the next start safe.
        """
        browser = self._dying
        if browser is None:
            return
        log.warning("reaping a browser left behind by an unfinished teardown")
        self._terminate(browser)
        process = getattr(browser, "_process", None)
        if process is not None and process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("reaped browser outlived terminate; killing it")
                with contextlib.suppress(Exception):
                    process.kill()
            except Exception as error:
                log.warning("waiting for the reaped browser failed: %s", error)
        self._dying = None

    @staticmethod
    def _terminate(browser) -> None:
        """Stop a browser that was launched but never handed over."""
        try:
            browser.stop()
        except Exception as error:
            log.warning("browser process did not stop after a failed start: %s", error)

    async def _live_tab(self, browser, tab, opener):
        """A tab that still answers CDP, if the one we hold no longer does.

        Used only on teardown, to read and clear cookies. The order is the order
        of trust: the page that opened a login window is where a finished hand-off
        lands, the tab we were driving is next, and any other live page is better
        than a guaranteed failure on a dead one.
        """
        try:
            # nodriver's `tabs` is a snapshot: without this the list can still
            # contain the closed window and miss the opener that survived it.
            await asyncio.wait_for(browser.update_targets(), timeout=3.0)
        except Exception as error:
            log.warning("could not refresh the tab list before the cookie fold: %s", error)
            return tab
        live = list(browser.tabs)
        if not live:
            log.warning("the browser has no live page tab to read cookies from")
            return tab
        for candidate in (opener, tab):
            if candidate is not None and any(candidate is item for item in live):
                return candidate
        return live[0]

    async def _stop_locked(self) -> None:
        """Tear the browser down; say whether the cookies went with it.

        The caller must hold the lock.
        """
        browser, tab, self._browser, self._tab = self._browser, self._tab, None, None
        # Handed to `_dying` before anything is awaited. Every step below is
        # bounded and guarded by `except Exception`, which does not catch a
        # cancellation: if this teardown is itself cancelled halfway, the process
        # must still be findable, or a headed Brave holding a live session is
        # orphaned and every later start dies on the profile's single-instance
        # lock. `_start` reaps whatever is parked here.
        if browser is not None:
            self._dying = browser
        # Taken before the fold below, cleared here: the fold may only write back
        # what this session put in, and a stale set would widen it.
        injected, self._injected = self._injected, set()
        # The page that opened a login window is kept alive on purpose: when that
        # window posts its result and closes itself, it is the only live view of
        # the session the user just completed.
        opener, self._opener = self._opener, None
        self._expect_handoff = False
        self._inflight.clear()
        self._main_status = None
        self._nav_error = ""
        self._main_frame = None
        self._session_open = False
        # False until something was actually cleared: a browser that never had a
        # tab never had cookies injected, and reporting `true` there would claim a
        # cleanup that did not run.
        cleared = False
        if tab is not None:
            # The tab we hold may be one the page closed itself: a login window
            # posts its result to the opener and closes, and then the only live
            # view of the session is the page that opened it. Reading cookies from
            # the dead tab answers "session not found" and throws away a login the
            # user just finished by hand, so pick a target that still answers first.
            tab = await self._live_tab(browser, tab, opener)
            if self.settings.browser_jar_writeback:
                # Read before clearing: this is the only moment the browser's own
                # view of the session exists. A login completed in this tab —
                # signed in through Google, a Reddit session, a GitHub device flow
                # — is worthless if it dies with the tab, and the jar is the only
                # store the curl tier reads.
                try:
                    held = await asyncio.wait_for(self._capture_cookies(tab), timeout=3.0)
                    folded = await asyncio.to_thread(self._fold_cookies, held, injected)
                    # Logged even when nothing was new: this is the line that
                    # proves the round trip happened at all.
                    log.info("folded the browser's cookies back into the jar: %d new", folded)
                except Exception as error:
                    log.warning("browser cookies were not folded into the jar: %s", error)
            # The profile is on disk, so cookies injected for a session are written
            # to Brave's cookie store and outlive the process: a second credential
            # store outside the 0600 jar, in a profile the harvest also uses. This
            # is the one place that runs on every way out — idle, timeout, failure,
            # shutdown — so the clearing belongs here, not in the callers.
            try:
                await asyncio.wait_for(self._clear_cookies(tab), timeout=3.0)
                cleared = True
            except Exception as error:
                log.warning("cookies were not cleared before teardown: %s", error)
            # The geolocation grant is browser-scoped rather than per target — it
            # was handed to every origin this browser saw. Take it back with the
            # cookies, so the on-disk profile does not keep a standing grant.
            from nodriver import cdp

            with contextlib.suppress(Exception):
                await asyncio.wait_for(tab.send(cdp.browser.reset_permissions()), timeout=3.0)
        if browser is None:
            return cleared
        try:
            # Bounded: the supervisor's shutdown gives this process a short window
            # before it kills it, and a websocket that will not close must not eat
            # that window — the process kill would then land while Brave is still
            # up, orphaning it.
            await asyncio.wait_for(browser.aclose(), timeout=3.0)
        except Exception as error:
            log.warning("browser connection did not close cleanly: %s", error)
        try:
            # `aclose()` is the websocket only — the process survives it. `stop()`
            # is synchronous and is what terminates Brave: measured, releasing on
            # idle without it left a headed window holding the profile, and the
            # next start then died on the single-instance lock.
            browser.stop()
        except Exception as error:
            log.warning("browser process did not stop: %s", error)
        # `stop()` only signals. The process is what holds the profile lock, so an
        # immediate restart must not race a Brave that is still going down.
        process = getattr(browser, "_process", None)
        if process is not None and process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("browser process outlived terminate; killing it")
                with contextlib.suppress(Exception):
                    process.kill()
            except Exception as error:
                log.warning("waiting for the browser process failed: %s", error)
        if self._dying is browser:
            self._dying = None
        return cleared

    async def close(self) -> None:
        watchdog, self._watchdog = self._watchdog, None
        if watchdog is not None:
            watchdog.cancel()
            # Awaited before the lock is taken: the watchdog stops the browser
            # under the lock, so waiting for it while holding it would deadlock.
            # CancelledError is a BaseException, so Exception alone misses it.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watchdog
        async with self._lock:
            await self._stop_locked()

    def _arm_watchdog(self) -> None:
        if self._watchdog is not None or self.settings.browser_idle_s <= 0:
            return
        self._watchdog = asyncio.create_task(self._idle_loop())

    async def _idle_loop(self) -> None:
        """Release the browser while it is not being used.

        The stop waits for the lock, so it can never pull a browser out from
        under a render that is in flight.
        """
        idle = self.settings.browser_idle_s
        while True:
            await asyncio.sleep(min(15.0, idle))
            if self._browser is None or time.monotonic() - self._last_used < idle:
                continue
            async with self._lock:
                if self._browser is not None and time.monotonic() - self._last_used >= idle:
                    await self._stop_locked()
                    log.info("browser released after %ss idle", idle)

    async def _apply_tab_policy(self, tab) -> None:
        """Pin identity and media policy onto whichever tab is being driven.

        Both emulation overrides are per target, so a window the session moves
        into needs them again. The geolocation one is useless without the
        permission: with the override set and the permission not granted,
        `getCurrentPosition` answers as a timeout — the position source is never
        asked. Measured on this machine: no grant -> `code=3 Timeout expired`,
        grant -> the configured coordinates.

        The grant is browser-scoped, not per target — it covers every origin this
        browser sees, which is why it is re-sent cheaply here and taken back in
        `_stop_locked` rather than left standing in the on-disk profile.

        `network.enable` belongs here for the same reason: it is what gives the
        block list and the request handlers meaning, and a window adopted
        mid-session has never had it sent on its own target.
        """
        from nodriver import cdp

        await tab.send(cdp.network.enable())
        if self.settings.timezone:
            await tab.send(cdp.emulation.set_timezone_override(self.settings.timezone))
        if self.settings.geolocation is not None:
            latitude, longitude = self.settings.geolocation
            await tab.send(cdp.browser.grant_permissions(permissions=[cdp.browser.PermissionType.GEOLOCATION]))
            await tab.send(
                cdp.emulation.set_geolocation_override(latitude=latitude, longitude=longitude, accuracy=1000.0)
            )
        patterns = self.settings.blocked_patterns
        if patterns:
            # The generated binding is mangled: CDP's `setBlockedURLs` arrives as
            # `set_blocked_ur_ls`. Patterns are matched in order and outrank any
            # wildcard, so this list is the whole policy — there are no exceptions.
            # It carries the media refusals and, with no exit configured, the
            # refusal to reach this machine.
            await tab.send(
                cdp.network.set_blocked_ur_ls(
                    url_patterns=[cdp.network.BlockPattern(url_pattern=pattern, block=True) for pattern in patterns]
                )
            )
        await self._record_fingerprint(tab)

    async def _record_fingerprint(self, tab) -> None:
        """Write down the identity the browser reports about itself.

        The curl tier reads this file at startup, so both halves answer as one
        client. A version string kept in config rots the day the browser updates,
        and `--version` is no answer for Brave: it prints Brave's own number, not
        the engine's. Once per session is enough — the engine does not change
        version under itself.
        """
        if self._fingerprint_recorded:
            return
        self._fingerprint_recorded = True
        script = (
            "(async () => {"
            " const data = navigator.userAgentData || null;"
            " const high = data ? await data.getHighEntropyValues(['platform', 'fullVersionList']) : {};"
            " return JSON.stringify({"
            " ua: navigator.userAgent,"
            " mobile: data ? (data.mobile ? '?1' : '?0') : '?0',"
            " brands: (high.fullVersionList || (data ? data.brands : [])) || [],"
            " platform: high.platform || (data ? data.platform : '')"
            " });"
            "})()"
        )
        try:
            record = json.loads(await tab.evaluate(script, await_promise=True))
        except Exception as error:
            # Not fatal: the curl tier keeps its derived defaults. Said out loud,
            # because a silently missing file is how the two tiers drift apart.
            log.warning("fingerprint probe failed: %s", error)
            return
        brands = record.get("brands") if isinstance(record.get("brands"), list) else []
        parts = [
            f'"{brand["brand"]}";v="{str(brand.get("version", "")).split(".")[0]}"'
            for brand in brands
            if isinstance(brand, dict) and brand.get("brand")
        ]
        payload = {
            "user_agent": str(record.get("ua") or ""),
            # The header lists majors; fullVersionList carries the full strings.
            "sec_ch_ua": ", ".join(parts),
            "sec_ch_ua_mobile": str(record.get("mobile") or "?0"),
            "sec_ch_ua_platform": f'"{record.get("platform") or "Linux"}"',
            "recorded_at": int(time.time()),
        }
        if not payload["user_agent"]:
            log.warning("fingerprint probe returned no user agent; keeping the previous record")
            return
        path = Path(self.settings.fingerprint_path)
        temporary = path.with_name(f"{path.name}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(payload), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(path)
        except OSError as error:
            log.warning("could not write %s: %s", path, error)

    def _track_network(self, reset: bool = True) -> None:
        """Follow the requests the browser has in flight, and its document status.

        Text stability alone is not enough: github's settings page paints an
        "there was an error while loading" boundary first, and that boundary is
        perfectly stable. The requests are the truth, and the document response
        is the only honest status code a browser render can report.
        """
        from nodriver import cdp

        # The in-flight set is per tab: requests from a tab we no longer drive
        # never report LoadingFinished to us, and their ids would keep every later
        # wait sitting out its whole budget.
        self._inflight = set()
        if reset:
            self._reset_capture()

        def driven(source) -> bool:
            # Handlers are never removed from a tab, so the page that opened a
            # window keeps firing while that window is the one being driven. Its
            # requests would sit in the in-flight set until every wait times out,
            # and its document response would be reported as the status of the
            # page in front of the agent. nodriver hands the owning tab to
            # two-argument handlers.
            return source is None or source is self._tab

        def on_request(event, source=None) -> None:
            if not driven(source):
                return
            # A new main-frame document (not a redirect hop, which reuses the id)
            # is a new page: a click, a script redirect or a replay moves the shown
            # page without passing through `open`, and the ring must follow it.
            if (
                _resource_type(event) == "document"
                and _is_main_frame(event, self._main_frame)
                and getattr(event, "redirect_response", None) is None
                and str(event.request_id) not in self._requests
                and str(getattr(event.request, "url", "")).startswith(("http://", "https://"))
            ):
                self._reset_capture(keep_early=str(event.request_id))
            self._inflight.add(str(event.request_id))
            self._note_request(str(event.request_id), event)

        def on_loaded(event, source=None) -> None:
            if not driven(source):
                return
            self._inflight.discard(str(event.request_id))
            entry = self._requests.get(str(event.request_id))
            if entry is not None:
                entry["end"] = time.time()
                entry["bytes"] = int(getattr(event, "encoded_data_length", 0) or 0)

        def on_response(event, source=None) -> None:
            if not driven(source):
                return
            entry = self._requests.get(str(event.request_id))
            if entry is not None:
                entry["status"] = int(event.response.status)
                entry["mime"] = str(event.response.mime_type or "")
            if _resource_type(event) == "document" and _is_main_frame(event, self._main_frame):
                # Last document response wins: a redirect chain ends at the page
                # the user is actually looking at.
                self._main_status = int(event.response.status)

        def on_failed(event, source=None) -> None:
            if not driven(source):
                return
            self._inflight.discard(str(event.request_id))
            entry = self._requests.get(str(event.request_id))
            if entry is not None:
                entry["error"] = str(getattr(event, "error_text", None) or getattr(event, "blocked_reason", None) or "failed")
            if _resource_type(event) == "document" and _is_main_frame(event, self._main_frame):
                self._nav_error = str(getattr(event, "error_text", None) or getattr(event, "blocked_reason", None) or "navigation failed")

        def on_extra_info(event, source=None) -> None:
            # Not every request gets one, and it may arrive before the request
            # itself; a missing entry is normal, not an error to report.
            if not driven(source):
                return
            entry = self._requests.get(str(event.request_id))
            headers = _redact_headers(event.headers)
            if entry is not None and not entry["headers"]:
                entry["headers"] = headers
                return
            # An entry that already has headers means this is the next hop of a
            # redirect (same request id), ahead of its RequestWillBeSent; it is held
            # for that hop instead of overwriting the previous one's.
            # CDP quirk: extra-info may precede RequestWillBeSent; dropping it
            # here left that request without headers for good.
            self._early_headers[str(event.request_id)] = headers
            while len(self._early_headers) > MAX_EARLY_HEADERS:
                self._early_headers.pop(next(iter(self._early_headers)))

        # One set of handlers per tab object: adopting a window and coming back to
        # the opener both re-enter here, and `add_handler` stacks rather than
        # replaces. The marker travels on the tab rather than in a set of target
        # ids, because the handlers live on the tab's connection and
        # `update_targets` hands back a fresh Tab object for a target it had
        # dropped and later re-sees — an id-keyed guard would then refuse to
        # register handlers onto a connection that has none, and the session would
        # never see a document response again.
        if not getattr(self._tab, "_dsh_tracked", False):
            self._tab._dsh_tracked = True
            self._tab.add_handler(cdp.network.RequestWillBeSent, on_request)
            self._tab.add_handler(cdp.network.LoadingFinished, on_loaded)
            self._tab.add_handler(cdp.network.LoadingFailed, on_failed)
            self._tab.add_handler(cdp.network.ResponseReceived, on_response)
            # The headers the network stack actually put on the wire — Chrome adds
            # its own after the page asked, so this is the only honest source.
            self._tab.add_handler(cdp.network.RequestWillBeSentExtraInfo, on_extra_info)

    def _reset_capture(self, keep_early: str | None = None) -> None:
        """Start a new navigation window: status, captured requests and cursor.

        `keep_early` names the document that opened the window: its extra-info
        may already have arrived, and dropping it loses its wire headers.
        """
        early = self._early_headers.get(keep_early) if keep_early else None
        self._main_status = None
        self._nav_error = ""
        self._requests = {}
        self._seen_requests = 0
        self._early_headers = {keep_early: early} if early is not None else {}
        self._nav_gen += 1

    def _ring_page(self) -> dict | None:
        """The newest main-frame document in the ring: the page the ring describes."""
        return next((rec for rec in reversed(self._requests.values()) if rec.get("main")), None)

    def _note_request(self, request_id: str, event) -> None:
        """Start the record of one request the page made.

        The cap is the point, not an optimisation: a normal page fires hundreds of
        requests, and the oldest are the least interesting. The counter keeps
        counting past the cap so a reader paging through the log is never shown the
        same entry twice.
        """
        request = event.request
        url = str(request.url)
        if not url.startswith(("http://", "https://")):
            # Only traffic that left the machine. A Google SERP carries a hundred
            # inline images, and Brave's own omnibox machinery reports its internal
            # resources on the same connection; both would crowd out the dozen
            # requests that actually crossed the wire.
            return
        self._seen_requests += 1
        self._capture_gen = self._session_gen
        self._requests[request_id] = {
            "n": self._seen_requests,
            # The CDP id travels in the listing: the body is fetched by id, and a
            # URL would be ambiguous for the same address requested twice.
            "id": request_id,
            "nav": self._nav_gen,
            "method": str(request.method),
            "url": url[:MAX_REQUEST_URL_CHARS],
            "fullUrl": url[:MAX_REPLAY_URL_CHARS],
            "urlChars": len(url),
            # nodriver names the field `type_`; reading `event.type` yields "" and
            # the listing's type column silently never fills in.
            "type": _resource_type(event),
            # The page's own document, marked so a reader can find it in a
            # hundred lines and a body call can reach it by number.
            "main": _resource_type(event) == "document" and _is_main_frame(event, self._main_frame),
            "start": time.time(),
            "status": None,
            "mime": "",
            "bytes": 0,
            "end": None,
            "error": "",
            "initiator": _initiator_of(event),
            # Filled by the extra-info event when the stack reports one.
            "headers": self._early_headers.pop(request_id, None),
            # What the page asked for, before the network stack added its own
            # (cookie, sec-fetch-*, accept-encoding): the fallback, labelled as such.
            "pageHeaders": _redact_headers(dict(getattr(request, "headers", None) or {})),
        }
        while len(self._requests) > MAX_TRACKED_REQUESTS:
            # The document is never an eviction victim: on a 500-request page a
            # plain oldest-first pop drops it, and the one entry that says what
            # this navigation was becomes invisible in the listing.
            victim = next((key for key, rec in self._requests.items() if not rec.get("main")), None)
            if victim is None:
                break
            self._requests.pop(victim)

    async def requests(self, since: int = 0, limit: int = 60) -> dict:
        """The captured window, oldest first, as a summary and nothing else.

        Bodies are a separate call with their own cap: a page's requests are a few
        hundred bytes each of description, while one JSON answer is tens of
        kilobytes, and mixing the two is what overflows a context.
        """
        entries = [entry for entry in self._requests.values() if entry["n"] > since]
        page = entries[: max(1, min(int(limit or 60), MAX_REQUEST_PAGE))]
        first = next(iter(self._requests.values()), None)
        last = next(reversed(self._requests.values()), None)
        return {
            "entries": [self._request_summary(entry) for entry in page],
            "next": page[-1]["n"] if page else since,
            "seen": self._seen_requests,
            # The captured range, so a body call that misses can be corrected
            # from the listing alone: everything outside it is gone by design.
            "captured": len(self._requests),
            "oldest": first["n"] if first else None,
            "newest": last["n"] if last else None,
            "inflight": len(self._inflight),
            "status": self._main_status,
            "page": (self._ring_page() or {}).get("url"),
        }

    @staticmethod
    def _request_summary(entry: dict) -> dict:
        parsed = urlsplit(entry["url"])
        query = f"?{parsed.query[:60]}" if parsed.query else ""
        return {
            "n": entry["n"],
            "id": entry["id"],
            "main": bool(entry.get("main")),
            "method": entry["method"],
            "host": parsed.netloc,
            "path": f"{parsed.path or '/'}{query}"[:120],
            "status": entry["status"],
            "type": entry["type"],
            "mime": entry["mime"],
            "bytes": entry["bytes"],
            "ms": round((entry["end"] - entry["start"]) * 1000) if entry["end"] else None,
            "initiator": entry["initiator"],
            "error": entry["error"],
        }

    def _capture_miss(self, token: str) -> BrowserUnavailable:
        """Name the miss the caller actually made, with the range that is valid now.

        Two different failures wore the same message: a session that was
        released and recreated (its captured set is simply gone), and an id or
        number from an older navigation or already evicted from the ring.
        """
        if self._tab is None or (not self._requests and self._capture_gen and self._capture_gen < self._session_gen):
            return BrowserUnavailable(
                "the browser session was released and recreated since that listing: its captured set is gone. "
                "Re-run browser_requests on the current page and use an id or #n from that listing."
            )
        head = (
            f"sequence #{token} is ambiguous or outside the captured window"
            if token.isdigit()
            else f"request {token} is from an older navigation or already evicted from the ring"
        )
        if self._requests:
            first = next(iter(self._requests.values()))
            last = next(reversed(self._requests.values()))
            window = f"the current captured range is #{first['n']}-#{last['n']} of {self._seen_requests} seen this navigation"
        else:
            window = "nothing is captured for the current navigation yet"
        return BrowserUnavailable(f"{head}: {window}. Re-run browser_requests for the current ids.")

    async def request_body(
        self,
        request_id: str,
        max_bytes: int = 4000,
        want_headers: bool = False,
        timeout_ms: int | None = None,
        replay_document: bool = False,
    ) -> dict:
        """One captured response body, capped, and the request headers on request.

        `Network.getResponseBody` answers only while the page still holds the body,
        which is why this takes the handle from the listing rather than a URL. The
        listing prints two handles — `[cdp-id]` and `#n` — and either is accepted
        here; an exact id match wins over a numeric token, so a CDP id that
        happens to be all digits is never mistaken for a sequence number. The
        headers travel on the same call because they are asked for by the same
        question — what did this request actually look like.

        Runs as a session operation: under the tab lock, inside one budget, and
        it refreshes the idle clock like every other call that touches the tab.
        """
        if self._body_in_flight:
            raise BrowserUnavailable(
                "another browser_body call is still running (its Fetch interception window may be armed); "
                "only one body read runs at a time — retry after it returns"
            )
        self._body_in_flight = True
        try:
            return await self._session_op(
                timeout_ms or self.settings.fetch_timeout_ms,
                lambda deadline: self._request_body_locked(request_id, max_bytes, want_headers, replay_document, deadline),
            )
        finally:
            self._body_in_flight = False

    async def _refuse_foreign_entry(self, token: str, entry: dict, deadline: float) -> None:
        """Refuse a lookup whose entry describes a page other than the one shown.

        Origin, not full URL: pushState moves the path without a new document,
        but it cannot move the origin.
        """
        would = f"{token} would have returned {entry['method']} {entry['url']}"
        if entry.get("nav") != self._nav_gen:
            raise BrowserUnavailable(
                f"refused: {would}, which was captured for an earlier navigation, not the page shown now. "
                "Re-run browser_requests and use an id or #n from that listing."
            )
        page = self._ring_page()
        if page is None:
            return
        shown = await asyncio.wait_for(
            self._tab.evaluate("document.location.href", return_by_value=True),
            timeout=max(0.1, min(NETWORK_BODY_TIMEOUT_S, deadline - time.monotonic())),
        )
        if not isinstance(shown, str):
            raise BrowserUnavailable(f"refused: the shown page's address could not be read (got {type(shown).__name__}); {would}")
        ring, now = urlsplit(page["url"]), urlsplit(shown)
        if (ring.scheme, ring.netloc) != (now.scheme, now.netloc):
            raise BrowserUnavailable(
                f"refused: the captured requests describe {page['url'][:160]} but the tab now shows {shown[:160]}; "
                f"{would}. Re-run browser_requests for the page shown."
            )

    async def _request_body_locked(
        self, request_id: str, max_bytes: int, want_headers: bool, replay_document: bool, deadline: float
    ) -> dict:
        from nodriver import cdp

        self._last_used = time.monotonic()
        token = str(request_id or "").strip()
        if self._tab is None:
            raise BrowserUnavailable(
                "the browser session was released since that listing: there is no session to read a body from. "
                "Re-open the page, re-run browser_requests, and use an id or #n from that listing."
            )
        if not token:
            raise BrowserUnavailable(
                "browser_body needs the request id in brackets or the #n sequence number from browser_requests"
            )
        entry = self._requests.get(token)
        # The listing prints the sequence as `#n`, so the `#` is part of what the
        # caller copies; bare digits are accepted too.
        number = token[1:] if token.startswith("#") else token
        if entry is None and number.isdigit():
            wanted = int(number)
            entry = next((rec for rec in self._requests.values() if rec["n"] == wanted), None)
        if entry is None:
            log.warning(
                "browser_body could not resolve %r: captured=%d seen=%d session_gen=%d capture_gen=%d",
                token, len(self._requests), self._seen_requests, self._session_gen, self._capture_gen,
            )
            raise self._capture_miss(token)
        await self._refuse_foreign_entry(token, entry, deadline)
        request_id = entry["id"]
        limit = max(200, min(int(max_bytes or 4000), MAX_REQUEST_BODY_BYTES))
        # The generated call asks for a RequestId, not the string the events carry:
        # passing the bare string fails inside nodriver on `.to_json()`.
        handle = cdp.network.RequestId(request_id)
        total, cut_early = None, False
        try:
            content, base64_encoded = await asyncio.wait_for(
                self._tab.send(cdp.network.get_response_body(request_id=handle)),
                timeout=max(0.1, min(NETWORK_BODY_TIMEOUT_S, deadline - time.monotonic())),
            )
            body_note = ""
        except Exception as error:
            # The browser keeps a body only while it holds the resource, so a body
            # asked for after a navigation is legitimately gone. A response served
            # from the profile's disk cache never enters the network stack's body
            # store at all — CDP answers "No resource with given identifier found".
            # Both say so in the report rather than returning a silent empty body.
            # The headers are still in hand, and the question is often about them.
            log.info("no body for %s: %s", request_id, error)
            content, base64_encoded = "", False
            body_note = "the browser no longer holds this body (served from the profile cache, or evicted after a navigation); headers may still answer"
            is_document = bool(entry.get("main")) or entry["type"] == "document"
            if is_document and not replay_document:
                # Replaying a document GET can consume a one-shot URL (an OAuth `?code=` callback, a magic link).
                body_note += (
                    "; this is a document, and its body needs an explicit replay (replayDocument: true), "
                    "which re-requests the URL and, for the page itself, re-navigates the tab"
                )
            else:
                # The Network domain is exhausted, but the Fetch domain can still
                # answer for a request it pauses in the Response stage, so replay
                # this one URL under a narrowly armed interception window.
                replayed = await self._fetch_body_via_interception(entry, limit, deadline)
                if isinstance(replayed, tuple):
                    content, base64_encoded, total, cut_early, body_note = replayed
                else:
                    body_note += f"; the replay produced no body: {replayed}"
        text = str(content or "")
        report = {
            "encoding": "base64" if base64_encoded else "text",
            "bytes": len(text) if total is None else total,
            "truncated": cut_early or len(text) > limit,
            "body": text[:limit],
            "bodyNote": body_note,
        }
        if want_headers:
            report["method"] = entry["method"]
            report["url"] = entry["url"]
            if entry["headers"]:
                report["headers"] = entry["headers"]
                report["headersSource"] = "wire"
                report["headersNote"] = ""
            elif entry.get("pageHeaders"):
                report["headers"] = entry["pageHeaders"]
                report["headersSource"] = "page"
                report["headersNote"] = (
                    "no extra-info event has arrived for this request yet, so these are the headers the page asked for, "
                    "without the ones the network stack adds (cookie, sec-fetch-*, accept-encoding). The wire headers "
                    "often arrive after the page settles: re-run browser_requests and ask for this id again"
                )
            else:
                report["headers"] = None
                report["headersSource"] = "none"
                report["headersNote"] = (
                    "no headers were captured for this request (no extra-info event, and the page set none). "
                    "Re-run browser_requests after the page settles and ask again; a request served from the memory cache never gets them"
                )
        return report

    @staticmethod
    async def _release_paused(tab, event, url: str, timeout_s: float) -> None:
        """Let one paused request go on; a request left paused hangs its loader."""
        from nodriver import cdp

        try:
            if event.response_status_code is not None or event.response_error_reason is not None:
                await asyncio.wait_for(tab.send(cdp.fetch.continue_response(request_id=event.request_id)), timeout_s)
            else:
                # No response-stage fields means the event came from the Request
                # stage, which only continue_request answers.
                await asyncio.wait_for(tab.send(cdp.fetch.continue_request(request_id=event.request_id)), timeout_s)
        except Exception as error:
            log.warning("could not release paused request %s (window for %s): %s", event.request_id, url[:120], error)

    async def _reacquire_tab(self, tab, timeout_s: float):
        """The Tab object nodriver now holds for `tab`'s target, or None if it is gone."""
        target_id = tab.target_id
        try:
            await asyncio.wait_for(self._browser.update_targets(), timeout=timeout_s)
        except Exception as error:
            log.warning("could not refresh the tab list to re-acquire target %s: %s", target_id, error)
            return None
        return next((item for item in self._browser.tabs if item.target_id == target_id), None)

    async def _fetch_body_via_interception(self, entry: dict, limit: int, op_deadline: float):
        """Re-issue one captured GET under Fetch interception and read its body.

        Protocol quirk: `Fetch.getResponseBody` may only be issued for a request
        paused in the Response stage, and it is mutually exclusive with the rest
        of the request's life — so the domain is armed with a pattern narrowed
        to this one URL at the Response stage, the request is re-issued, the
        body is read from the paused state, the request is released, and
        `Fetch.disable` runs on every path. Interception is never left standing.

        The replayed request is a new request: it may carry different
        credentials or headers than the original, and a cross-origin one carries
        none. The body is the best available answer for this URL, not a
        byte-for-byte replay. Only GETs are replayed — re-issuing a POST would
        repeat a state change the page already made.

        Runs under the tab lock (see `request_body`), so no other operation can
        navigate the tab inside the window; the generation check still makes a
        released or re-created session abandon the work instead of touching it.

        Returns `(content, is_base64, total_bytes, truncated, note)`, or a
        string naming why no body came back — never a silent empty body.
        """
        from nodriver import cdp

        tab = self._tab
        generation = self._session_gen
        # The listing's url is cut at MAX_REQUEST_URL_CHARS; replaying that would
        # chase a URL nobody asked for, so the replay reads its own longer copy.
        url = entry.get("fullUrl") or entry["url"]
        if entry["method"] != "GET":
            log.info("not replaying %s %s: only GETs are re-issued", entry["method"], url[:120])
            return f"only GETs are replayed, and this was a {entry['method']}"
        if int(entry.get("urlChars") or len(url)) > len(url):
            log.warning("refusing to replay %s: the url is %s chars, over the %d kept", url[:120], entry.get("urlChars"), MAX_REPLAY_URL_CHARS)
            return (
                f"refused: the request URL is {entry.get('urlChars')} chars and only {MAX_REPLAY_URL_CHARS} were kept, "
                "so a replay would request a different URL"
            )

        def stale() -> bool:
            return self._session_gen != generation or self._browser is None or self._tab is not tab

        def abandon(stage: str) -> BrowserUnavailable:
            log.warning("abandoning body replay of %s %s: the browser session was released or re-created", url[:120], stage)
            return BrowserUnavailable(
                f"the browser session was released or re-created {stage}; the body replay was abandoned "
                "and the current page was not touched. Re-open the page and re-run browser_requests."
            )

        # A document replay downloads the whole page through the proxy before
        # Fetch.getResponseBody answers; a large one outlived the short window and
        # came back as 0 bytes, so it gets the rest of the operation budget.
        window_s = FETCH_BODY_WINDOW_S if not entry.get("main") else max(FETCH_BODY_WINDOW_S, op_deadline - time.monotonic())
        deadline = min(time.monotonic() + window_s, op_deadline - FETCH_CLEANUP_RESERVE_S)

        def remaining() -> float:
            return max(0.1, deadline - time.monotonic())

        picked: asyncio.Future = asyncio.get_running_loop().create_future()
        strays: list[asyncio.Task] = []

        def on_paused(event, source=None):
            if source is not None and source is not tab:
                return
            # `url_pattern` treats '*' and '?' as wildcards, so a sibling request
            # can match the pattern; only the replayed URL is taken, the first
            # match pins the requestId, and everything else is released at once.
            if not picked.done() and str(event.request.url) == url and str(event.request.method) == "GET":
                picked.set_result(event)
            else:
                strays.append(asyncio.ensure_future(self._release_paused(tab, event, url, FETCH_CLEANUP_RESERVE_S)))

        tab.add_handler(cdp.fetch.RequestPaused, on_paused)
        armed_on = tab
        replay = None
        try:
            if stale():
                raise abandon("before the interception window opened")
            try:
                await asyncio.wait_for(tab.send(cdp.fetch.enable(patterns=[
                    cdp.fetch.RequestPattern(url_pattern=url, request_stage=cdp.fetch.RequestStage.RESPONSE)
                ])), remaining())
            except Exception as error:
                log.warning("could not arm Fetch interception for %s: %s", url[:120], error)
                return f"Fetch interception could not be armed: {error}"

            if entry.get("main"):
                if stale():
                    raise abandon("before the document replay navigated the tab")
                # A main-frame document cannot be re-requested from page context
                # without replacing the page underneath the agent, so the honest
                # replay is to re-navigate the tab to the same URL. Not `tab.get`:
                # nodriver's `get` drives the browser's first page target and then
                # re-attaches it, swapping the session id out from under the Fetch
                # domain armed here.
                replay = asyncio.create_task(tab.send(cdp.page.navigate(url)))
            else:
                script = (
                    f"(async()=>{{const r=await fetch({url!r},{{credentials:'same-origin'}});"
                    "await r.arrayBuffer();return r.status})()"
                )
                replay = asyncio.create_task(tab.evaluate(script, await_promise=True))

            try:
                event = await asyncio.wait_for(asyncio.shield(picked), remaining())
            except asyncio.TimeoutError:
                log.info("no Fetch.requestPaused event for %s within the armed window", url[:120])
                return (
                    "the replayed request never reached the interception window "
                    "(served from a cache, or it did not leave the page in time)"
                )
            if entry.get("main"):
                # nodriver quirk: after a navigation the Tab object we hold can go
                # stale, while `update_targets()` hands back the live one.
                live = await self._reacquire_tab(tab, remaining())
                if live is None:
                    log.warning("abandoning the document replay of %s: its tab could not be re-acquired", url[:120])
                    replay.cancel()
                    replay = None
                    await self._release_paused(tab, event, url, remaining())
                    raise BrowserUnavailable(
                        "the tab could not be re-acquired after the document replay navigated it; "
                        "the replay was abandoned. Re-open the page and re-run browser_requests."
                    )
                if live is not tab:
                    log.info("re-acquired a fresh Tab object for %s after the document replay", url[:120])
                    await self._apply_tab_policy(live)
                    self._tab = live
                    self._main_frame = live.target_id
                    self._track_network(reset=False)
                    tab = live
            try:
                body, base64_encoded = await asyncio.wait_for(
                    tab.send(cdp.fetch.get_response_body(request_id=event.request_id)), remaining()
                )
            except Exception as error:
                log.warning("Fetch.getResponseBody failed for %s: %s", url[:120], error)
                return f"the replayed response (status {event.response_status_code}) had no readable body: {error}"
            finally:
                # Release on every path, including the failure paths above: a
                # request left paused hangs the replay and the page's own
                # loader, which is a worse failure than a missing body.
                if not stale():
                    await self._release_paused(tab, event, url, remaining())
            if stale():
                raise abandon("while the interception window was open")

            # Measured: Fetch.getResponseBody answers base64 even for text bodies,
            # unlike the Network domain. Only the slice the cap can use is decoded.
            content, base64_encoded, total, cut = _bounded_fetch_body(str(body or ""), bool(base64_encoded), limit)
            return content, base64_encoded, total, cut, (
                "body re-fetched by replaying the request under Fetch interception; "
                "the replay is a new request and may differ in credentials or headers"
            )
        finally:
            if replay is not None and stale():
                # Nothing of the old session is awaited: the replay is dropped
                # rather than allowed to drive whatever tab now exists.
                replay.cancel()
                log.warning("dropped the replay of %s: the session changed during the window", url[:120])
            elif replay is not None:
                try:
                    # wait_for cancels the replay if it outlives the window, so a
                    # request that was never released cannot outlive the call.
                    await asyncio.wait_for(replay, remaining())
                except asyncio.TimeoutError:
                    log.info("replay of %s did not settle within the armed window", url[:120])
                except Exception as error:
                    # The replay can fail on its own (a CORS refusal when page
                    # script drains the body); the body question was already
                    # answered from the paused state, so this is context, not a
                    # failure of the call.
                    log.info("replay of %s failed: %s", url[:120], error)
            # The handler lives on the object it was registered on; the fresh one
            # is asked too, so neither can keep it.
            armed_on.remove_handler(cdp.fetch.RequestPaused, on_paused)
            tab.remove_handler(cdp.fetch.RequestPaused, on_paused)
            if strays:
                # Each release logs its own failure; this only bounds the wait.
                await asyncio.wait(strays, timeout=1.0)
            if self._session_gen != generation or self._browser is None:
                # The old target went with its browser; a disable sent now could
                # only reach a session that never armed interception.
                log.warning("not sending Fetch.disable for %s: the session changed during the window", url[:120])
            else:
                try:
                    await asyncio.wait_for(tab.send(cdp.fetch.disable()), FETCH_CLEANUP_RESERVE_S)
                except Exception as error:
                    log.warning("Fetch.disable failed after replaying %s: %s", url[:120], error)

    async def _wait_load(self, deadline: float) -> None:
        from nodriver import cdp

        errors = 0
        while time.monotonic() < deadline:
            try:
                result = await self._tab.send(cdp.runtime.evaluate(expression="document.readyState", return_by_value=True))
                errors = 0
            except Exception:
                errors += 1
                if errors >= TAB_ERROR_LIMIT:
                    raise RuntimeError("the tab stopped answering during load")
                result = None
            # `send` hands back (RemoteObject, ExceptionDetails): the value lives
            # on the first item, and the second is the error this is checking for.
            value = result[0].value if isinstance(result, tuple) and result and result[0] is not None else None
            if value == "complete":
                break
            await asyncio.sleep(READY_POLL_S)

    async def _wait_network_idle(self, deadline: float, quiet_s: float = NETWORK_QUIET_S) -> None:
        quiet_since: float | None = None
        while time.monotonic() < deadline:
            if not self._inflight:
                if quiet_since is None:
                    quiet_since = time.monotonic()
                elif time.monotonic() - quiet_since >= quiet_s:
                    return
            else:
                quiet_since = None
            await asyncio.sleep(NETWORK_POLL_S)

    async def _wait_settled(self, deadline: float) -> int:
        """Wait until the rendered text stops growing, and return its length.

        The load event is not the end of the story: a React app paints after it.
        A fixed sleep was measured to be both too short and wasteful, so the page
        is watched instead.
        """
        previous = -1
        stable = 0
        errors = 0
        while time.monotonic() < deadline:
            try:
                length = await self._tab.evaluate("document.body ? document.body.innerText.length : 0", return_by_value=True)
                errors = 0
            except Exception:
                errors += 1
                if errors >= TAB_ERROR_LIMIT:
                    raise RuntimeError("the tab stopped answering during settle")
                length = -1
            length = length if isinstance(length, int) else -1
            if length < 0:
                # No reading, not a page that stopped growing. Two failed reads
                # must not read as a settled page and end this wait early; only
                # the error counter is allowed to do that.
                previous, stable = -1, 0
                continue
            if length == previous:
                stable += 1
                if stable >= SETTLE_STABLE_POLLS:
                    return length
            else:
                stable = 0
                previous = length
            await asyncio.sleep(SETTLE_POLL_S)
        return previous

    async def _capture_cookies(self, tab) -> list[dict]:
        """What the browser holds right now, in the jar's own record shape."""
        from nodriver import cdp

        cookies = await tab.send(cdp.storage.get_cookies())
        records: list[dict] = []
        for item in cookies or []:
            same_site = getattr(item, "same_site", None)
            records.append({
                "name": item.name,
                "value": item.value,
                "domain": item.domain,
                "path": item.path,
                # CDP flags session cookies separately and reports their expiry as
                # -1; the jar uses -1 for the same thing, so a login the site ends
                # at browser close stays exactly that.
                "expires": -1 if getattr(item, "session", False) else int(getattr(item, "expires", -1) or -1),
                "httpOnly": bool(getattr(item, "http_only", False)),
                "secure": bool(getattr(item, "secure", True)),
                "sameSite": None if same_site is None else str(getattr(same_site, "name", same_site)),
            })
        return records

    def _fold_cookies(self, records: list[dict], injected: set[str]) -> int:
        """Split what the browser held by group and fold each into its own set.

        Only named groups are written, and only those this session put into the
        browser. The catch-all bucket is never sent anywhere (routing gives it
        `sendJar: false`), so filling it would create a credential store nothing
        reads; and the profile is shared with the harvester, so a cookie that was
        already in it is not this session's to vouch for.
        """
        if self.jar is None:
            return 0
        by_group: dict[str, list[dict]] = {}
        for record in records:
            domain = record.get("domain") or ""
            group = group_for(f"https://{domain.lstrip('.')}")
            if group not in injected:
                continue
            by_group.setdefault(group, []).append(record)
        return sum(self.jar.merge_from_cdp(group, items) for group, items in by_group.items())

    async def _clear_cookies(self, tab=None) -> None:
        """Drop every cookie the browser holds.

        The cookie store is browser-wide, not per render. Without this, a session
        injected for one group is still sent on the next render of another, and
        `send_jar=False` would only skip the injection, not the leftovers. The tab
        is a parameter because teardown clears after it has been unbound.
        """
        from nodriver import cdp

        await (tab if tab is not None else self._tab).send(cdp.network.clear_browser_cookies())

    async def _inject(self, group: str) -> None:
        """Hand the group's stored session to the browser."""
        from nodriver import cdp

        if self.jar is None or not group:
            return
        # Jar reads are disk work; the event loop belongs to the other requests.
        records = await asyncio.to_thread(self.jar.to_cdp_cookies, group)
        if not records:
            return
        params = []
        same_map = {
            "strict": cdp.network.CookieSameSite.STRICT,
            "lax": cdp.network.CookieSameSite.LAX,
            "none": cdp.network.CookieSameSite.NONE,
        }
        for item in records:
            expires = item.pop("expires", None)
            same = same_map.get(str(item.pop("sameSite", "") or "").lower())
            # `expires` is not a plain number to CDP: nodriver's TimeSinceEpoch
            # is a float subclass that carries the serializer.
            params.append(cdp.network.CookieParam(**item, expires=cdp.network.TimeSinceEpoch(expires) if expires is not None else None, same_site=same))
        await self._tab.send(cdp.storage.set_cookies(cookies=params))
        self._injected.add(group)
        log.info("injected %d cookies for group %s", len(params), group)

    async def render(self, url: str, max_chars: int, timeout_ms: int, send_jar: bool = True) -> dict:
        """Navigate, let the page settle, and hand back its rendered document."""
        page = await self.render_html(url, timeout_ms, send_jar)
        html = page["html"]
        text, links, truncated = await asyncio.to_thread(
            extract, html, max_chars, base_url=url, max_links=self.settings.max_links
        )
        return {
            "url": page["url"],
            "statusCode": page["status"],
            "text": text,
            "links": links,
            "truncated": truncated or page["htmlCut"],
            "contentType": "text/html",
            "engine": ENGINE,
            "htmlChars": len(html),
        }

    async def render_html(self, url: str, timeout_ms: int, send_jar: bool = True) -> dict:
        """The rendered document itself (`html`, `htmlCut`, `url`, `status`), for a caller that parses structure."""
        if self._session_open:
            # One tab. A web_fetch that escalates to the browser would navigate the
            # page away from a session the caller is driving and clear its cookies
            # on the way out, silently. The session is the more expensive thing.
            raise BrowserUnavailable("the tab is held by an open browser session; close that session first")
        timeout_s = max(1.0, timeout_ms / 1000)
        self._arm_watchdog()
        # One deadline for the whole call: waiting for the tab counts against the
        # budget, and must not be followed by a second full budget.
        deadline = time.monotonic() + timeout_s
        # Waiting for the tab is part of the budget: a queued render must not
        # inherit an unbounded wait behind the one page allowed to be open.
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=timeout_s)
        except asyncio.TimeoutError:
            raise BrowserUnavailable(f"the single browser tab was busy for longer than {timeout_s:.0f}s") from None

        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            page = await asyncio.wait_for(self._render_locked(url, send_jar, deadline), timeout=remaining)
        except asyncio.TimeoutError:
            # wait_for has cancelled the inner task mid-navigation; the browser it
            # was driving is terminated rather than left holding a session.
            await self._stop_locked()
            raise BrowserUnavailable(f"render exceeded {timeout_s:.0f}s") from None
        finally:
            self._lock.release()
        return page

    async def _render_locked(self, url: str, send_jar: bool, deadline: float) -> dict:
        if self._browser is None:
            await self._start()
        self._last_used = time.monotonic()
        try:
            # Same rule as the curl tier: an origin that never sees the session
            # must not see it rendered either — so the store is emptied first,
            # then filled with exactly the group being visited.
            await self._clear_cookies()
            if send_jar:
                await self._inject(group_for(url))
            self._inflight.clear()
            self._reset_capture()
            await self._tab.get(url)
            await self._wait_load(deadline)
            await self._wait_network_idle(min(deadline, time.monotonic() + SETTLE_MAX_S))
            await self._wait_settled(min(deadline, time.monotonic() + SETTLE_MAX_S))
            html, html_cut = _bounded_html(await self._tab.get_content())
            final_url = await self._tab.evaluate("document.location.href", return_by_value=True)
        except asyncio.CancelledError:
            # The supervisor cancels abandoned requests; a half-driven browser
            # with a session in it is not a thing to leave behind.
            await self._stop_locked()
            raise
        except Exception as error:
            # A dead tab or a lost connection: tear the browser down rather than
            # leave a half-broken one for the next caller.
            await self._stop_locked()
            raise BrowserUnavailable(f"render failed: {error}") from error
        finally:
            self._last_used = time.monotonic()
            if self._tab is not None:
                # `Exception` only, and bounded: a cancellation delivered here
                # means the supervisor abandoned this request, and swallowing it
                # would let the sidecar keep running something nobody is waiting
                # for — the same BaseException trap noted around the watchdog.
                try:
                    await asyncio.wait_for(self._clear_cookies(), timeout=3.0)
                except Exception as error:
                    log.warning("cookies were not cleared after the render: %s", error)

        if self._main_status is None:
            # No document response means the navigation itself failed (DNS,
            # proxy, TLS). Chrome's error page must not be reported as a 200.
            raise BrowserUnavailable(f"no document response: {self._nav_error or 'the navigation produced nothing'}")
        return {
            "html": html,
            "htmlCut": html_cut,
            "url": final_url if isinstance(final_url, str) and final_url else url,
            "status": int(self._main_status),
        }

    # --- the session: one page, kept open between calls ---------------------

    async def _session_op(self, timeout_ms: int, operation):
        """Run one session operation under the lock, inside the caller's budget.

        Same shape as `render`: waiting for the tab counts against the budget,
        and going over it tears the browser down rather than leave a page
        half-navigated with a session inside it.
        """
        timeout_s = max(1.0, timeout_ms / 1000)
        self._arm_watchdog()
        deadline = time.monotonic() + timeout_s
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=timeout_s)
        except asyncio.TimeoutError:
            raise BrowserUnavailable(f"the single browser tab was busy for longer than {timeout_s:.0f}s") from None
        try:
            # One deadline for waiting on the tab and for the work itself: an
            # operation must not get a second full budget after the queue.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            return await asyncio.wait_for(operation(deadline), timeout=remaining)
        except asyncio.TimeoutError:
            await self._stop_locked()
            raise BrowserUnavailable(f"the browser operation exceeded {timeout_s:.0f}s") from None
        except BrowserUnavailable:
            # The engine's own answer (no session open, tab busy): nothing to tear
            # down, and the reason must not be rewritten.
            raise
        except CaptchaFailure:
            # A solver refusal or a page with nothing solvable on it is an answer,
            # not a broken session: the browser is still healthy, and rewriting the
            # code to `browser-unavailable` sends the caller off to restart a tab
            # that never went wrong.
            raise
        except asyncio.CancelledError:
            await self._stop_locked()
            raise
        except Exception as error:
            # A dead tab or a lost CDP connection does not heal itself: end the
            # session here instead of failing every later call until the idle
            # timer happens to fire.
            await self._stop_locked()
            raise BrowserUnavailable(f"the browser session failed: {error}") from error
        finally:
            # Any call that touched the tab is use. A session driven through
            # state/act alone must not be reaped by the idle watchdog mid-flow.
            self._last_used = time.monotonic()
            self._lock.release()

    def _require_session(self) -> None:
        if self._browser is None or self._tab is None:
            raise BrowserUnavailable("no page is open; open one first")

    def _check_landing(self, url: str) -> None:
        """Re-apply the address gate to where the page actually ended up.

        The gate on `open` covers the URL the caller asked for. A click, a form
        post, a redirect or a script-driven location change is the page's choice,
        and it can land on an address the caller was refused — loopback included,
        since Chrome routes loopback around the proxy unless told otherwise.
        """
        try:
            admit(url)
        except RejectedUrl as error:
            raise BrowserUnavailable(f"the page moved to a refused address: {error}") from error

    async def _settle_tabs(self) -> dict:
        """Adopt a login window, or close a tab the page opened behind our back.

        One tab is the rule, and a `target=_blank` link is noise that gets closed.
        But a window that follows a click into a frame is the site's own sign-in
        hand-off: it runs on the identity provider, posts the result back to
        `window.opener`, and closes itself. Closing it mid-flight breaks the login
        and reports success, so the session moves into it and the page that opened
        it is kept alive until the hand-off ends.
        """
        if self._browser is None or self._tab is None:
            return {"adopted": False, "adoptedUrl": "", "closed": 0}
        # The tab list is a snapshot, not a live view: nodriver rebuilds it only
        # on a Target.getTargets round trip. Without this, a window the page just
        # opened is invisible here, and the policy below decides on stale data.
        try:
            await self._browser.update_targets()
        except Exception as error:
            log.warning("the tab list could not be refreshed: %s", error)
        # The page that opened the window we are driving is an extra tab on
        # purpose: it is the hand-off's `window.opener` and must survive every
        # later settle, or the result of the login has nowhere to land.
        extras = [tab for tab in self._browser.tabs if tab is not self._tab and tab is not self._opener]
        if not extras:
            # No window to decide about. The licence is not spent: a popup that
            # attaches after this call still has to be recognised as the hand-off.
            return {"adopted": False, "adoptedUrl": "", "closed": 0}
        wanted, self._expect_handoff = self._expect_handoff, False
        if wanted:
            # The window the press opened is adopted even if the page also spawned
            # noise in the same breath; the noise goes, the hand-off stays.
            popup, strays = extras[0], extras[1:]
            url = str(getattr(popup, "url", "") or "")
            # The same gate as any navigation: a login window is not exempt from
            # where it is allowed to be. A popup that has not navigated yet has no
            # address to judge, and the snapshot below re-checks where it landed.
            if url.startswith(("http://", "https://")):
                self._check_landing(url)
            # Configured before the session moves into it. If the policy call
            # fails — the window closed itself mid-press, CDP rejected something —
            # the failure must not leave us driving a window that answers with the
            # host's clock and a real position.
            await self._apply_tab_policy(popup)
            self._opener = self._tab
            self._tab = popup
            self._main_frame = popup.target_id
            # The status and in-flight tracking are per tab: without re-attaching,
            # the adopted window reports no requests and no document status. The
            # opener's status is dropped rather than kept: it describes a page we
            # are no longer looking at, and reporting it against the adopted URL
            # would tell the caller that a window it never loaded answered 200.
            # Whatever arrives after `network.enable` here is about this window.
            self._main_status = None
            self._inflight.clear()
            self._track_network(reset=False)
            log.info("the session moved into the window the page opened")
            for tab in strays:
                with contextlib.suppress(Exception):
                    await tab.close()
            return {"adopted": True, "adoptedUrl": url, "closed": len(strays)}
        for tab in extras:
            with contextlib.suppress(Exception):
                await tab.close()
        return {"adopted": False, "adoptedUrl": "", "closed": len(extras)}

    async def _heal_tab(self) -> None:
        """Take the session back to the opener when the window we drove closed.

        A sign-in popup posts its result and closes itself; the login then lives in
        the page that opened it, which is still there. Without this, the next call
        would fail on a dead target and the caller would lose a finished login.
        """
        if self._browser is None or self._tab is None:
            return
        # Ask before concluding, every time: the list is a snapshot, and a window
        # that closed itself is often still in the copy we hold. Trusting that
        # copy returns a tab whose CDP session is gone, and the next raw read then
        # dies on "Session with given id not found" instead of moving back to the
        # page that opened it. Bounded like the other CDP calls: a wedged socket
        # must not spend the whole remaining operation budget here.
        try:
            await asyncio.wait_for(self._browser.update_targets(), timeout=5.0)
        except asyncio.TimeoutError as error:
            raise BrowserUnavailable("the browser stopped answering while tabs were being listed") from error
        if self._tab in self._browser.tabs:
            return
        opener, self._opener = self._opener, None
        if opener is not None and opener in self._browser.tabs:
            # Re-asserted rather than assumed, and before the switch: the invariant
            # is that whichever tab is being driven carries the overrides.
            await self._apply_tab_policy(opener)
            self._tab = opener
            self._main_frame = opener.target_id
            # Nothing has been observed on this target since the window closed, so
            # no status is claimed for it.
            self._main_status = None
            self._inflight.clear()
            self._track_network(reset=False)
            log.info("the window closed; the session moved back to the page that opened it")
            return
        # Nothing left to drive. The session ends here rather than being marked
        # open on a dead tab, or every later call would fail on a session that
        # exists only in our bookkeeping.
        await self._stop_locked()
        raise BrowserUnavailable("the tab the session was driving is gone")

    async def _evaluate_json(self, script: str, what: str) -> dict:
        """Run a page script that answers with a JSON string.

        nodriver asks CDP for deep serialization, which leaves a plain object as
        a RemoteObject or a list of key/value pairs. A string survives intact,
        which is why the page scripts stringify their answers.
        """
        await self._heal_tab()
        raw = await self._tab.evaluate(script, return_by_value=True)
        if not isinstance(raw, str):
            raise RuntimeError(f"{what} did not come back as a string (got {type(raw).__name__})")
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise RuntimeError(f"{what} came back as {type(parsed).__name__}, expected an object")
        return parsed

    async def _snapshot(self, max_elements: int) -> dict:
        # The caller's number is a request, not a licence: the configured cap is
        # the ceiling. An unbounded one is a multi-megabyte line on the wire, and
        # the sidecar's framing drops the whole connection over that.
        limit = max(0, min(int(max_elements), self.settings.browser_max_elements))
        page = await self._evaluate_json(snapshot_script(limit), "the element snapshot")
        if not isinstance(page.get("elements"), list):
            raise RuntimeError("the element snapshot has no 'elements' list")
        if limit == 0:
            # The caller asked for no listing. The page identity still comes back,
            # and an empty list that was asked for is not a list that was cut.
            page["elements"] = []
            page["truncated"] = False
        return page

    async def _visible_text(self, max_chars: int) -> tuple[str, bool]:
        """What a person would read on screen, whitespace collapsed.

        Also says whether it was cut: a preview has to admit that the page goes
        on, or the caller reads half a page and believes it saw the page.
        """
        await self._heal_tab()
        raw = await self._tab.evaluate("document.body ? document.body.innerText : ''", return_by_value=True)
        if not isinstance(raw, str):
            # nodriver returns the RemoteObject whenever the value is falsy — an
            # empty page answers with an empty string — and the ExceptionDetails
            # when the page raised. Neither is page text, and str() of either
            # would read as a confident paragraph of Python internals.
            if raw is None or getattr(raw, "value", None) == "":
                return "", False
            raise RuntimeError(f"the page text came back as {type(raw).__name__}, not a string")
        # A preview is a preview: the configured size is the ceiling, whatever the
        # caller asked for.
        limit = max(0, min(int(max_chars), self.settings.browser_text_chars))
        text = " ".join(raw.split())
        return text[:limit], len(text) > limit

    async def _text_length(self) -> int:
        """How much text the page holds.

        A change check that only compares the preview misses content added below
        the cut; the length cannot be fooled that way.
        """
        # Asked for as a string: nodriver hands back the RemoteObject for any
        # falsy value, so a page with no text at all would read as unknown
        # instead of as zero.
        raw = await self._tab.evaluate("String(document.body ? document.body.innerText.length : 0)", return_by_value=True)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return -1

    async def open(self, url: str, send_jar: bool, max_elements: int, text_chars: int, timeout_ms: int) -> dict:
        """Navigate and leave the page open: this is the start of a session."""

        async def run(deadline: float) -> dict:
            if self._browser is None:
                await self._start()
            self._last_used = time.monotonic()
            try:
                # A session starts from exactly one group's cookies. They are not
                # cleared after each call — a login flow needs them to survive —
                # but they are cleared when the session ends.
                await self._clear_cookies()
                if send_jar:
                    await self._inject(group_for(url))
                self._inflight.clear()
                self._reset_capture()
                await self._tab.get(url)
                await self._wait_load(deadline)
                await self._wait_network_idle(min(deadline, time.monotonic() + SETTLE_MAX_S))
                await self._wait_settled(min(deadline, time.monotonic() + SETTLE_MAX_S))
                page = await self._snapshot(max_elements)
                page["text"], page["textTruncated"] = await self._visible_text(text_chars)
                # The navigation may have ended somewhere else than asked: a
                # redirect is the page's choice, not the caller's, and the address
                # gate has to be applied to where the agent actually landed.
                final = str(page.get("url") or url)
                self._check_landing(final)
                tabs = await self._settle_tabs()
                if tabs["adopted"]:
                    # A window took the session. What the caller is told about this
                    # open is what is on screen now, and that address goes through
                    # the gate like any other landing.
                    page = await self._snapshot(max_elements)
                    page["text"], page["textTruncated"] = await self._visible_text(text_chars)
                    final = str(page.get("url") or "")
                    if final:
                        self._check_landing(final)
            except asyncio.CancelledError:
                await self._stop_locked()
                raise
            except Exception as error:
                await self._stop_locked()
                raise BrowserUnavailable(f"open failed: {error}") from error
            finally:
                self._last_used = time.monotonic()
            if self._main_status is None:
                raise BrowserUnavailable(f"no document response: {self._nav_error or 'the navigation produced nothing'}")
            self._session_open = True
            page["url"] = final
            page["statusCode"] = int(self._main_status)
            page["group"] = group_for(url)
            page["closedTabs"] = tabs["closed"]
            page["handoff"] = tabs["adopted"]
            page["adoptedTab"] = tabs["adoptedUrl"]
            return page

        return await self._session_op(timeout_ms, run)

    async def state(self, max_elements: int, text_chars: int, timeout_ms: int) -> dict:
        """What is on screen now: numbered elements plus a text preview."""

        async def run(deadline: float) -> dict:
            self._require_session()
            page = await self._snapshot(max_elements)
            page["text"], page["textTruncated"] = await self._visible_text(text_chars)
            # A page can move itself between two of our calls. What is shown here
            # goes through the gate like anywhere else, or a refused origin would
            # reach the caller as just another page.
            try:
                self._check_landing(str(page.get("url") or ""))
            except BrowserUnavailable:
                await self._stop_locked()
                raise
            return page

        return await self._session_op(timeout_ms, run)

    async def _click_at(self, x: int, y: int, src: str = "") -> dict:
        """A real mouse click at viewport coordinates.

        For an element that hosts a document of its own: its contents are closed
        to our DOM, but input events go to whatever is painted at those pixels,
        cross-origin included. This is how a sign-in widget gets pressed.

        The frame's own session has to be in the browser first. Only the group of
        the page we opened is injected, and a sign-in widget belongs to the
        identity provider, not to the site that embedded it — pressed without it,
        the login screen asks for credentials we already hold.
        """
        from nodriver import cdp

        if src:
            # The frame's address is the page's own claim, so it goes through the
            # same gate as any address the page hands us. A refused or private
            # target does not get a session, whatever the element says it is.
            try:
                admit(src)
            except RejectedUrl as error:
                log.warning("no session loaded for the frame at %r: %s", src[:200], error)
            else:
                group = group_for(src)
                if group != FALLBACK_GROUP:
                    await self._inject(group)
        for kind in ("mousePressed", "mouseReleased"):
            # The module is `input_`: `input` is a Python keyword, and nodriver
            # keeps the CDP name with the underscore the generator adds.
            await self._tab.send(cdp.input_.dispatch_mouse_event(
                type_=kind, x=float(x), y=float(y), button=cdp.input_.MouseButton.LEFT, click_count=1))
        # Whatever this press opens, it was opened by a press into a frame: the
        # window that appears is the site's own login, so `_settle_tabs` adopts it.
        self._expect_handoff = True
        return {"ok": True, "tag": "frame", "text": "", "method": "coordinates"}

    async def act(self, index: int, action: str, value: str, max_elements: int, text_chars: int, timeout_ms: int) -> dict:
        """Do one thing to one numbered element, then re-snapshot the page."""
        # Built here, outside the lock: an unknown action is a caller error and
        # must fail before a browser is touched.
        script = act_script(index, action, value)

        async def run(deadline: float) -> dict:
            self._require_session()
            # The window we were driving may have closed itself: heal before the
            # first raw read, or a finished login dies on a detached target.
            await self._heal_tab()
            before_url = await self._tab.evaluate("document.location.href", return_by_value=True)
            # A form that posts to the same path leaves the URL untouched, so the
            # URL alone cannot say whether anything happened.
            before_len = await self._text_length()
            # Compared against the preview read after the action, so it is taken at
            # the same cap: comparing a 400-char sample against a 2500-char one
            # would call every page "changed".
            before_text = (await self._visible_text(text_chars))[0]
            if action == "click":
                # A press on a frame element fires on the frame, not on the button
                # drawn inside it, so the box is measured first and the press is
                # routed to the pixels when the element hosts another document.
                box = await self._evaluate_json(box_script(index), "the element box")
                if not box.get("ok"):
                    return {"ok": False, "reason": str(box.get("reason") or "the element is not on this page")}
                if box.get("tag") in EMBEDDED_TAGS:
                    applied = await self._click_at(int(box["x"]), int(box["y"]), str(box.get("src") or ""))
                else:
                    applied = await self._evaluate_json(script, "the action")
            else:
                applied = await self._evaluate_json(script, "the action")
            if not applied.get("ok"):
                return {"ok": False, "reason": str(applied.get("reason") or "the action did not apply")}
            # The action has landed. Everything below reads the page back, and a
            # failed read must not be reported as a failed action: the caller
            # would retry and submit the form a second time.
            try:
                await self._wait_load(deadline)
                await self._wait_network_idle(min(deadline, time.monotonic() + SETTLE_MAX_S))
                await self._wait_settled(min(deadline, time.monotonic() + SETTLE_MAX_S))
                tabs = await self._settle_tabs()
                page = await self._snapshot(max_elements)
                page["text"], page["textTruncated"] = await self._visible_text(text_chars)
                self._check_landing(str(page.get("url") or ""))
            except asyncio.CancelledError:
                raise
            except BrowserUnavailable:
                # The page moved somewhere the caller was refused. The session ends
                # on that, and the reason stays the gate, not a read failure.
                await self._stop_locked()
                raise
            except Exception as error:
                log.warning("the page could not be read back after %s: %s", action, error)
                # The settle never ran, so the hand-off licence would otherwise
                # survive into the next action and adopt an unrelated window.
                self._expect_handoff = False
                return {"ok": True, "applied": applied, "page": None, "rereadError": str(error)}
            # The numbering is rebuilt on every snapshot, so the caller has to be
            # told when the page underneath it moved. The length is compared as
            # well: a validation error or a new block of results can sit below the
            # preview, where comparing the preview alone would say "nothing".
            # A failed diagnostic must not destroy the session: the action has
            # already landed by here, and this is exactly the moment right after a
            # login someone waited for. -1 means "unknown", and an unknown length
            # does not get to claim the page changed.
            try:
                after_len = await self._text_length()
            except Exception as error:
                log.warning("the page length could not be read after %s: %s", action, error)
                after_len = -1
            page["navigated"] = page.get("url") != before_url
            page["changed"] = bool(page["navigated"]) or str(page.get("text", "")) != before_text
            if after_len >= 0:
                page["changed"] = page["changed"] or after_len != before_len
            page["closedTabs"] = tabs["closed"]
            page["handoff"] = tabs["adopted"]
            page["adoptedTab"] = tabs["adoptedUrl"]
            return {"ok": True, "applied": applied, "page": page}

        return await self._session_op(timeout_ms, run)

    async def read(self, max_chars: int, timeout_ms: int) -> dict:
        """The current page as text and links, the same shape curl would return."""

        async def run(deadline: float) -> dict:
            self._require_session()
            await self._heal_tab()
            final_url = await self._tab.evaluate("document.location.href", return_by_value=True)
            address = final_url if isinstance(final_url, str) else ""
            # The same gate as open and act: the page may have moved since the
            # last call, and its text is not handed over before that is checked.
            if address:
                try:
                    self._check_landing(address)
                except BrowserUnavailable:
                    await self._stop_locked()
                    raise
            html, html_cut = _bounded_html(await self._tab.get_content())
            return {"html": html, "htmlCut": html_cut, "url": address if address else ""}

        page = await self._session_op(timeout_ms, run)
        # Same ceiling as the curl tier: the caller's number cannot buy a bigger
        # answer than the profile is configured for.
        limit = max(0, min(int(max_chars), self.settings.browser_max_chars))
        text, links, truncated = await asyncio.to_thread(
            extract, page["html"], limit, base_url=page["url"], max_links=self.settings.max_links
        )
        return {"url": page["url"], "text": text, "links": links, "truncated": truncated or page["htmlCut"]}

    async def captcha(self, solve: bool, timeout_ms: int) -> dict:
        """What captcha machinery the page carries, and — on request — a bought token.

        Solving spends money from the account, so it never happens unless the
        caller asks for it. The token itself is not handed back: it is a
        credential-shaped blob whose only use is inside the page, and the reply
        travels into the caller's context.
        """

        async def run(deadline: float) -> dict:
            self._require_session()
            await self._heal_tab()
            # The widget is put on the page by the page's own script, well after
            # the document settles: probed once right after a navigation, a
            # challenge page reads as a heading that says "Loading" and nothing
            # else. Poll a bounded window and stop at the first widget.
            probe: dict = {}
            for attempt in range(6):
                probe = await self._evaluate_json(captcha_script(), "the captcha probe")
                if probe.get("widgets") or deadline - time.monotonic() < 2.0:
                    break
                await asyncio.sleep(1.0)
            widgets = probe.get("widgets") if isinstance(probe.get("widgets"), list) else []
            answer = {
                "pageUrl": str(probe.get("pageUrl") or ""),
                "widgets": widgets,
                "dataS": probe.get("dataS") if isinstance(probe.get("dataS"), list) else [],
                "responseFields": int(probe.get("responseFields") or 0),
                "answerFields": probe.get("answerFields") if isinstance(probe.get("answerFields"), list) else [],
                "alreadyAnswered": bool(probe.get("filled")),
                "hasGrecaptcha": bool(probe.get("hasGrecaptcha")),
                "hasEnterpriseApi": bool(probe.get("hasEnterpriseApi")),
                "hasChallengeCallback": bool(probe.get("hasChallengeCallback")),
                "v3Render": str(probe.get("v3Render") or ""),
                "solved": False,
            }
            if not solve:
                return answer
            if not self.anticaptcha.configured:
                raise CaptchaFailure("not-configured", "no anti-captcha key is configured")
            solvable = [w for w in widgets if isinstance(w, dict) and w.get("sitekey") and "v2" in str(w.get("kind", ""))]
            if not solvable:
                raise CaptchaFailure("nothing-solvable", "no reCAPTCHA v2 widget with a site key on this page")
            widget = solvable[0]
            identity = captcha_identity(
                answer["pageUrl"], str(widget["sitekey"]), str(widget.get("kind") or ""), bool(widget.get("enterprise"))
            )
            # Claimed before the solver is contacted: the cap counts attempts,
            # not successes. Runs under the session lock, so no two claims race.
            attempt = self.solve_budget.claim(identity)
            log.info("solve attempt %d/%d for %s", attempt, self.solve_budget.cap, identity)
            solved = await self.anticaptcha.solve_recaptcha_v2(
                answer["pageUrl"],
                str(widget["sitekey"]),
                deadline,
                enterprise=bool(widget.get("enterprise")),
                # The widget's own `data-s` if it carries one, else the page's.
                data_s=str(widget.get("dataS") or (answer["dataS"][0] if answer["dataS"] else "")),
            )
            applied = await self._evaluate_json(captcha_inject_script(solved["token"]), "the token injection")
            answer.update({
                "solved": bool(applied.get("ok")),
                "taskId": solved["taskId"],
                "cost": solved.get("cost"),
                # The token was minted by a browser like this one; a mismatch in
                # the submission is the usual reason a valid token is refused.
                "workerUserAgent": solved["workerUserAgent"],
                "applied": applied.get("applied") or [],
                "widget": widget,
                "captchaIdentity": identity,
                "attempt": attempt,
                "attemptCap": self.solve_budget.cap,
            })
            return answer

        return await self._session_op(timeout_ms, run)

    async def close_session(self, timeout_ms: int = 20_000) -> dict:
        """End the session: cookies out, browser out.

        Bounded like every other call, and honest about the thing the caller is
        really closing the session for: if the cookies did not go, saying so is
        the difference between a closed session and a claimed one.
        """
        timeout_s = max(1.0, timeout_ms / 1000)
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=timeout_s)
        except asyncio.TimeoutError:
            raise BrowserUnavailable("the browser tab was busy for longer than the close budget") from None
        try:
            cleared = await self._stop_locked()
        finally:
            self._lock.release()
        return {"closed": True, "cookiesCleared": cleared}
