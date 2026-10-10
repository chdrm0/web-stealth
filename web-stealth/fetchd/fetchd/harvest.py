"""One-time interactive cookie harvest.

Opens each origin in a real browser that exits through the same proxy the curl
tier will use, waits for a human to log in, then writes one cookie set per group
into the jar. Values are never printed — only names, domains and counts.

Run it from a terminal on a display you can see:

    STEALTH_JAR_DIR=~/.dsh/web-stealth/jar python -m fetchd.harvest

Modes:
    default   launch a browser on a private profile and wait for login
    --attach  connect to a browser you started yourself (remote-debugging-port)
    --smoke   no interaction: open the origins and report what appears
"""

from __future__ import annotations

import argparse
import asyncio
import queue
import signal
import sys
import threading
from pathlib import Path

from nodriver import cdp

from .config import Settings
from .jar import Jar, group_for

#: Where a human is expected to sign in. Kept deliberately boring: the plain
#: entry point of each origin, not a deep link that may itself be gated.
LOGIN_URLS = {
    "google": "https://www.google.com/",
    "github": "https://github.com/login",
    "brave": "https://search.brave.com/",
}

DEFAULT_BROWSER = "/usr/bin/brave"
DEFAULT_PROFILE = "~/.dsh/web-stealth/browser-profile"


def to_record(cookie: cdp.network.Cookie) -> dict:
    """CDP cookie -> the canonical jar record (same shape as CookieManager)."""
    record = {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path,
        "expires": cookie.expires,
        "httpOnly": cookie.http_only,
        "secure": cookie.secure,
        "sameSite": cookie.same_site.value if cookie.same_site else None,
    }
    if cookie.partition_key:
        record["partitionKey"] = cookie.partition_key.to_json()
    return record


def split_by_group(cookies: list[cdp.network.Cookie]) -> dict[str, list[dict]]:
    """Bucket cookies by jar group.

    A leading dot (`.google.com`) is a domain-match marker, not part of the host.
    """
    buckets: dict[str, list[dict]] = {}
    for cookie in cookies:
        host = (cookie.domain or "").lstrip(".").lower()
        if not host:
            continue
        buckets.setdefault(group_for(f"https://{host}"), []).append(to_record(cookie))
    return buckets


async def open_origins(tab, groups: list[str], settle_s: float) -> None:
    for group in groups:
        url = LOGIN_URLS.get(group)
        if url is None:
            print(f"  ? no login url known for group {group!r}", file=sys.stderr)
            continue
        print(f"  opening {url}")
        await tab.send(cdp.page.navigate(url=url))
        await asyncio.sleep(settle_s)


async def harvest(settings: Settings, args: argparse.Namespace) -> int:
    import nodriver as uc

    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    jar = Jar(settings.jar_dir)
    attached = args.attach is not None

    if attached:
        browser = await uc.start(host="127.0.0.1", port=args.attach)
        tab = browser.main_tab
        if tab is None:
            print("attached browser has no tab to read a context from", file=sys.stderr)
            return 2
    else:
        config = uc.Config(
            user_data_dir=Path(args.profile).expanduser(),
            headless=args.headless,
            browser_executable_path=args.browser,
            browser_args=["--no-first-run", "--no-default-browser-check"],
            sandbox=False,
        )
        browser = await uc.start(config=config)

    try:
        if not attached:
            # Proxy belongs to the context, not the process: one exit for the
            # whole session, and the session outlives the tab.
            tab = await browser.create_context(
                url="about:blank",
                new_window=True,
                dispose_on_detach=False,
                proxy_server=settings.browser_proxy,
            )
            await asyncio.sleep(1)

        info = await tab.send(cdp.target.get_target_info(tab.target_id))
        context_id = info.browser_context_id
        print(f"browser up: proxy={settings.browser_proxy} context={context_id}")

        await open_origins(tab, groups, settle_s=3.0)

        if not args.smoke:
            print()
            print("Log in in the browser window. The origins opened for you:")
            for group in groups:
                print(f"  - {group}: {LOGIN_URLS.get(group, '(unknown)')}")
            print(f"Press Enter here when you are done (or after {args.wait}s).")
            if wait_for_line(args.wait):
                print("login window closed by you; harvesting")
            else:
                print(f"wait window of {args.wait}s elapsed; harvesting what is there")

        cookies = await browser.send(cdp.storage.get_cookies(browser_context_id=context_id))
        buckets = split_by_group(list(cookies))

        print()
        print(f"harvested {len(cookies)} cookie(s) from the context")
        written = 0
        for group in groups:
            records = buckets.get(group, [])
            if not records:
                print(f"  {group:<8} 0 cookies — nothing written, existing set kept")
                continue
            if args.smoke:
                # A report is not a write. Smoke answers "what does this exit look
                # like right now", and a run that only looked must not replace a
                # set a real login built.
                print(f"  {group:<8} {len(records)} cookie(s) — smoke run, nothing written")
                written += len(records)
                continue
            jar.save(group, records)
            written += len(records)
            names = ", ".join(sorted({r["name"] for r in records})[:8])
            print(f"  {group:<8} {len(records)} cookie(s) -> {jar.path(group)}")
            print(f"           names: {names}{' …' if len(records) > 8 else ''}")
        ungrouped = sum(len(v) for k, v in buckets.items() if k not in groups)
        if ungrouped:
            print(f"  (skipped {ungrouped} cookie(s) outside the requested groups)")
        print(f"total written: {written}")
        return 0 if written else 1
    finally:
        if attached:
            # Never kill a browser we did not start.
            await browser.detach()
        else:
            # `stop()` is synchronous in 0.50.5; `aclose()` is the awaitable form.
            await browser.aclose()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m fetchd.harvest", description=__doc__.splitlines()[0])
    parser.add_argument("--groups", default="google,github,brave", help="comma-separated jar groups")
    parser.add_argument("--attach", type=int, default=None, help="connect to a browser on this remote-debugging port")
    parser.add_argument("--headless", action="store_true", help="launch without a window (login is then impossible)")
    parser.add_argument("--smoke", action="store_true", help="open the origins, report cookies, do not wait")
    parser.add_argument("--wait", type=int, default=900, help="seconds to wait for the manual login")
    parser.add_argument("--browser", default=DEFAULT_BROWSER, help="browser executable")
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="persistent profile directory for the harvest browser")
    return parser.parse_args(argv)


class HarvestCancelled(Exception):
    """Raised from the SIGTERM handler so the teardown runs instead of dying."""


def _raise_cancelled(signum, frame):
    raise HarvestCancelled()


def wait_for_line(timeout: float) -> bool:
    """True when a line arrived on stdin, False when the window closed.

    A daemon thread, deliberately: `asyncio.to_thread` runs on the default
    executor, and `asyncio.run` drains that executor on the way out — a thread
    still blocked in `readline` would keep the process alive with the browser
    holding the profile lock. A daemon thread is simply gone at exit. A loop
    reader is not an option either: `add_reader` needs an epoll-able fd and stdin
    is not always one.
    """
    box: queue.Queue = queue.Queue(maxsize=1)

    def reader():
        try:
            box.put(('line', sys.stdin.readline()))
        except Exception as error:  # a closed or redirected stdin is a closed window
            box.put(('error', str(error)))

    threading.Thread(target=reader, daemon=True).start()
    try:
        kind, value = box.get(timeout=timeout)
    except queue.Empty:
        return False
    if kind == 'error':
        print(f"stdin is not readable ({value}); harvesting what the window gave")
    return True


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = Settings.from_env()
    # The plugin cancels with SIGTERM. Left at its default that kills the process
    # between bytecodes, the `finally` never runs, and the browser it launched
    # keeps the profile lock — every later browser call on this machine then fails
    # with a message blaming the sandbox. Raising instead of dying lets the
    # teardown run.
    signal.signal(signal.SIGTERM, _raise_cancelled)
    try:
        return asyncio.run(harvest(settings, args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except HarvestCancelled:
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
