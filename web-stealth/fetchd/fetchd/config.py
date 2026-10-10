"""Runtime settings, read from the environment the JS supervisor provides.

Every value has a safe default so the sidecar can also be run by hand. A
malformed value fails at startup, not mid-request.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from error
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return default if raw is None or raw == "" else raw


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


#: The identity the curl tier presents belongs to the browser on the same machine,
#: so its version comes from the binary and not from a constant written here: a
#: hardcoded Chrome/153 sat beside an updated browser, and a site comparing the two
#: tiers saw two clients.
UA_TEMPLATE = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
# Chrome's not-brand pair is a rotating decoy: it does not follow from the major
# version. This pair is what the browser here sends at 155, measured; the
# fingerprint probe replaces it with the header set the browser really sends.
SEC_CH_UA_TEMPLATE = '"Google Chrome";v="{major}", "Chromium";v="{major}", "Not(A:Brand";v="24"'


def _browser_major(executable: str) -> int | None:
    """The Chromium major version, only when the binary states it unambiguously.

    Brave prints `Brave Browser 154.1.96.61` — Brave's own number, not the engine's
    (measured: that build runs Chromium 155). So a bare version is trusted only for
    binaries that name their engine, and the browser tier's own report is what the
    caller prefers anyway.
    """
    try:
        completed = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or "") + (completed.stderr or "")
    chromium = re.search(r"Chromium:\s*(\d{2,3})\.", output)
    if chromium:
        return int(chromium.group(1))
    if re.match(r"^\s*(Chromium|Google Chrome|Microsoft Edge)\b", output):
        majors = re.findall(r"\b(\d{2,3})\.\d+\.\d+\.\d+\b", output)
        return int(majors[0]) if majors else None
    return None


def _chrome_target(major: int | None) -> str:
    """The curl_cffi Chrome target to impersonate when the config names none.

    curl_cffi ships a fixed ladder of Chrome builds and its newest is not the
    newest Chrome. The rule is the newest target that is not ahead of the browser
    being imitated: a curl tier claiming `chrome150` while the browser tier reports
    131 is two identities, and the mismatch shows in TLS, headers and HTTP/2 at
    once. When the browser is ahead of everything curl_cffi knows, the newest
    available is the closest thing to it, and a pinned constant would only rot.
    """
    from curl_cffi.requests.impersonate import BrowserType

    ladder = sorted(
        (
            int(match.group(1))
            for match in (re.fullmatch(r"chrome(\d+)", member.value) for member in BrowserType)
            if match
        ),
        reverse=True,
    )
    if not ladder:
        # A curl_cffi build listing no Chrome target: let it choose its own default.
        return "chrome"
    if major is None:
        return f"chrome{ladder[0]}"
    for candidate in ladder:
        if candidate <= major:
            return f"chrome{candidate}"
    return f"chrome{ladder[0]}"


def _fingerprint_path(jar_dir: str) -> str:
    """Where the browser tier records what it measured about itself."""
    return os.path.join(os.path.dirname(os.path.abspath(jar_dir)), "fingerprint.json")


def _observed_fingerprint(jar_dir: str) -> dict[str, str]:
    """What the browser tier measured about itself, if it has measured anything.

    Absent or malformed is not an error — the derived defaults stand in.
    """
    try:
        with open(_fingerprint_path(jar_dir), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


#: What the browser refuses to fetch. These are URLPattern strings, not globs —
#: CDP validates them and rejects a glob with `failed to parse as a URLPattern`.
#: `*` spans path separators and the pattern is anchored, so `/*.png` covers a
#: nested path and ignores the query string. `*.ts` is deliberately absent: it
#: collides with JavaScript bundles, and HLS segments are caught by m3u8 and m4s.
BLOCK_MEDIA_PATTERNS = (
    "*://*/*.png", "*://*/*.jpg", "*://*/*.jpeg", "*://*/*.gif", "*://*/*.webp",
    "*://*/*.avif", "*://*/*.bmp", "*://*/*.ico", "*://*/*.svg",
    "*://*/*.mp4", "*://*/*.webm", "*://*/*.m4v", "*://*/*.mov", "*://*/*.gifv",
    "*://*/*.m3u8", "*://*/*.mpd", "*://*/*.m4s",
    # Pathname matching is case-sensitive, so the extensions that really do show
    # up spelled uppercase in the wild are listed again rather than trusted to a
    # pattern group.
    "*://*/*.PNG", "*://*/*.JPG", "*://*/*.JPEG", "*://*/*.GIF", "*://*/*.WEBP",
    "*://*/*.MP4",
    # Hosts that serve media with no extension to match on. Reddit's player puts
    # `packaged-media.redd.it/.../pb/m2` on the <video> element itself and the
    # playlist on v.redd.it; blocking both leaves the element at
    # networkState=NETWORK_NO_SOURCE instead of a stalled loader.
    "*://v.redd.it/*", "*://packaged-media.redd.it/*",
    "*://*.googlevideo.com/*", "*://*.vimeocdn.com/*",
    "*://*.youtube.com/embed/*",
)

#: What the browser refuses when there is no exit at all. With a proxy, loopback is
#: forced through it (`--proxy-bypass-list=<-loopback>`) and the proxy refuses it.
#: With no proxy that flag guards nothing, so a page inside a session-carrying
#: browser could reach the harness port, a CDP endpoint, or link-local metadata —
#: and the address gate would never see the request, because it is the browser
#: making it. So the machine is refused inside the browser instead.
#:
#: Known gaps, stated rather than papered over: WebSocket upgrades are not covered
#: by `setBlockedURLs`, the carrier-grade range 100.64.0.0/10 is not listed, and an
#: IPv6 loopback *literal* cannot be listed at all — CDP rejects `*://[::1]/*` as an
#: unparseable URLPattern, which is measured, not assumed. Loopback *names* are sent
#: to a blackhole by the resolver rule the engine adds in direct mode. Direct mode
#: is a weaker posture than an exit, and the settings page says so.
LOOPBACK_GUARD_PATTERNS = (
    "*://127.*/*",
    "*://localhost/*",
    "*://*.localhost/*",
    "*://0.0.0.0/*",
    "*://169.254.*/*",
    "*://10.*/*",
    "*://192.168.*/*",
    # 172.16/12 is private, 172.64/13 is Cloudflare — a bare `172.*` would break
    # real sites, so the private sixteen are named.
    *(f"*://172.{second}.*/*" for second in range(16, 32)),
)


def _patterns(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """A comma-separated override, or the built-in list when unset.

    An override that parses to nothing, or to something that cannot be a
    URLPattern, is a startup failure: a bad pattern is not rejected until CDP
    sees it, which is on every tab and on every navigation, mid-session.
    """
    raw = _str(name, "")
    if not raw:
        return default
    parts = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not parts:
        raise ConfigError(f"{name} is set but contains no pattern")
    for part in parts:
        if "://" not in part:
            raise ConfigError(f"{name} entry {part!r} is not a URLPattern")
    return parts


def _geo(name: str, default: str) -> tuple[float, float] | None:
    """`lat,lon`, or an empty value to send no location at all."""
    raw = os.environ.get(name, default).strip()
    if not raw:
        return None
    parts = raw.split(",")
    if len(parts) != 2:
        raise ConfigError(f"{name} must be 'lat,lon', got {raw!r}")
    try:
        lat, lon = float(parts[0]), float(parts[1])
    except ValueError as error:
        raise ConfigError(f"{name} must be two numbers, got {raw!r}") from error
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ConfigError(f"{name} is out of range: {raw!r}")
    return lat, lon


@dataclass(frozen=True)
class Settings:
    proxy: str
    jar_dir: str
    impersonate: str
    accept_language: str
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    #: Empty leaves the impersonated profile's own Accept, which is not what the
    #: browser sends. Set it to the browser's value to make the two agree.
    accept: str
    sec_gpc: bool
    max_chars: int
    max_links: int
    #: Hard ceiling on a PDF body accepted for text extraction. The response is
    #: already in memory when the cap is checked; the cap keeps a 500 MB "PDF"
    #: from reaching the parser and names its size to the caller.
    pdf_max_bytes: int
    #: Ceiling on extracted PDF text, applied together with the caller's
    #: maxChars (the smaller wins). Page-level skipping is reported, never silent.
    pdf_max_chars: int
    #: Widest page range one `#page=N-M` fragment may ask for; the hint for the
    #: next slice of a cut PDF never names a wider one.
    pdf_max_range_pages: int
    fetch_timeout_ms: int
    max_retries: int
    search_engine: str
    idle_timeout_s: int
    browser_executable: str
    browser_profile: str
    browser_idle_s: int
    browser_max_elements: int
    browser_text_chars: int
    browser_max_chars: int
    #: What the browser observed is folded back into the jar on teardown, so a
    #: login obtained in the browser tier is usable by the curl tier afterwards.
    browser_jar_writeback: bool
    #: Anti-Captcha account key. Empty means the solver is off: a captcha stays a
    #: reported wall rather than something bought around.
    anticaptcha_key: str
    #: How long one solve may take, from task creation to token.
    anticaptcha_timeout_ms: int
    timezone: str
    geolocation: tuple[float, float] | None
    #: Images and video are not fetched at all. The agent has no vision to spend
    #: them on, and a media-heavy front page is the fastest way to run a small
    #: machine out of memory.
    block_media: bool
    #: CDP URL globs, matched in order, applied per tab.
    block_media_patterns: tuple[str, ...]

    @property
    def browser_proxy(self) -> str:
        """The same exit, spelled the way Chrome spells it.

        Chrome has no `socks5h`. Its `socks://` scheme is SOCKS5 with remote
        (proxy-side) resolution, which is the behaviour the curl tier needs:
        local resolution hands the tunnel IPv6 literals it cannot carry.
        """
        if self.proxy.startswith("socks5h://"):
            return "socks://" + self.proxy[len("socks5h://") :]
        return self.proxy

    @property
    def direct(self) -> bool:
        """No exit at all — then the machine has to be refused inside the browser."""
        return not self.proxy

    @property
    def fingerprint_path(self) -> str:
        """Where the browser tier writes the identity it reports about itself.

        The curl tier reads it back at startup, so the two halves answer as one
        client without anyone maintaining a version string by hand.
        """
        return _fingerprint_path(self.jar_dir)

    @property
    def blocked_patterns(self) -> tuple[str, ...]:
        """Everything the browser must not fetch, as one list.

        CDP's `setBlockedURLs` takes the whole policy at once — patterns are matched
        in order and outrank any wildcard, with no exceptions — so media and the
        direct-mode guard are composed here rather than set from two places.
        """
        patterns: list[str] = []
        if self.block_media:
            patterns.extend(self.block_media_patterns)
        if self.direct:
            patterns.extend(LOOPBACK_GUARD_PATTERNS)
        return tuple(patterns)

    @property
    def extra_headers(self) -> dict[str, str]:
        """Headers that pull the impersonated fingerprint back to this machine.

        curl_cffi's chrome target is shaped for another platform and another
        version; the machine is Linux and the browser's version comes from its own
        binary. Overriding these headers leaves the TLS/HTTP2 layer untouched and
        removes the mismatches a site can see without asking the network for
        anything.
        """
        return {
            "user-agent": self.user_agent,
            "accept-language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": self.sec_ch_ua_mobile,
            "sec-ch-ua-platform": self.sec_ch_ua_platform,
            # Measured against the browser's own SERP request: the impersonated
            # profile still sends the signed-exchange token the browser stopped
            # sending, and it sends no sec-gpc at all. Both are visible to a site
            # without asking the network anything.
            **({"accept": self.accept} if self.accept else {}),
            **({"sec-gpc": "1"} if self.sec_gpc else {}),
        }

    @classmethod
    def from_env(cls) -> "Settings":
        # There is no default exit. An unset variable is a configuration error, not
        # a silent route through someone else's tunnel; an empty value is the
        # supported "no exit" posture and has to survive the read, because `_str`
        # treats empty as unset and would quietly turn a direct connection back into
        # a proxied one.
        raw_proxy = os.environ.get("STEALTH_PROXY")
        if raw_proxy is None:
            raise ConfigError(
                "STEALTH_PROXY is not set. Set it to socks5h://host:port for an exit, "
                "or to an empty string to connect directly. There is no default exit."
            )
        proxy = raw_proxy.strip()
        # socks5 (local resolution) hands the proxy an IPv6 literal it cannot
        # carry, which surfaces as a TLS reset. Remote resolution is mandatory.
        if proxy.startswith("socks5://"):
            raise ConfigError(
                "STEALTH_PROXY must use socks5h:// (remote DNS). socks5:// resolves locally "
                "and passes IPv6 literals the tunnel cannot carry."
            )
        # Cookie sets are credentials, so the fallback lives under the harness home
        # and never inside the plugin's own directory.
        jar_dir = _str(
            "STEALTH_JAR_DIR",
            os.path.join(os.path.expanduser("~"), ".dsh", "web-stealth", "jar"),
        )
        browser_executable = _str("STEALTH_BROWSER", "/usr/bin/brave")
        # Which Chromium this machine actually runs is asked of the binary, and the
        # headers the browser tier measured about itself win where they exist. A
        # constant here rots the day the browser updates, and then the two tiers
        # disagree about who they are — which is itself a fingerprint.
        major = _browser_major(browser_executable)
        observed = _observed_fingerprint(jar_dir)
        impersonate_target = _chrome_target(major)
        # The user agent and client hints claim the same major as the TLS profile,
        # or the two layers disagree about who they are.
        target_major = re.fullmatch(r"chrome(\d+)", impersonate_target)
        fallback_major = int(target_major.group(1)) if target_major else 150
        return cls(
            proxy=proxy,
            jar_dir=jar_dir,
            impersonate=_str("STEALTH_IMPERSONATE", impersonate_target),
            accept_language=_str("STEALTH_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
            user_agent=_str(
                "STEALTH_UA",
                observed.get("user_agent") or UA_TEMPLATE.format(major=major or fallback_major),
            ),
            sec_ch_ua=_str(
                "STEALTH_SEC_CH_UA",
                observed.get("sec_ch_ua") or SEC_CH_UA_TEMPLATE.format(major=major or fallback_major),
            ),
            sec_ch_ua_mobile=_str("STEALTH_SEC_CH_UA_MOBILE", observed.get("sec_ch_ua_mobile") or "?0"),
            sec_ch_ua_platform=_str("STEALTH_SEC_CH_UA_PLATFORM", observed.get("sec_ch_ua_platform") or '"Linux"'),
            accept=_str("STEALTH_ACCEPT", observed.get("accept") or ""),
            sec_gpc=_bool("STEALTH_SEC_GPC", True),
            max_chars=_int("STEALTH_MAX_CHARS", 12_000),
            max_links=_int("STEALTH_MAX_LINKS", 100),
            pdf_max_bytes=_int("STEALTH_PDF_MAX_BYTES", 20_000_000),
            # ~40 pages of dense monograph prose at ~3.5k chars/page carries a
            # whole chapter, and stays under the plugin's 200k protocol ceiling.
            pdf_max_chars=_int("STEALTH_PDF_MAX_CHARS", 150_000),
            pdf_max_range_pages=_int("STEALTH_PDF_MAX_RANGE_PAGES", 50),
            fetch_timeout_ms=_int("STEALTH_FETCH_TIMEOUT_MS", 45_000),
            max_retries=_int("STEALTH_MAX_RETRIES", 3),
            # google is primary: it answers a logged-in curl request with a real
            # SERP. brave works anonymously but rate-limits quickly (R14), so it
            # is the fallback rather than the default.
            search_engine=_str("STEALTH_SEARCH_ENGINE", "google"),
            # The sidecar is long-lived on purpose (connection reuse), but it must
            # not outlive a code change: exiting when idle lets the supervisor
            # start a fresh generation on the next request.
            idle_timeout_s=_int("STEALTH_IDLE_TIMEOUT_S", 300, minimum=0),
            # Tier 2 runs the same executable and profile the harvest uses, but
            # the session is injected from the jar: the harvest signs in inside a
            # context it creates for the run, so nothing is waiting in the
            # profile on disk (measured, not assumed).
            browser_executable=browser_executable,
            browser_profile=_str("STEALTH_BROWSER_PROFILE", os.path.expanduser("~/.dsh/web-stealth/browser-profile")),
            # A browser costs far more than this process does; it is started on
            # demand and released while idle. The window has to outlast the gap
            # between two tool calls, which is thinking time rather than work.
            browser_idle_s=_int("STEALTH_BROWSER_IDLE_S", 180, minimum=0),
            # Numbered interactive elements per page. Past this the list is a
            # wall the caller cannot act on anyway. Content pages put a related-
            # items sidebar inside `main`, and on a forum topic that sidebar alone
            # took 36 of the old 60 before the post's own controls ran out.
            browser_max_elements=_int("STEALTH_BROWSER_MAX_ELEMENTS", 120),
            # open/state/act answer with a text preview rather than the whole
            # page: there the caller is choosing an element, and a full article
            # in every listing is context spent on nothing. The read op still
            # gives the whole page at `max_chars`.
            browser_text_chars=_int("STEALTH_BROWSER_TEXT_CHARS", 2500),
            # browser_read's whole-page budget. Its own number, not the fetch
            # tier's max_chars: the plugin states a browser cap, and the sidecar
            # must not answer with a different one and call it "the configured
            # limit" the user never configured.
            browser_max_chars=_int("STEALTH_BROWSER_MAX_CHARS", 12_000),
            # A login earned in the browser tier is worthless if it dies with the
            # tab: on teardown the cookies the browser holds are folded back into
            # the jar, which is the only store the curl tier reads.
            browser_jar_writeback=_bool("STEALTH_BROWSER_JAR_WRITEBACK", True),
            # The solver's key arrives from the plugin, which reads it from the
            # project's .env. It is never printed, and never sent anywhere but
            # api.anti-captcha.com.
            anticaptcha_key=_str("STEALTH_ANTICAPTCHA_KEY", ""),
            anticaptcha_timeout_ms=_int("STEALTH_ANTICAPTCHA_TIMEOUT_MS", 180_000, minimum=10_000),
            # The only emulation in use: where we are and what clock we keep. Both
            # belong to the exit, not to the machine, and no published default can
            # know either — shipping one city to a machine whose exit is elsewhere
            # manufactures exactly the layer mismatch a wall reads as deception. So
            # unset means send nothing, and the owner sets the pair next to the
            # proxy they chose.
            timezone=_str("STEALTH_TIMEZONE", ""),
            geolocation=_geo("STEALTH_GEO", ""),
            # Refused at the network layer, so nothing is downloaded, decoded or
            # held in the renderer. Switch off only for a page that cannot work
            # without its images.
            block_media=_bool("STEALTH_BLOCK_MEDIA", True),
            block_media_patterns=_patterns("STEALTH_BLOCK_MEDIA_PATTERNS", BLOCK_MEDIA_PATTERNS),
        )
