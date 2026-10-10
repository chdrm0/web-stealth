"""Canonical cookie store.

One named set per origin group, on disk, mode 0600, written atomically. The
record shape is the one already used by the existing CookieManager
(name, value, domain, path, expires, httpOnly, secure, sameSite, partitionKey)
so a harvested set can move between the browser tier and curl without a
translation layer.

There is deliberately no pool and no reuse cooldown here: this project runs one
stable identity, not a rotating fleet.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

RECORD_FIELDS = ("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite")

#: Longest-suffix match. Kept explicit rather than guessing registrable domains.
_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("google", ("google.com", "google.ru", "google.se", "googleusercontent.com", "gstatic.com")),
    ("github", ("github.com", "githubusercontent.com", "githubassets.com")),
    ("brave", ("brave.com", "search.brave.com")),
    # A named group is what makes a login reusable: the catch-all bucket is never
    # sent anywhere (routing gives it sendJar false), so a site whose session the
    # user actually earned has to be named to be worth keeping.
    ("reddit", ("reddit.com", "redd.it", "redditstatic.com", "redditmedia.com")),
)
FALLBACK_GROUP = "other"


def group_for(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    for group, suffixes in _GROUPS:
        for suffix in suffixes:
            if host == suffix or host.endswith("." + suffix):
                return group
    return FALLBACK_GROUP


class Jar:
    def __init__(self, directory: str) -> None:
        self.dir = Path(directory).expanduser().resolve()
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, group: str) -> Path:
        return self.dir / f"{group}.json"

    def load(self, group: str) -> list[dict]:
        """Read one set. A corrupt file is quarantined, never silently ignored."""
        path = self.path(group)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            quarantine = path.with_suffix(".corrupt")
            stamp = 0
            while quarantine.exists():
                stamp += 1
                quarantine = path.with_suffix(f".corrupt{stamp}")
            try:
                path.rename(quarantine)
            except OSError:
                pass
            return []
        return data if isinstance(data, list) else []

    def save(self, group: str, records: list[dict]) -> int:
        """Atomic replace with 0600: the set is a credential, not a cache."""
        path = self.path(group)
        tmp = path.with_name(f".{path.name}.tmp")
        payload = json.dumps(records, ensure_ascii=False, indent=2)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            if path.exists():
                # One previous copy, kept because a run that saw fewer cookies than
                # a real login left behind still replaces the set. `load` reads only
                # `<group>.json`, so the backup is never picked up by accident.
                backup = path.with_name(f"{path.name}.bak")
                with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as saved:
                    saved.write(path.read_bytes())
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return len(records)

    def apply_to_session(self, session, group: str) -> int:
        """Load unexpired cookies for the group into a curl session."""
        now = time.time()
        applied = 0
        for record in self.load(group):
            name = record.get("name")
            value = record.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            expires = record.get("expires")
            if isinstance(expires, (int, float)) and 0 < expires < now:
                continue
            domain = record.get("domain")
            if not isinstance(domain, str) or not domain:
                # A cookie with no domain rides along to any host. The jar is
                # grouped, so a record without one is corruption, not a wildcard.
                continue
            session.cookies.set(name, value, domain=domain, path=record.get("path") or "/")
            applied += 1
        return applied

    def to_cdp_cookies(self, group: str) -> list[dict]:
        """The stored set as CDP cookie parameters, for the browser tier.

        Measured, not assumed: the harvest logs in inside a context it creates
        for the run, so that session never lands in the on-disk profile. The jar
        is therefore the only store that survives, and the browser is handed the
        same set the curl tier uses instead of a profile that is not logged in.
        """
        now = time.time()
        cookies: list[dict] = []
        for record in self.load(group):
            name, value, domain = record.get("name"), record.get("value"), record.get("domain")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            if not isinstance(domain, str) or not domain:
                continue
            expires = record.get("expires")
            if isinstance(expires, (int, float)) and 0 < expires < now:
                continue
            item = {
                "name": name,
                "value": value,
                "domain": domain,
                "path": record.get("path") or "/",
                "secure": bool(record.get("secure", True)),
                "http_only": bool(record.get("httpOnly", False)),
                # Carried through as the stored word ("Lax"/"Strict"/"None"): the
                # caller turns it into the CDP enum. Dropping it here would
                # re-inject a SameSite=None cookie as a default one, and a session
                # that worked in the browser would fail as a cross-site send.
                "sameSite": record.get("sameSite"),
            }
            if isinstance(expires, (int, float)) and expires > 0:
                item["expires"] = int(expires)
            cookies.append(item)
        return cookies

    @staticmethod
    def _bare(domain: str) -> str:
        """`curl` and CDP disagree about the leading dot; compare without it."""
        return (domain or "").lstrip(".").lower()

    def merge_from_session(self, group: str, session, host: str = "") -> int:
        """Fold back only the cookies that belong to this group.

        Two rules, both learned the hard way. Domains are read from curl's own
        jar, which does carry them (`Cookies.jar` is an `http.cookiejar.CookieJar`)
        — the earlier version assumed it did not and stamped every collected
        cookie with the current request host, which shipped one site's session
        cookies to another site. And a cookie whose domain does not belong to the
        group is skipped outright, so a shared session can never cross-contaminate
        a stored set.

        Matched by (name, domain): an existing record keeps its attributes and
        only the value moves, so a refreshed NID does not lose its flags.
        """
        records = self.load(group)
        index = {(r.get("name"), self._bare(r.get("domain", ""))): r for r in records if isinstance(r, dict) and r.get("name")}
        added = 0
        for cookie in getattr(session.cookies, "jar", ()):
            name = getattr(cookie, "name", None)
            value = getattr(cookie, "value", None)
            domain = self._bare(getattr(cookie, "domain", "") or host)
            if not isinstance(name, str) or not isinstance(value, str) or not domain:
                continue
            if group_for(f"https://{domain}") != group:
                continue
            existing = index.get((name, domain))
            if existing is not None:
                if existing.get("value") != value:
                    existing["value"] = value
            else:
                expires = getattr(cookie, "expires", None)
                record = {
                    "name": name,
                    "value": value,
                    "domain": getattr(cookie, "domain", None) or domain,
                    "path": getattr(cookie, "path", None) or "/",
                    "expires": int(expires) if isinstance(expires, (int, float)) and expires > 0 else -1,
                    "httpOnly": bool(getattr(cookie, "http_only", False)),
                    "secure": bool(getattr(cookie, "secure", False)),
                    "sameSite": None,
                }
                records.append(record)
                index[(name, domain)] = record
                added += 1
        self.save(group, records)
        return added

    def merge_from_cdp(self, group: str, cookies: list[dict]) -> int:
        """Fold back what the browser held, so a login earned there is usable here.

        The same domain rule as `merge_from_session`: a cookie whose domain does
        not belong to this group is skipped, so a page's third-party cookies can
        never be stored under another site's name. Session cookies (CDP reports
        `expires = -1`) are stored as -1 and re-injected without an expiry, which
        is what keeps a login that the site itself intends to end at browser close.
        """
        records = self.load(group)
        index = {(r.get("name"), self._bare(r.get("domain", ""))): r for r in records if isinstance(r, dict) and r.get("name")}
        added = 0
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name, value = cookie.get("name"), cookie.get("value")
            domain = self._bare(cookie.get("domain") or "")
            if not isinstance(name, str) or not isinstance(value, str) or not domain:
                continue
            if group_for(f"https://{domain}") != group:
                continue
            existing = index.get((name, domain))
            if existing is not None:
                if existing.get("value") != value:
                    existing["value"] = value
                continue
            expires = cookie.get("expires")
            records.append({
                "name": name,
                "value": value,
                "domain": cookie.get("domain"),
                "path": cookie.get("path") or "/",
                "expires": int(expires) if isinstance(expires, (int, float)) and expires > 0 else -1,
                "httpOnly": bool(cookie.get("httpOnly", False)),
                "secure": bool(cookie.get("secure", True)),
                "sameSite": cookie.get("sameSite"),
            })
            index[(name, domain)] = records[-1]
            added += 1
        self.save(group, records)
        return added

    def stale_path(self, group: str) -> Path:
        return self.dir / f"{group}.stale"

    def mark_stale(self, group: str, reason: str, status_code: int | None = None) -> None:
        """Record that the stored set was just rejected.

        Renewal is on fact, not on a timer: this marker is what turns a silent
        retry loop into an explicit 're-harvest' signal for the caller.
        """
        payload = json.dumps({"reason": reason, "status": status_code, "at": int(time.time())}, ensure_ascii=False)
        path = self.stale_path(group)
        tmp = path.with_name(f".{path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    def clear_stale(self, group: str) -> None:
        self.stale_path(group).unlink(missing_ok=True)

    def is_stale(self, group: str) -> dict | None:
        path = self.stale_path(group)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"reason": "unreadable marker", "status": None, "at": None}
        return data if isinstance(data, dict) else {"reason": "malformed marker", "status": None, "at": None}

    def status(self) -> dict:
        now = time.time()
        out: dict[str, dict] = {}
        for group, _ in _GROUPS:
            path = self.path(group)
            records = self.load(group)
            if not path.exists():
                out[group] = {"present": False, "count": 0, "stale": self.is_stale(group)}
                continue
            live = [r for r in records if isinstance(r, dict) and not (isinstance(r.get("expires"), (int, float)) and 0 < r["expires"] < now)]
            out[group] = {
                "present": True,
                "count": len(records),
                "live": len(live),
                "savedAt": int(path.stat().st_mtime),
                "stale": self.is_stale(group),
            }
        return out
