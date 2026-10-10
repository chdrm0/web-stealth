"""Per-origin retrieval policy, seeded from measurements rather than guesses.

Measured on the harvested jar (2026-10-05, one rented exit — the exit itself is
not part of what these numbers claim):

    google.com/search   200, real SERP, 11 external links, no consent wall
    search.brave.com    200, 28 external links, works anonymously
    github.com/*        200; content pages extract, app pages are React shells

Two independent knobs per group:

    policy    which tier may be used once the browser tier exists
    send_jar  whether account cookies are sent at all

`send_jar` matters for more than function: an origin that works anonymously
should not see the logged-in session, because every extra presentation of that
session is one more correlation surface.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

POLICIES = ("curl_only", "curl_then_browser", "browser_first")
#: The closed set `jar.group_for` can return. An override naming anything else is
#: a typo that would otherwise sit there doing nothing.
KNOWN_GROUPS = ("google", "github", "brave", "reddit", "other")

DEFAULTS: dict[str, dict] = {
    "google": {"policy": "curl_only", "sendJar": True},
    # github answers curl for everything that has a document. Its authenticated
    # UI is a React shell, but automatic escalation there is parked: the rendered
    # page came back with github's include-fragment error boundary while the same
    # URL rendered fine by hand, and a browser launched behind the agent's back
    # is a cost that has to be earned. `browser.render` reaches it on request.
    "github": {"policy": "curl_only", "sendJar": True},
    "brave": {"policy": "curl_only", "sendJar": False},
    # A named group is what makes a login worth having: without this line reddit
    # inherits `other` and is sent nothing, so a session earned in the browser
    # would never be replayed by curl. Named, earned, sent.
    "reddit": {"policy": "curl_only", "sendJar": True},
    # Unknown origins get no session at all. They are the group where a leak is
    # cheapest: the jar holds account cookies, and an arbitrary site has done
    # nothing to earn them. Override per group when a login is actually wanted.
    "other": {"policy": "curl_only", "sendJar": False},
}


@dataclass(frozen=True)
class Policy:
    group: str
    policy: str
    send_jar: bool


def overrides_from_env() -> dict[str, dict]:
    """`STEALTH_ORIGIN_POLICY` as a JSON object of group -> {policy, sendJar}."""
    raw = os.environ.get("STEALTH_ORIGIN_POLICY")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"STEALTH_ORIGIN_POLICY is not valid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise ValueError("STEALTH_ORIGIN_POLICY must be a JSON object of group -> settings")
    for group, settings in parsed.items():
        if not isinstance(settings, dict):
            raise ValueError(f"STEALTH_ORIGIN_POLICY[{group!r}] must be an object")
        if group not in KNOWN_GROUPS:
            raise ValueError(f"STEALTH_ORIGIN_POLICY has unknown group {group!r}; expected one of {KNOWN_GROUPS}")
        policy = settings.get("policy")
        if policy is not None and policy not in POLICIES:
            raise ValueError(f"STEALTH_ORIGIN_POLICY[{group!r}].policy must be one of {POLICIES}")
        send_jar = settings.get("sendJar")
        if send_jar is not None and not isinstance(send_jar, bool):
            raise ValueError(f"STEALTH_ORIGIN_POLICY[{group!r}].sendJar must be a boolean, not {type(send_jar).__name__}")
    return parsed


def resolve(group: str, overrides: dict[str, dict] | None = None) -> Policy:
    base = dict(DEFAULTS.get(group) or DEFAULTS["other"])
    base.update((overrides or {}).get(group) or {})
    return Policy(group=group, policy=base["policy"], send_jar=base["sendJar"] is True)
