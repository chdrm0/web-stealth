"""Line-delimited JSON protocol shared with the JS side of @local/web-stealth.

stdout carries protocol frames only. Every log line goes to stderr.
"""

__all__ = ["PROTOCOL_VERSION", "ERROR_CODES", "decode_request", "response_ok", "response_error", "handshake"]

PROTOCOL_VERSION = "0.3.0"

#: Codes the JS supervisor maps onto its own failure class. Keep in sync with
#: web-stealth/lib/sidecar.js and PLAN.md.
ERROR_CODES = frozenset(
    {
        "invalid-url",
        "blocked-url",
        "unknown-op",
        "bad-request",
        "browser-start",
        "browser-unavailable",
        "navigation",
        "timeout",
        "cancelled",
        "unsupported-content",
        "network",
        "upstream",
        "challenge",
        "jar-stale",
        "captcha",
        "internal",
    }
)

#: Ops that carry an integer id the supervisor is waiting on. Only ops that are
#: actually implemented belong here: an unlisted op is refused at the door.
ID_OPS = frozenset(
    {
        "fetch",
        "raw",
        "search",
        "cancel",
        "jar.status",
        "browser.render",
        "browser.open",
        "browser.state",
        "browser.act",
        "browser.read",
        "browser.requests",
        "browser.body",
        "browser.captcha",
        "browser.close",
    }
)

#: Ceiling on a per-request timeout. The browser tier owns one tab, so an
#: unbounded timeout is an unbounded claim on it.
MAX_TIMEOUT_MS = 180_000


def decode_request(line: str) -> dict:
    """Parse and shape-check one inbound frame.

    A missing or renamed field raises here instead of propagating as None.
    """
    import json

    frame = json.loads(line)
    if not isinstance(frame, dict):
        raise ValueError("frame is not an object")
    op = frame.get("op")
    if not isinstance(op, str) or not op:
        raise ValueError("frame has no string 'op'")
    if op in ("shutdown",):
        return frame
    if op not in ID_OPS:
        raise ValueError(f"unsupported op {op!r}")
    if not isinstance(frame.get("id"), int):
        raise ValueError(f"op={op} requires an integer 'id'")
    if op in ("fetch", "raw", "browser.render", "browser.open", "browser.state", "browser.act", "browser.read", "browser.close", "browser.captcha"):
        for key in ("maxChars", "maxBytes", "timeoutMs", "maxElements", "textChars"):
            value = frame.get(key)
            # `bool` is an `int` in Python, so True would pass as a 1 ms timeout.
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise ValueError(f"op={op} field '{key}' must be a positive integer")
        # A caller asking for an hour holds the single browser tab for an hour.
        if frame.get("timeoutMs") is not None and frame["timeoutMs"] > MAX_TIMEOUT_MS:
            raise ValueError(f"op={op} field 'timeoutMs' must be <= {MAX_TIMEOUT_MS}")
    if op in ("fetch", "raw", "browser.render", "browser.open"):
        if not isinstance(frame.get("url"), str) or not frame["url"]:
            raise ValueError(f"op={op} requires a non-empty string 'url'")
    if op == "browser.act":
        index = frame.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 1:
            raise ValueError("op=browser.act requires an integer 'index' >= 1")
        if not isinstance(frame.get("action"), str) or not frame["action"]:
            raise ValueError("op=browser.act requires a non-empty string 'action'")
        if frame.get("value") is not None and not isinstance(frame["value"], str):
            raise ValueError("op=browser.act field 'value' must be a string")
    if op == "browser.captcha":
        # The flag is what spends money, so it is read strictly: anything but a
        # JSON true means "report only".
        solve = frame.get("solve")
        if solve is not None and not isinstance(solve, bool):
            raise ValueError("op=browser.captcha field 'solve' must be a boolean")
    if op == "browser.body":
        timeout_ms = frame.get("timeoutMs")
        if timeout_ms is not None and (
            not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= MAX_TIMEOUT_MS
        ):
            raise ValueError(f"op=browser.body field 'timeoutMs' must be an integer in 1..{MAX_TIMEOUT_MS}")
        replay_document = frame.get("replayDocument")
        if replay_document is not None and not isinstance(replay_document, bool):
            raise ValueError("op=browser.body field 'replayDocument' must be a boolean")
    if op == "search":
        if not isinstance(frame.get("query"), str) or not frame["query"]:
            raise ValueError("op=search requires a non-empty string 'query'")
        for key in ("maxResults", "timeoutMs"):
            value = frame.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise ValueError(f"op=search field '{key}' must be a positive integer")
        if frame.get("engine") is not None and not isinstance(frame["engine"], str):
            raise ValueError("op=search field 'engine' must be a string")
    return frame


def handshake(engines: list[str]) -> dict:
    return {"op": "ready", "version": PROTOCOL_VERSION, "engines": engines}


def response_ok(request_id: int, data: dict) -> dict:
    return {"id": request_id, "ok": True, "data": data}


def response_error(request_id: int, code: str, message: str) -> dict:
    if code not in ERROR_CODES:
        # An unknown code is a bug in this package, not a condition to forward.
        code = "internal"
    return {"id": request_id, "ok": False, "error": {"code": code, "message": message}}
