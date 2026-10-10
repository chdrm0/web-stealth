"""Anti-Captcha client: the only place the solver's API key is used.

The solver is a paid third party: every call spends money, so nothing here runs
without an explicit request from the caller. The key is never logged, never
echoed into a reply, and the request goes out without the retrieval proxy — the
key belongs to our account, and an unrelated exit has no business carrying it.

The task types are "proxyless": Anti-Captcha solves from its own workers, and
Google does not currently tie the solved token to the IP that solved it, so the
token is submitted from our exit.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from urllib.parse import urlsplit

log = logging.getLogger("fetchd.captcha")

API_URL = "https://api.anti-captcha.com/"
#: How long a poll between two getTaskResult calls. The service answers in
#: seconds for reCAPTCHA v2; a tighter loop is traffic for nothing.
POLL_S = 2.0
#: A task that is not ready by then is abandoned: the caller is waiting on a
#: browser that is holding a lock.
SOLVE_MAX_S = 240.0


#: Hard cap on solve attempts for one captcha identity. The owner set it: a loop
#: that keeps asking must stop at a known spend, not at an empty balance.
SOLVE_ATTEMPT_CAP = 5
#: How long an identity's count is remembered, and how many identities are held.
#: Both bound memory; the size bound evicts the oldest identity first.
SOLVE_BUDGET_TTL_S = 6 * 3600.0
SOLVE_BUDGET_MAX_IDENTITIES = 256


def captcha_identity(page_url: str, sitekey: str, kind: str, enterprise: bool) -> str:
    """What makes two solve requests "the same captcha": site key, widget family, page origin."""
    parts = urlsplit(page_url or "")
    origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else "unknown-origin"
    family = f"{kind or 'unknown'}{'-enterprise' if enterprise else ''}"
    return f"{family}|{sitekey}|{origin}"


class SolveBudget:
    """Per-identity solve attempt counter, bounded in time and in size.

    An attempt is counted before the solver is contacted, whatever its outcome:
    a failed createTask can still have been billed, and a counter that only
    counted successes would not stop a loop of failures.
    """

    def __init__(
        self,
        cap: int = SOLVE_ATTEMPT_CAP,
        ttl_s: float = SOLVE_BUDGET_TTL_S,
        max_identities: int = SOLVE_BUDGET_MAX_IDENTITIES,
    ) -> None:
        self.cap = cap
        self.ttl_s = ttl_s
        self.max_identities = max_identities
        # identity -> (attempts, monotonic time of the first attempt)
        self._counts: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def _expire(self, now: float) -> None:
        for identity in [key for key, (_, first) in self._counts.items() if now - first > self.ttl_s]:
            del self._counts[identity]

    def attempts(self, identity: str) -> int:
        self._expire(time.monotonic())
        return self._counts.get(identity, (0, 0.0))[0]

    def claim(self, identity: str) -> int:
        """Count one attempt and return its number, or refuse once the cap is spent."""
        now = time.monotonic()
        self._expire(now)
        used, first = self._counts.get(identity, (0, now))
        if used >= self.cap:
            left_s = max(0, int(self.ttl_s - (now - first)))
            log.warning("solve refused: cap of %d attempts reached for %s", self.cap, identity)
            raise CaptchaFailure(
                "solve-cap-reached",
                f"the cap of {self.cap} solve attempts was reached for captcha {identity}; "
                f"this attempt was refused before the solver was contacted, so nothing was spent on it. "
                f"The count resets in about {left_s // 60} min or when the sidecar restarts",
            )
        self._counts[identity] = (used + 1, first)
        self._counts.move_to_end(identity)
        while len(self._counts) > self.max_identities:
            self._counts.popitem(last=False)
        return used + 1


class CaptchaFailure(RuntimeError):
    """The solver refused, timed out, or is not configured.

    `code` is routable: the caller maps it to a tool notice rather than a stack.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AntiCaptcha:
    """createTask → poll getTaskResult, with one deadline over both."""

    def __init__(self, api_key: str, max_solve_s: float = SOLVE_MAX_S) -> None:
        self.api_key = api_key
        self.max_solve_s = max(SOLVE_MAX_S, float(max_solve_s))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def _post(self, method: str, payload: dict, timeout_s: float) -> dict:
        from curl_cffi import AsyncSession

        # No impersonation and no proxy: this is our own API call, not a target
        # site, and the account key must not travel through a retrieval exit.
        async with AsyncSession(timeout=timeout_s) as session:
            response = await session.post(f"{API_URL}{method}", json=payload, headers={"Content-Type": "application/json"})
        if response.status_code != 200:
            raise CaptchaFailure("http-error", f"anti-captcha {method} returned HTTP {response.status_code}")
        body = response.json()
        if not isinstance(body, dict):
            raise CaptchaFailure("bad-reply", f"anti-captcha {method} returned {type(body).__name__}, expected an object")
        error_id = body.get("errorId")
        if error_id not in (0, None):
            # The service's own code and description: enough to route on, and it
            # never carries the key.
            raise CaptchaFailure(
                str(body.get("errorCode") or f"error{error_id}"),
                str(body.get("errorDescription") or "anti-captcha refused the task"),
            )
        return body

    async def solve_recaptcha_v2(
        self, website_url: str, sitekey: str, deadline: float, enterprise: bool = False, data_s: str = ""
    ) -> dict:
        """Solve one reCAPTCHA v2 widget and return its response token.

        `enterprise` picks the task type, not a variant of the same one: an
        enterprise anchor is served by a different API, and a token bought as an
        ordinary v2 is refused by it.
        """
        if not self.configured:
            raise CaptchaFailure("not-configured", "no anti-captcha key is configured (config.antiCaptchaKey or .env API_KEY)")
        if not sitekey:
            raise CaptchaFailure("no-sitekey", "the widget has no site key to send")
        remaining = deadline - time.monotonic()
        if remaining < 5.0:
            raise CaptchaFailure("no-budget", "the request ran out of time before the solver could be asked")
        budget = min(self.max_solve_s, remaining)
        task_type = "RecaptchaV2EnterpriseTaskProxyless" if enterprise else "RecaptchaV2TaskProxyless"
        task = {
            "type": task_type,
            "websiteURL": website_url,
            "websiteKey": sitekey,
        }
        if data_s:
            # Google's own widgets pair the site key with a per-challenge `data-s`
            # token. A task without it describes a different challenge, and the
            # answer comes back valid-looking and refused.
            task["dataSValue"] = data_s

        created = await self._post(
            "createTask",
            {"clientKey": self.api_key, "task": task},
            timeout_s=min(30.0, budget),
        )
        task_id = created.get("taskId")
        if not isinstance(task_id, (int, str)):
            raise CaptchaFailure("bad-reply", "anti-captcha accepted the task but named no taskId")
        log.info("anti-captcha task %s created for %s", task_id, website_url[:120])

        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise CaptchaFailure("solve-timeout", f"anti-captcha did not solve task {task_id} within {int(budget)}s")
            reply = await self._post(
                "getTaskResult",
                {"clientKey": self.api_key, "taskId": task_id},
                timeout_s=min(30.0, max(5.0, left)),
            )
            status = reply.get("status")
            if status == "ready":
                solution = reply.get("solution")
                token = solution.get("gRecaptchaResponse") if isinstance(solution, dict) else None
                if not isinstance(token, str) or not token:
                    raise CaptchaFailure("bad-reply", "anti-captcha reported the task ready without a token")
                return {
                    "taskId": task_id,
                    "token": token,
                    # The worker's user agent: the token was minted by a browser
                    # like it, and a mismatch is the usual reason a submission fails.
                    "workerUserAgent": str(solution.get("userAgent") or ""),
                    "cost": reply.get("cost"),
                }
            if status not in ("processing", None):
                raise CaptchaFailure("bad-status", f"anti-captcha task {task_id} reported status {status!r}")
            await asyncio.sleep(min(POLL_S, max(0.5, left)))
