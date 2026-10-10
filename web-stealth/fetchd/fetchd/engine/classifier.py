"""What a response actually was, as opposed to what its status line said.

M1 keeps this deliberately thin: enough to stop reporting a consent wall or a
JS shell as a successful read. The escalation policy that consumes these labels
lands in M2.
"""

from __future__ import annotations

CHALLENGE_MARKERS = (
    "unusual traffic",
    "captcha",
    "are you a robot",
    "verify you are human",
    "access denied",
    "request blocked",
    "cf-browser-verification",
    "just a moment",
    # Cloudflare's two canonical interstitials: the block page ("Attention
    # Required!") and the automatic interstitial. Without these a 403 challenge
    # is reported as a plain http-error and the escalation policy never fires.
    "attention required",
    "checking your browser",
    "cloudflare ray id",
)
CONSENT_MARKERS = (
    "consent.google.com",
    "consent.youtube.com",
    "accept cookies",
    "onetrust",
)

#: A page that answered 200 but whose body is a script bootstrap.
SHELL_MARKERS = ("you need to enable javascript", "enable javascript and run")

#: Bodies that are a gate demanding cookies or script, not the document. The
#: pmc.ncbi.nlm.nih.gov case: a 203 whose whole text is "Cookies must be
#: enabled / Enable cookies for ... and reload this page to continue." — it
#: reads as a thin article unless the phrase is named. Matched case-insensitively
#: against the lowered text, like every other table here.
INTERSTITIAL_MARKERS = (
    "cookies must be enabled",
    "enable cookies",
    "cookies are disabled",
    "cookies appear to be disabled",
    "javascript is disabled",
    "enable javascript to continue",
    "you need to enable javascript",
    "a service on your browser was not verified",
    "enable javascript and reload",
)

#: The false-positive guard, same shape as the challenge one: an article *about*
#: enabling cookies says the phrase in perfect good faith, so the phrase only
#: decides when the page is thin and link-poor. Measured: the pmc gate is 100
#: characters with 1 link (its "Enable cookies" anchor), while gov.uk/help/cookies
#: runs to thousands of characters. A legitimately short page (example.com, 156
#: characters) carries none of these phrases, so it passes untouched.
INTERSTITIAL_MAX_CHARS = 1200
INTERSTITIAL_MAX_LINKS = 3


#: A 200 carrying a challenge marker is only believed when the page is thin.
#: An interstitial has nothing else on it, while an article *about* bot
#: protection says "checking your browser" in perfect good faith — and a false
#: `challenge` does more than mislabel: it marks a healthy cookie jar stale.
CHALLENGE_ON_200_MAX_CHARS = 1200


def classify(status_code: int, text: str, content_type: str, links: int = 0) -> str:
    """Return one of: ok, http-error, rate-limited, challenge, consent, interstitial, empty-shell.

    Short is not the same as blank: example.com is a legitimate 150-character
    page, and a search result page can be thin prose but rich in links. So a
    200 that yielded links is never an empty shell, and the length threshold
    only applies when nothing was extracted at all.
    """
    lowered = (text or "").lower()
    if status_code == 429:
        return "rate-limited"
    if status_code >= 400:
        if any(marker in lowered for marker in CHALLENGE_MARKERS):
            return "challenge"
        return "http-error"
    if links == 0 and len(lowered.strip()) < CHALLENGE_ON_200_MAX_CHARS and any(marker in lowered for marker in CHALLENGE_MARKERS):
        return "challenge"
    if any(marker in lowered for marker in CONSENT_MARKERS) and len(lowered) < 4000:
        return "consent"
    # Named before the shell check and apart from `empty-shell`: a gate that
    # demands cookies or script is a refusal, while `empty-shell` also covers a
    # genuinely empty body — the caller must be able to tell the two apart.
    if (
        links <= INTERSTITIAL_MAX_LINKS
        and len(lowered.strip()) < INTERSTITIAL_MAX_CHARS
        and any(marker in lowered for marker in INTERSTITIAL_MARKERS)
    ):
        return "interstitial"
    if any(marker in lowered for marker in SHELL_MARKERS):
        return "empty-shell"
    if links > 0 or len(lowered.strip()) >= 40:
        return "ok"
    return "empty-shell"
