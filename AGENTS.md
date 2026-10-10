## Web access

- `web_fetch` and `web_search` route through the `stealth-web` provider (bundle
  `@local/web-stealth`, this repository's `web-stealth/`, Python sidecar in its
  `fetchd/`). Self-hosted, no cost per request. Two tiers:
  **curl** (`curl_cffi`, Chrome TLS profile, the cookie jar, the configured proxy —
  fast, no vision) and **browser** (headed Chrome through nodriver/CDP; it reads its
  own version and client hints back and feeds them to the curl tier, so both report
  one identity).
- Never `web_fetch` a search-engine results page — `web_search` parses the SERP into
  `sources[]` with title, snippet and date.
- **Never invent a URL.** A path assembled from a site's conventions is a guess, and
  a 404 from it says something about the guess, not about the site. After a 404, a
  `not found`, or an empty answer from any URL not taken from a search result or a
  page already read, run `web_search` and work from what it returns. Retrieval here
  is free, so searching is free.
- A `[stealth] …` notice at the head of a body is the provider explaining what
  happened. Read it — it usually carries more than the body does.
- Search tries engines in order (configured primary first, then google → brave →
  duckduckgo) and moves on only at a wall — `js-proof`, `rate-limited`, `challenge`,
  `unparsed`, `filtered-out`, `interstitial` — never on an empty answer. An empty
  answer is claimed only when the engine says so in words. `interstitial` is a gate
  demanding cookies or script: a refusal, not a thin page. The fallthrough notice
  lists every engine attempted and its verdict; if one is missing from that list,
  that is a plugin defect, not an engine being down.
- **Engine availability fluctuates.** Measured on 2026-10-08: one session got 9
  google answers before a wall, another got 0 of 41 with the wall persisting across
  sessions, a third saw google answer with none of the usual parameters. Treat
  google as unavailable until re-measured in the current session; duckduckgo has
  carried whole sessions competently, including JA/ZH/RU queries.
- **PDFs are read by the curl tier**, page by page. Seek into a long one with a URL
  fragment: `#page=N` or `#page=N-M` (bare `#N` works). This is the only seek
  mechanism, because `web_fetch` takes a URL only. Out-of-range and over-wide ranges
  are refused with the page count and a valid suggestion. A truncated PDF names the
  stop page, the total and the exact next fragment; a truncated HTML/text page names
  returned length, total, percentage and the section it stopped inside. Trust those
  over guessing, and ignore the generic "fetch a more specific URL" line for a PDF.
  Not handled: scanned PDFs (reported as `scanned`, no OCR), CJK PDFs with CID fonts
  and no ToUnicode (mojibake), password-protected PDFs, PDFs over 20 MB.
- Browser tools: `browser_open`, `browser_state`, `browser_act`, `browser_read`,
  `browser_requests`, `browser_body`, `browser_close`, `browser_captcha`. Elements
  are numbered for the page shown and renumbered after every action — re-read the
  state before acting again. Open shadow roots are reached, closed ones are not.
- `browser_requests` lists what the page asked the network for (summary only, the
  page's own document marked `*`, captured window in the header). `browser_body`
  takes the id in brackets **or** the `#n` number and returns real headers (cookie
  values redacted to their size) or a body. A body is available only while the tab
  still holds it; a missing one is re-requested under short-lived Fetch interception.
  A **document** body needs `replayDocument: true`, which re-navigates the tab,
  renumbers elements and consumes one-shot GETs such as an OAuth callback. Bodies
  served from the renderer's memory cache stay unreachable.
- Images and video are blocked at the network layer (no vision to spend them on).
  No origin escalates to the browser automatically, and the browser is never a retry
  for a refusal — a challenge or a 403 is reported as itself. Open and read pages
  freely; **ask first** before submitting anything that changes state.
- Captcha: `browser_captcha` describes the widget; only `solve: true` buys a token,
  so a spend is always explicit, and **at most 5 attempts per captcha** (family +
  site key + origin) — the 6th is refused before anything is bought. The key comes
  from the plugin's masked settings field or the project's `.env`; it is never
  logged, returned, or handed to the agent.
- Cookie jar: `~/.dsh/web-stealth/jar`, one file per group, bound to the proxy exit.
  After an exit change, re-harvest:
  `cd web-stealth/fetchd && ./.venv/bin/python -m fetchd.harvest`.
  Proof the provider is live: the jar's mtime moves on each request.
- Sidecar (Python) edits need no restart — it retires after `STEALTH_IDLE_TIMEOUT_S`
  (300 s) and respawns on the next request. Plugin JS and `cordis.patch.yml` require
  a profile restart. The installed bundle is a symlink to the project directory.
