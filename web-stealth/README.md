# web-stealth — a stealth web provider for the harness

Replaces `web_fetch` and `web_search` for one profile with a local provider:
impersonated HTTP through a SOCKS5 exit for ordinary pages, a real headed browser
for the pages that need script execution, and one cookie set per site group that
both tiers share. Nothing is distributed; this is a personal setup.

## Layout

| Path | What it is |
| --- | --- |
| `web-stealth/` | the provider package: the seam contract, URL policy, sidecar supervisor, browser tools, the settings endpoints |
| `web-stealth/fetchd/` | the Python sidecar: `curl_cffi` retrieval, the browser tier, the jar, the harvest |
| `web-stealth-ui/` | the settings page (a Client package; its own row, so the provider is mounted once) |

The provider is one long-lived Python process speaking line-JSON over stdio. The
JS half never touches the network.

## On a new machine

Prerequisites: a harness profile already running, `uv`, Python 3.13+, a Chromium
browser. A SOCKS5 exit is optional — without one the machine goes out as itself.
Copy the **whole project directory**: the settings page is a second package sitting
next to the provider, and the installer expects both.

```sh
cd web-stealth && ./install.sh          # venv from uv.lock, both packages into the profile
# restart the profile — the JS half and the patch are read at startup
cd fetchd && ./.venv/bin/python -m fetchd.harvest   # sign in once, in a window you can see
./install.sh doctor                     # what is still missing
```

Checked against dsh `0.1.7-alpha.2` and `0.2.0-rc.2`: both pin the same loader
stack (`@deepseek-ai/cordis` 4.0.4, loader 1.0.5, include 1.0.9, timer 1.1.6), the
fetch/search provider host is byte-identical between them, and the settings page's
slot and locale APIs are unchanged. The manifest declares `peerDependencies` on
`@deepseek-ai/dsh` because 0.2.0 added a compatibility check that refuses an
install whose declared range excludes the running harness — a bundle declaring
nothing is skipped by that check, and declaring the range is the honest option.

`install.sh` writes no secrets. It reads `.env` if present and reports if it is
not: the captcha key is optional, retrieval works without it. It rewrites nothing:
the bundle patch pins no paths, because the plugin derives the sidecar directory,
its interpreter and the cookie jar from where the bundle and the harness live. The
installer only checks that the profile can see this copy's venv — a sidecar that
cannot be found is not a loud failure, retrieval just stops being stealthed.

## Configuration

The authority is the `config:` block in `web-stealth/cordis.patch.yml`. A patch
`config` **replaces** the plugin's defaults, so changing a default in `index.js`
alone changes nothing. The knobs that matter:

- `proxy` — one exit for both tiers, `socks5h://host:port` (remote DNS; plain
  `socks5://` is refused on purpose). **There is no shipped default**: an owner's
  tunnel is not a value a published default can carry, so unset is a configuration
  error on the sidecar and empty means **no exit** — retrieval and the browser leave
  as this machine itself. The browser spelling is derived from it.
  Chrome's `--proxy-bypass-list=<-loopback>` guards nothing without a proxy, so the
  browser refuses this machine instead — loopback and the private ranges are blocked
  per tab, and loopback names resolve to a blackhole. Measured: a page's own request
  to the harness port fails while its request to a public host goes through. Not
  covered: WebSocket upgrades and the carrier-grade range 100.64.0.0/10. An exit is
  the stronger posture, and a cookie set belongs to the exit it was harvested
  through.
- `browserExecutable` — which browser the browser tier drives, an absolute path.
  Empty means "use one that is installed here"; the settings page lists what was
  found and switches it without a restart.
- `searchEngine` — the engine tried first. On this exit google answers `js-proof`
  and brave answers 429, so it is `duckduckgo`; the others stay in the chain.
- `blockMedia` — images and video refused at the network layer. A byte saving for
  images, a real memory saving for video.
- `browserIdleS`, `browserMaxElements`, `browserTextChars` — how long a browser
  lives and how much a page listing costs in context.

The settings page writes through the harness's own config editor, so its changes
land in the **profile** patch and apply without a restart. A patch `config` row
replaces the layer below it wholesale, so the first write copies the whole
effective config into the profile — the captcha key is copied only if it was typed
into the settings page, never read out of `.env` into the patch. From then on the
bundle's own patch is only the default: editing it changes nothing until that
profile row is removed.

## The settings page

Settings → **Stealth web**: the exit — an address field, or **No exit** for the
machine going out as itself — the browsers this machine has and which one is
chosen, the Anti-Captcha key (masked, shown only on request, cleared only on an
explicit Clear; this field is where the key belongs, `.env` is a development
fallback), the cookie sets with counts and age, and the harvest — start,
"I am done", cancel, with the run's own output.

It talks to `/api/stealth` on the same origin the page was served from, and the
endpoint answers only to a request that says it is same-origin. It accepts no
URL, no path and no command: read state, change the exit, pick among the browsers
it found by itself, store or clear the key, start or stop a harvest.

## Cookie jar

`~/.dsh/web-stealth/jar/<group>.json`, mode 0600, one file per group (google,
github, brave, reddit, other). A set is bound to the exit it was harvested
behind: change the exit and re-harvest. A login completed in the browser tier is
folded back into the jar when the tab closes, which is what makes "sign in once,
reuse it" true beyond the groups harvested by hand.

## What this setup does not do

- One browser per machine: the profile is shared, so a second session's browser
  call fails while the first holds it.
- The curl tier is walled by google and refused by brave on this exit; the
  browser tier reaches both. That is the scripted client being refused, not the
  address.
- No device emulation, no fingerprint rotation, no proxy pool. The identity is
  one exit, one timezone, one geolocation, one signed-in session.

## License

AGPL-3.0 — the same terms as `nodriver`, which the browser tier is built on. That
is not a stylistic choice: the bundle imports nodriver and ships a patch applied to
that library, so the combined work carries the same copyleft. The rest are
permissive — `curl_cffi` (MIT), `pypdf` (BSD-3-Clause), `beautifulsoup4` (MIT).
