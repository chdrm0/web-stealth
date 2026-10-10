# web-stealth

Web retrieval for the DeepSeek Harness through a local sidecar instead of the
harness's built-in client. `web_fetch` and `web_search` go through two tiers that
report one identity:

- **curl** — `curl_cffi` with a Chrome TLS profile, a real cookie jar, your exit.
  Fast, no rendering. Reads PDFs page by page.
- **browser** — headed Chromium over CDP (nodriver). It reads its own version and
  client hints back and feeds them to the curl tier, so both claim the same
  browser. Also exposed to the agent as browser tools.

No cost per request, no third-party API, nothing leaves the machine except the
request itself.

## Install

Needs the harness (`>=0.1.7-alpha.2 <0.3.0`), [`uv`](https://docs.astral.sh/uv/),
and a Chromium-family browser.

```sh
git clone https://github.com/chdrm0/web-stealth
cd web-stealth/web-stealth
./install.sh
# restart the profile — the JS half and the patch are read at startup
(cd fetchd && ./.venv/bin/python -m fetchd.harvest)   # sign in once, optional
./install.sh doctor                                   # what is still missing
```

`install.sh` builds the sidecar venv from `uv.lock` and mounts both bundles into
the profile. It writes no secrets and rewrites no paths: the sidecar directory,
its interpreter and the cookie jar are derived from where the bundle and the
harness live.

## Settings

The authority is the `config:` block in `web-stealth/cordis.patch.yml`; the
settings page writes the same keys. A patch `config` **replaces** the plugin's
defaults wholesale, so a value pinned in one row wins over the default in code.

| Key | What it does |
| --- | --- |
| `proxy` | `socks5h://host:port`, or empty to connect directly. `socks5://` is refused: local DNS hands the tunnel an IPv6 literal it cannot carry and the session comes back reset. |
| `timezone` | What the exit claims, e.g. `Europe/Berlin`. Empty sends nothing and the browser reports this machine's clock. |
| `geolocation` | `lat,lon`, e.g. `52.52,13.40`. Empty sends no location at all. |
| `impersonate` | TLS profile for the curl tier. Empty picks the newest profile curl_cffi ships that does not outrun the real browser. |
| `browserExecutable` | Which browser drives the browser tier and the login window. |
| `searchEngine` | Primary engine. The chain falls through google → brave → duckduckgo only at a wall, never on an empty answer. |
| `maxChars` / `timeoutMs` | Body budget per fetch; per-request timeout. |
| `antiCaptchaKey` | Optional, also read from `.env`. Never logged, returned, or handed to the agent. |

The city and the clock belong to the **exit**, not to this machine: set them
together with `proxy`, or a Berlin exit reporting a New York clock is exactly the
mismatch a site reads as a bot.

Cookies live in `~/.dsh/web-stealth/jar/<group>.json`, mode 0600, and a set
belongs to the exit it was harvested behind — change the exit, re-harvest.

## Routing the exit through xray

The plugin only needs a SOCKS5 endpoint, so xray sits in front of any exit. This
inbound listens on loopback and sends everything to one outbound:

```json
{
  "loglevel": "warning",
  "inbounds": [
    { "tag": "socks", "port": 10800, "protocol": "socks",
      "settings": { "auth": "noauth", "udp": true } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "vmess", "tag": "exit",
      "settings": { "vnext": [{ "address": "<server>", "port": 443,
        "users": [{ "id": "<uuid>" }] }] } }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "direct", "ip": ["127.0.0.0/8"] },
      { "type": "field", "outboundTag": "direct", "domain": ["<server>"] }
    ]
  }
}
```

Then set `proxy: socks5h://127.0.0.1:10800`.

Three things that are easy to get wrong:

- **`socks5h://`, never `socks5://`.** With local resolution the tunnel is handed
  an AAAA record it cannot carry, and TLS comes back reset (`curl 35`).
- **Route the xray server itself direct.** Without that rule the tunnel carries
  its own connection and loops.
- **One exit for both tiers.** There is a single `proxy` setting on purpose: a
  cookie set that moves between addresses is what an identity provider reads as
  suspicious.

## Agent instructions

`AGENTS.md` at the root is the guidance this plugin is developed under: how the
search chain behaves, what the `[stealth]` notices mean, where the traps are. The
harness reads it for anyone working in this repository. To have your own agent
use it, copy the sections you agree with into your harness's instruction file
(`~/.dsh/AGENTS.md`).

## License

AGPL-3.0 — the same terms as `nodriver`, which the browser tier is built on and
which this repository patches. `curl_cffi` (MIT), `pypdf` (BSD-3-Clause) and
`beautifulsoup4` (MIT) are permissive.

`PLAN.md` and `DESIGN.md` are the working record: measured facts and closed
defects. They are kept on purpose — the plugin's behaviour is easier to change
when the measurements that shaped it are in the tree.
