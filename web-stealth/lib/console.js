/**
 * The plugin's own control surface: the HTTP endpoints behind its settings page.
 *
 * Why an HTTP route and not a generated remote namespace: a remote needs a
 * typert manifest (generated, zod-shaped, one artifact per face), and this
 * bundle deliberately imports nothing from the harness tree — a profile-installed
 * bundle resolves its imports from its own directory, where the harness packages
 * are not reachable. The harness already serves the page from this same HTTP
 * carrier, so the page can reach a route with a plain `fetch`, and the only
 * contract to keep is the JSON shape below.
 *
 * Who may call it: the page that is served from this server. A browser sends
 * `Sec-Fetch-Site: same-origin` (and an `Origin`) on such a request; a script, a
 * form on another site, or a local process sending hand-built bytes does not.
 * That is the whole authentication, so the endpoints stay narrow: read state,
 * change the exit, start or stop a harvest. Nothing here accepts a URL, a path,
 * or a command.
 *
 * Writing the proxy goes through the harness's own config editor: it validates
 * the candidate, writes the profile patch, reconciles that entry.
 * A plugin editing its own row is a supported shape, and it means the page does
 * not have to restart the profile for the change to take effect.
 *
 * @module @local/web-stealth/lib/console
 */
import fs from 'node:fs';
import process from 'node:process';

const ROUTE_PATH = '/api/stealth';
const MAX_BODY_BYTES = 4096;
const JAR_GROUPS = ['google', 'github', 'brave', 'reddit', 'other'];

/** The same exit, spelled the way Chrome spells it (mirrors the sidecar). */
function browserProxyOf(proxy) {
	return typeof proxy === 'string' && proxy.startsWith('socks5h://')
		? `socks://${proxy.slice('socks5h://'.length)}`
		: proxy;
}

/**
 * Where a Chromium-family browser usually lives on Linux. A starting point for a
 * choice, not a filesystem search: the page offers what is actually installed and
 * executable here, and the plugin config may still name any path.
 */
const BROWSER_CANDIDATES = [
	['brave', '/usr/bin/brave'],
	['brave', '/opt/brave-bin/brave'],
	['chrome', '/usr/bin/google-chrome'],
	['chrome', '/usr/bin/google-chrome-stable'],
	['chromium', '/usr/bin/chromium'],
	['chromium', '/usr/bin/chromium-browser'],
	['chromium', '/snap/bin/chromium'],
	['edge', '/usr/bin/microsoft-edge'],
];

/**
 * The browsers on this machine, one entry per family. Deduplicating by what the
 * path resolves to does not work here: `/usr/bin/brave` is a wrapper script that
 * execs `/opt/brave-bin/brave`, so the two are different files and both pass. The
 * list is ordered by preference, so the first hit per family is the one to offer.
 */
function detectBrowsers() {
	const seen = new Set();
	const found = [];
	for (const [name, path] of BROWSER_CANDIDATES) {
		if (seen.has(name)) continue;
		try {
			fs.accessSync(path, fs.constants.X_OK);
		} catch {
			// Not installed here — the normal case for most of the list.
			continue;
		}
		seen.add(name);
		found.push({ name, path });
	}
	return found;
}

/**
 * Only a remote-DNS SOCKS5 exit, or no exit at all. `socks5://` is refused for the
 * same reason the sidecar refuses it: local resolution hands the tunnel an IPv6
 * literal it cannot carry and the TLS session comes back reset.
 *
 * With no exit Chrome drops `--proxy-server` and `--proxy-bypass-list=<-loopback>`
 * stops meaning anything, so the browser tier refuses this machine at its own
 * network layer instead. Measured: a page's own request to the harness port fails
 * while its request to a public host goes through.
 */
function assertProxy(raw) {
	if (raw === '' || raw === null || raw === undefined) return '';
	if (typeof raw !== 'string' || raw.length > 200) throw new Error('proxy must be a short string');
	if (!raw.startsWith('socks5h://')) throw new Error('proxy must be socks5h://host:port, or empty for no exit');
	const rest = raw.slice('socks5h://'.length);
	const host = rest.split(':')[0];
	const port = Number(rest.split(':')[1]);
	if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('proxy must be socks5h://host:port');
	return raw;
}

/**
 * The city the exit claims. Checked against the platform's own zone table rather
 * than a pattern: a name `Intl` rejects is a name the browser would reject too, and
 * an override silently ignored is worse than a refusal.
 */
function assertTimezone(raw) {
	if (raw === '' || raw === null || raw === undefined) return '';
	if (typeof raw !== 'string' || raw.length > 64) throw new Error('timezone must be a short IANA name, or empty for no override');
	try {
		new Intl.DateTimeFormat('en', { timeZone: raw });
	} catch (error) {
		throw new Error(`timezone ${JSON.stringify(raw)} is not a zone this machine knows: ${error.message}`);
	}
	return raw;
}

/** `lat,lon` where the exit is, or empty to send no location at all. */
function assertGeolocation(raw) {
	if (raw === '' || raw === null || raw === undefined) return '';
	if (typeof raw !== 'string') throw new Error('geolocation must be "lat,lon", or empty');
	const parts = raw.split(',');
	if (parts.length !== 2) throw new Error('geolocation must be "lat,lon"');
	const [lat, lon] = parts.map((part) => Number(part.trim()));
	if (!Number.isFinite(lat) || !Number.isFinite(lon)) throw new Error('geolocation must be two numbers');
	if (lat < -90 || lat > 90 || lon < -180 || lon > 180) throw new Error('geolocation is out of range');
	return `${lat},${lon}`;
}

/**
 * One jar group as the page sees it: how many cookies, when the set was last
 * written, and whether the sidecar marked it refused. Values are never read out
 * of the file — a count is computed and the array is dropped. Async because the
 * page polls this every couple of seconds and the request path is the event loop.
 */
async function jarGroupState(dir, group) {
	const file = `${dir}/${group}.json`;
	try {
		const [body, stat, stale] = await Promise.all([
			fs.promises.readFile(file, 'utf8'),
			fs.promises.stat(file),
			fs.promises.stat(`${dir}/${group}.stale.json`).then(() => true, () => false),
		]);
		const records = JSON.parse(body);
		return { group, count: Array.isArray(records) ? records.length : 0, updatedAt: Math.floor(stat.mtimeMs), stale };
	} catch {
		return { group, count: 0, updatedAt: null, stale: false };
	}
}

async function jarState(dir) {
	return Promise.all(JAR_GROUPS.map((group) => jarGroupState(dir, group)));
}

/**
 * A request the page this server served could have made: a browser carries
 * `Sec-Fetch-Site`/`Origin` on it, and a page on another origin cannot forge them
 * from its script. That is the whole point of the check — cross-site pages. A
 * local process can write either header, but a local process can also edit the
 * profile patch by hand, so it was never outside the trust boundary.
 */
function sameOrigin(req) {
	if (req.headers['sec-fetch-site'] === 'same-origin') return true;
	const origin = req.headers.origin;
	if (!origin) return false;
	try {
		return new URL(origin).host === req.headers.host;
	} catch {
		return false;
	}
}

function send(res, status, body) {
	const payload = JSON.stringify(body);
	res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store' });
	res.end(payload);
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on('data', (chunk) => {
			size += chunk.length;
			if (size > MAX_BODY_BYTES) {
				reject(new Error('request body too large'));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on('end', () => {
			if (chunks.length === 0) return resolve({});
			try {
				resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
			} catch (error) {
				reject(new Error(`body is not JSON: ${error.message}`));
			}
		});
		req.on('error', reject);
	});
}

/**
 * Build the route handler.
 *
 * The services arrive as plain references captured during activation. A request
 * callback runs outside the fiber's activation window, and the context refuses a
 * service property lookup from there — `cannot get required service … in inactive
 * context` — so the capture has to happen while the plugin is being applied.
 *
 * @param deps - `{ configEditor, config, harvest, entryId, browsers, browserExecutable }` for this generation.
 */
export function consoleRoute(deps) {
	const { configEditor, config, harvest, entryId, browsers, browserExecutable, antiCaptchaConfigured } = deps;

	const snapshot = async () => ({
		proxy: config.proxy,
		browserProxy: browserProxyOf(config.proxy),
		// Which posture the machine is in: an exit, or none. The page says so out
		// loud rather than leaving it to be inferred from an empty field.
		direct: config.proxy === '',
		// Where the exit claims to be. Empty means nothing is overridden. The
		// machine's own zone travels beside them so an override that stopped
		// matching the exit is visible on the page instead of being guessed.
		timezone: config.timezone,
		geolocation: config.geolocation,
		machineTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? '',
		browser: browserExecutable,
		browsers,
		searchEngine: config.searchEngine,
		blockMedia: config.blockMedia,
		// The solver's key as the page may see it: never the value — only whether
		// one is in force, whether it came from this row or a fallback, and its
		// length. The key is write-only through this surface: the page sends it,
		// the row stores it, the sidecar's environment receives it, nothing reads
		// it back.
		antiCaptcha: {
			configured: Boolean(antiCaptchaConfigured),
			present: config.antiCaptchaKey !== '',
			length: config.antiCaptchaKey.length,
			masked: config.antiCaptchaKey === '' ? '' : '*'.repeat(Math.min(24, Math.max(8, config.antiCaptchaKey.length))),
		},
		jarDir: config.jarDir,
		jar: await jarState(config.jarDir),
		harvest: harvest.current ? harvest.current.status() : { running: false, groups: [], exit: null, lines: 0, startedAt: null },
	});

	/**
	 * The row this plugin was activated with. `configEditor` writes the profile
	 * layer, so the bundle's own patch stays untouched and the change is visible
	 * in `dsh --profile … --dump-config` like any other profile setting.
	 */
	const ownEntry = () => {
		const entries = configEditor.entries();
		const found = entries.find((entry) => entry?.options?.id === entryId);
		if (found) return found;
		// Named, not just "not found": the row id is the one assumption here, and
		// the page has to say which rows the profile does consider editable.
		const ids = entries.map((entry) => entry?.options?.id).filter(Boolean).slice(0, 8);
		throw new Error(`the row "${entryId}" is not editable from the profile layer (editable: ${ids.join(', ') || 'none'})`);
	};

	/**
	 * The whole effective config, minus what must never be frozen into the row. A
	 * patch `config` row replaces the layer below it wholesale, so changing one
	 * field means writing every field — and two kinds of value must not be spread
	 * in. The secret: its resolved value may come from a `.env` fallback that was
	 * never meant to be copied into YAML. And the settings whose empty value is
	 * meaningful — the impersonation target and the two claims about where the exit
	 * is: copying a resolved value there pins a choice that was only meant for
	 * today, and the pin outlives every later change (measured: an old
	 * `impersonate: chrome150` survived in the row after the default became
	 * "choose it yourself", so the auto-selection never ran). Anything the owner
	 * set explicitly already rides in `current`, so it survives saving other fields
	 * either way; clearing one is its own request.
	 */
	const neverCopied = new Set(['antiCaptchaKey', 'impersonate', 'timezone', 'geolocation']);
	const writableConfig = () => Object.fromEntries(Object.entries(config).filter(([key]) => !neverCopied.has(key)));

	async function applyProxy(proxy) {
		const entry = ownEntry();
		await configEditor.edit(entry, (current) => ({ ...writableConfig(), ...(current ?? {}), proxy }));
		return proxy;
	}

	/**
	 * One non-secret setting written the same way the exit is written. The city and
	 * the clock belong to the exit, so they are saved through the same door and
	 * land in the same profile row — changing the exit and changing the claim about
	 * where the exit is should never require two different places.
	 */
	async function applySetting(key, value) {
		const entry = ownEntry();
		await configEditor.edit(entry, (current) => ({ ...writableConfig(), ...(current ?? {}), [key]: value }));
		return value;
	}

	/**
	 * Which browser the browser tier drives. Only a path this machine actually
	 * offers is accepted: writing an arbitrary string from an HTTP request would
	 * put an executable path into a config that is later spawned.
	 */
	async function applyBrowser(wanted) {
		const known = browsers.filter((browser) => browser.path === wanted);
		if (known.length === 0) throw new Error(`"${wanted}" is not a browser installed here (found: ${browsers.map((browser) => browser.path).join(', ') || 'none'})`);
		const entry = ownEntry();
		await configEditor.edit(entry, (current) => ({ ...writableConfig(), ...(current ?? {}), browserExecutable: wanted }));
		return wanted;
	}

	return async function handler(req, res) {
		if (!sameOrigin(req)) return send(res, 403, { error: 'this endpoint is only reachable from the harness page' });
		const path = (req.url ?? '').split('?')[0].replace(/\/+$/, '');
		const sub = path.slice(ROUTE_PATH.length).replace(/^\//, '');
		const method = req.method ?? 'GET';
		try {
			if (method === 'GET' && (sub === '' || sub === 'state')) return send(res, 200, await snapshot());

			if (method === 'POST' && sub === 'proxy') {
				const body = await readBody(req);
				// The key has to be there: an absent one would read as "no exit", and
				// switching the machine to direct is not something a malformed request
				// should be able to do by omission.
				if (!('proxy' in body)) throw new Error('proxy is required — send an empty string for no exit');
				const proxy = assertProxy(body.proxy);
				await applyProxy(proxy);
				// The reconcile re-activates this row, so the reply is the state as
				// it was asked for; the page re-reads it on its next poll.
				return send(res, 200, { ...(await snapshot()), applied: true });
			}

			if (method === 'POST' && (sub === 'timezone' || sub === 'geolocation')) {
				const body = await readBody(req);
				// Required in the body for the same reason the proxy is: an absent
				// field would read as "stop overriding", and dropping the claim about
				// where the exit is should not happen by omission.
				if (!(sub in body)) throw new Error(`${sub} is required — send an empty string to send nothing`);
				const value = sub === 'timezone' ? assertTimezone(body[sub]) : assertGeolocation(body[sub]);
				await applySetting(sub, value);
				return send(res, 200, { ...(await snapshot()), applied: true });
			}

			if (method === 'POST' && sub === 'browser') {
				const body = await readBody(req);
				if (typeof body.browser !== 'string' || body.browser.length === 0) throw new Error('browser must name an installed executable');
				const chosen = await applyBrowser(body.browser);
				return send(res, 200, { ...(await snapshot()), applied: true, browser: chosen });
			}

			// The solver's key: write-only. The page sends it, the profile row
			// stores it, the sidecar's environment receives it on the next spawn.
			// Nothing here echoes it back — the reply is the masked snapshot, and
			// no error message carries the value.
			if (method === 'POST' && sub === 'anticaptcha') {
				const body = await readBody(req);
				const entry = ownEntry();
				if (body.clear === true) {
					// Clearing is explicit, never a side effect of saving another
					// field: the row loses the key and the `.env` fallback answers.
					await configEditor.edit(entry, (current) => {
						const { antiCaptchaKey, ...rest } = current ?? {};
						return { ...writableConfig(), ...rest };
					});
					return send(res, 200, { ...(await snapshot()), applied: true, cleared: true });
				}
				if (typeof body.key !== 'string' || body.key.trim().length === 0) throw new Error('key must be a non-empty string, or send { clear: true } to fall back to .env');
				const key = body.key.trim();
				if (key.length > 200) throw new Error('key is too long');
				await configEditor.edit(entry, (current) => ({ ...writableConfig(), ...(current ?? {}), antiCaptchaKey: key }));
				return send(res, 200, { ...(await snapshot()), applied: true });
			}

			if (method === 'POST' && sub === 'harvest') {
				if (harvest.active) return send(res, 409, { error: 'a harvest is already running' });
				const body = await readBody(req);
				const run = harvest.start({ groups: body.groups, waitS: body.waitS, smoke: Boolean(body.smoke) });
				return send(res, 200, { started: true, groups: run.groups, waitS: run.waitS });
			}
			if (method === 'POST' && sub === 'harvest/progress') {
				const run = harvest.current;
				if (!run) return send(res, 409, { error: 'no harvest has run' });
				const body = await readBody(req);
				// A poll, not a stream: the page sends the cursor it last saw and
				// gets everything after it, so a reload loses nothing.
				return send(res, 200, run.since(Number(body.after) || 0));
			}
			if (method === 'POST' && sub === 'harvest/finish') {
				const run = harvest.current;
				if (!run) return send(res, 409, { error: 'no harvest has run' });
				return send(res, 200, { signalled: run.finish() });
			}
			if (method === 'POST' && sub === 'harvest/cancel') {
				const run = harvest.current;
				if (!run) return send(res, 409, { error: 'no harvest has run' });
				return send(res, 200, { cancelled: await run.cancel() });
			}
			return send(res, 404, { error: `no such endpoint: ${method} ${path}` });
		} catch (error) {
			// The message is written for a person reading a settings page: it names
			// what to change, and it never carries a cookie value or a key.
			return send(res, 400, { error: error instanceof Error ? error.message : String(error) });
		}
	};
}

export { ROUTE_PATH, assertProxy, browserProxyOf, jarState, detectBrowsers };
