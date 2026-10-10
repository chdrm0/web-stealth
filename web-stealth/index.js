/**
 * Stealth `web_fetch`: a `ctx.web` fetch provider whose retrieval runs in a
 * Python sidecar (curl_cffi first, browser tier later).
 *
 * Division of labour: this module owns the seam contract (provider id, result
 * shape, error codes), the URL policy and the sidecar lifecycle. Every retrieval
 * decision — fingerprint, cookies, proxy, extraction — lives in the Python
 * process and is reached only through `lib/sidecar.js`.
 *
 * Deliberate choice: no `Config` export and no runtime dependencies. A
 * profile-installed bundle resolves its imports from the profile tree, where
 * `@deepseek-ai/dsh-web` is not guaranteed to be reachable, so `WebError` is NOT
 * imported here. Failures carry a local `code` field instead.
 *
 * @module @local/web-stealth
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { Sidecar, SidecarFailure } from './lib/sidecar.js';
import { assertFetchableUrl, UrlPolicyFailure } from './lib/policy.js';
import { registerBrowserTools } from './lib/browser-tools.js';
import { HarvestRunner } from './lib/harvest.js';
import { ROUTE_PATH, consoleRoute, detectBrowsers } from './lib/console.js';

const name = 'web-stealth';
// `configEditor` is a real dependency, not an optional one: the context refuses
// `ctx.get` for a service the plugin did not declare, so the settings page's
// "change the exit" control needs the row present. It is in the base profile, and
// a profile without it should fail at activation rather than serve a page whose
// only button throws.
const inject = ['web', 'tools', 'webServer', 'configEditor'];

/** Registry key the `web` row pins as `fetchProvider`. */
const PROVIDER_ID = 'stealth-web';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** `~/.dsh` fallback; `$DSH_PROFILE_DIR` is set for every profile-launched harness. */
function dshHome() {
	if (typeof process.env.DSH_PROFILE_DIR === 'string' && process.env.DSH_PROFILE_DIR.length > 0) return process.env.DSH_PROFILE_DIR;
	return path.join(process.env.HOME ?? '', '.dsh');
}

const DEFAULTS = Object.freeze({
	// The venv belongs to the sidecar package and ships beside the bundle.
	python: path.resolve(HERE, 'fetchd', '.venv', 'bin', 'python'),
	sidecarDir: path.resolve(HERE, 'fetchd'),
	// Wall clock for one fetch. A browser render is not an HTTP GET: 30s is tight.
	timeoutMs: 45000,
	// Inline budget. dsh-tool-web slices at its own fetchMaxOutputChars (200000)
	// and the harness spills past ~12500 tokens, so a smaller cap keeps the
	// result readable instead of merely stored elsewhere. 30000 chars is ~7500
	// tokens — still inline — and is what lets a PDF page range arrive whole
	// instead of in three calls.
	maxChars: 30000,
	maxLinks: 100,
	blockPrivateNetworks: true,
	// Cookie sets are credentials: outside the repo, under the profile directory.
	jarDir: path.join(dshHome(), 'web-stealth', 'jar'),
	// Remote DNS is mandatory: socks5:// resolves locally, hands the tunnel an
	// IPv6 literal it cannot carry, and the TLS handshake comes back reset.
	// There is no default exit — a shipped default cannot know anyone's tunnel.
	// Empty means connect directly, which is a supported posture, not a mistake.
	proxy: '',
	// Empty means the sidecar picks the newest curl_cffi Chrome target that is not
	// ahead of the browser being imitated. A pinned constant rots the day either
	// side updates, and then the two tiers disagree about who they are.
	impersonate: '',
	acceptLanguage: 'en-US,en;q=0.9',
	// Where the exit is, as the browser sees it. Both follow the proxy and neither
	// has a default: a city shipped to a machine whose exit is elsewhere is a
	// mismatch a risk engine reads as deception. Empty sends nothing.
	timezone: '',
	geolocation: '',
	// Overrides for the sidecar's measured routing table; {} keeps the defaults.
	originPolicy: {},
	// The sidecar exits when idle so a Python change reaches a fresh generation.
	idleTimeoutS: 300,
	// google answers a logged-in curl request with a real SERP; brave works but
	// rate-limits quickly, so it is the fallback rather than the default.
	searchEngine: 'google',
	maxSearchResults: 10,
	// The browser tier: one tab at a time, its own budget (a render is not an
	// HTTP GET), and the caps that keep a page listing inside the context.
	browserTimeoutMs: 90000,
	browserMaxChars: 12000,
	// open/state/act answer with a text preview; only browser_read gives the
	// whole page. A full article in every listing is context spent on nothing.
	browserTextChars: 2500,
	// The cap is spent in DOM order, and a shopping page puts its whole filter
	// block inside `main` before the listings: at 60 an eBay search ended at the
	// filters and never listed a single item.
	browserMaxElements: 120,
	browserIdleS: 180,
	// A login earned in the browser tier is folded back into the jar when the tab
	// closes, which is what makes "sign in once, reuse the session" true for
	// sites beyond the three that were harvested by hand.
	browserJarWriteback: true,
	// Which browser the browser tier drives. Empty means "whatever this machine
	// has" — the console endpoint lists the installed candidates and the settings
	// page picks one, which is what makes a copied bundle work on a machine that
	// has chromium instead of brave.
	browserExecutable: '',
	// Images and video are refused at the network layer, so they are never
	// downloaded, decoded or held in the renderer: there is no vision to spend
	// them on, and a media-heavy front page is the fastest way to run a small
	// machine out of memory. Empty patterns mean the sidecar's built-in list.
	blockMedia: true,
	blockMediaPatterns: '',
	// The solver's key. Left empty here, it is read from a `.env` beside the
	// bundle or beside the project (see resolveAntiCaptchaKey).
	antiCaptchaKey: '',
	// Wall clock for one bought solve, task creation to token.
	antiCaptchaTimeoutMs: 180000,
});

/** Failure with a machine-routable code, mirroring the seam's WebError shape. */
class StealthFailure extends Error {
	constructor(code, message, cause) {
		super(message);
		this.code = code;
		if (cause !== undefined) this.cause = cause;
	}
}

function positiveInt(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (!Number.isSafeInteger(raw) || raw < 1) throw new StealthFailure('config', `${name}: config.${key} must be a positive integer, got ${JSON.stringify(raw)}`);
	return raw;
}

// Zero is a meaningful value here (the sidecar never retires on its own), so the
// positive-only validator would make the documented "0 disables" unreachable.
function nonNegativeInt(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (!Number.isSafeInteger(raw) || raw < 0) throw new StealthFailure('config', `${name}: config.${key} must be an integer >= 0, got ${JSON.stringify(raw)}`);
	return raw;
}

function text(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (typeof raw !== 'string' || raw.trim().length === 0) throw new StealthFailure('config', `${name}: config.${key} must be a non-empty string`);
	return raw;
}

/**
 * A string where empty is a value rather than a mistake: the exit ("direct"), the
 * impersonation target ("choose it yourself") and the two claims about where the
 * exit is ("send nothing"). `text` rejects exactly what the settings page writes
 * for "no override", and a rejected field fails the whole entry — which takes
 * retrieval down with it.
 */
function optionalText(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (typeof raw !== 'string') throw new StealthFailure('config', `${name}: config.${key} must be a string; empty means the default posture`);
	return raw.trim();
}

/**
 * Which browser the browser tier drives: an absolute path, or empty for "detect one
 * on this machine". A relative path is refused rather than resolved against the
 * sidecar's working directory, which is not the directory anyone means.
 */
function browserPath(raw) {
	if (raw === undefined || raw === null) return '';
	if (typeof raw !== 'string') throw new StealthFailure('config', `${name}: config.browserExecutable must be an absolute path or empty`);
	const value = raw.trim();
	if (value !== '' && !value.startsWith('/')) throw new StealthFailure('config', `${name}: config.browserExecutable must be an absolute path, or empty to detect one`);
	return value;
}

function bool(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (typeof raw !== 'boolean') throw new StealthFailure('config', `${name}: config.${key} must be a boolean`);
	return raw;
}

function patternList(raw, key, fallback) {
	// A row that is neither a string nor a list of strings must not reach the
	// sidecar as "false" or "[object Object]": the sidecar would then replace the
	// whole built-in block list with one pattern matching nothing useful.
	if (raw === undefined) return fallback;
	if (typeof raw === 'string') return raw;
	if (Array.isArray(raw) && raw.every((item) => typeof item === 'string' && item.trim().length > 0)) return raw.join(',');
	throw new StealthFailure('config', `${name}: config.${key} must be a string or a list of strings`);
}

function objectConfig(raw, key, fallback) {
	if (raw === undefined) return fallback;
	if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new StealthFailure('config', `${name}: config.${key} must be an object`);
	return raw;
}

// Keep in sync with POLICIES / KNOWN_GROUPS in fetchd/fetchd/engine/routing.py.
// Checked on both sides deliberately: this object decides which credentials are
// presented to which origins, so a typo must fail at activation rather than sit
// there silently — and `sendJar: "false"` must not read as true.
const ORIGIN_POLICIES = new Set(['curl_only', 'curl_then_browser', 'browser_first']);
const ORIGIN_GROUPS = new Set(['google', 'github', 'brave', 'reddit', 'other']);

function normalizeOriginPolicy(raw, key) {
	if (raw === undefined) return DEFAULTS.originPolicy;
	if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new StealthFailure('config', `${name}: config.${key} must be an object of group -> settings`);
	for (const [group, settings] of Object.entries(raw)) {
		if (!ORIGIN_GROUPS.has(group)) throw new StealthFailure('config', `${name}: config.${key} has unknown group ${JSON.stringify(group)}; expected one of ${[...ORIGIN_GROUPS].join(', ')}`);
		if (settings === null || typeof settings !== 'object' || Array.isArray(settings)) throw new StealthFailure('config', `${name}: config.${key}.${group} must be an object`);
		if (settings.policy !== undefined && !ORIGIN_POLICIES.has(settings.policy)) throw new StealthFailure('config', `${name}: config.${key}.${group}.policy must be one of ${[...ORIGIN_POLICIES].join(', ')}`);
		if (settings.sendJar !== undefined && typeof settings.sendJar !== 'boolean') throw new StealthFailure('config', `${name}: config.${key}.${group}.sendJar must be a boolean`);
	}
	return raw;
}

// Keep in sync with ENGINE_URLS in fetchd/fetchd/engine/search.py. Validating
// here turns a typo into an activation error instead of a dead child process.
const SEARCH_ENGINES = new Set(['google', 'brave', 'duckduckgo']);

function searchEngineName(raw) {
	if (raw === undefined) return DEFAULTS.searchEngine;
	if (typeof raw !== 'string' || !SEARCH_ENGINES.has(raw)) {
		throw new StealthFailure('config', `${name}: config.searchEngine must be one of ${[...SEARCH_ENGINES].join(', ')}, got ${JSON.stringify(raw)}`);
	}
	return raw;
}

/** Validate at activation: a bad row fails loudly instead of building a broken provider. */
/** The sidecar's protocol ceiling for a frame's timeoutMs. Configured above it,
 *  every call would be refused outright rather than run longer, so the value is
 *  clamped instead of trusted. */
const PROTOCOL_MAX_TIMEOUT_MS = 180000;

/** A reply is one JSON line, and the reader drops the whole connection over a
 *  line longer than 4 MiB. An element costs a few hundred bytes, so the element
 *  cap is clamped for the same reason the timeouts are: a configured 20000 is a
 *  way to kill the sidecar, not to see more of the page. */
const PROTOCOL_MAX_ELEMENTS = 500;

/** The same line bound covers the text budgets: a configured 5 000 000 is a way
 *  to kill the sidecar, not a way to read more of the page. */
const PROTOCOL_MAX_CHARS = 200000;
const PROTOCOL_MAX_TEXT_CHARS = 20000;
const PROTOCOL_MAX_LINKS = 2000;
const PROTOCOL_MAX_SEARCH_RESULTS = 50;

/** Read `KEY=value` lines from a .env file. Missing or unreadable is not an
 *  error: the caller falls through to the next source. */
function readEnvFile(file) {
	let contents;
	try {
		contents = fs.readFileSync(file, 'utf8');
	} catch {
		return null;
	}
	const keys = {};
	for (const line of contents.split('\n')) {
		const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
		if (!match) continue;
		keys[match[1]] = match[2].trim().replace(/^["']|["']$/g, '');
	}
	return keys;
}

/** Names the key may live under, most specific first. `API_KEY` last: a bare
 *  name is the project's convention, not the solver's. */
const ANTI_CAPTCHA_KEY_NAMES = ['ANTI_CAPTCHA_API_KEY', 'ANTICAPTCHA_API_KEY', 'API_KEY'];

/**
 * Where the solver's account key comes from: the plugin config, then a `.env`
 * beside the bundle or beside the project, then the harness environment.
 *
 * The value is never logged and never reaches a tool reply; it is handed to the
 * sidecar's environment, which is the only process allowed to use it.
 */
function resolveAntiCaptchaKey(config) {
	// An empty row means "not configured", not "refuse to activate": the settings
	// page may save an empty field, and the fallbacks below must still answer.
	const raw = config.antiCaptchaKey;
	if (raw !== undefined && raw !== null && typeof raw !== 'string') throw new StealthFailure('config', `${name}: config.antiCaptchaKey must be a string`);
	const explicit = typeof raw === 'string' ? raw.trim() : '';
	if (explicit) return explicit;
	for (const file of [path.resolve(HERE, '.env'), path.resolve(HERE, '..', '.env')]) {
		const keys = readEnvFile(file);
		if (!keys) continue;
		for (const key of ANTI_CAPTCHA_KEY_NAMES) if (keys[key]) return keys[key];
	}
	for (const key of ANTI_CAPTCHA_KEY_NAMES) if (process.env[key]) return process.env[key];
	return '';
}

function normalizeConfig(raw) {
	if (raw !== undefined && raw !== null && (typeof raw !== 'object' || Array.isArray(raw))) throw new StealthFailure('config', `${name}: config must be an object`);
	const config = raw ?? {};
	// An empty proxy is a supported posture — no exit at all — and the browser tier
	// then refuses this machine at its own network layer. Any other value must be a
	// remote-DNS SOCKS5 exit: `socks5://` resolves locally and the tunnel drops IPv6
	// targets, and an HTTP proxy is not what this identity is built around.
	const proxy = config.proxy === undefined || config.proxy === null
		? (process.env.WEB_STEALTH_PROXY ?? DEFAULTS.proxy)
		: String(config.proxy).trim();
	if (proxy !== '' && !proxy.startsWith('socks5h://')) throw new StealthFailure('config', `${name}: config.proxy must be socks5h://host:port or empty for no exit; socks5:// resolves locally and the tunnel drops IPv6 targets`);
	return {
		python: text(config.python, 'python', DEFAULTS.python),
		sidecarDir: text(config.sidecarDir, 'sidecarDir', DEFAULTS.sidecarDir),
		timeoutMs: Math.min(positiveInt(config.timeoutMs, 'timeoutMs', DEFAULTS.timeoutMs), PROTOCOL_MAX_TIMEOUT_MS),
		maxChars: Math.min(positiveInt(config.maxChars, 'maxChars', DEFAULTS.maxChars), PROTOCOL_MAX_CHARS),
		maxLinks: Math.min(positiveInt(config.maxLinks, 'maxLinks', DEFAULTS.maxLinks), PROTOCOL_MAX_LINKS),
		blockPrivateNetworks: bool(config.blockPrivateNetworks, 'blockPrivateNetworks', DEFAULTS.blockPrivateNetworks),
		jarDir: text(config.jarDir, 'jarDir', DEFAULTS.jarDir),
		proxy,
		impersonate: optionalText(config.impersonate, 'impersonate', DEFAULTS.impersonate),
		timezone: optionalText(config.timezone, 'timezone', DEFAULTS.timezone),
		geolocation: optionalText(config.geolocation, 'geolocation', DEFAULTS.geolocation),
		acceptLanguage: text(config.acceptLanguage, 'acceptLanguage', DEFAULTS.acceptLanguage),
		originPolicy: normalizeOriginPolicy(config.originPolicy, 'originPolicy'),
		idleTimeoutS: nonNegativeInt(config.idleTimeoutS, 'idleTimeoutS', DEFAULTS.idleTimeoutS),
		searchEngine: searchEngineName(config.searchEngine),
		maxSearchResults: Math.min(positiveInt(config.maxSearchResults, 'maxSearchResults', DEFAULTS.maxSearchResults), PROTOCOL_MAX_SEARCH_RESULTS),
		browserTimeoutMs: Math.min(positiveInt(config.browserTimeoutMs, 'browserTimeoutMs', DEFAULTS.browserTimeoutMs), PROTOCOL_MAX_TIMEOUT_MS),
		browserMaxChars: Math.min(positiveInt(config.browserMaxChars, 'browserMaxChars', DEFAULTS.browserMaxChars), PROTOCOL_MAX_CHARS),
		browserTextChars: Math.min(positiveInt(config.browserTextChars, 'browserTextChars', DEFAULTS.browserTextChars), PROTOCOL_MAX_TEXT_CHARS),
		browserMaxElements: Math.min(positiveInt(config.browserMaxElements, 'browserMaxElements', DEFAULTS.browserMaxElements), PROTOCOL_MAX_ELEMENTS),
		browserIdleS: nonNegativeInt(config.browserIdleS, 'browserIdleS', DEFAULTS.browserIdleS),
		browserJarWriteback: config.browserJarWriteback !== false,
		browserExecutable: browserPath(config.browserExecutable),
		blockMedia: bool(config.blockMedia, 'blockMedia', DEFAULTS.blockMedia),
		blockMediaPatterns: patternList(config.blockMediaPatterns, 'blockMediaPatterns', DEFAULTS.blockMediaPatterns),
		antiCaptchaKey: resolveAntiCaptchaKey(config),
		antiCaptchaTimeoutMs: Math.min(positiveInt(config.antiCaptchaTimeoutMs, 'antiCaptchaTimeoutMs', DEFAULTS.antiCaptchaTimeoutMs), PROTOCOL_MAX_TIMEOUT_MS),
	};
}

/**
 * Shape-check the sidecar reply before it reaches the seam. A renamed or
 * missing field must fail here, not propagate into `WebFetchResult` as undefined.
 */
function assertFetchReply(reply, url) {
	if (reply === null || typeof reply !== 'object') throw new StealthFailure('bad-reply', `sidecar returned no object for ${url}`);
	if (typeof reply.url !== 'string' || reply.url.length === 0) throw new StealthFailure('bad-reply', `sidecar reply for ${url} is missing a string \`url\``);
	if (!Number.isInteger(reply.statusCode)) throw new StealthFailure('bad-reply', `sidecar reply for ${url} is missing an integer \`statusCode\``);
	if (typeof reply.text !== 'string') throw new StealthFailure('bad-reply', `sidecar reply for ${url} is missing a string \`text\``);
	if (reply.outcome !== undefined && typeof reply.outcome !== 'string') throw new StealthFailure('bad-reply', `sidecar reply for ${url} has a non-string \`outcome\``);
	return reply;
}

/**
 * The seam has one channel: `body.content`. Links therefore ride inside the
 * text rather than in a parallel field the renderer would never show.
 *
 * Budget rule: the link block gets its own slice of `maxChars` and the sidecar
 * is asked for correspondingly less text. Asking the sidecar for the whole
 * budget and appending afterwards silently drops every link.
 */
const LINK_BUDGET_RATIO = 0.3;
const LINK_BUDGET_MAX = 4000;
// On a results page the links ARE the payload: a flat 30% cut a google SERP down
// to three of seventeen results, so search gets the larger share instead.
const SEARCH_LINK_BUDGET_RATIO = 0.65;
const SEARCH_LINK_BUDGET_MAX = 8000;

// Each entry states its own navigation hosts rather than deriving them from the
// page host. Derivation is a trap: results pages whose results live on the
// engine itself (github) would have every result filtered out.
// Not the same list as SELF_HOST_SUFFIXES in fetchd/engine/search.py, which also
// drops youtube.com: there it filters result *candidates* out of a SERP, while
// here it filters links out of a fetched page, and a youtube result is a real
// result. Only hosts that can never be a destination are listed.
const SEARCH_RESULT_PAGES = [
	{ hosts: ['www.google.com', 'google.com'], path: '/search', dropHosts: ['google.com', 'googleusercontent.com', 'gstatic.com'] },
	{ hosts: ['search.brave.com'], path: '/search', dropHosts: ['brave.com'] },
	{ hosts: ['html.duckduckgo.com'], path: '/html', dropHosts: ['duckduckgo.com'] },
	{ hosts: ['github.com', 'www.github.com'], path: '/search', dropHosts: [] },
];

function searchPageOf(rawUrl) {
	try {
		const parsed = new URL(rawUrl);
		for (const page of SEARCH_RESULT_PAGES) {
			if (!page.hosts.includes(parsed.hostname)) continue;
			// A path boundary, so /searching-something is not a results page.
			if (parsed.pathname === page.path || parsed.pathname.startsWith(`${page.path}/`)) return page;
		}
		return null;
	} catch {
		return null;
	}
}

function isDropHost(rawUrl, dropHosts) {
	try {
		const host = new URL(rawUrl).hostname;
		return dropHosts.some((domain) => host === domain || host.endsWith(`.${domain}`));
	} catch {
		return false;
	}
}

function linkBudget(maxChars, search) {
	return Math.min(search ? SEARCH_LINK_BUDGET_MAX : LINK_BUDGET_MAX, Math.floor(maxChars * (search ? SEARCH_LINK_BUDGET_RATIO : LINK_BUDGET_RATIO)));
}

function composeBody(reply, maxChars, page) {
	const text = reply.text;
	let links = Array.isArray(reply.links) ? reply.links : [];
	// Navigation of an engine whose results live elsewhere (SignOutOptions, AI
	// Mode, help) is not a result and only eats the link budget.
	if (page && page.dropHosts.length > 0) {
		links = links.filter((link) => !isDropHost(link.url, page.dropHosts));
	}
	const textTruncated = reply.truncated === true;
	if (links.length === 0) {
		return { content: text.slice(0, maxChars), truncated: textTruncated || text.length > maxChars };
	}
	const header = '\n\nLinks:\n';
	const room = Math.max(0, Math.min(linkBudget(maxChars, page !== null), maxChars - text.length - header.length));
	const kept = [];
	let used = 0;
	for (const link of links) {
		const line = link.text ? `- ${link.url} — ${link.text}` : `- ${link.url}`;
		if (used + line.length + 1 > room) break;
		kept.push(line);
		used += line.length + 1;
	}
	const content = kept.length === 0 ? text.slice(0, maxChars) : `${text}${header}${kept.join('\n')}`;
	return {
		content: content.slice(0, maxChars),
		truncated: textTruncated || kept.length < links.length || content.length > maxChars,
	};
}

// Room kept at the end of `content` for the truncation line; the section title
// quoted in it is capped so the line always fits.
const TRUNCATION_LINE_RESERVE = 400;
const TRUNCATION_HEADING_MAX = 120;

/**
 * One factual line for a cut HTML/text page: how much text was returned, how
 * long the extracted text was, and where the cut fell. `textChars` is the
 * sidecar's pre-cut length; a tier that does not report it is named as such.
 */
function truncationLine(reply, shown) {
	const total = Number.isInteger(reply.textChars) && reply.textChars >= shown ? reply.textChars : null;
	const shownText = reply.text.slice(0, shown);
	let heading = null;
	// Only a heading whose whole line was returned: a cut one would be misquoted.
	for (const match of shownText.matchAll(/^#{1,5} (.+)\n/gm)) heading = match[1];
	const of = total === null ? 'of an unreported total' : `of ${total}`;
	const share = total === null || total === 0 ? '' : ` (${Math.round((shown / total) * 100)}%)`;
	const where = heading === null ? '' : `, inside the section "${heading.slice(0, TRUNCATION_HEADING_MAX)}"`;
	return `[stealth] Text truncated: returned ${shown} ${of} characters; stopped at character ${shown}${share}${where}. Fetch a narrower URL (a section or sub-page) for the rest.`;
}

async function runFetch(sidecar, config, request, signal) {
	const url = assertFetchableUrl(request.url, config.blockPrivateNetworks);
	const page = searchPageOf(url);
	const textBudget = Math.max(1000, config.maxChars - linkBudget(config.maxChars, page !== null) - '\n\nLinks:\n'.length);
	let reply;
	try {
		reply = await sidecar.request({ op: 'fetch', url, maxChars: textBudget, maxLinks: config.maxLinks, timeoutMs: config.timeoutMs }, { signal });
	} catch (error) {
		if (error instanceof SidecarFailure) throw new StealthFailure(error.code, error.message, error);
		throw error;
	}
	assertFetchReply(reply, url);
	const body = composeBody(reply, config.maxChars, page);
	// A hint goes FIRST: it is the part that must survive truncation, because it
	// says why the rest of the payload is not the document that was asked for.
	const notice = typeof reply.hint === 'string' && reply.hint.length > 0 ? `[stealth] ${reply.hint}\n\n` : '';
	let content = `${notice}${body.content}`.slice(0, config.maxChars);
	// A PDF carries its own page-numbered cut notice inside `text`.
	const isPdf = reply.contentType === 'application/pdf' || reply.pdf !== undefined;
	const textFits = Math.min(reply.text.length, Math.max(0, config.maxChars - notice.length));
	if (!isPdf && (reply.truncated === true || textFits < reply.text.length)) {
		const limit = Math.max(0, config.maxChars - TRUNCATION_LINE_RESERVE);
		const shown = Math.min(reply.text.length, Math.max(0, limit - notice.length));
		content = `${`${notice}${body.content}`.slice(0, limit)}\n\n${truncationLine(reply, shown)}`;
	}
	return {
		// The seam expects the FINAL url after redirects; the sidecar reports it.
		url: reply.url,
		statusCode: reply.statusCode,
		// `text`, not `html`: dsh-tool-web would slice raw HTML at 200k source
		// characters before turndown, and heavy pages lose their tail.
		body: { kind: 'text', content },
		// The notice is prepended after the body was already sized, so it can push
		// text off the end. `truncated` has to admit that, not just report what the
		// sidecar itself cut.
		truncated: body.truncated || notice.length + body.content.length > config.maxChars,
	};
}

/** Shape-check the search reply before it becomes a `WebSearchResult`. */
function assertSearchReply(reply, query) {
	const label = `search ${JSON.stringify(query)}`;
	if (reply === null || typeof reply !== 'object') throw new StealthFailure('bad-reply', `sidecar returned no object for ${label}`);
	if (!Array.isArray(reply.results)) throw new StealthFailure('bad-reply', `sidecar reply for ${label} is missing an array \`results\``);
	if (!Number.isInteger(reply.statusCode)) throw new StealthFailure('bad-reply', `sidecar reply for ${label} is missing an integer \`statusCode\``);
	for (const result of reply.results) {
		if (result === null || typeof result !== 'object' || typeof result.url !== 'string') {
			throw new StealthFailure('bad-reply', `sidecar reply for ${label} contains a result without a string \`url\``);
		}
	}
	return reply;
}

async function runSearch(sidecar, config, request, signal) {
	const query = typeof request.query === 'string' ? request.query.trim() : '';
	if (query.length === 0) throw new StealthFailure('config', `${name}: search was called with an empty query`);
	const maxResults = request.maxResults === undefined ? config.maxSearchResults : positiveInt(request.maxResults, 'maxResults', config.maxSearchResults);
	let reply;
	try {
		reply = await sidecar.request({ op: 'search', query, maxResults, engine: config.searchEngine, timeoutMs: config.timeoutMs }, { signal });
	} catch (error) {
		if (error instanceof SidecarFailure) throw new StealthFailure(error.code, error.message, error);
		throw error;
	}
	assertSearchReply(reply, query);
	const sources = [];
	for (const result of reply.results.slice(0, maxResults)) {
		const source = { url: result.url };
		if (typeof result.title === 'string' && result.title.length > 0) source.title = result.title;
		if (typeof result.snippet === 'string' && result.snippet.length > 0) source.snippet = result.snippet;
		if (typeof result.publishedAt === 'string' && result.publishedAt.length > 0) source.publishedAt = result.publishedAt;
		sources.push(source);
	}
	const out = { sources, truncated: false };
	// `content` is the only channel a search result has for a warning, so the
	// hint rides there instead of being dropped.
	if (typeof reply.hint === 'string' && reply.hint.length > 0) out.content = `[stealth] ${reply.hint}`;
	return out;
}

function apply(ctx, rawConfig) {
	const config = normalizeConfig(rawConfig);
	// An empty `browserExecutable` is not "no browser": it means the machine picks
	// its own. The candidates are read once per activation, and the same list is
	// what the settings page offers, so the page cannot offer something this
	// process would not have used.
	const browsers = detectBrowsers();
	const browserExecutable = config.browserExecutable || (browsers[0]?.path ?? '');
	const sidecar = new Sidecar({
		python: config.python,
		cwd: config.sidecarDir,
		idleMs: config.idleTimeoutS * 1000,
		env: {
			STEALTH_JAR_DIR: config.jarDir,
			STEALTH_PROXY: config.proxy,
			STEALTH_BROWSER: browserExecutable,
			STEALTH_MAX_CHARS: String(config.maxChars),
			STEALTH_MAX_LINKS: String(config.maxLinks),
			STEALTH_FETCH_TIMEOUT_MS: String(config.timeoutMs),
			STEALTH_IMPERSONATE: config.impersonate,
			STEALTH_TIMEZONE: config.timezone,
			STEALTH_GEO: config.geolocation,
			STEALTH_ACCEPT_LANGUAGE: config.acceptLanguage,
			STEALTH_ORIGIN_POLICY: JSON.stringify(config.originPolicy),
			// Retirement is owned by the supervisor (see Sidecar.#syncIdle); the
			// child's own watchdog is left off to avoid two timers racing.
			STEALTH_IDLE_TIMEOUT_S: '0',
			STEALTH_SEARCH_ENGINE: config.searchEngine,
			// The caps the tools print are the caps the sidecar enforces: one
			// number, stated once, in the plugin config.
			STEALTH_BROWSER_MAX_ELEMENTS: String(config.browserMaxElements),
			STEALTH_BROWSER_TEXT_CHARS: String(config.browserTextChars),
			STEALTH_BROWSER_MAX_CHARS: String(config.browserMaxChars),
			STEALTH_BROWSER_IDLE_S: String(config.browserIdleS),
			STEALTH_BROWSER_JAR_WRITEBACK: config.browserJarWriteback ? '1' : '0',
			STEALTH_BLOCK_MEDIA: config.blockMedia ? '1' : '0',
			// Empty means "keep the sidecar's own list"; the list lives on the
			// Python side, and a composition may replace it wholesale.
			STEALTH_BLOCK_MEDIA_PATTERNS: config.blockMediaPatterns,
			// The key travels to the sidecar and nowhere else. It is not put in a
			// log line, a tool reply or an error message on any path.
			STEALTH_ANTICAPTCHA_KEY: config.antiCaptchaKey,
			STEALTH_ANTICAPTCHA_TIMEOUT_MS: String(config.antiCaptchaTimeoutMs),
		},
	});

	// Everything this generation owns is registered as an effect, not returned as a
	// cleanup. A function *declaration* named `apply` is treated as a class by the
	// loader — it is invoked with `new`, so the value it returns becomes the
	// instance and is never run as a disposer. Effects are the sanctioned teardown,
	// and they run in reverse registration order: the sidecar is registered first
	// so it stops last, after the routes, tools and providers that talk to it.
	ctx.effect(() => () => sidecar.stop(), 'web-stealth: sidecar');

	ctx.effect(() => ctx.web.registerFetchProvider({
		id: PROVIDER_ID,
		// The contract forbids network calls here: usability is a local fact —
		// a startable child process, checked without a request.
		available: () => sidecar.canStart(),
		fetch: (request, signal) => runFetch(sidecar, config, request, signal),
	}), 'web-stealth: fetch provider');

	ctx.effect(() => ctx.web.registerSearchProvider({
		id: PROVIDER_ID,
		available: () => sidecar.canStart(),
		search: (request, signal) => runSearch(sidecar, config, request, signal),
	}), 'web-stealth: search provider');

	ctx.effect(() => registerBrowserTools(ctx, sidecar, config), 'web-stealth: browser tools');

	// The harvest is driven from the plugin's own settings page, so it gets the
	// facts it needs about the machine — where the jar lives, which exit to use and
	// which browser to open — and nothing else. The captcha key is not passed: a
	// harvest never solves.
	const harvest = new HarvestRunner({
		python: config.python,
		cwd: config.sidecarDir,
		browser: browserExecutable,
		env: { STEALTH_JAR_DIR: config.jarDir, STEALTH_PROXY: config.proxy },
	});
	// A login window owned by a plugin generation that no longer exists is a window
	// nobody can finish, so the run goes with it; the page sees the cancelled exit.
	ctx.effect(() => () => {
		if (harvest.active) void harvest.current.cancel();
	}, 'web-stealth: harvest');
	ctx.effect(() => ctx.webServer.register({
		kind: 'prefix',
		path: ROUTE_PATH,
		handler: consoleRoute({
			configEditor: ctx.configEditor,
			config,
			harvest,
			entryId: name,
			browsers,
			browserExecutable,
			// Whether the key was set explicitly in this row, before the fallbacks
			// resolved it — the page distinguishes "configured" from ".env fallback".
			antiCaptchaConfigured: typeof rawConfig?.antiCaptchaKey === 'string' && rawConfig.antiCaptchaKey.trim().length > 0,
		}),
	}), 'web-stealth: console routes');
}

export { apply, inject, name, PROVIDER_ID, StealthFailure, UrlPolicyFailure, composeBody, normalizeConfig };
