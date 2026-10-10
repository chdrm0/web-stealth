/**
 * The browser tier as agent tools: one page at a time, opened, read, and acted
 * on by element index.
 *
 * Division of labour is the same as for `web_fetch`: every retrieval decision
 * (fingerprint, cookies, proxy, when to start a browser at all) lives in the
 * Python sidecar. This module only turns a sidecar reply into what the model
 * reads, and refuses a reply whose shape it did not ask for.
 *
 * The element numbering is deliberately page-scoped and rebuilt on every
 * snapshot, so a number is only valid until the page changes. Every reply that
 * lists elements says so.
 *
 * @module @local/web-stealth/browser-tools
 */
import { assertFetchableUrl } from './policy.js';

const ACTIONS = ['click', 'type', 'select', 'submit', 'focus'];

/** One interactive element as a single line the caller can quote back by index. */
function describeElement(element) {
	const kind = `${element.tag}${element.role ? `[${element.role}]` : ''}${element.type ? `:${element.type}` : ''}`;
	const parts = [`[${element.index}] ${kind}`];
	if (element.text) parts.push(JSON.stringify(element.text));
	if (element.name) parts.push(`name=${element.name}`);
	if (typeof element.value === 'string' && element.value.length > 0) parts.push(`value=${JSON.stringify(element.value)}`);
	if (element.href) parts.push(`-> ${element.href}`);
	if (element.disabled === true) parts.push('(disabled)');
	return parts.join(' ');
}

/** The page as the caller sees it: where it is, what it can do, what it says. */
function renderPage(page) {
	// A reply missing its listing is a broken sidecar, not a page with no links:
	// saying "no interactive elements" would send the caller off to re-read a page
	// that never arrived.
	if (!Array.isArray(page.elements)) throw new Error('the page reply carries no element list');
	const lines = [`URL: ${typeof page.url === 'string' ? page.url : ''}`, `Title: ${typeof page.title === 'string' ? page.title : ''}`];
	const elements = page.elements;
	if (elements.length > 0) {
		lines.push('', 'Elements (numbering is valid for this page only):');
		let lastRegion = '';
		for (const element of elements) {
			const region = element.region === 'page' ? 'page' : 'main';
			// The listing puts the page's own content first, so say where that
			// content stops.
			if (lastRegion !== '' && region !== lastRegion) lines.push(region === 'page' ? '— outside the main content:' : '— main content:');
			lastRegion = region;
			lines.push(describeElement(element));
		}
		if (page.truncated === true) lines.push('… the list was cut at the configured limit.');
	} else {
		lines.push('', 'No interactive elements found.');
	}
	if (typeof page.text === 'string' && page.text.length > 0) {
		lines.push('', page.textTruncated === true ? 'Text (a preview — browser_read gives the whole page):' : 'Text:', page.text);
	}
	return lines.join('\n');
}

function renderLinks(links, maxChars) {
	if (!Array.isArray(links) || links.length === 0) return '';
	const lines = links.map((link) => (link.text ? `- ${link.url} — ${link.text}` : `- ${link.url}`));
	return `\n\nLinks:\n${lines.join('\n')}`.slice(0, maxChars);
}

/**
 * The captured request log as one line per request. Deliberately terse: a page
 * fires over a hundred, and a listing that costs a kilobyte each is a listing
 * nobody reads twice.
 */
function renderRequests(reply) {
	const entries = Array.isArray(reply.entries) ? reply.entries : [];
	const lines = entries.map((entry) => {
		const status = entry.status === null || entry.status === undefined ? '···' : entry.status;
		const ms = entry.ms === null || entry.ms === undefined ? 'running' : `${entry.ms}ms`;
		const tail = entry.error ? ` error=${entry.error}` : entry.initiator ? ` from=${entry.initiator}` : '';
		return `#${entry.n}${entry.main ? '*' : ''} [${entry.id}] ${entry.method} ${entry.host}${entry.path} -> ${status} ${entry.type || '-'} ${entry.bytes}b ${ms}${tail}`;
	});
	// The captured window, not just the count: a reader who holds a number
	// outside it can see the valid range without guessing. Numbers are not reused
	// within a session, so a number that is outside the window is a stale
	// reference, never a renumbered one.
	const window = reply.oldest === null || reply.oldest === undefined ? '' : ` (captured #${reply.oldest}-#${reply.newest})`;
	// Which page the ring describes, stated rather than inferred: a listing that
	// silently belongs to an earlier navigation is the failure this tool has made
	// before, and it is cheap to name the page it answers for.
	const describes = typeof reply.page === 'string' && reply.page !== '' ? ` The listing describes ${reply.page}.` : '';
	const header = `${entries.length} of ${reply.seen ?? 0} requests this navigation${window}, ${reply.inflight ?? 0} still in flight, document status ${reply.status ?? 'unknown'}. * marks the page's own document.${describes}`;
	const footer = entries.length > 0 ? '\n\nA body: browser_body with the id in brackets or the #n number. Entries are dropped on the next navigation and the numbering does not restart with them: an id from an earlier page is refused, not reinterpreted.' : '';
	return [header, ...lines].join('\n') + footer;
}

function requireObject(reply, op) {
	if (reply === null || typeof reply !== 'object') throw new Error(`sidecar returned no object for op=${op}`);
	return reply;
}

/**
 * The caller's element count is a request, not a licence: the configured cap is
 * the ceiling. An unbounded number is a multi-megabyte line on the wire, and the
 * sidecar drops the whole connection over one of those.
 */
function elementLimit(requested, ceiling) {
	// Absent means the ceiling. Zero means "no listing" — a caller asking for the
	// text only must not be handed the maximum listing instead.
	if (requested === undefined || requested === null) return ceiling;
	const wanted = Number(requested);
	if (!Number.isFinite(wanted)) throw new Error(`maxElements must be a number, got ${requested}`);
	return Math.max(0, Math.min(Math.trunc(wanted), ceiling));
}

/** Say when the page opened a window: whether the session moved into it, or it was closed. */
function popups(reply) {
	const notes = [];
	// The address can be empty — a window that has not navigated yet — so the
	// hand-off is read from its own flag, never from the URL being truthy.
	if (reply.handoff === true) notes.push(`The page opened a window and the session moved into it${reply.adoptedTab ? ` (${reply.adoptedTab})` : ''}: read the state to see what it shows.`);
	if (Number.isInteger(reply.closedTabs) && reply.closedTabs > 0) notes.push(`${reply.closedTabs} tab(s) the page tried to open were closed: one tab at a time.`);
	return notes.length ? `\n${notes.join(' ')}` : '';
}

/**
 * Register the browser tools on this context.
 *
 * @param ctx - the plugin context (`tools` must be injected).
 * @param sidecar - the sidecar supervisor, shared with the web providers.
 * @param config - the normalized plugin config (limits and budget).
 * @returns the disposer that unregisters every tool this call added.
 */
export function registerBrowserTools(ctx, sidecar, config) {
	const budget = config.browserTimeoutMs;
	const maxElements = config.browserMaxElements;
	const maxChars = config.browserMaxChars;
	const textChars = config.browserTextChars;
	// A bought solve is a queue on someone else's workers: its own budget, stated
	// in the plugin config, not the browser navigation one.
	const captchaTimeoutMs = config.antiCaptchaTimeoutMs;
	// The tool budget is the sidecar's plus the round trip, so the harness does
	// not cut a call that the sidecar is still honouring.
	const toolTimeoutMs = budget + 15_000;
	const disposers = [];

	const add = (definition) => disposers.push(ctx.tools.register(definition));

	add({
		name: 'browser_open',
		description:
			'Open a URL in the browser tier — a real browser, one tab at a time — and return its visible text plus its interactive elements, numbered. ' +
			'Use it when the plain fetch tier cannot retrieve the page or when the page has to be interacted with; it is not a retry for a refusal. ' +
			'The numbering is valid for this page only and is rebuilt after every action.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: { url: { type: 'string', description: 'The HTTP(S) URL to open.' } },
			required: ['url'],
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const url = assertFetchableUrl(String(args?.url ?? ''), config.blockPrivateNetworks);
			const reply = requireObject(await sidecar.request({ op: 'browser.open', url, maxElements, textChars, timeoutMs: budget }, { signal: exec.signal }), 'browser.open');
			// A page we navigated to must have a status: no status means the
			// navigation produced nothing. A window the session moved into is the
			// exception — its document response arrived before we were listening
			// on that target, and reporting the opener's status against it would
			// claim a page we never loaded. The hand-off note below says which.
			const status = Number.isInteger(reply.statusCode) ? String(reply.statusCode) : 'unknown';
			if (status === 'unknown' && reply.handoff !== true) throw new Error('the browser did not report a status for the page it opened');
			return { text: `${renderPage(reply)}\n\nStatus: ${status}${popups(reply)}` };
		},
	});

	add({
		name: 'browser_state',
		description: 'Re-read the page currently open in the browser tier: its visible text and its interactive elements, renumbered. Call it after an action, because the numbering follows the page.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: { maxElements: { type: 'integer', minimum: 0, description: 'How many elements to list at most. 0 means the text only, no listing.' } },
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const reply = requireObject(
				await sidecar.request(
					{ op: 'browser.state', maxElements: elementLimit(args?.maxElements, maxElements), textChars, timeoutMs: budget },
					{ signal: exec.signal },
				),
				'browser.state',
			);
			return { text: renderPage(reply) };
		},
	});

	add({
		name: 'browser_act',
		description:
			'Do one thing to one numbered element of the open page: click, type (into a field, with `value`), select (a dropdown option, with `value`), submit (a form), focus. ' +
			'Returns the page as it is afterwards, renumbered. Do not submit anything that changes state on someone else’s behalf without asking first.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: {
				index: { type: 'integer', description: 'The element number from the last page listing.' },
				action: { type: 'string', enum: ACTIONS, description: 'What to do with that element.' },
				value: { type: 'string', description: 'The text or option value for type/select.' },
			},
			required: ['index', 'action'],
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const index = Number(args?.index);
			const action = String(args?.action ?? '');
			if (!Number.isInteger(index) || index < 1) throw new Error('browser_act needs an integer `index` from the last page listing');
			if (!ACTIONS.includes(action)) throw new Error(`browser_act action must be one of ${ACTIONS.join(', ')}`);
			// The protocol wants a string; anything else would be dropped by the
			// sidecar without an answer.
			const value = args?.value === undefined || args?.value === null ? '' : String(args.value);
			const reply = requireObject(
				await sidecar.request({ op: 'browser.act', index, action, value, maxElements, textChars, timeoutMs: budget }, { signal: exec.signal }),
				'browser.act',
			);
			if (reply.ok !== true) return { text: `The action did not apply: ${reply.reason ?? 'the page did not answer'}` };
			if (reply.page === null || typeof reply.page !== 'object') {
				// The action landed and only the re-read failed. Reporting that as a
				// failed action is how a form gets submitted twice.
				return {
					text: `${action} on [${index}] was applied, but the page could not be read back: ${reply.rereadError ?? 'unknown reason'}\n\nRe-read the page with browser_state before doing anything else.`,
				};
			}
			const page = reply.page;
			const moved =
				page.changed !== true
					? 'nothing on the page changed'
					: page.navigated === true
						? 'the page and its URL changed'
						: 'the page changed, the URL did not';
			const head = `${action} on [${index}] — ${moved}`;
			return { text: `${head}\n\n${renderPage(page)}${popups(page)}` };
		},
	});

	add({
		name: 'browser_read',
		description: 'Read the page currently open in the browser tier as text plus its links, in the same shape web_fetch returns. Use it after navigating, when the interest is the content rather than the controls.',
		parameters: { type: 'object', additionalProperties: false, properties: {} },
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(_args, exec) {
			const reply = requireObject(await sidecar.request({ op: 'browser.read', maxChars, timeoutMs: budget }, { signal: exec.signal }), 'browser.read');
			const text = typeof reply.text === 'string' ? reply.text : '';
			const notice = reply.truncated === true ? '\n\n(the page was cut at the configured limit)' : '';
			return { text: `URL: ${reply.url ?? ''}\n\n${text}${renderLinks(reply.links, maxChars)}${notice}` };
		},
	});

	add({
		name: 'browser_requests',
		description: 'List what the page currently open asked the network for: method, host, path, status, type, size, duration and who initiated it. Summary only — bodies are a separate call. Use it to learn how a site really loads; it is not a way to read a page.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: {
				since: { type: 'integer', description: 'Return entries after this sequence number, as the previous call returned.' },
				limit: { type: 'integer', description: 'At most this many entries (1-80).' },
			},
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const reply = requireObject(
				await sidecar.request({ op: 'browser.requests', since: args.since ?? 0, limit: args.limit ?? 60, timeoutMs: budget }, { signal: exec.signal }),
				'browser.requests',
			);
			return { text: renderRequests(reply) };
		},
	});

	add({
		name: 'browser_body',
		description: 'Read one captured response body by the id or the #n sequence number browser_requests shows. Capped. When the page no longer holds the body, a GET is replayed under a brief Fetch-interception window, so an older entry can still answer — the replay is a new request and may differ in credentials. The id, not the URL, decides which of two requests to the same address is returned. A page document is not replayed unless replayDocument is true.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: {
				id: { type: 'string', description: 'The request id in brackets, or the #n sequence number, from browser_requests.' },
				maxBytes: { type: 'integer', description: 'Cap on the returned body (200-20000).' },
				headers: { type: 'boolean', description: 'Also return the request headers the browser put on the wire. Cookie values are redacted to their size.' },
				replayDocument: { type: 'boolean', default: false, description: 'Allow replaying a document whose body is gone. Costly: it re-requests the page URL, replaces the current page and its element numbering (re-read the state after), and consumes one-shot GETs such as an OAuth callback or a magic link.' },
			},
			required: ['id'],
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: toolTimeoutMs,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const reply = requireObject(
				await sidecar.request(
				// `requestId`, never `id`: the sidecar client stamps its own
				// integer correlation id onto every frame and would overwrite
				// the handle sent under that name.
				{ op: 'browser.body', requestId: String(args.id), maxBytes: args.maxBytes ?? 4000, headers: args.headers === true, replayDocument: args.replayDocument === true, timeoutMs: budget },
					{ signal: exec.signal },
				),
				'browser.body',
			);
			const body = typeof reply.body === 'string' ? reply.body : '';
			const cut = reply.truncated === true ? ` (cut at ${body.length} of ${reply.bytes} bytes)` : '';
			const headerLines = reply.headers && typeof reply.headers === 'object' ? Object.entries(reply.headers) : [];
			// A note travels with the headers too: page-side headers are a fallback
			// and say so, and an empty set must never read as "no headers were sent".
			const headersNote = reply.headersNote ? `${reply.headersNote}\n` : '';
			const headers = headerLines.length > 0
				? `${reply.method ?? ''} ${reply.url ?? ''} (headers: ${reply.headersSource ?? 'wire'})\n${headerLines.map(([name, value]) => `${name}: ${value}`).join('\n')}\n${headersNote}\n`
				: (args.headers === true ? `Headers: none captured. ${headersNote || 're-run browser_requests after the page settles and ask again\n'}\n` : '');
			return { text: `${headers}${reply.bodyNote ? `${reply.bodyNote}\n\n` : ''}${reply.encoding}, ${reply.bytes} bytes${cut}\n\n${body}` };
		},
	});

	add({
		name: 'browser_captcha',
		description:
			'Report the captcha machinery on the page currently open: widget kind, site key, whether an answer is already in the page. ' +
			'With solve: true it buys a reCAPTCHA v2 token from the configured solver and places it where the page expects it — that spends money from the solver account, so say what you are about to spend and why. At most 5 solve attempts are made per captcha (widget family, site key, page origin); a further one is refused without spending. ' +
			'The token itself is never returned: it is only ever used inside the page.',
		parameters: {
			type: 'object',
			additionalProperties: false,
			properties: { solve: { type: 'boolean', description: 'Buy a token and inject it. Defaults to false: report only, spend nothing.' } },
		},
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		// A bought solve is a queue and a human-scale task, not a request.
		timeoutMs: captchaTimeoutMs + 15_000,
		isConcurrencySafe: () => false,
		async execute(args, exec) {
			const solve = args?.solve === true;
			const reply = requireObject(await sidecar.request({ op: 'browser.captcha', solve, timeoutMs: captchaTimeoutMs }, { signal: exec.signal }), 'browser.captcha');
			const widgets = Array.isArray(reply.widgets) ? reply.widgets : [];
			const lines = [`URL: ${reply.pageUrl ?? ''}`, `Widgets: ${widgets.length}`];
			for (const widget of widgets) lines.push(`  - ${widget.kind ?? 'unknown'} sitekey ${widget.sitekey ?? ''} (${widget.source ?? ''})`);
			if (reply.answerFields?.length) lines.push(`Where the answer goes in this page: ${reply.answerFields.join(', ')}`);
			if (reply.responseFields) lines.push(`Answer fields in the page: ${reply.responseFields}${reply.alreadyAnswered === true ? ' (one is already filled)' : ''}`);
			if (reply.hasEnterpriseApi === true) lines.push('The page carries the enterprise reCAPTCHA API; the token is bought as an enterprise task.');
			if (reply.hasChallengeCallback === true) lines.push('The page exposes its own completion callback (recaptcha.challengeCompleted).');
			if (reply.v3Render) lines.push(`reCAPTCHA v3 render parameter: ${reply.v3Render} — v3 has no checkbox; it scores the visit, and this tool does not buy it.`);
			if (widgets.length === 0) lines.push('Nothing captcha-shaped was found. A wall here may be the site’s own JS check rather than a widget.');
			if (solve) {
				if (reply.captchaIdentity) lines.push(`Solve attempt ${reply.attempt} of ${reply.attemptCap} for ${reply.captchaIdentity}`);
				lines.push(reply.solved === true ? `Solved: task ${reply.taskId}, cost ${reply.cost ?? 'unknown'}, injected via ${(reply.applied ?? []).join(', ') || 'nothing'}` : `Not injected: ${(reply.applied ?? []).join(', ') || 'the page has nowhere to put the token'}`);
				if (reply.workerUserAgent) lines.push(`The token was minted by: ${reply.workerUserAgent} — a different browser on submit is the usual reason a valid token is refused.`);
			}
			return { text: lines.join('\n') };
		},
	});

	add({
		name: 'browser_close',
		description: 'Close the browser session and drop the cookies that were injected into it. Call it when the task is done; an idle session is also released on its own after a few minutes.',
		parameters: { type: 'object', additionalProperties: false, properties: {} },
		output: {
			schema: { type: 'object', additionalProperties: true, properties: { text: { type: 'string' } } },
			render: (_args, value) => [{ type: 'text', text: value.text }],
		},
		timeoutMs: 30_000,
		isConcurrencySafe: () => false,
		async execute(_args, exec) {
			const reply = requireObject(await sidecar.request({ op: 'browser.close', timeoutMs: 20_000 }, { signal: exec.signal }), 'browser.close');
			// The cookies are the reason for closing. Claiming they are gone when
			// the browser did not answer would be the one lie worth avoiding here,
			// so only an explicit true is allowed to say so.
			if (reply.cookiesCleared !== true) {
				return { text: 'The browser session was closed, but its injected cookies could not be cleared: the on-disk profile may still hold them.' };
			}
			return { text: 'The browser session is closed and its injected cookies are gone.' };
		},
	});

	return () => {
		for (const dispose of disposers.reverse()) dispose();
	};
}

export { ACTIONS, describeElement, renderLinks, renderPage };
