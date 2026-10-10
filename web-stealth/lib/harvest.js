/**
 * One harvest run: the interactive cookie harvest driven from the plugin, not
 * from a terminal.
 *
 * It is a separate Python process, deliberately not the request sidecar. A
 * harvest waits minutes for a human to log in, and the sidecar is one stdio
 * channel with an idle watchdog shared by every request; a login window must not
 * be able to starve retrieval. The harvest also runs its browser on its own
 * persistent profile, so its lifetime belongs to neither tier.
 *
 * The child speaks the protocol `fetchd.harvest` already has: it prints progress
 * lines and finishes when a line arrives on its stdin (or its wait window ends).
 * Values are never in that output — the harvest prints names, domains and counts
 * only — but the line count and length are bounded anyway, because the lines are
 * handed to a page.
 *
 * Output is a ring the page polls with a cursor rather than a stream: a settings
 * page reloads, and a finished run's last lines are the answer to "did it work".
 *
 * @module @local/web-stealth/lib/harvest
 */
import process from 'node:process';
import { spawn } from 'node:child_process';

const MAX_LINES = 400;
const MAX_LINE_CHARS = 300;
const GROUPS = ['google', 'github', 'brave', 'reddit', 'other'];

class HarvestFailure extends Error {
	constructor(code, message) {
		super(message);
		this.code = code;
	}
}

/** Groups are a closed set on the Python side; a page must not invent a sixth. */
function groupList(raw) {
	// The default set is where a login exists. Brave search has no account and
	// answers anonymously (measured: 200 with 28 links, no wall), so harvesting it
	// yields a set that earns nothing and expires against the exit. `brave` remains
	// a valid group for anyone who names it.
	if (raw === undefined || raw === null || raw === '') return ['google', 'github'];
	const list = Array.isArray(raw) ? raw : String(raw).split(',');
	const picked = list.map((item) => String(item).trim()).filter((item) => item.length > 0);
	if (picked.length === 0) throw new HarvestFailure('config', 'harvest requires at least one group');
	const unknown = picked.filter((item) => !GROUPS.includes(item));
	if (unknown.length > 0) throw new HarvestFailure('config', `harvest groups must be one of ${GROUPS.join(', ')}; got ${unknown.join(', ')}`);
	return [...new Set(picked)];
}

export class HarvestRunner {
	#options;
	#active = null;
	#last = null;

	constructor(options) {
		this.#options = options;
	}

	/** A harvest is one browser on one profile: two at once would fight over it. */
	get active() {
		return this.#active !== null;
	}

	/**
	 * The run a page should look at: the live one, or the one that just finished.
	 * Keeping the finished run is what lets a reloaded page still show the result
	 * instead of "no harvest has run".
	 */
	get current() {
		return this.#active ?? this.#last;
	}

	start(input = {}) {
		if (this.#active !== null) throw new HarvestFailure('busy', 'a harvest is already running');
		const { python, cwd, env } = this.#options;
		const groups = groupList(input.groups);
		const waitS = Math.min(Math.max(Number(input.waitS) || 900, 30), 3600);
		const args = ['-m', 'fetchd.harvest', '--groups', groups.join(','), '--wait', String(waitS)];
		// The same browser the browser tier drives, not the script's own default:
		// a cookie set harvested by a different browser than the one that will
		// carry it is a second identity, not a copy of the first.
		if (this.#options.browser) args.push('--browser', this.#options.browser);
		if (input.smoke) args.push('--smoke');
		// Unbuffered: with stdout on a pipe Python block-buffers its prints, and the
		// page would show nothing until the run ended — while the point of the panel
		// is watching the login window being opened.
		const child = spawn(python, args, { cwd, env: { ...process.env, PYTHONUNBUFFERED: '1', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });

		const run = {
			groups,
			waitS,
			lines: [],
			overflowed: false,
			running: true,
			exit: null,
			startedAt: Date.now(),
		};

		const push = (text) => {
			const line = text.replace(/\s+$/, '');
			if (line === '') return;
			if (run.lines.length >= MAX_LINES) {
				run.overflowed = true;
				return;
			}
			run.lines.push(line.slice(0, MAX_LINE_CHARS));
		};

		const feed = (stream) => {
			let pending = '';
			stream.setEncoding('utf8');
			stream.on('data', (chunk) => {
				pending += chunk;
				const parts = pending.split('\n');
				pending = parts.pop() ?? '';
				for (const part of parts) push(part);
			});
			stream.on('end', () => {
				if (pending !== '') push(pending);
			});
		};
		feed(child.stdout);
		feed(child.stderr);

		// The listeners run after `start` has returned, so they compare against the
		// handle the caller was given rather than the raw record.
		let handle = null;
		const clear = () => {
			if (this.#active === handle) this.#active = null;
		};

		child.on('error', (error) => {
			// A missing interpreter is the common case, and the page has to say so.
			push(`could not start the harvest process: ${error.message}`);
			run.exit = { code: null, signal: null, spawnError: error.message };
			run.running = false;
			clear();
		});
		child.on('close', (code, signal) => {
			run.exit = { code, signal };
			run.running = false;
			clear();
		});

		handle = {
			...run,
			/** What a page shows without pulling the whole transcript. */
			status: () => ({ running: run.running, exit: run.exit, groups: run.groups, waitS: run.waitS, lines: run.lines.length, startedAt: run.startedAt }),
			/** The child waits for a line on stdin: that is "I am done logging in". */
			finish: () => {
				if (!run.running || child.stdin.destroyed) return false;
				child.stdin.write('\n');
				return true;
			},
			cancel: async () => {
				if (!run.running) return false;
				child.kill('SIGTERM');
				const gone = await new Promise((resolve) => {
					const timer = setTimeout(() => resolve(false), 5000);
					child.once('close', () => {
						clearTimeout(timer);
						resolve(true);
					});
				});
				if (!gone) child.kill('SIGKILL');
				return true;
			},
			/** Lines the caller has not seen yet. The cursor is the caller's. */
			since: (index) => {
				const from = Number.isInteger(index) && index > 0 ? Math.min(index, run.lines.length) : 0;
				return {
					lines: run.lines.slice(from),
					next: run.lines.length,
					running: run.running,
					exit: run.exit,
					overflowed: run.overflowed,
				};
			},
		};
		// The handle, not the raw record: `current` is what the page reads, and it
		// needs the run's methods, not only its fields.
		this.#active = handle;
		this.#last = handle;
		return handle;
	}
}

export { HarvestFailure, groupList };
