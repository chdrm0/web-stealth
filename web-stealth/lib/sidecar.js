/**
 * Sidecar supervisor: one long-lived Python process, line-delimited JSON over
 * stdio, request/response correlation by id.
 *
 * Invariants:
 * - stdout carries protocol lines ONLY. Diagnostics go to stderr and are kept
 *   in a bounded ring for error context, never in a model-facing payload.
 * - A dead child fails every in-flight request loudly; it is restarted lazily
 *   on the next request, with a bounded restart budget.
 * - Cancellation is cooperative: an aborted signal sends `cancel` and rejects
 *   locally. The child may still finish the page; that work is discarded.
 *
 * @module @local/web-stealth/sidecar
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import readline from 'node:readline';

const MAX_LINE_BYTES = 4 * 1024 * 1024;
const STDERR_TAIL_LINES = 80;
const HANDSHAKE_TIMEOUT_MS = 15000;
const SHUTDOWN_GRACE_MS = 3000;
const MAX_RESTARTS = 3;
const RESTART_WINDOW_MS = 5 * 60 * 1000;

/** Failure with a machine-routable code; the caller maps it onto the seam error. */
class SidecarFailure extends Error {
	constructor(code, message, cause) {
		super(message);
		this.code = code;
		if (cause !== undefined) this.cause = cause;
	}
}

/** Strip `user:pass@` from anything URL-shaped before it reaches an error message. */
function redact(text) {
	return String(text).replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^\s/@]+:[^\s/@]+@/g, '$1***:***@');
}

class Sidecar {
	/**
	 * @param options - `{ python, cwd, env, args? }`; `env` entries are ADDED to
	 *   `process.env`, so secrets stay in the environment rather than in config.
	 */
	constructor(options) {
		this.options = options;
		this.child = null;
		this.rl = null;
		this.started = null;
		this.pending = new Map();
		this.seq = 0;
		this.stderrTail = [];
		this.restartAt = [];
		this.stopping = false;
		this.handshake = null;
		// A planned exit (idle timeout) must not be counted as a crash.
		this.lastExitClean = true;
		// Retirement is owned here, not in the child: this side is the only one
		// that knows both whether a request is in flight and whether one is about
		// to be written, so it is the only place the timer can be race-free.
		this.idleMs = Number(options.idleMs) || 0;
		this.idleTimer = null;
		this.retiring = false;
		this.exitPromise = null;
	}

	/** Local-only usability fact, safe inside the provider's `available()`. */
	isAlive() {
		return this.child !== null && this.child.exitCode === null && this.child.signalCode === null;
	}

	/**
	 * Whether a start would be sensible before one is needed. The child is
	 * spawned lazily, so `isAlive()` is false until the first request; the
	 * provider's `available()` must answer for a not-yet-started sidecar.
	 */
	canStart() {
		if (this.stopping) return false;
		const now = Date.now();
		if (this.restartAt.filter((at) => now - at < RESTART_WINDOW_MS).length >= MAX_RESTARTS) return false;
		const python = this.options.python;
		if (typeof python !== 'string' || python.length === 0) return false;
		// A bare name is resolved by PATH at spawn time; a path must exist now.
		if (python.includes('/')) return fs.existsSync(python);
		return true;
	}

	async ensureStarted() {
		if (this.started !== null) return this.started;
		const attempt = this.#spawn();
		this.started = attempt;
		try {
			await attempt;
		} catch (error) {
			this.started = null;
			throw error;
		}
		return attempt;
	}

	#spawn() {
		const now = Date.now();
		this.restartAt = this.restartAt.filter((at) => now - at < RESTART_WINDOW_MS);
		// A planned exit (idle timeout, shutdown) is not a crash and must not
		// burn the budget: with a 300s idle the sidecar would otherwise exit about
		// once per window and lock itself out of ever restarting.
		if (!this.lastExitClean) this.restartAt.push(now);
		if (this.restartAt.length >= MAX_RESTARTS) {
			throw new SidecarFailure('restart-budget', `sidecar restarted ${MAX_RESTARTS} times within ${RESTART_WINDOW_MS / 60000} minutes; refusing to restart again. Recent stderr: ${this.stderrTail.join(' | ')}`);
		}

		const args = this.options.args ?? ['-m', 'fetchd'];
		let child;
		try {
			child = spawn(this.options.python, args, {
				cwd: this.options.cwd,
				env: { ...process.env, ...(this.options.env ?? {}) },
				stdio: ['pipe', 'pipe', 'pipe'],
			});
		} catch (error) {
			throw new SidecarFailure('spawn-failed', `could not spawn ${this.options.python} in ${this.options.cwd}: ${error.message}`, error);
		}
		this.child = child;

		child.stderr.setEncoding('utf8');
		child.stderr.on('data', (chunk) => {
			for (const line of redact(chunk).split('\n')) {
				if (line.trim().length === 0) continue;
				this.stderrTail.push(line);
				if (this.stderrTail.length > STDERR_TAIL_LINES) this.stderrTail.shift();
			}
		});

		// ENOENT and friends arrive as an `error` event, never as a throw from spawn().
		child.on('error', (error) => {
			const failure = new SidecarFailure('spawn-error', `sidecar process error: ${redact(error.message)}`, error);
			// A spawn failure never reaches `exit`, so without this the restart
			// budget would never fill and a broken interpreter path would be
			// respawned on every single request.
			this.lastExitClean = false;
			this.handshake?.reject(failure);
			this.handshake = null;
			this.#teardown(`process error: ${redact(error.message)}`);
		});
		child.on('exit', (code, signalName) => {
			const reason = `exit code=${code} signal=${signalName}`;
			// Clean exit with nothing in flight = the sidecar retired on purpose.
			this.lastExitClean = code === 0 && this.pending.size === 0;
			this.handshake?.reject(new SidecarFailure('spawn-failed', `sidecar exited before its handshake (${reason}). Recent stderr: ${this.stderrTail.join(' | ') || '(none)'}`));
			this.handshake = null;
			this.#teardown(reason);
		});

		const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
		this.rl = rl;
		rl.on('line', (line) => this.#onLine(line));

		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				reject(new SidecarFailure('handshake-timeout', `sidecar sent no \`ready\` handshake within ${HANDSHAKE_TIMEOUT_MS} ms. Recent stderr: ${this.stderrTail.join(' | ') || '(none)'}`));
			}, HANDSHAKE_TIMEOUT_MS);
			this.handshake = { resolve: () => { clearTimeout(timer); resolve(); }, reject: (error) => { clearTimeout(timer); reject(error); } };
		}).catch((error) => {
			this.#teardown('handshake failed');
			throw error;
		});
	}

	#onLine(line) {
		if (line.length > MAX_LINE_BYTES) {
			this.#failAll(new SidecarFailure('protocol', `sidecar line exceeded ${MAX_LINE_BYTES} bytes; the stream is not trusted`));
			this.#teardown('oversized line');
			return;
		}
		let message;
		try {
			message = JSON.parse(line);
		} catch {
			return; // a non-JSON stdout line is a protocol violation, but a recoverable one: log and ignore
		}
		if (message === null || typeof message !== 'object') return;

		if (message.op === 'ready') {
			this.handshake?.resolve();
			this.handshake = null;
			return;
		}
		if (message.op === 'event') return; // progress/telemetry: reserved, currently unused

		const waiter = this.pending.get(message.id);
		if (waiter === undefined) return; // a reply for a cancelled request: drop it
		this.pending.delete(message.id);
		if (message.ok === true) waiter.resolve(message.data);
		else waiter.reject(new SidecarFailure(message?.error?.code ?? 'sidecar-error', redact(message?.error?.message ?? 'sidecar reported a failure without a message')));
	}

	#failAll(error) {
		for (const [, waiter] of this.pending) waiter.reject(error);
		this.pending.clear();
	}

	#teardown(reason) {
		this.started = null;
		const child = this.child;
		this.rl?.close();
		this.rl = null;
		if (child !== null && child.exitCode === null && child.signalCode === null) {
			try { child.kill('SIGTERM'); } catch { /* already gone */ }
		}
		this.child = null;
		this.#failAll(new SidecarFailure('sidecar-exit', `sidecar stopped (${reason}). Recent stderr: ${this.stderrTail.join(' | ') || '(none)'}`));
	}

	/**
	 * Send one request and await its reply.
	 * @param payload - protocol body without `id`.
	 * @param options.signal - cooperative cancellation.
	 */
	async request(payload, { signal } = {}) {
		if (this.stopping) throw new SidecarFailure('stopping', 'sidecar is shutting down');
		// A planned retirement is not an error: wait for the child to leave and
		// respawn it. Doing this before clearing the timer is what keeps the idle
		// path race-free — once this method starts, no timer can fire underneath it.
		if (this.retiring) {
			await this.exitPromise;
			this.retiring = false;
		}
		this.#clearIdle();
		await this.ensureStarted();

		const id = ++this.seq;
		const deadline = typeof payload.timeoutMs === 'number' ? payload.timeoutMs : 30000;

		try {
			return await new Promise((resolve, reject) => {
				const timer = setTimeout(() => {
					this.pending.delete(id);
					this.#write({ op: 'cancel', id });
					reject(new SidecarFailure('timeout', `sidecar did not answer op=${payload.op} within ${deadline} ms`));
				}, deadline);

				const abort = () => {
					this.pending.delete(id);
					clearTimeout(timer);
					this.#write({ op: 'cancel', id });
					reject(new SidecarFailure('aborted', `request op=${payload.op} was cancelled by the caller`));
				};
				if (signal !== undefined) {
					if (signal.aborted) { abort(); return; }
					signal.addEventListener('abort', abort, { once: true });
				}

				this.pending.set(id, {
					resolve: (data) => { clearTimeout(timer); signal?.removeEventListener('abort', abort); resolve(data); },
					reject: (error) => { clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(error); },
				});

				if (!this.#write({ ...payload, id })) {
					this.pending.delete(id);
					clearTimeout(timer);
					reject(new SidecarFailure('write-failed', `could not write to the sidecar stdin for op=${payload.op}`));
				}
			});
		} finally {
			this.#syncIdle();
		}
	}

	#write(object) {
		const child = this.child;
		if (child === null || child.stdin === null || child.stdin.destroyed) return false;
		return child.stdin.write(`${JSON.stringify(object)}\n`);
	}

	#clearIdle() {
		if (this.idleTimer !== null) {
			clearTimeout(this.idleTimer);
			this.idleTimer = null;
		}
	}

	/**
	 * Arm the retirement timer, but only while nothing is in flight.
	 *
	 * Retirement lives here rather than in the child because this side is the
	 * only one that knows both that a request is outstanding and that one is
	 * about to be written. A timer inside the child can fire after a frame has
	 * reached the pipe but before the child has read it, which loses a request
	 * the caller is still waiting on.
	 */
	#syncIdle() {
		this.#clearIdle();
		if (this.idleMs <= 0 || this.stopping || this.retiring || this.child === null) return;
		if (this.pending.size > 0) return;
		this.idleTimer = setTimeout(() => this.#retire(), this.idleMs).unref();
	}

	/** Ask the child to leave. Cooperative, so the last request's cookies land. */
	#retire() {
		this.idleTimer = null;
		const child = this.child;
		if (child === null || this.stopping || this.retiring) return;
		this.retiring = true;
		this.exitPromise = new Promise((resolve) => {
			if (child.exitCode !== null || child.signalCode !== null) resolve();
			else child.once('exit', resolve);
		});
		this.#write({ op: 'shutdown' });
		setTimeout(() => {
			if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
		}, SHUTDOWN_GRACE_MS).unref();
	}

	stop() {
		this.#clearIdle();
		this.stopping = true;
		const child = this.child;
		if (child === null) return;
		this.#write({ op: 'shutdown' });
		setTimeout(() => {
			if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
		}, SHUTDOWN_GRACE_MS).unref();
	}
}

export { Sidecar, SidecarFailure };
