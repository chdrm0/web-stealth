/**
 * URL admission for the stealth provider.
 *
 * Scope of this pass — deliberately narrow, and the gap is stated rather than
 * hidden:
 * - Checked here: scheme, embedded credentials, length, and literal private /
 *   loopback / link-local targets.
 * - NOT checked here: a public hostname that resolves to a private address.
 *   The stock `http` provider closes that hole by resolving once, rejecting the
 *   whole answer set, and pinning the connection. A browser cannot be pinned
 *   the same way, so the equivalent here is a proxy policy or a pre-resolution
 *   check plus `--host-resolver-rules`. See ARCHITECTURE.md, open point O2.
 *
 * @module @local/web-stealth/policy
 */

const MAX_URL_CHARS = 2048;

class UrlPolicyFailure extends Error {
	constructor(code, message) {
		super(message);
		this.code = code;
	}
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Address classes that must never be reached from a browser driven by a model argument. */
function isPrivateV4(address) {
	const [a, b] = address.split('.').map(Number);
	if (a === 10) return true; // RFC1918
	if (a === 127) return true; // loopback
	if (a === 0) return true; // "this network"
	if (a === 169 && b === 254) return true; // link-local
	if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
	if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
	if (a === 192 && b === 168) return true; // RFC1918
	if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
	if (a >= 224) return true; // multicast + reserved
	return false;
}

function isPrivateV6(address) {
	const normalized = address.toLowerCase().replace(/^\[|\]$/g, '');
	if (normalized === '::1' || normalized === '::') return true;
	if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true; // ULA fc00::/7
	if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true; // link-local fe80::/10
	if (/^::ffff:/.test(normalized)) {
		const mapped = normalized.slice(7);
		return IPV4.test(mapped) && isPrivateV4(mapped);
	}
	if (/^64:ff9e(:|$)/.test(normalized) || /^64:ff9b(:|$)/.test(normalized)) return true; // NAT64 well-known
	return false;
}

/**
 * Validate and normalize one fetch target.
 * @param raw - the URL as received from the seam request.
 * @param blockPrivateNetworks - when false, private literals are admitted (the
 *   operator opted out; the caller owns the consequence).
 * @returns the normalized URL string.
 */
function assertFetchableUrl(raw, blockPrivateNetworks) {
	if (typeof raw !== 'string' || raw.trim().length === 0) throw new UrlPolicyFailure('invalid-url', 'url must be a non-empty string');
	if (raw.length > MAX_URL_CHARS) throw new UrlPolicyFailure('invalid-url', `url is ${raw.length} characters, over the ${MAX_URL_CHARS} character limit`);

	let parsed;
	try {
		parsed = new URL(raw);
	} catch (error) {
		throw new UrlPolicyFailure('invalid-url', `url is not parseable: ${error.message}`);
	}

	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new UrlPolicyFailure('blocked-url', `refused: scheme ${parsed.protocol} is not http or https`);
	// Credentials in a model-supplied URL are a leak vector, not a feature.
	if (parsed.username.length > 0 || parsed.password.length > 0) throw new UrlPolicyFailure('blocked-url', 'refused: the url embeds credentials; a proxy credential must come from the environment, not from the url');

	const host = parsed.hostname;
	if (host.length === 0) throw new UrlPolicyFailure('invalid-url', 'url has no hostname');
	if (host === 'localhost' || host.endsWith('.localhost')) throw new UrlPolicyFailure('blocked-url', 'refused: localhost is not a public target');

	if (blockPrivateNetworks) {
		const literal = host.replace(/^\[|\]$/g, '');
		if (IPV4.test(literal) && isPrivateV4(literal)) throw new UrlPolicyFailure('blocked-url', `refused: ${literal} is a private or reserved IPv4 address`);
		if (literal.includes(':') && isPrivateV6(literal)) throw new UrlPolicyFailure('blocked-url', `refused: ${literal} is a private or reserved IPv6 address`);
	}

	return parsed.toString();
}

export { assertFetchableUrl, UrlPolicyFailure, MAX_URL_CHARS };
