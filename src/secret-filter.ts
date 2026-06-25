/**
 * Secret filter — the hard rule of the terminal agent.
 *
 * Every byte of tool output passes through `sanitize()` before it is sent
 * back over the WebSocket, and every path is checked with the blocklist
 * before it is read or written. Two independent layers, plus the read-only
 * mode and command whitelist, mean a token/credential must defeat several
 * controls to ever reach chat history. We prefer over-redaction (false
 * positives like git SHAs) to any leak.
 *
 * Layers here:
 *   1. isBlockedPath()/makeIsBlocked() — never even open a secret-bearing
 *      file. A built-in hard floor (always on, not user-disableable) plus
 *      optional user globs from config.
 *   2. sanitize() — content regexes for common token shapes + 64-hex +
 *      "password: …" assignments + user-supplied literal strings.
 */

import picomatch from "picomatch";
import { homedir } from "node:os";

const REDACTED = "[REDACTED]";

/**
 * Content patterns. Order is irrelevant (each replaces independently and the
 * replacement contains no secret material, so passes are idempotent).
 */
const SECRET_PATTERNS: RegExp[] = [
	// Anthropic explicit
	/sk-ant-[a-zA-Z0-9_-]{20,}/g,
	// OpenAI / Stripe / generic dash-prefixed: sk- pk- rk- (covers sk-proj-)
	/(?:sk|pk|rk)-[a-zA-Z0-9_-]{20,}/g,
	// Stripe underscore live/test keys: sk_live_… rk_test_… pk_live_…
	/(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{10,}/g,
	// GitHub tokens: ghp_ gho_ ghu_ ghs_ ghr_
	/gh[opusr]_[a-zA-Z0-9]{20,}/g,
	// GitHub fine-grained PAT
	/github_pat_[a-zA-Z0-9_]{50,}/g,
	// GitLab PAT
	/glpat-[a-zA-Z0-9_-]{20,}/g,
	// Slack tokens + webhooks
	/xox[abprs]-[a-zA-Z0-9-]{10,}/g,
	/https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g,
	// AWS access key ids (long-term + temporary)
	/A(?:KIA|SIA)[0-9A-Z]{16}/g,
	// Google API key
	/AIza[0-9A-Za-z_-]{35}/g,
	// npm automation token
	/npm_[A-Za-z0-9]{36}/g,
	// Replicate
	/r8_[a-zA-Z0-9]{20,}/g,
	// Twilio API key SID
	/SK[0-9a-fA-F]{32}/g,
	// SendGrid
	/SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
	// Generic long Cloudflare-ish token names
	/CF[_-][A-Za-z0-9_-]{30,}/g,
	// JWT (header.payload[.signature])
	/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}(?:\.[a-zA-Z0-9_-]+)?/g,
	// HTTP auth headers
	/Bearer\s+[a-zA-Z0-9._~+/-]+=*/g,
	/Basic\s+[A-Za-z0-9+/]{16,}={0,2}/g,
	// PEM private key blocks (whole block, multiline) + bare header
	/-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----/g,
	/-----BEGIN[^-]*PRIVATE KEY-----/g,
	// Telegram bot token
	/\b\d{6,}:AA[\w-]{30,}\b/g,
	// Discord token
	/[MNO][A-Za-z\d_-]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}/g,
	// DigitalOcean / Docker PAT
	/dop_v1_[a-f0-9]{64}/g,
	/dckr_pat_[A-Za-z0-9_-]{20,}/g,
	// URL-embedded credentials: scheme://user:password@host
	/\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]{2,}@/gi,
	// key[suffix]: value / key = value assignments for sensitive names. The
	// [\w-]* after the keyword catches PG_PASSWORD_VALUE=… style names where
	// the keyword isn't immediately adjacent to the separator.
	/(?:password|passwd|pwd|secret|token|apikey|api[_-]?key|access[_-]?key|auth|client[_-]?secret|passphrase)[\w-]*\s*[:=]\s*['"]?[^\s'"]{6,}/gi,
	// 64+ char hex run (SHA-256 / many hex secrets, including longer keys).
	// Over-redacts git SHAs by design — better safe than leaking.
	/[a-f0-9]{64,}/gi,
];

/**
 * Redact secrets in `output`. `extraLiterals` are exact strings (≥8 chars)
 * the user listed in config.secret_literals — redacted everywhere.
 */
export function sanitize(output: string, extraLiterals: readonly string[] = []): string {
	let result = output;
	for (const pattern of SECRET_PATTERNS) {
		result = result.replace(pattern, REDACTED);
	}
	for (const literal of extraLiterals) {
		if (typeof literal === "string" && literal.length >= 8) {
			result = result.split(literal).join(REDACTED);
		}
	}
	return result;
}

// ── Path blocklist ───────────────────────────────────────────────────

/**
 * Directory names whose subtree is always off-limits (anywhere in the path).
 * Compared case-insensitively — macOS APFS/HFS is case-insensitive, so `.SSH`
 * opens the same inode as `.ssh`.
 */
const BLOCKED_DIR_SEGMENTS = new Set([
	".ssh",
	".gnupg",
	".aws",
	".gpg",
	".password-store",
	".kube",
	".docker",
	".terraform.d",
	".chef",
]);

/** Exact basenames that are always off-limits (compared lowercased). */
const BLOCKED_BASENAMES = new Set([
	".env",
	".dev.vars",
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".pgpass",
	".my.cnf",
	"credentials",
	"kubeconfig",
	"rclone.conf",
	"id_rsa",
	"id_dsa",
	"id_ecdsa",
	"id_ed25519",
]);

/** Suffixes that are always off-limits (compared on the lowercased basename). */
const BLOCKED_SUFFIXES = [
	".pem",
	".key",
	".p12",
	".pfx",
	".keychain",
	".keystore",
	".jks",
	".gpg",
	".asc",
	".tfstate",
	".kdbx",
	".ovpn",
];

/**
 * The built-in hard floor — always on, not configurable. Returns true for
 * any path that obviously holds credentials. Conservative substring/suffix
 * checks plus ancestor-directory checks. Note this is defense-in-depth
 * BEHIND the allowed_read_dirs/allowed_write_dirs containment, which is the
 * primary boundary (out-of-tree files are unreadable regardless).
 */
export function hardBlocked(absPath: string): boolean {
	const segments = absPath.split("/").filter((s) => s.length > 0);
	const base = (segments[segments.length - 1] ?? "").toLowerCase();

	// Any ancestor (or the leaf itself) being a blocked secret dir
	// (case-insensitive, matching the filesystem semantics).
	for (const seg of segments) {
		if (BLOCKED_DIR_SEGMENTS.has(seg.toLowerCase())) return true;
	}

	if (BLOCKED_BASENAMES.has(base)) return true;
	if (base.startsWith(".env")) return true; // .env, .env.local, .env.production …
	for (const suffix of BLOCKED_SUFFIXES) {
		if (base.endsWith(suffix)) return true;
	}
	if (
		base.includes("secret") ||
		base.includes("credential") ||
		base.includes("keychain") ||
		base.includes("id_rsa")
	) {
		return true;
	}
	return false;
}

function expandTilde(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return `${homedir()}/${p.slice(2)}`;
	return p;
}

/**
 * Build a path-blocked predicate combining the hard floor with the user's
 * extra globs from config.blocked_paths. Globs are matched against the
 * absolute path (and a leading-slash-stripped variant); relative patterns
 * (no leading "/") also get a "**\/"-prefixed variant so "**\/.env"-style
 * entries match at any depth.
 */
export function makeIsBlocked(extraGlobs: readonly string[] = []): (absPath: string) => boolean {
	const matchers: ((p: string) => boolean)[] = [];
	for (const raw of extraGlobs) {
		if (typeof raw !== "string" || raw.length === 0) continue;
		const expanded = expandTilde(raw);
		const variants = new Set<string>([expanded]);
		if (!expanded.startsWith("/")) variants.add(`**/${expanded}`);
		for (const v of variants) {
			const isMatch = picomatch(v, { dot: true });
			matchers.push((p) => isMatch(p) || isMatch(p.replace(/^\/+/, "")));
		}
	}
	return (absPath: string): boolean => {
		if (hardBlocked(absPath)) return true;
		for (const m of matchers) {
			if (m(absPath)) return true;
		}
		return false;
	};
}

/** Convenience single-shot check against the hard floor only. */
export function isBlockedPath(absPath: string): boolean {
	return hardBlocked(absPath);
}
