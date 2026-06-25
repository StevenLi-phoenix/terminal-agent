import { describe, expect, test } from "bun:test";
import { hardBlocked, makeIsBlocked, sanitize } from "./secret-filter";

describe("sanitize — redacts known secret shapes", () => {
	// Vendor-prefixed vectors are split with `+` so the SOURCE file never holds a
	// contiguous real-token shape (avoids GitHub secret-scanning false positives);
	// the runtime-concatenated value is exactly the token the sanitizer must redact.
	const cases: Array<[string, string]> = [
		["anthropic", "sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"],
		["openai sk-proj", "sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123456789"],
		["stripe live", "sk_" + "live_abcdefghijklmnop1234567890"],
		["github pat", "ghp" + "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"],
		["github fine-grained", "github" + "_pat_" + "a".repeat(60)],
		["gitlab", "glpat" + "-abcdefghij1234567890XY"],
		["slack bot", "xox" + "b-1234567890-ABCDEFGHIJKLMNOP"],
		["aws akia", "AKIA" + "IOSFODNN7EXAMPLE"],
		["google", "AIza" + "SyA1234567890abcdefghijklmnopqrstuvw"],
		["npm", "npm" + "_" + "a".repeat(36)],
		["jwt", "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF"],
		["bearer", "Authorization: Bearer abcdef.ghijkl-MNOPqr_stuv"],
		["64-hex", "deadbeef".repeat(8)],
		["password assignment", 'password: "hunter2hunter2"'],
		["api_key assignment", "api_key=" + "sk_" + "test_abcdefghijklmnop"],
		["telegram", "123456789:" + "AAH-abcdefghijklmnopqrstuvwxyz012345"],
		["url credentials", "postgres://admin:" + "Pr0dDbP4ss" + "@db.host:5432/app"],
		["password with suffix name", "PG_PASSWORD_VALUE=hunter2isweak"],
		["digitalocean", "dop" + "_v1_" + "a".repeat(64)],
	];
	for (const [name, secret] of cases) {
		test(name, () => {
			const out = sanitize(`before ${secret} after`);
			expect(out).toContain("[REDACTED]");
			expect(out).not.toContain(secret);
		});
	}
});

describe("sanitize — keeps benign text", () => {
	test("normal prose untouched", () => {
		const text = "The quick brown fox jumps over the lazy dog. v1.2.3 build ok.";
		expect(sanitize(text)).toBe(text);
	});
	test("short code identifiers survive", () => {
		const text = "const handler = makeHandler(config);";
		expect(sanitize(text)).toBe(text);
	});
});

describe("sanitize — literal redaction", () => {
	test("redacts a configured literal (>=8 chars)", () => {
		expect(sanitize("token is supersecretvalue here", ["supersecretvalue"])).not.toContain(
			"supersecretvalue",
		);
	});
	test("ignores too-short literals", () => {
		expect(sanitize("abc abc abc", ["abc"])).toBe("abc abc abc");
	});
});

describe("hardBlocked — credential paths refused", () => {
	const blocked = [
		"/Users/x/proj/.env",
		"/Users/x/proj/.env.production",
		"/Users/x/.dev.vars",
		"/Users/x/.ssh/id_rsa",
		"/Users/x/.ssh/config",
		"/Users/x/.aws/credentials",
		"/Users/x/.gnupg/secring.gpg",
		"/Users/x/certs/server.pem",
		"/Users/x/certs/server.key",
		"/Users/x/app/secrets.json",
		"/Users/x/app/db_credentials.yaml",
		"/Users/x/.npmrc",
		"/Users/x/Library/Keychains/login.keychain",
		// expanded coverage
		"/Users/x/.ssh/config",
		"/Users/x/.kube/config",
		"/Users/x/.docker/config.json",
		"/Users/x/.pgpass",
		"/Users/x/.my.cnf",
		"/Users/x/infra/prod.tfstate",
		"/Users/x/vault.kdbx",
		// case-insensitive (macOS): .SSH opens the same inode as .ssh
		"/Users/x/.SSH/known_hosts",
		"/Users/x/.AWS/config",
		"/Users/x/.Password-Store/github.gpg",
	];
	for (const p of blocked) {
		test(`blocks ${p}`, () => expect(hardBlocked(p)).toBe(true));
	}
});

describe("hardBlocked — normal files allowed", () => {
	const ok = [
		"/Users/x/proj/src/index.ts",
		"/Users/x/proj/README.md",
		"/Users/x/proj/package.json",
		"/Users/x/proj/environment.ts",
		"/Users/x/proj/keyboard.ts",
	];
	for (const p of ok) {
		test(`allows ${p}`, () => expect(hardBlocked(p)).toBe(false));
	}
});

describe("makeIsBlocked — config globs add to the hard floor", () => {
	const isBlocked = makeIsBlocked(["**/private/**", "**/*.secretkey"]);
	test("hard floor still applies", () => {
		expect(isBlocked("/Users/x/.env")).toBe(true);
	});
	test("extra glob — private dir", () => {
		expect(isBlocked("/Users/x/proj/private/data.txt")).toBe(true);
	});
	test("extra glob — suffix", () => {
		expect(isBlocked("/Users/x/proj/app.secretkey")).toBe(true);
	});
	test("unrelated path allowed", () => {
		expect(isBlocked("/Users/x/proj/src/app.ts")).toBe(false);
	});
});
