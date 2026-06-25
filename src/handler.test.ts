import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentConfig } from "./config";
import { escalationNotificationScript, Handler } from "./handler";

let base: string;
let allowed: string;
let outside: string;
let handler: Handler;

const CODE = "424242";

beforeAll(() => {
	base = mkdtempSync(join(tmpdir(), "tagent-"));
	allowed = join(base, "allowed");
	outside = join(base, "outside");
	mkdirSync(allowed, { recursive: true });
	mkdirSync(outside, { recursive: true });

	writeFileSync(join(allowed, "normal.txt"), "line one\nline two\nline three\n");
	writeFileSync(join(allowed, ".env"), "SECRET_DB_PASSWORD=hunter2hunter2\n");
	writeFileSync(join(outside, "data_target.txt"), "TOP_DATA_NOPATTERN_123\n");

	// symlink (inside allowed) pointing OUT of the allowed root
	symlinkSync(join(outside, "data_target.txt"), join(allowed, "link_out.txt"));
	// symlinked DIRECTORY inside allowed pointing out
	symlinkSync(outside, join(allowed, "evil_dir"));
	// symlinked leaf for write tests
	symlinkSync(join(outside, "data_target.txt"), join(allowed, "leaf_link.txt"));

	const config: AgentConfig = {
		server: "wss://x",
		token: "x",
		machine: "test",
		mode: "read-write",
		default_cwd: allowed,
		max_output_bytes: 8192,
		command_timeout_ms: 10000,
		allowed_read_dirs: [allowed],
		allowed_write_dirs: [allowed],
		blocked_paths: [],
		secret_literals: [],
		extra_read_binaries: [],
		notify_on_switch: false, // don't pop real macOS notifications during tests
		elevation_timeout_ms: 0, // no auto-revert in the shared handler tests
	};
	handler = new Handler(config, CODE);
});

afterAll(() => {
	rmSync(base, { recursive: true, force: true });
});

describe("read_file — containment + blocklist + symlinks", () => {
	test("reads a normal file inside the root", async () => {
		const out = await handler.dispatch("read_file", { path: "normal.txt" });
		expect(out).toContain("line one");
	});

	test("refuses an absolute path outside allowed_read_dirs", async () => {
		expect(handler.dispatch("read_file", { path: "/etc/hostname" })).rejects.toThrow();
	});

	test("refuses ../ traversal outside the root", async () => {
		expect(
			handler.dispatch("read_file", { path: "../outside/data_target.txt" }),
		).rejects.toThrow(/outside allowed_read_dirs/);
	});

	test("refuses a symlink that resolves outside the root", async () => {
		expect(handler.dispatch("read_file", { path: "link_out.txt" })).rejects.toThrow(
			/outside allowed_read_dirs/,
		);
	});

	test("refuses a blocked credential file inside the root", async () => {
		expect(handler.dispatch("read_file", { path: ".env" })).rejects.toThrow(/blocked path/);
	});
});

describe("write_file — confinement + symlink rejection", () => {
	test("writes a new file inside an allowed dir", async () => {
		const out = await handler.dispatch("write_file", { path: "out.txt", content: "hello" });
		expect(out).toContain('"ok": true');
	});

	test("refuses writing outside allowed_write_dirs", async () => {
		expect(
			handler.dispatch("write_file", { path: join(outside, "x.txt"), content: "x" }),
		).rejects.toThrow();
	});

	test("refuses writing through a symlinked directory", async () => {
		expect(
			handler.dispatch("write_file", { path: "evil_dir/x.txt", content: "x" }),
		).rejects.toThrow();
	});

	test("refuses writing through a symlinked leaf", async () => {
		expect(
			handler.dispatch("write_file", { path: "leaf_link.txt", content: "x", mode: "overwrite" }),
		).rejects.toThrow(/symlink/);
	});
});

describe("run_command — whitelist + path-arg blocklist", () => {
	test("refuses cat (content reader not whitelisted)", async () => {
		expect(handler.dispatch("run_command", { command: "cat normal.txt" })).rejects.toThrow();
	});

	test("refuses a whitelisted binary aimed at a blocked path", async () => {
		expect(handler.dispatch("run_command", { command: "wc .env" })).rejects.toThrow(/blocked/);
	});

	test("allows a whitelisted binary on a normal file", async () => {
		const out = await handler.dispatch("run_command", { command: "wc -l normal.txt" });
		expect(out).toContain("$ wc -l normal.txt");
	});

	test("refuses a whitelisted binary aimed outside the read roots", async () => {
		expect(
			handler.dispatch("run_command", { command: `wc -l ${join(outside, "data_target.txt")}` }),
		).rejects.toThrow(/outside allowed_read_dirs/);
	});
});

describe("switch_mode — request → confirm gate", () => {
	test("request step (no code) returns confirmation_required, does not switch", async () => {
		const out = await handler.dispatch("switch_mode", { mode: "read-write" });
		expect(out).toContain("confirmation_code");
		expect(out).toContain('"ok": false');
	});

	test("rejects elevation with a wrong code", async () => {
		expect(
			handler.dispatch("switch_mode", { mode: "bypass", confirmation_code: "000000" }),
		).rejects.toThrow(/confirmation_code/);
	});

	test("accepts elevation with the right code", async () => {
		const out = await handler.dispatch("switch_mode", { mode: "bypass", confirmation_code: CODE });
		expect(out).toContain('"mode": "bypass"');
		// restore to read-only (no code needed to de-escalate)
		await handler.dispatch("switch_mode", { mode: "read-only" });
	});
});

describe("switch_mode — elevation auto-reverts to read-only", () => {
	test("read-write reverts to read-only after the TTL", async () => {
		const cfg: AgentConfig = {
			server: "wss://x",
			token: "x",
			machine: "test",
			mode: "read-only",
			default_cwd: allowed,
			max_output_bytes: 8192,
			command_timeout_ms: 10000,
			allowed_read_dirs: [allowed],
			allowed_write_dirs: [allowed],
			blocked_paths: [],
			secret_literals: [],
			extra_read_binaries: [],
			notify_on_switch: false,
			elevation_timeout_ms: 60, // 60ms TTL for the test
		};
		const h = new Handler(cfg, CODE);
		const out = await h.dispatch("switch_mode", { mode: "read-write", confirmation_code: CODE });
		expect(out).toContain('"mode": "read-write"');
		expect(h.getMode()).toBe("read-write");
		await new Promise((r) => setTimeout(r, 150));
		expect(h.getMode()).toBe("read-only"); // auto-reverted
	});
});

describe("escalationNotificationScript", () => {
	test("request notification embeds the mode + code", () => {
		const s = escalationNotificationScript("macm4", "read-write", "424242", "request");
		expect(s).toContain("display notification");
		expect(s).toContain("read-write");
		expect(s).toContain("424242");
		expect(s).toContain("terminal-agent");
	});
	test("applied notification confirms the switch without the code", () => {
		const s = escalationNotificationScript("macm4", "bypass", "424242", "applied");
		expect(s).toContain("switched to bypass");
		expect(s).not.toContain("424242");
	});
	test("escapes quotes/backslashes in the machine name", () => {
		const s = escalationNotificationScript('m"x\\y', "read-write", "1", "request");
		expect(s).toContain('m\\"x\\\\y');
	});
});
