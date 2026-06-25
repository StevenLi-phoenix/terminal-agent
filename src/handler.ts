/**
 * Tool dispatch for the terminal agent.
 *
 * Every tool routes through `dispatch()`, whose single sanitize point means
 * no tool output can skip the secret filter. The optional `_system`
 * preamble (machine/os/cwd/mode/env-var NAMES only) is prepended after
 * sanitizing the body — it is curated metadata with no secret values.
 *
 * Tool errors (blocked path, bad command, wrong mode) throw; index.ts turns
 * them into a sanitized WS `error` message → an MCP isError result.
 */

import { appendFile, lstat, readdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { execFile } from "node:child_process";
import type { AgentConfig, TerminalMode } from "./config";
import { resolvePath } from "./config";
import { checkCommand, runCommand } from "./commands";
import { makeIsBlocked, sanitize } from "./secret-filter";

const MAX_READ_BYTES = 10 * 1024 * 1024; // refuse whole-file reads above this
const READ_RANGE_CAP = 200; // lines per ranged read_file
const HEAD_LINES = 80;
const TAIL_LINES = 20;
const SEARCH_MATCH_CAP = 50;
const LIST_ENTRY_CAP = 800;

/** Dirs we never descend into when listing or searching. */
const WALK_EXCLUDES = new Set([
	"node_modules",
	".git",
	".venv",
	"venv",
	"dist",
	"build",
	".next",
	".cache",
	"__pycache__",
	".turbo",
	"target",
	".ssh",
	".gnupg",
	".aws",
]);

/** Glob excludes handed to ripgrep so it never even opens a secret file. */
const RG_EXCLUDES = [
	"!**/.env",
	"!**/.env.*",
	"!**/.dev.vars",
	"!**/*.pem",
	"!**/*.key",
	"!**/.ssh/**",
	"!**/.aws/**",
	"!**/.gnupg/**",
	"!**/*secret*",
	"!**/*credential*",
];

/** PATH augmented with common Homebrew/user locations (launchd has a bare PATH). */
const EXEC_PATH = [
	"/opt/homebrew/bin",
	"/opt/homebrew/sbin",
	"/usr/local/bin",
	"/usr/bin",
	"/bin",
	"/usr/sbin",
	"/sbin",
	process.env.PATH ?? "",
]
	.filter(Boolean)
	.join(":");

export interface ToolParams {
	[key: string]: unknown;
	with_system?: boolean;
}

export class Handler {
	private mode: TerminalMode;
	private readonly isBlocked: (absPath: string) => boolean;
	private lastNotifyAt = 0;
	private elevationTimer: ReturnType<typeof setTimeout> | null = null;

	/** Called when the runtime mode changes so index.ts can re-register. */
	onModeChange: ((mode: TerminalMode) => void) | null = null;

	constructor(
		private readonly config: AgentConfig,
		private readonly confirmationCode: string,
	) {
		this.mode = config.mode;
		this.isBlocked = makeIsBlocked(config.blocked_paths);
	}

	getMode(): TerminalMode {
		return this.mode;
	}

	/** Run a tool and return display-ready, sanitized text. Throws on tool errors. */
	async dispatch(tool: string, params: ToolParams): Promise<string> {
		const raw = await this.runTool(tool, params);
		const safe = sanitize(raw, this.config.secret_literals);
		if (params?.with_system) {
			return `${this.systemPreamble()}\n\n${safe}`;
		}
		return safe;
	}

	private async runTool(tool: string, params: ToolParams): Promise<string> {
		switch (tool) {
			case "search_files":
				return this.searchFiles(params);
			case "read_file":
				return this.readFileTool(params);
			case "list_directory":
				return this.listDirectory(params);
			case "run_command":
				return this.runCommandTool(params);
			case "write_file":
				return this.writeFileTool(params);
			case "switch_mode":
				return this.switchMode(params);
			default:
				throw new Error(`unknown tool: ${tool}`);
		}
	}

	// ── tools ────────────────────────────────────────────────────────────

	private async searchFiles(params: ToolParams): Promise<string> {
		const pattern = requireString(params.pattern, "pattern");
		const lexical = params.path
			? resolvePath(requireString(params.path, "path"), this.config.default_cwd)
			: this.config.default_cwd;
		const searchPath = await this.resolveReadTarget(lexical);
		const glob = typeof params.glob === "string" ? params.glob : undefined;

		const args = [
			"--line-number",
			"--with-filename",
			"--null", // NUL after the path so a ':' in a filename can't fool the post-filter
			"--color=never",
			"--no-messages",
			"--no-heading",
			"--max-filesize",
			"5M",
		];
		// User glob FIRST, hard excludes LAST: ripgrep is last-match-wins, so
		// a user-supplied positive glob can never re-include a secret file.
		if (glob) args.push("--glob", glob);
		for (const ex of RG_EXCLUDES) args.push("--glob", ex);
		for (const b of this.config.blocked_paths) args.push("--glob", `!${b}`);
		args.push("-e", pattern, "--", searchPath);

		const res = await execCapture("rg", args, {
			cwd: this.config.default_cwd,
			timeoutMs: this.config.command_timeout_ms,
			maxBytes: 256 * 1024,
		});

		if (res.errno === "ENOENT") {
			throw new Error("ripgrep (rg) is not installed or not on PATH on the agent machine.");
		}
		if (res.code !== 0 && res.code !== 1) {
			throw new Error(`search failed (rg exit ${res.code}): ${res.stderr.trim() || "unknown error"}`);
		}

		// With --null, each line is `PATH\0LINENO:CONTENT`. Split on the NUL
		// (a filename can't contain one) to get the real path, drop blocked
		// matches, then render the NUL back as ':' for display.
		const lines = res.stdout
			.split("\n")
			.filter((l) => l.length > 0)
			.map((l) => {
				const nul = l.indexOf("\0");
				return { path: nul >= 0 ? l.slice(0, nul) : l, line: l };
			})
			.filter((m) => !this.isBlocked(m.path))
			.map((m) => m.line.replace("\0", ":"));

		if (lines.length === 0) {
			return `No matches for /${pattern}/ under ${searchPath}.`;
		}

		const shown = lines.slice(0, SEARCH_MATCH_CAP);
		const more = lines.length - shown.length;
		const header = `${lines.length} match${lines.length === 1 ? "" : "es"} for /${pattern}/ (showing ${shown.length}${more > 0 ? `, ${more} more` : ""}):`;
		return `${header}\n${shown.join("\n")}`;
	}

	private async readFileTool(params: ToolParams): Promise<string> {
		const lexical = resolvePath(requireString(params.path, "path"), this.config.default_cwd);
		const path = await this.resolveReadTarget(lexical);
		const lineStart = optionalInt(params.line_start);
		const lineEnd = optionalInt(params.line_end);

		let st: Awaited<ReturnType<typeof stat>>;
		try {
			st = await stat(path);
		} catch (err) {
			throw new Error(`cannot stat ${path}: ${errMsg(err)}`);
		}
		if (!st.isFile()) throw new Error(`${path} is not a regular file.`);

		const hasRange = lineStart !== undefined;
		if (!hasRange && st.size > MAX_READ_BYTES) {
			throw new Error(
				`${path} is ${st.size} bytes (> ${MAX_READ_BYTES}); pass line_start/line_end (≤${READ_RANGE_CAP} lines) to read a window.`,
			);
		}

		const buf = await readFile(path);
		if (isBinary(buf)) {
			return `[binary file: ${path}, ${st.size} bytes]`;
		}
		const allLines = buf.toString("utf8").split(/\r?\n/);
		const total = allLines.length;

		if (hasRange) {
			const start = Math.max(1, lineStart!);
			const endRequested = lineEnd !== undefined ? Math.max(start, lineEnd) : start;
			const end = Math.min(endRequested, start + READ_RANGE_CAP - 1, total);
			if (start > total) {
				throw new Error(`line_start ${start} is past end of file (${total} lines).`);
			}
			const slice = allLines.slice(start - 1, end);
			return `${path} (lines ${start}-${end} of ${total}):\n${numberLines(slice, start)}`;
		}

		if (total <= 200) {
			return `${path} (${total} lines):\n${numberLines(allLines, 1)}`;
		}

		const head = allLines.slice(0, HEAD_LINES);
		const tail = allLines.slice(total - TAIL_LINES);
		const omitted = total - HEAD_LINES - TAIL_LINES;
		return [
			`${path} (${total} lines — showing head ${HEAD_LINES} + tail ${TAIL_LINES}; use line_start/line_end for the middle):`,
			numberLines(head, 1),
			`        … ${omitted} lines omitted …`,
			numberLines(tail, total - TAIL_LINES + 1),
		].join("\n");
	}

	private async listDirectory(params: ToolParams): Promise<string> {
		const lexical = params.path
			? resolvePath(requireString(params.path, "path"), this.config.default_cwd)
			: this.config.default_cwd;
		const path = await this.resolveReadTarget(lexical);
		const maxDepth = optionalInt(params.max_depth) ?? 2;

		const out: string[] = [`${path}`];
		let count = 0;
		let capped = false;

		const walk = async (dir: string, depth: number, prefix: string): Promise<void> => {
			if (depth > maxDepth || capped) return;
			let entries: import("node:fs").Dirent[];
			try {
				entries = await readdir(dir, { withFileTypes: true });
			} catch {
				return;
			}
			entries.sort((a, b) => {
				const ad = a.isDirectory() ? 0 : 1;
				const bd = b.isDirectory() ? 0 : 1;
				return ad !== bd ? ad - bd : a.name.localeCompare(b.name);
			});
			for (const e of entries) {
				if (capped) return;
				const full = `${dir}/${e.name}`;
				// Never list or descend into blocked (credential) paths.
				if (this.isBlocked(full)) continue;
				if (count >= LIST_ENTRY_CAP) {
					capped = true;
					out.push(`${prefix}… (entry cap ${LIST_ENTRY_CAP} reached; narrow the path or lower max_depth)`);
					return;
				}
				const isDir = e.isDirectory();
				out.push(`${prefix}${isDir ? "📁 " : "   "}${e.name}`);
				count += 1;
				if (isDir && !WALK_EXCLUDES.has(e.name) && !e.isSymbolicLink()) {
					await walk(full, depth + 1, `${prefix}  `);
				}
			}
		};

		await walk(path, 1, "  ");
		return out.join("\n");
	}

	private async runCommandTool(params: ToolParams): Promise<string> {
		const command = requireString(params.command, "command");
		const check = checkCommand(command, this.mode, new Set(this.config.extra_read_binaries));
		if (!check.ok) throw new Error(check.reason);

		// Even whitelisted binaries must not be aimed at a blocked path or
		// outside the read roots — this closes `wc ~/.aws/credentials`-style
		// reads and `ls /etc`-style recon that bypass the read-tool boundary.
		// Bypass mode is intentionally exempt (unrestricted).
		if (this.mode !== "bypass") {
			for (const arg of check.parsed.args) {
				await this.assertArgAllowed(arg);
			}
		}

		const res = await runCommand(check.parsed, {
			cwd: this.config.default_cwd,
			timeoutMs: this.config.command_timeout_ms,
			maxBytes: this.config.max_output_bytes,
		});

		const parts: string[] = [`$ ${command}`];
		if (res.stdout) parts.push(res.stdout.replace(/\n$/, ""));
		if (res.stderr) parts.push(`[stderr]\n${res.stderr.replace(/\n$/, "")}`);
		if (res.code !== 0) parts.push(`[exit ${res.code}]`);
		if (res.truncated) parts.push(`[output truncated at ${this.config.max_output_bytes} bytes]`);
		return parts.join("\n");
	}

	private async writeFileTool(params: ToolParams): Promise<string> {
		if (this.mode === "read-only") {
			throw new Error(
				"write_file requires read-write or bypass mode. Use switch_mode with the confirmation code first.",
			);
		}
		const lexical = resolvePath(requireString(params.path, "path"), this.config.default_cwd);
		// realpath the parent + reject a symlinked leaf, so the write cannot
		// escape allowed_write_dirs through a symlink (dir or leaf).
		const { path, exists } = await this.resolveWriteTarget(lexical);
		const mode = ((): "create" | "overwrite" | "append" => {
			const m = params.mode;
			return m === "overwrite" || m === "append" ? m : "create";
		})();
		const content = typeof params.content === "string" ? params.content : "";

		if (mode === "create") {
			if (exists) {
				throw new Error(`${path} already exists; use mode "overwrite" or "append" to change it.`);
			}
			await writeFile(path, content, "utf8");
		} else if (mode === "append") {
			await appendFile(path, content, "utf8");
		} else {
			await writeFile(path, content, "utf8");
		}

		return JSON.stringify(
			{ ok: true, path, mode, bytes: Buffer.byteLength(content, "utf8") },
			null,
			2,
		);
	}

	private async switchMode(params: ToolParams): Promise<string> {
		const target = params.mode;
		if (target !== "read-only" && target !== "read-write" && target !== "bypass") {
			throw new Error(`invalid mode: ${String(target)}`);
		}
		// De-escalating to read-only never needs a code.
		if (target === "read-only") {
			const previous = this.mode;
			this.mode = target;
			this.clearElevationTimer();
			this.onModeChange?.(target);
			return JSON.stringify({ ok: true, previous_mode: previous, mode: target }, null, 2);
		}

		// Escalation flow is two steps:
		//   1. REQUEST — caller invokes switch_mode WITHOUT a code; the agent
		//      pushes the confirmation code to the operator's Mac as a
		//      notification and tells the caller to ask the human for it.
		//   2. CONFIRM — caller invokes again WITH the code the operator relayed.
		const code = typeof params.confirmation_code === "string" ? params.confirmation_code.trim() : "";

		if (code === "") {
			const sent = this.notifyEscalation(target, "request");
			return JSON.stringify(
				{
					ok: false,
					requested_mode: target,
					action_required: "confirmation_code",
					message: sent
						? `Requested ${target}. A confirmation code was sent to the operator's Mac (${this.config.machine}) as a notification — ask the human to read it to you, then call switch_mode again with mode="${target}" and that confirmation_code.`
						: `Switching to ${target} needs the 6-digit confirmation code printed in the agent's startup banner/log on ${this.config.machine}. Ask the human operator for it, then call switch_mode again with it.`,
				},
				null,
				2,
			);
		}

		if (code !== this.confirmationCode) {
			this.notifyEscalation(target, "request"); // wrong guess → re-send the code
			throw new Error(
				`invalid confirmation_code for ${target}. A fresh notification with the code was sent to ${this.config.machine} — ask the operator for the 6-digit code and retry.`,
			);
		}

		const previous = this.mode;
		this.mode = target;
		this.onModeChange?.(target);
		this.notifyEscalation(target, "applied");
		// Elevated privilege is temporary — auto-revert to read-only after the
		// TTL so a forgotten read-write/bypass session doesn't stay open.
		this.armElevationTimer(target);
		const ttlMin = Math.round(this.config.elevation_timeout_ms / 60000);
		return JSON.stringify(
			{
				ok: true,
				previous_mode: previous,
				mode: target,
				auto_revert_in:
					this.config.elevation_timeout_ms > 0 ? `${ttlMin} min → read-only` : "disabled",
			},
			null,
			2,
		);
	}

	// ── helpers ──────────────────────────────────────────────────────────

	/** Sanitize a message (including configured literals) for the wire. Used
	 *  for error strings in index.ts so the error path matches the happy path. */
	redactError(message: string): string {
		return sanitize(message, this.config.secret_literals);
	}

	/**
	 * Push a macOS notification when a mode switch is requested/applied, so the
	 * operator gets the confirmation code on their Mac (where the cloud AI
	 * cannot see it) instead of grepping a log. Fire-and-forget; never throws;
	 * no-op off darwin or when notify_on_switch is false. "request" notifications
	 * are debounced (4s) to avoid spam on retries; "applied" always fires.
	 * Returns whether a notification was (or recently was) sent.
	 */
	private notifyEscalation(mode: TerminalMode, kind: "request" | "applied" | "reverted"): boolean {
		if (!this.config.notify_on_switch || process.platform !== "darwin") return false;
		if (kind === "request") {
			const now = Date.now();
			if (now - this.lastNotifyAt < 4000) return true; // already pushed recently
			this.lastNotifyAt = now;
		}
		const script = escalationNotificationScript(this.config.machine, mode, this.confirmationCode, kind);
		try {
			execFile("/usr/bin/osascript", ["-e", script], { timeout: 5000 }, () => {});
			return true;
		} catch {
			return false;
		}
	}

	private clearElevationTimer(): void {
		if (this.elevationTimer) {
			clearTimeout(this.elevationTimer);
			this.elevationTimer = null;
		}
	}

	/** Arm (or re-arm) the auto-revert: after elevation_timeout_ms, drop back to
	 *  read-only and notify. ttl <= 0 disables auto-revert (always-on opt-out). */
	private armElevationTimer(elevatedMode: TerminalMode): void {
		this.clearElevationTimer();
		const ttl = this.config.elevation_timeout_ms;
		if (ttl <= 0) return;
		this.elevationTimer = setTimeout(() => {
			this.elevationTimer = null;
			if (this.mode === "read-only") return; // already de-escalated
			this.mode = "read-only";
			this.onModeChange?.("read-only");
			this.notifyEscalation(elevatedMode, "reverted");
		}, ttl);
	}

	/**
	 * True if `realTarget` (already realpath'd) is inside any of `roots`
	 * (each realpath'd to defeat a symlinked root). `allowRootItself` permits
	 * the root path equalling the target (used for read/list of a root dir).
	 */
	private async withinRoots(
		realTarget: string,
		roots: readonly string[],
		allowRootItself: boolean,
	): Promise<boolean> {
		for (const root of roots) {
			let realRoot: string;
			try {
				realRoot = await realpath(root);
			} catch {
				continue;
			}
			const rel = relative(realRoot, realTarget);
			if (rel === "") {
				if (allowRootItself) return true;
				continue;
			}
			if (!rel.startsWith("..") && !isAbsolute(rel)) return true;
		}
		return false;
	}

	/**
	 * Resolve a read target through symlinks, then enforce (1) the path
	 * blocklist on the real AND lexical path and (2) containment within
	 * allowed_read_dirs. Returns the canonical real path to read from. Works
	 * for files and directories (search/list roots).
	 */
	private async resolveReadTarget(lexicalPath: string): Promise<string> {
		let real: string;
		try {
			real = await realpath(lexicalPath);
		} catch (err) {
			throw new Error(`cannot resolve ${lexicalPath}: ${errMsg(err)}`);
		}
		if (this.isBlocked(real) || this.isBlocked(lexicalPath)) {
			throw new Error(`blocked path: refusing to access a credential-bearing file (${lexicalPath}).`);
		}
		if (!(await this.withinRoots(real, this.config.allowed_read_dirs, true))) {
			throw new Error(
				`refusing to read ${lexicalPath}: resolved path is outside allowed_read_dirs (${this.config.allowed_read_dirs.join(", ")}).`,
			);
		}
		return real;
	}

	/**
	 * Resolve a write target: realpath its PARENT (so a symlinked directory
	 * component is dereferenced and confinement is checked on the real
	 * parent), reject a symlinked leaf, enforce the blocklist, and confine to
	 * allowed_write_dirs. Returns the real target path + whether it exists.
	 */
	private async resolveWriteTarget(lexicalPath: string): Promise<{ path: string; exists: boolean }> {
		const parent = dirname(lexicalPath);
		let realParent: string;
		try {
			realParent = await realpath(parent);
		} catch (err) {
			throw new Error(
				`cannot write ${lexicalPath}: parent directory missing or unreadable (${parent}): ${errMsg(err)}`,
			);
		}
		const target = join(realParent, basename(lexicalPath));
		if (this.isBlocked(target) || this.isBlocked(lexicalPath)) {
			throw new Error(`blocked path: refusing to write a credential-bearing file (${lexicalPath}).`);
		}
		if (!(await this.withinRoots(realParent, this.config.allowed_write_dirs, true))) {
			throw new Error(
				`refusing to write ${lexicalPath}: outside allowed_write_dirs (${this.config.allowed_write_dirs.join(", ")}).`,
			);
		}
		let leaf: Awaited<ReturnType<typeof lstat>> | null = null;
		try {
			leaf = await lstat(target);
		} catch {
			leaf = null;
		}
		if (leaf?.isSymbolicLink()) {
			throw new Error(`refusing to write through a symlink: ${target}`);
		}
		// A hardlink leaf (nlink > 1) is a second name for an inode that may
		// live outside the allowed roots — lstat can't see the other path, so
		// refuse multiply-linked targets outright.
		if (leaf && leaf.nlink > 1) {
			throw new Error(`refusing to write a hardlinked file (nlink=${leaf.nlink}): ${target}`);
		}
		return { path: target, exists: leaf !== null };
	}

	/**
	 * Reject a run_command argument that names a blocked or out-of-read-root
	 * path. Considers the bare arg AND any `--flag=value` value (so a path
	 * smuggled inside a flag is still checked), runs the blocklist on the
	 * lexical path *before* realpath (so a blocked-named not-yet-existing
	 * target is caught), and enforces the same allowed_read_dirs containment
	 * the read tools use (so `ls /etc`/`wc /var/log/x` can't recon outside
	 * the read roots).
	 */
	private async assertArgAllowed(arg: string): Promise<void> {
		const candidates: string[] = [];
		if (!arg.startsWith("-")) candidates.push(arg);
		const eq = arg.indexOf("=");
		if (eq >= 0 && eq < arg.length - 1) candidates.push(arg.slice(eq + 1));

		for (const c of candidates) {
			const lexical = resolvePath(c, this.config.default_cwd);
			if (this.isBlocked(lexical)) {
				throw new Error(`command refused: argument resolves to a blocked path (${c}).`);
			}
			let real: string;
			try {
				real = await realpath(lexical);
			} catch {
				continue; // doesn't exist → can't read content from it
			}
			if (this.isBlocked(real)) {
				throw new Error(`command refused: argument resolves to a blocked path (${c}).`);
			}
			if (!(await this.withinRoots(real, this.config.allowed_read_dirs, true))) {
				throw new Error(
					`command refused: argument "${c}" is outside allowed_read_dirs (${this.config.allowed_read_dirs.join(", ")}).`,
				);
			}
		}
	}

	private systemPreamble(): string {
		const keys = Object.keys(process.env).sort();
		return [
			"# _system (first call only)",
			`machine: ${this.config.machine}`,
			`hostname: ${hostname()}`,
			`os: ${process.platform} ${process.arch}`,
			`runtime: ${process.version}`,
			`shell: ${process.env.SHELL ?? "?"}`,
			`cwd: ${this.config.default_cwd}`,
			`mode: ${this.mode}`,
			`allowed_write_dirs: ${this.config.allowed_write_dirs.join(", ")}`,
			`env_keys (${keys.length}, names only): ${keys.join(", ")}`,
		].join("\n");
	}
}

// ── module-level helpers ───────────────────────────────────────────────

/**
 * Build the AppleScript for a switch_mode notification. Pure + exported for
 * testing. The body of a "request" carries the confirmation code so the
 * operator can relay it; "applied" just confirms the switch.
 */
export function escalationNotificationScript(
	machine: string,
	mode: string,
	code: string,
	kind: "request" | "applied" | "reverted",
): string {
	const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
	let subtitle: string;
	let body: string;
	if (kind === "request") {
		subtitle = `${machine} · ${mode} requested`;
		body = `Cloud requested ${mode}. Confirmation code: ${code}`;
	} else if (kind === "reverted") {
		subtitle = `${machine} · back to read-only`;
		body = `Auto-reverted to read-only (${mode} session expired).`;
	} else {
		subtitle = `${machine} · now ${mode}`;
		body = `Mode switched to ${mode}.`;
	}
	return `display notification "${esc(body)}" with title "terminal-agent" subtitle "${esc(subtitle)}" sound name "Glass"`;
}

function requireString(v: unknown, name: string): string {
	if (typeof v !== "string" || v.length === 0) {
		throw new Error(`missing or invalid "${name}" (expected a non-empty string).`);
	}
	return v;
}

function optionalInt(v: unknown): number | undefined {
	if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
	return undefined;
}

function numberLines(lines: string[], startNo: number): string {
	const lastNo = startNo + lines.length - 1;
	const width = String(lastNo).length;
	return lines.map((l, i) => `${String(startNo + i).padStart(width)}\t${l}`).join("\n");
}

function isBinary(buf: Buffer): boolean {
	const n = Math.min(buf.length, 8000);
	for (let i = 0; i < n; i++) {
		if (buf[i] === 0) return true;
	}
	return false;
}

function errMsg(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

interface CaptureResult {
	stdout: string;
	stderr: string;
	code: number | null;
	errno: string | null;
}

/** Internal execFile (rg/find) with augmented PATH; never throws. */
function execCapture(
	bin: string,
	args: string[],
	opts: { cwd: string; timeoutMs: number; maxBytes: number },
): Promise<CaptureResult> {
	return new Promise((resolveP) => {
		execFile(
			bin,
			args,
			{
				cwd: opts.cwd,
				timeout: opts.timeoutMs,
				maxBuffer: Math.max(opts.maxBytes * 4, 1024 * 1024),
				shell: false,
				windowsHide: true,
				env: { ...process.env, PATH: EXEC_PATH },
			},
			(err, stdout, stderr) => {
				const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
				const errno = e && typeof e.code === "string" ? e.code : null;
				const code =
					e && typeof e.code === "number" ? e.code : err ? 2 : 0;
				const clip = (s: string) => (s.length > opts.maxBytes ? s.slice(0, opts.maxBytes) : s);
				resolveP({
					stdout: clip(stdout ?? ""),
					stderr: clip(stderr ?? ""),
					code,
					errno,
				});
			},
		);
	});
}
