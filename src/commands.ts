/**
 * run_command safety: parse → whitelist → exec without a shell.
 *
 * First principles for "read-only": a command is safe only if it cannot
 * mutate state or run arbitrary code. So:
 *   - No shell. We tokenize ourselves and execFile the binary directly, so
 *     there is no `;`, `&&`, `|`, `$(...)`, backtick, or redirection to
 *     smuggle a second command through.
 *   - Any operator token from the parse → reject outright.
 *   - The binary must be a bare name (no "/") on a fixed read-only allowlist.
 *   - `git` is special-cased: only read-only subcommands, and `-c` (inline
 *     config → pager/alias RCE) is rejected.
 *   - python -c / node -e / perl -e etc. are NOT on the list: they are
 *     arbitrary code execution and would defeat read-only. Opt in via
 *     config.extra_read_binaries or bypass mode if you accept the risk.
 *
 * In bypass mode the whitelist is skipped, but we STILL run without a shell
 * and reject operator tokens — the user asked for unrestricted *commands*,
 * not shell injection. (A real shell pipeline → use a local terminal.)
 */

import { execFile } from "node:child_process";
import { parse as shellParse } from "shell-quote";
import type { TerminalMode } from "./config";

/**
 * Binaries allowed by run_command in read-only / read-write mode.
 *
 * Deliberately excludes:
 *  - File-CONTENT readers (cat/head/tail/nl/grep/sort/uniq/cut/md5/shasum,
 *    and `file` — its -f/--files-from echoes file lines): they dump arbitrary
 *    file contents, which belongs to read_file/search_files (those enforce the
 *    path blocklist + read-root containment). Letting them through run_command
 *    would bypass that layer. git's content subcommands (show/diff/blame/
 *    cat-file) are excluded for the same reason — see GIT_READONLY_SUBCOMMANDS.
 *  - Subprocess/codepath-spawning binaries (find -exec, rg --pre): these are
 *    arbitrary code execution / filesystem mutation in "read-only" mode.
 *  - Anything that can write (find -delete, etc.).
 *
 * What remains is diagnostics that surface metadata, not file bodies. Path
 * arguments are still scanned against the blocklist in handler.runCommandTool.
 */
export const READ_ONLY_BINARIES = new Set<string>([
	"git", // guarded: read-only subcommands only, dangerous flags rejected
	"ls",
	"stat",
	"wc",
	"du",
	"df",
	"uptime",
	"uname",
	"sw_vers",
	"which",
	"echo",
	"pwd",
	"date",
	"whoami",
	"hostname",
	"sysctl",
	"vm_stat",
]);

/**
 * Read-only, METADATA-ONLY git subcommands. Everything else is refused.
 *
 * Deliberately EXCLUDES:
 *  - mutating forms (branch -D, tag -d, remote add, reflog expire) — whole
 *    subcommands dropped rather than flag-vetting their read forms.
 *  - file-CONTENT emitters (show, diff, blame, cat-file, whatchanged): these
 *    dump committed file bodies — including credential files read_file
 *    refuses — bypassing the read_file/search_files blocklist + containment.
 *    Route file content through those tools. `log` stays (commit metadata),
 *    but its patch flags (-p/-u/-L/--patch/--unified) are rejected below.
 */
export const GIT_READONLY_SUBCOMMANDS = new Set<string>([
	"log",
	"status",
	"describe",
	"rev-parse",
	"rev-list",
	"ls-files",
	"ls-tree",
	"show-ref",
	"shortlog",
	"count-objects",
	"name-rev",
	"merge-base",
]);

/**
 * `git log` can be turned into a file-content dump by a LONG and growing list
 * of diff-implying flags (-p, --patch, -U, -L, --cc, --remerge-diff, -m,
 * --diff-merges, -W, --function-context, --raw, …) — denylisting them is
 * whack-a-mole. So for `log` we ALLOWLIST known-safe metadata/formatting flags
 * and reject everything else. (`-S`/`-G` pickaxe is blocked globally below as
 * a content-existence oracle.)
 */
const SAFE_GIT_LOG_FLAG_EXACT = new Set<string>([
	"--oneline",
	"--graph",
	"--no-graph",
	"--decorate",
	"--no-decorate",
	"--abbrev-commit",
	"--no-abbrev-commit",
	"--name-only",
	"--name-status",
	"--stat",
	"--shortstat",
	"--numstat",
	"--summary",
	"--all",
	"--branches",
	"--tags",
	"--remotes",
	"--first-parent",
	"--no-merges",
	"--merges",
	"--reverse",
	"--topo-order",
	"--date-order",
	"--author-date-order",
	"--no-color",
	"--relative-date",
	"--children",
	"--left-right",
	"--all-match",
	"--invert-grep",
	"--regexp-ignore-case",
	"--extended-regexp",
	"--fixed-strings",
	"--basic-regexp",
	"--perl-regexp",
	"--no-pager",
	"--pretty",
	"--format",
	"--root",
	"--source",
	"--no-patch",
	"-n",
	"-i",
]);

const SAFE_GIT_LOG_FLAG_PREFIXES = [
	"--format=",
	"--pretty=",
	"--abbrev=",
	"--decorate=",
	"--date=",
	"--since=",
	"--until=",
	"--after=",
	"--before=",
	"--author=",
	"--committer=",
	"--grep=",
	"--max-count=",
	"--skip=",
	"--color=",
	"--branches=",
	"--tags=",
	"--remotes=",
	"--min-parents=",
	"--max-parents=",
	"--encoding=",
];

function isSafeGitLogArg(a: string): boolean {
	if (!a.startsWith("-")) return true; // ref / pathspec — vetted elsewhere
	if (a === "--") return true;
	if (/^-\d+$/.test(a)) return true; // -5 (count shorthand)
	if (SAFE_GIT_LOG_FLAG_EXACT.has(a)) return true;
	return SAFE_GIT_LOG_FLAG_PREFIXES.some((p) => a.startsWith(p));
}

/** Pickaxe flags — content-existence oracle (does string/regex appear in any
 *  historical diff). Rejected on every git invocation. */
function isGitPickaxe(a: string): boolean {
	return a.startsWith("-S") || a.startsWith("-G") || a.startsWith("--pickaxe");
}

export interface ParsedCommand {
	bin: string;
	args: string[];
}

export type CommandCheck =
	| { ok: true; parsed: ParsedCommand }
	| { ok: false; reason: string };

/**
 * Tokenize and validate a command string for the given mode. Returns the
 * argv to execFile, or a rejection reason.
 */
export function checkCommand(
	command: string,
	mode: TerminalMode,
	extraBinaries: ReadonlySet<string> = new Set(),
): CommandCheck {
	// Belt-and-suspenders: reject command substitution / variable expansion
	// up front. We run shell-free (execFile, no shell) so these never fire,
	// but shell-quote treats backticks as a literal word — rejecting the raw
	// syntax keeps the command obviously safe and future-proofs against ever
	// flipping to shell:true. Quoted regex alternation (rg 'a|b') is untouched
	// because it uses "|", not these.
	if (command.includes("`") || command.includes("$(") || command.includes("${")) {
		return {
			ok: false,
			reason: "command substitution / variable expansion (backticks, $(...), ${...}) is not allowed.",
		};
	}

	const tokens = shellParse(command);

	// shell-quote yields a string for a plain word and an object for any
	// operator/comment/glob-op. Any non-string token means shell syntax we
	// refuse to honor.
	const words: string[] = [];
	for (const t of tokens) {
		if (typeof t === "string") {
			words.push(t);
		} else {
			return {
				ok: false,
				reason:
					"shell operators, pipes, redirection, globs and substitutions are not allowed — run a single bare command.",
			};
		}
	}

	if (words.length === 0) return { ok: false, reason: "empty command" };

	const bin = words[0];
	const args = words.slice(1);

	if (bin.includes("/")) {
		return { ok: false, reason: `binary must be a bare name on the whitelist, not a path: "${bin}"` };
	}

	if (mode === "bypass") {
		return { ok: true, parsed: { bin, args } };
	}

	const allowed = READ_ONLY_BINARIES.has(bin) || extraBinaries.has(bin);
	if (!allowed) {
		return {
			ok: false,
			reason: `command "${bin}" is not allowed in ${mode} mode. Allowed read-only binaries: ${[...READ_ONLY_BINARIES].sort().join(", ")}. Use switch_mode("bypass") with the confirmation code to lift this.`,
		};
	}

	if (bin === "git") {
		// Reject flags that turn a read subcommand into code execution or a
		// file writer/reader:
		//   -c / --config / --config-env  → inline config → pager/alias RCE,
		//                                    core.fsmonitor/sshCommand exec
		//   --exec-path                    → hijack helper dispatch dir
		//   --output / -o / -O             → write output to an arbitrary file
		//   --upload-pack / --receive-pack → run an arbitrary remote helper
		//   --no-index                     → diff (read) two arbitrary files
		for (const a of args) {
			if (
				a === "-c" ||
				a.startsWith("-c") ||
				a.startsWith("--config") ||
				a.startsWith("--exec-path") ||
				a === "--output" ||
				a.startsWith("--output") ||
				a === "-o" ||
				a === "-O" ||
				a.startsWith("--upload-pack") ||
				a.startsWith("--receive-pack") ||
				a === "--no-index" ||
				isGitPickaxe(a)
			) {
				return {
					ok: false,
					reason: `git flag "${a}" is not allowed (it can execute code, write files, or read/oracle arbitrary content). Use read_file/search_files for file access.`,
				};
			}
		}
		const sub = args.find((a) => !a.startsWith("-"));
		if (!sub || !GIT_READONLY_SUBCOMMANDS.has(sub)) {
			return {
				ok: false,
				reason: `git subcommand "${sub ?? "(none)"}" is not a read-only, metadata-only operation. Allowed: ${[...GIT_READONLY_SUBCOMMANDS].sort().join(", ")}. For file contents use read_file/search_files.`,
			};
		}
		// `log` can emit patches via a long, growing set of diff-implying flags;
		// allowlist safe metadata flags instead of chasing each dangerous one.
		if (sub === "log") {
			for (const a of args) {
				if (!isSafeGitLogArg(a)) {
					return {
						ok: false,
						reason: `git log flag "${a}" is not on the safe metadata allowlist (it may emit file content). For history use --oneline/--stat/--name-only/--format; for file contents use read_file/search_files.`,
					};
				}
			}
		}
		// `git status -v/-vv/--verbose` prints the staged (and unstaged) DIFF,
		// i.e. file content — refuse it.
		if (sub === "status") {
			for (const a of args) {
				if (a === "--verbose" || /^-v+$/.test(a)) {
					return {
						ok: false,
						reason: `git status flag "${a}" prints file diffs (content). Use --short/--porcelain for status; read_file/search_files for content.`,
					};
				}
			}
		}
	}

	return { ok: true, parsed: { bin, args } };
}

export interface RunResult {
	stdout: string;
	stderr: string;
	code: number | null;
	truncated: boolean;
}

/**
 * Execute a validated command with no shell, a wall-clock timeout, and an
 * output cap. Never throws for non-zero exits — they come back as `code`.
 */
export function runCommand(
	parsed: ParsedCommand,
	opts: { cwd: string; timeoutMs: number; maxBytes: number },
): Promise<RunResult> {
	return new Promise((resolve) => {
		execFile(
			parsed.bin,
			parsed.args,
			{
				cwd: opts.cwd,
				timeout: opts.timeoutMs,
				maxBuffer: Math.max(opts.maxBytes * 4, 1024 * 1024),
				shell: false,
				windowsHide: true,
				env: {
					...process.env,
					// Neutralize git's pager and any prompt so output is plain
					// and nothing can block or shell out.
					GIT_PAGER: "cat",
					PAGER: "cat",
					GIT_TERMINAL_PROMPT: "0",
					GIT_OPTIONAL_LOCKS: "0",
				},
			},
			(err, stdout, stderr) => {
				const cap = (s: string): { text: string; truncated: boolean } => {
					if (s.length <= opts.maxBytes) return { text: s, truncated: false };
					return { text: s.slice(0, opts.maxBytes), truncated: true };
				};
				const out = cap(stdout ?? "");
				const errOut = cap(stderr ?? "");
				const code =
					err && typeof (err as NodeJS.ErrnoException & { code?: number }).code === "number"
						? ((err as unknown as { code: number }).code ?? null)
						: err
							? 1
							: 0;
				resolve({
					stdout: out.text,
					stderr: errOut.text,
					code,
					truncated: out.truncated || errOut.truncated,
				});
			},
		);
	});
}
