/**
 * Config loading for the terminal agent.
 *
 * Reads ./config.yaml (override with TERMINAL_AGENT_CONFIG), substitutes
 * ${ENV_VAR} references (so the token never has to live in the file),
 * expands "~" in paths, and fills sensible defaults. Fails loudly if the
 * token is empty after substitution — an unauthenticated agent is useless.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";

export type TerminalMode = "read-only" | "read-write" | "bypass";

export interface AgentConfig {
	server: string;
	token: string;
	machine: string;
	mode: TerminalMode;
	default_cwd: string;
	max_output_bytes: number;
	command_timeout_ms: number;
	allowed_read_dirs: string[];
	allowed_write_dirs: string[];
	blocked_paths: string[];
	secret_literals: string[];
	extra_read_binaries: string[];
	notify_on_switch: boolean;
	elevation_timeout_ms: number;
}

const DEFAULTS = {
	server: "wss://mcp.lishuyu.app/mcp/terminal/ws",
	machine: "unknown-machine",
	mode: "read-only" as TerminalMode,
	// "." → the agent's launch dir, a tight default. Never "~": defaulting the
	// read root to the whole home directory would expose ~/.config app tokens,
	// shell history, ~/Library, etc. The shipped config.example.yaml sets an
	// explicit project dir.
	default_cwd: ".",
	max_output_bytes: 8192,
	command_timeout_ms: 20_000,
	allowed_read_dirs: [] as string[], // defaults to [default_cwd] when empty
	allowed_write_dirs: ["~/Codes", "/tmp"],
	blocked_paths: [] as string[],
	secret_literals: [] as string[],
	extra_read_binaries: [] as string[],
	notify_on_switch: true,
	elevation_timeout_ms: 600_000, // read-write/bypass auto-reverts to read-only after 10 min
};

export function expandTilde(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return `${homedir()}/${p.slice(2)}`;
	return p;
}

/** Resolve a path to absolute, expanding "~" first. */
export function resolvePath(p: string, cwd?: string): string {
	const expanded = expandTilde(p);
	return resolve(cwd ?? process.cwd(), expanded);
}

/** Replace ${VAR} with process.env[VAR] (empty string if unset). */
function substituteEnv(value: string): string {
	return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, name) => process.env[name] ?? "");
}

function isMode(v: unknown): v is TerminalMode {
	return v === "read-only" || v === "read-write" || v === "bypass";
}

function asStringArray(v: unknown, fallback: string[]): string[] {
	if (!Array.isArray(v)) return fallback;
	return v.filter((x): x is string => typeof x === "string");
}

export function configPath(): string {
	return process.env.TERMINAL_AGENT_CONFIG ?? resolve(process.cwd(), "config.yaml");
}

export function loadConfig(path: string = configPath()): AgentConfig {
	let raw: Record<string, unknown>;
	try {
		raw = (parseYaml(readFileSync(path, "utf8")) as Record<string, unknown>) ?? {};
	} catch (err) {
		throw new Error(
			`failed to read config at ${path}: ${err instanceof Error ? err.message : String(err)}. Copy config.example.yaml to config.yaml.`,
		);
	}

	const token = substituteEnv(typeof raw.token === "string" ? raw.token : "").trim();
	if (!token) {
		throw new Error(
			"config token is empty. Set `token: ${TERMINAL_AGENT_TOKEN}` in config.yaml and export TERMINAL_AGENT_TOKEN (must equal the Worker's TERMINAL_TOKEN secret).",
		);
	}

	const server = typeof raw.server === "string" && raw.server ? raw.server : DEFAULTS.server;
	if (!/^wss?:\/\//.test(server)) {
		throw new Error(`config server must be a ws:// or wss:// URL, got: ${server}`);
	}

	const mode = isMode(raw.mode) ? raw.mode : DEFAULTS.mode;
	const default_cwd = resolvePath(
		typeof raw.default_cwd === "string" && raw.default_cwd ? raw.default_cwd : DEFAULTS.default_cwd,
	);
	const allowed_write_dirs = asStringArray(raw.allowed_write_dirs, DEFAULTS.allowed_write_dirs).map(
		(d) => resolvePath(d),
	);
	// Reads are confined to these roots (realpath-checked at use). Empty →
	// default to just the working directory: a deliberately tight default so
	// the read surface is an allowlist of project dirs, not the whole disk.
	const readDirsRaw = asStringArray(raw.allowed_read_dirs, DEFAULTS.allowed_read_dirs);
	const allowed_read_dirs = (readDirsRaw.length > 0 ? readDirsRaw.map((d) => resolvePath(d)) : [
		default_cwd,
	]);
	// Loud warning if a read root is dangerously wide — the whole home dir or
	// the filesystem root expose far more than a project tree.
	const home = homedir();
	for (const dir of allowed_read_dirs) {
		if (dir === home || dir === "/") {
			console.warn(
				`[config] WARNING: allowed_read_dirs includes "${dir}" — the agent can read almost everything under it. Set default_cwd / allowed_read_dirs to a specific project directory.`,
			);
		}
	}

	return {
		server,
		token,
		machine:
			typeof raw.machine === "string" && raw.machine ? raw.machine.slice(0, 64) : DEFAULTS.machine,
		mode,
		default_cwd,
		max_output_bytes:
			typeof raw.max_output_bytes === "number" && raw.max_output_bytes > 0
				? Math.min(raw.max_output_bytes, 1_000_000)
				: DEFAULTS.max_output_bytes,
		command_timeout_ms:
			typeof raw.command_timeout_ms === "number" && raw.command_timeout_ms > 0
				? Math.min(raw.command_timeout_ms, 120_000)
				: DEFAULTS.command_timeout_ms,
		allowed_read_dirs,
		allowed_write_dirs,
		blocked_paths: asStringArray(raw.blocked_paths, DEFAULTS.blocked_paths),
		secret_literals: asStringArray(raw.secret_literals, DEFAULTS.secret_literals),
		extra_read_binaries: asStringArray(raw.extra_read_binaries, DEFAULTS.extra_read_binaries),
		notify_on_switch:
			typeof raw.notify_on_switch === "boolean" ? raw.notify_on_switch : DEFAULTS.notify_on_switch,
		elevation_timeout_ms:
			typeof raw.elevation_timeout_ms === "number" && raw.elevation_timeout_ms >= 0
				? Math.min(raw.elevation_timeout_ms, 24 * 3600 * 1000)
				: DEFAULTS.elevation_timeout_ms,
	};
}
