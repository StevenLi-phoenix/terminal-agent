/**
 * terminal-agent entrypoint.
 *
 * Connects outbound to the bridge WebSocket, registers, and serves tool
 * calls from claude.ai (via the CF Worker). Reconnects with backoff on any
 * drop, and drives an app-level ping the bridge auto-answers so the edge
 * keeps the connection alive without waking the (hibernating) DO.
 *
 * Security posture lives in handler.ts / secret-filter.ts / commands.ts.
 * This file is just transport + lifecycle. Tool output is already
 * sanitized by the handler; we additionally sanitize error messages here
 * before they go on the wire.
 */

import { randomInt } from "node:crypto";
import WebSocket from "ws";
import { TERMINAL_TOKEN_HEADER } from "./constants";
import { loadConfig, type AgentConfig } from "./config";
import { Handler, type ToolParams } from "./handler";

const PING_INTERVAL_MS = 25_000;
const PONG_TIMEOUT_MS = 60_000;
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

interface AgentMessage {
	type: string;
	id?: string;
	tool?: string;
	params?: ToolParams;
	[k: string]: unknown;
}

function main(): void {
	let config: AgentConfig;
	try {
		config = loadConfig();
	} catch (err) {
		console.error(`[config] ${err instanceof Error ? err.message : String(err)}`);
		process.exit(1);
	}

	const confirmationCode = String(randomInt(0, 1_000_000)).padStart(6, "0");
	const handler = new Handler(config, confirmationCode);

	printBanner(config, confirmationCode);

	let backoff = RECONNECT_MIN_MS;
	let stopped = false;

	const connect = (): void => {
		const ws = new WebSocket(config.server, {
			headers: { [TERMINAL_TOKEN_HEADER]: config.token },
			handshakeTimeout: 15_000,
		});

		let lastPong = Date.now();
		let pingTimer: ReturnType<typeof setInterval> | null = null;

		const sendRegister = (): void => {
			send(ws, { type: "register", machine: config.machine, mode: handler.getMode() });
		};
		handler.onModeChange = () => {
			if (ws.readyState === WebSocket.OPEN) sendRegister();
		};

		ws.on("open", () => {
			backoff = RECONNECT_MIN_MS;
			lastPong = Date.now();
			console.log(`[ws] connected to ${config.server} as "${config.machine}" (${handler.getMode()})`);
			sendRegister();
			pingTimer = setInterval(() => {
				if (Date.now() - lastPong > PONG_TIMEOUT_MS) {
					console.warn("[ws] pong timeout — terminating to reconnect");
					ws.terminate();
					return;
				}
				send(ws, { type: "ping" });
			}, PING_INTERVAL_MS);
		});

		ws.on("message", (data: WebSocket.RawData) => {
			let msg: AgentMessage;
			try {
				msg = JSON.parse(data.toString());
			} catch {
				return;
			}
			switch (msg.type) {
				case "call":
					void handleCall(ws, handler, msg);
					return;
				case "pong":
					lastPong = Date.now();
					return;
				case "ping":
					send(ws, { type: "pong" });
					return;
				case "registered":
					lastPong = Date.now();
					console.log(`[ws] registered (mode=${(msg as { mode?: string }).mode ?? "?"})`);
					return;
			}
		});

		const cleanup = (): void => {
			if (pingTimer) clearInterval(pingTimer);
			handler.onModeChange = null;
		};

		ws.on("close", (code: number, reason: Buffer) => {
			cleanup();
			console.warn(`[ws] closed (${code}${reason?.length ? ` ${reason.toString()}` : ""})`);
			scheduleReconnect();
		});

		ws.on("error", (err: Error) => {
			cleanup();
			console.error(`[ws] error: ${err.message}`);
			// 'close' fires after 'error'; reconnect is scheduled there.
		});
	};

	const scheduleReconnect = (): void => {
		if (stopped) return;
		const delay = backoff;
		backoff = Math.min(backoff * 2, RECONNECT_MAX_MS);
		console.log(`[ws] reconnecting in ${Math.round(delay / 1000)}s`);
		setTimeout(connect, delay);
	};

	const shutdown = (): void => {
		stopped = true;
		console.log("\n[agent] shutting down");
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);

	connect();
}

async function handleCall(ws: WebSocket, handler: Handler, msg: AgentMessage): Promise<void> {
	const id = typeof msg.id === "string" ? msg.id : "";
	const tool = typeof msg.tool === "string" ? msg.tool : "";
	const params: ToolParams = (msg.params as ToolParams) ?? {};
	if (!id || !tool) return;

	const label = `${tool}${params.with_system ? " +_system" : ""}`;
	console.log(`[call] ${label}`);
	try {
		const content = await handler.dispatch(tool, params);
		send(ws, { type: "result", id, content });
	} catch (err) {
		// redactError applies the same sanitize + configured secret_literals
		// as the happy path, so a literal embedded in an error never leaks.
		const message = handler.redactError(err instanceof Error ? err.message : String(err));
		console.warn(`[call] ${tool} error: ${message}`);
		send(ws, { type: "error", id, message });
	}
}

function send(ws: WebSocket, obj: Record<string, unknown>): void {
	if (ws.readyState !== WebSocket.OPEN) return;
	try {
		ws.send(JSON.stringify(obj));
	} catch {
		/* socket gone */
	}
}

function printBanner(config: AgentConfig, code: string): void {
	const bar = "─".repeat(54);
	console.log(bar);
	console.log("  terminal-agent");
	console.log(`  machine : ${config.machine}`);
	console.log(`  server  : ${config.server}`);
	console.log(`  mode    : ${config.mode}`);
	console.log(`  cwd     : ${config.default_cwd}`);
	console.log(bar);
	console.log(`  switch_mode confirmation code:  ${code}`);
	console.log("  (give this to the assistant only when YOU want to");
	console.log("   enable read-write / bypass — it cannot self-escalate)");
	console.log(bar);
}

main();
