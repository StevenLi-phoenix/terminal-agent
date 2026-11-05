# AS 2026.Nov. This has become offical for anthropic desktop app, thus, no longer maintained.

# terminal-agent

Local daemon for the **terminal MCP bridge**. It connects *outbound* over a
WebSocket to `wss://mcp.lishuyu.app/mcp/terminal/ws`, receives tool calls
that originate in claude.ai (or chatgpt.com), runs them against the local
file system, and returns results — **after sanitizing every byte** so that
no token or credential can ever reach chat history.

```
claude.ai ──(MCP, OAuth)──▶ mcp.lishuyu.app/mcp/terminal
                                   │  TerminalBridge DO
                                   │  WebSocket (this agent dials in, PSK auth)
                                   ▼
                            terminal-agent ──▶ local files
                                   │ ┌────────────────┐
                                   │ │ secret filter  │ ← every output, before it leaves
                                   │ └────────────────┘
```

## The hard rule

Defense in depth, every layer on the machine, before any byte leaves:

1. **Read containment** — `read_file`/`search_files`/`list_directory` are
   confined to `allowed_read_dirs` (default `~/Codes`), checked *after*
   resolving symlinks. Files outside the allowlist (`/etc`, `~/.config`,
   `~/.ssh`, another project) are simply unreadable. This is the primary
   boundary.
2. **Path blocklist** — within the allowed roots, credential files
   (`.env*`, `.ssh/**`, `*.pem`, `*.key`, `*secret*`, `*credential*`,
   `.aws/**`, `.kube/**`, `.pgpass`, …) are still refused (case-insensitive,
   symlink-resolved). Always on, not user-disableable.
3. **`sanitize()`** — content regexes for `sk-…`, `ghp_…`, JWTs, PEM blocks,
   64+ hex, `password: …`, URL credentials, etc. + your `secret_literals`,
   applied to *all* tool output and error messages. Over-redaction (a git
   SHA gets `[REDACTED]`) is preferred to any leak.
4. **Write confinement** — writes are confined to `allowed_write_dirs`,
   realpath-checked, with symlinked leaves/dirs rejected.
5. **No shell + a tight read-only command whitelist** (see below).

## Tools

Read-only (default mode):

| tool | what |
|------|------|
| `terminal_status` | is a machine connected, and in which mode |
| `search_files(pattern, path?, glob?)` | ripgrep, `file:line:match`, ≤50 matches |
| `read_file(path, line_start?, line_end?)` | line-numbered; head+tail for big files; ≤200-line ranges |
| `list_directory(path?, max_depth?)` | tree, excludes node_modules/.git/… |
| `run_command(command)` | single read-only command, **no shell** (no pipes/redirection/substitution). Whitelist is metadata-only: git *metadata* subcommands (log/status/rev-parse/ls-files/…, with patch flags `-p`/`-u`/`-L`/`--patch` and write/exec flags rejected), plus ls, stat, wc, du, df, ps, uptime, uname, … Binaries that read file *contents* (cat/grep/head/`file`/git show/diff/blame/cat-file/`git log -p`) or spawn processes / write files (find/rg/tree) are excluded — use read_file/search_files. Every path arg is blocklist-checked **and** confined to `allowed_read_dirs`. |

Read-write / bypass (opt-in via `switch_mode`):

| tool | what |
|------|------|
| `write_file(path, content, mode?)` | confined to `allowed_write_dirs`; for handing off a HANDOFF.md/spec to local Claude Code |
| `switch_mode(mode, confirmation_code)` | enter read-write/bypass; needs the 6-digit code printed in THIS terminal at startup |

`run_command` deliberately does **not** whitelist `python -c` / `node -e` /
`perl -e`: those are arbitrary code execution and would defeat read-only.
Opt in per-binary via `extra_read_binaries`, or use `bypass` mode, only if
you accept the risk. Even in bypass mode the agent runs shell-free and
rejects pipes/redirection/`$()`/backticks — for a real pipeline, use a real
terminal.

### `switch_mode` is the anti-prompt-injection gate

The agent generates a random 6-digit code on startup. Entering read-write or
bypass is a two-step gate:

1. **Request** — the cloud calls `switch_mode(mode)` *without* a code. The
   agent fires a **macOS notification** (`notify_on_switch: true`) carrying the
   code to your Mac, and tells the cloud "ask the operator for the code."
2. **Confirm** — you read the code off the notification and relay it; the cloud
   calls `switch_mode(mode, confirmation_code)` to apply.

A prompt-injected assistant cannot see your Mac's notifications (or your
terminal), so it cannot self-escalate — you hand it the code only when *you*
want to enable writes. The code rotates on every restart. (Off macOS, or with
`notify_on_switch: false`, the code is read from the startup banner/log.)

**Elevation is temporary.** read-write/bypass auto-reverts to read-only after
`elevation_timeout_ms` (default 10 min; each switch resets the clock), and you
get a notification when it does. A forgotten elevation can't stay open — and a
launchd restart also resets to the configured `mode:` (read-only). Set
`elevation_timeout_ms: 0` to keep it manual.

## Setup

Requires [Bun](https://bun.sh) (recommended) or Node ≥ 20.

```bash
cd ~/Codes/terminal-agent
bun install
cp config.example.yaml config.yaml      # edit machine/cwd/allowed_write_dirs

# The pre-shared token must equal the Worker's TERMINAL_TOKEN secret.
export TERMINAL_AGENT_TOKEN='…'         # put in ~/.zshrc or the launchd plist
bun run src/index.ts
```

On a successful connect you'll see `[ws] connected … registered`. In
claude.ai, add the connector `https://mcp.lishuyu.app/mcp/terminal`, then
call `terminal_status` to confirm the machine is online.

## config.yaml

See `config.example.yaml`. Key fields: `server`, `token` (`${ENV}` is
substituted), `machine`, `mode`, `default_cwd`, `max_output_bytes`,
`command_timeout_ms`, `allowed_write_dirs`, `blocked_paths` (extra globs,
added to the hard floor), `secret_literals`, `extra_read_binaries`.

## Run at login (launchd)

Copy `com.lishuyu.terminal-agent.plist.example` to
`~/Library/LaunchAgents/com.lishuyu.terminal-agent.plist`, fill in the
absolute paths, your token, and the Bun binary path, then:

```bash
launchctl load ~/Library/LaunchAgents/com.lishuyu.terminal-agent.plist
launchctl start com.lishuyu.terminal-agent
# logs → the StandardOut/StandardError paths in the plist
```

The confirmation code is in the agent's StandardOut log; `grep` it there
when you need to `switch_mode`.

## Tests

```bash
bun test          # secret-filter + command-whitelist unit tests
bun run type-check
```
