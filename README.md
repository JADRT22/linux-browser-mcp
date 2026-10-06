# linux-browser-mcp

An MCP server that gives an AI agent a **headless Chromium inside a hardened Docker container** — web navigation, DOM snapshots, screenshots, clicks, and form filling — without touching your real desktop.

## Why this exists

Giving an agent your keyboard, mouse, and screen is the most useful thing you can hand it, and the least reversible. Most desktop-automation MCP servers grab all of that at once, with no way to say *that, but not that*.

This project takes a different route: instead of driving your desktop, the agent drives a **disposable browser that lives in a container**. Your screen, your files, and your running apps are never in scope. If the browser gets compromised by a malicious page, the blast radius ends at a `cap-drop`'d, memory-capped container that vanishes with `--rm`.

## How it works

```
Claude Code / any MCP client
        │  stdio (JSON-RPC)
        ▼
   server.py  (host, stdlib only)
        │  stdin/stdout JSON-lines
        ▼  docker run --rm -i (lazy spawn)
   driver.py  (container, Playwright + Chromium headless)
```

- **Host (`server.py`)** — pure standard library, zero dependencies. Speaks MCP over stdio, spawns the container lazily on the first tool call, and proxies each call as one JSON line. Every call lands in an append-only audit log with typed-text redaction.
- **Driver (`driver.py`)** — runs inside the container. Owns one persistent Playwright page (Chromium headless, 1280×720). Handles navigation, DOM snapshots, screenshots, clicks, fills, and key presses.

## Security model

Layers, from outside in:

1. **No desktop access.** There is no X11 socket, no Wayland socket, no host bind-mount except the driver directory (read-only). The agent cannot see or touch your machine.
2. **Hardened container.** The browser runs as non-root `pwuser` with `--cap-drop=ALL` (zero added capabilities), `--security-opt=no-new-privileges:true`, `--pids-limit=256`, `--shm-size=256m`, `-m 512m`, `--cpus=1`.
3. **Chromium sandbox: off, and here is why.** Chromium's sandbox needs unprivileged user namespaces, which kernels with AppArmor userns restrictions (Ubuntu 23.10+, CachyOS, and this project's dev machine) deny outright — launch fails as root *and* as non-root. So this project makes the documented trade: sandbox off (= Playwright's own default), containment from the container boundary instead. The in-page SSRF route guard and the URL gate still apply. If your kernel allows userns, flip `chromium_sandbox` to `True` in `driver.py` — one line.
4. **SSRF gate, fail-closed.** `is_blocked_url()` checks scheme, strips trailing dots, blocks `localhost` and special-use TLDs, rejects ambiguous numeric forms Chromium would parse as loopback (`0x7f.0.0.1`, `2130706433`, `127.1`), **resolves DNS and validates every returned IP is globally routable**, and re-checks the final URL after redirects. Unresolvable hosts block. Requests inside pages are additionally filtered by a route guard.
5. **Secret hygiene.** Snapshot element names never include input values (no `e.value` fallback) — a prefilled password field shows up as an empty name. Typed text is stored in the audit log as length + salted SHA-256 prefix only. Query strings and embedded credentials are redacted from URLs in both the audit log and error messages.
6. **Stale-ref protection.** Snapshot element refs carry a generation (`s3-e5`). Clicking a ref from an older snapshot is refused instead of landing on whatever element now sits at that index.
7. **Bounded everything.** Host↔driver reads use absolute deadlines (no `select`-then-`readline` hang). Every timeout is clamped to 1–60 s. Ambiguous selectors (0 or 2+ matches) refuse instead of guessing.

**Honest limits:** DNS resolution happens inside the container, so a DNS-rebinding race between gate check and page load is theoretically possible — the in-page route guard narrows that window but does not close it. Audit-log integrity is append-only against accidents, not against a malicious writer with your UID. If you need proof against that, ship the log off-machine.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `browser_navigate` | `url` (required), `timeout_ms` | `{url, title}` |
| `browser_snapshot` | — | `{url, title, snapshot_id, elements: [{ref, role, name, inputType?}]}` |
| `browser_screenshot` | — | PNG as MCP `image` content (viewport only) |
| `browser_click` | `target` (required), `timeout_ms` | `{clicked}` |
| `browser_type` | `target`, `text` (required), `timeout_ms` | `{filled, text_len}` |
| `browser_key` | `key` (required) | `{pressed}` |
| `browser_close` | — | `{closed}` |

`target` accepts a snapshot ref (`s3-e5`) or any CSS selector. Refs expire on the next snapshot.

## Prerequisites

- Docker (any recent version; tested with 29.x)
- Python 3.10+ on the host (standard library only — no `pip install` needed)
- ~2 GB disk for the driver image (one-time pull + build)
- ~512 MB RAM + 1 CPU while the browser is running

Build the driver image once:

```bash
docker build -t linux-browser-mcp-driver:1.49.0 driver/
```

## Installation

Claude Code:

```bash
claude mcp add linux-browser -- python -I -u /path/to/linux-browser-mcp/server.py
```

Manual `mcp.json` (Cursor, VS Code, Windsurf — see `mcp.json.example`):

```json
{
  "mcpServers": {
    "linux-browser": {
      "command": "python",
      "args": ["-I", "-u", "/path/to/linux-browser-mcp/server.py"]
    }
  }
}
```

## Usage example

```
→ browser_navigate {"url": "https://example.com"}
← {"url": "https://example.com/", "title": "Example Domain"}

→ browser_snapshot {}
← {"snapshot_id": 1, "elements": [{"ref": "s1-e0", "role": "a", "name": "Learn more"}]}

→ browser_click {"target": "s1-e0"}
← {"clicked": "s1-e0"}

→ browser_screenshot {}
← [PNG image]
```

## Testing

```bash
pytest tests/ -m "not slow"   # unit tests, no Docker needed
pytest tests/test_e2e.py      # end-to-end inside a real container
```

## Project layout

```
server.py            MCP stdio server (host, stdlib only)
driver/
  driver.py          Playwright driver (container)
  Dockerfile         hardened image (non-root user, pinned playwright)
tests/
  test_driver.py     URL gate, timeout clamp, stale-ref unit tests
  test_server.py     audit redaction, param validation, JSON-RPC errors
  test_e2e.py        live container round-trip (marked slow)
mcp.json.example     manual client config
```

## License

MIT — see [LICENSE](LICENSE).
