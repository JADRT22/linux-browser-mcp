"""MCP server (host). Stdlib only. Spawns the driver container on demand.

Registration:
  claude mcp add linux-browser -- python -I -u /path/to/linux-browser-mcp/server.py
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER_DIR = os.path.join(HERE, "driver")
IMAGE = "linux-browser-mcp-driver:1.49.0"
STATE_DIR = os.path.expanduser("~/.local/state/linux-browser-mcp")
AUDIT_LOG = os.path.join(STATE_DIR, "audit.jsonl")

TOOLS = ["browser_navigate", "browser_snapshot", "browser_screenshot",
         "browser_click", "browser_type", "browser_key", "browser_close"]

TOOL_INPUTS = {
    "browser_navigate": {"url": {"type": "string"}, "timeout_ms": {"type": "integer"}},
    "browser_snapshot": {},
    "browser_screenshot": {},
    "browser_click": {"target": {"type": "string"}, "timeout_ms": {"type": "integer"}},
    "browser_type": {"target": {"type": "string"}, "text": {"type": "string"},
                     "timeout_ms": {"type": "integer"}},
    "browser_key": {"key": {"type": "string"}},
    "browser_close": {},
}

TOOL_REQUIRED = {
    "browser_navigate": ["url"],
    "browser_click": ["target"],
    "browser_type": ["target", "text"],
    "browser_key": ["key"],
}

TO_CMD = {
    "browser_navigate": "goto",
    "browser_snapshot": "snapshot",
    "browser_screenshot": "screenshot",
    "browser_click": "click",
    "browser_type": "fill",
    "browser_key": "press",
    "browser_close": "close",
}

DEFAULT_TIMEOUT_S = 60.0

_SALT = secrets.token_hex(16)
_proc = None
_req_id = 0
_launch_log = os.path.join(STATE_DIR, "driver-stderr.log")


_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>]+")


def _redact_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme in ("http", "https") and (parts.query or "@" in parts.netloc):
            netloc = parts.netloc
            if "@" in netloc:
                netloc = netloc.rpartition("@")[2]
            safe = parts._replace(netloc=netloc,
                                  query="redacted" if parts.query else "",
                                  fragment="")
            return urllib.parse.urlunsplit(safe)
    except Exception:
        pass
    return url[:200]


def _redact(value) -> str:
    if not isinstance(value, str):
        return "<non-string>"
    redacted = _URL_IN_TEXT.sub(lambda m: _redact_url(m.group(0)), value)
    return redacted[:300]


def audit_entry(tool: str, params: dict, ok: bool = True,
                salt: str = _SALT, err: str | None = None) -> dict:
    entry = {"ts": time.time(), "tool": tool, "ok": ok}
    if isinstance(params, dict):
        if "url" in params:
            entry["url"] = _redact(params.get("url"))
        if "target" in params:
            entry["target"] = str(params.get("target"))[:120]
        if "key" in params:
            entry["key"] = str(params.get("key"))[:40]
        if "text" in params:
            text = params.get("text") or ""
            entry["text_len"] = len(text)
            entry["text_sha"] = hashlib.sha256((salt + text).encode()).hexdigest()[:16]
    if err is not None:
        entry["err"] = _redact(str(err))[:300]
    return entry


def append_audit(entry: dict) -> None:
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd = os.open(AUDIT_LOG, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (json.dumps(entry) + "\n").encode())
    finally:
        os.close(fd)


def _log_stderr(text: str) -> None:
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        fd = os.open(_launch_log, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, text[-4000:].encode(errors="replace"))
        finally:
            os.close(fd)
    except OSError:
        pass


def _reap() -> None:
    global _proc
    if _proc is None:
        return
    try:
        _proc.wait(timeout=5)
    except Exception:
        try:
            _proc.kill()
        except Exception:
            pass
        try:
            _proc.wait(timeout=5)
        except Exception:
            pass
    for stream in (_proc.stdin, _proc.stdout, getattr(_proc, "stderr", None)):
        try:
            if stream is not None:
                stream.close()
        except Exception:
            pass
    _proc = None


def _spawn():
    global _proc
    _reap()
    log_fd = os.open(_launch_log, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    _proc = subprocess.Popen(
        ["docker", "run", "--rm", "-i",
         "--user", "pwuser",
         "--cap-drop=ALL",
         "--security-opt=no-new-privileges:true",
         "--pids-limit=256",
         "--shm-size=256m",
         "-m", "512m", "--cpus=1", "--pull=missing",
         "-v", DRIVER_DIR + ":/driver:ro",
         IMAGE, "python", "-u", "/driver/driver.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=log_fd, text=True, bufsize=1,
    )
    return _proc


def _dead():
    return _proc is None or _proc.poll() is not None


def _readline_deadline(stream, deadline: float) -> str:
    chunks = []
    fd = stream.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("container response timed out (partial line)")
            r, _, _ = select.select([stream], [], [], remaining)
            if not r:
                raise RuntimeError("container response timed out (partial line)")
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not data:
                break
            chunks.append(data)
            if b"\n" in data:
                break
        raw = b"".join(chunks).decode(errors="replace")
        line, _, _ = raw.partition("\n")
        return line
    finally:
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
        except OSError:
            pass


def _exchange(payload: dict, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    line = json.dumps(payload) + "\n"
    try:
        _proc.stdin.write(line)
        _proc.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise RuntimeError(f"container stdin broken: {exc}")
    out = _readline_deadline(_proc.stdout, deadline)
    if not out:
        raise RuntimeError("container died (EOF on stdout); see driver-stderr.log")
    return json.loads(out)


def _validated_params(name: str, args: dict) -> dict:
    declared = TOOL_INPUTS.get(name, {})
    unknown = [k for k in args if k not in declared]
    if unknown:
        raise ValueError(f"unexpected params: {', '.join(sorted(unknown))}")
    missing = [k for k in TOOL_REQUIRED.get(name, []) if k not in args]
    if missing:
        raise ValueError(f"missing params: {', '.join(missing)}")
    params = {}
    for key, spec in declared.items():
        if key not in args:
            continue
        value = args[key]
        want = spec.get("type")
        if want == "string" and not isinstance(value, str):
            raise ValueError(f"param {key!r} must be a string")
        if want == "integer":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"param {key!r} must be an integer")
            value = max(1000, min(60000, value))
        params[key] = value
    return params


def call_driver(cmd: str, params: dict, timeout_s: float = DEFAULT_TIMEOUT_S) -> dict:
    global _req_id
    payload = {"id": 0, "cmd": cmd, "params": params}
    last_error = "container unavailable"
    for _ in range(2):
        if _dead():
            try:
                _spawn()
            except Exception as exc:
                last_error = f"container failed to start: {exc}"
                break
        _req_id += 1
        payload["id"] = _req_id
        try:
            resp = _exchange(payload, timeout_s)
        except RuntimeError as exc:
            last_error = str(exc)
            _log_stderr(f"\n[{time.time():.0f}] exchange failed: {exc}\n")
            _reap()
            continue
        if not resp.get("ok"):
            raise RuntimeError(str(resp.get("error", "unknown driver error")))
        return resp.get("result", {})
    raise RuntimeError(last_error)


def _rpc_result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _rpc_error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle_request(req: dict):
    method = req.get("method", "")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return _rpc_result(rid, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "linux-browser-mcp", "version": "0.2.0"},
        })
    if method == "ping":
        return _rpc_result(rid, {})
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        tools = []
        for t in TOOLS:
            schema = {"type": "object",
                      "properties": dict(TOOL_INPUTS[t]),
                      "additionalProperties": False}
            if t in TOOL_REQUIRED:
                schema["required"] = list(TOOL_REQUIRED[t])
            tools.append({"name": t, "description": t, "inputSchema": schema})
        return _rpc_result(rid, {"tools": tools})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        if name not in TO_CMD:
            return _rpc_error(rid, -32602, f"unknown tool: {name}")
        try:
            clean = _validated_params(name, args)
            result = call_driver(TO_CMD[name], clean)
            append_audit(audit_entry(name, clean, ok=True))
            if name == "browser_screenshot":
                content = [{"type": "image", "data": result["png_base64"],
                            "mimeType": "image/png"}]
            else:
                content = [{"type": "text", "text": json.dumps(result)}]
            return _rpc_result(rid, {"content": content})
        except Exception as exc:
            append_audit(audit_entry(name, args, ok=False, err=str(exc)))
            return _rpc_result(rid, {"content": [{"type": "text",
                "text": f"error: {exc}"}], "isError": True})
    if rid is not None:
        return _rpc_error(rid, -32601, f"method not found: {method}")
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        if isinstance(req, list):
            sys.stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32600,
                           "message": "batch requests not supported"}}) + "\n")
            sys.stdout.flush()
            continue
        if "method" not in req:
            sys.stdout.write(json.dumps(
                _rpc_error(req.get("id"), -32600, "invalid request: no method")) + "\n")
            sys.stdout.flush()
            continue
        try:
            resp = handle_request(req)
        except Exception as exc:
            resp = _rpc_error(req.get("id"), -32603, str(exc))
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
