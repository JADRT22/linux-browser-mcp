"""Driver that runs INSIDE the container.

Protocol: JSON-lines on stdin/stdout. One call per line:
  {"id": 1, "cmd": "goto", "params": {"url": "..."}}
Response:
  {"id": 1, "ok": true, "result": {...}}
  {"id": 1, "ok": false, "error": "..."}

Playwright is imported lazily inside _ensure_page() so pure helpers
(is_blocked_url, _clamp_timeout_ms) work without that dependency.
"""

import base64
import ipaddress
import json
import re
import socket
import sys
from urllib.parse import urlparse

_pw = None
_browser = None
_context = None
_page = None
_snap_gen = 0

_NUMERICISH = re.compile(r"[0-9A-Fa-fxX:.]+")
_REF = re.compile(r"^s(\d+)-e(\d+)$")
_SPECIAL_SUFFIXES = (
    ".localhost",
    ".test",
    ".example",
    ".invalid",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".localdomain",
    ".corp",
    ".intranet",
)


def _canonical_host(host: str) -> str:
    return (host or "").lower().rstrip(".").strip("[]")


def _ambiguous_numeric(host: str) -> bool:
    if not host or not _NUMERICISH.fullmatch(host):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        # Chromium parses hex/octal/decimal forms that Python rejects.
        return True


def _host_blocked_literal(host: str) -> bool:
    host = _canonical_host(host)
    if not host:
        return True
    if host == "localhost" or host.endswith(_SPECIAL_SUFFIXES):
        return True
    if _ambiguous_numeric(host):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def _resolved_ips(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("dns resolution failed") from exc
    ips = [info[4][0] for info in infos if info and len(info) > 4]
    if not ips:
        raise ValueError("dns resolution failed")
    return ips


def is_blocked_url(url: str) -> bool:
    """Fail closed: unknown, unresolvable, or non-global destinations block."""
    try:
        parts = urlparse(url)
    except Exception:
        return True
    if parts.scheme not in ("http", "https"):
        return True
    host = _canonical_host(parts.hostname or "")
    if _host_blocked_literal(host):
        return True
    try:
        for ip_text in _resolved_ips(host):
            try:
                if not ipaddress.ip_address(ip_text).is_global:
                    return True
            except ValueError:
                return True
    except ValueError:
        return True
    return False


def _clamp_timeout_ms(value, default: int) -> int:
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return default
    return max(1000, min(60000, ms))


def _guard_route(route) -> None:
    try:
        host = _canonical_host(urlparse(route.request.url).hostname or "")
        if _host_blocked_literal(host):
            route.abort()
        else:
            route.continue_()
    except Exception:
        try:
            route.continue_()
        except Exception:
            pass


def _ensure_page():
    global _pw, _browser, _context, _page
    if _page is not None:
        return _page
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    browser = context = page = None
    try:
        # chromium_sandbox=False: kernels that block unprivileged user
        # namespaces (AppArmor userns restrictions, e.g. Ubuntu 23.10+,
        # CachyOS) cannot initialize Chromium's sandbox at all — launch
        # fails with zygote sys_chroot errors as root AND as non-root.
        # Isolation comes from the container instead (non-root user,
        # --cap-drop=ALL, no-new-privileges, pids/mem/cpu limits).
        # On kernels WITH userns allowed, flip this to True.
        browser = pw.chromium.launch(headless=True, chromium_sandbox=False)
        context = browser.new_context(viewport={"width": 1280, "height": 720})
        context.route("**/*", _guard_route)
        page = context.new_page()
    except Exception:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        try:
            pw.stop()
        except Exception:
            pass
        raise
    _pw, _browser, _context, _page = pw, browser, context, page
    return _page


def _snapshot_elements(page):
    global _snap_gen
    _snap_gen += 1
    js = """() => {
      const els = [...document.querySelectorAll(
        'a,button,input,select,textarea,[role=button],[role=link]')];
      const vis = els.filter(e => {
        const r = e.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      }).slice(0, 100);
      return vis.map((e, i) => {
        const name = (e.getAttribute('aria-label') || e.getAttribute('placeholder') ||
                      e.getAttribute('name') || e.getAttribute('title') ||
                      (e.innerText || '')).trim().slice(0, 80);
        const role = e.getAttribute('role') || e.tagName.toLowerCase();
        const out = {role, name};
        if (e.tagName.toLowerCase() === 'input') {
          out.inputType = (e.getAttribute('type') || 'text').slice(0, 20);
        }
        return {i, ...out};
      });
    }"""
    found = page.evaluate(js)
    elements = []
    for item in found:
        ref = f"s{_snap_gen}-e{item['i']}"
        page.evaluate(
            "(args) => { const el = [...document.querySelectorAll("
            "'a,button,input,select,textarea,[role=button],[role=link]')]"
            ".filter(e => { const r = e.getBoundingClientRect();"
            " return r.width > 0 && r.height > 0; })[args[0]];"
            " if (el) el.dataset.mcpRef = args[1]; }",
            [item["i"], ref],
        )
        element = {"ref": ref, "role": item["role"], "name": item["name"]}
        if "inputType" in item:
            element["inputType"] = item["inputType"]
        elements.append(element)
    return {"snapshot_id": _snap_gen, "elements": elements}


def _resolve_locator(page, target):
    match = _REF.fullmatch(target or "")
    if match:
        if int(match.group(1)) != _snap_gen:
            raise ValueError("stale snapshot ref: take a fresh snapshot first")
        return page.locator(f'[data-mcp-ref="{target}"]')
    if not target:
        raise ValueError("empty target")
    return page.locator(target)


def handle(cmd: str, params: dict) -> dict:
    if cmd not in ("close", "goto", "snapshot", "screenshot",
                   "click", "fill", "press"):
        raise ValueError(f"unknown cmd: {cmd!r}")
    if cmd == "close":
        global _pw, _browser, _context, _page
        try:
            if _browser is not None:
                _browser.close()
        finally:
            _page = None
            _context = None
            _browser = None
            if _pw is not None:
                try:
                    _pw.stop()
                except Exception:
                    pass
                _pw = None
        return {"closed": True}

    if cmd == "goto":
        url = params.get("url", "")
        timeout_ms = _clamp_timeout_ms(params.get("timeout_ms"), 30000)
        if is_blocked_url(url):
            raise ValueError("blocked url")
        page = _ensure_page()
        page.goto(url, timeout=timeout_ms)
        if is_blocked_url(page.url):
            try:
                page.goto("about:blank")
            except Exception:
                pass
            raise ValueError("blocked redirect target")
        return {"url": page.url, "title": page.title()}

    page = _ensure_page()

    if cmd == "snapshot":
        snap = _snapshot_elements(page)
        return {"url": page.url, "title": page.title(),
                "snapshot_id": snap["snapshot_id"], "elements": snap["elements"]}

    if cmd == "screenshot":
        png = page.screenshot(full_page=False)
        return {"png_base64": base64.b64encode(png).decode("ascii")}

    if cmd == "click":
        target = params.get("target", "")
        timeout_ms = _clamp_timeout_ms(params.get("timeout_ms"), 30000)
        loc = _resolve_locator(page, target)
        count = loc.count()
        if count != 1:
            raise ValueError(f"selector matched {count} elements, need exactly 1")
        loc.click(timeout=timeout_ms)
        return {"clicked": target}

    if cmd == "fill":
        target = params.get("target", "")
        text = params.get("text", "")
        timeout_ms = _clamp_timeout_ms(params.get("timeout_ms"), 30000)
        loc = _resolve_locator(page, target)
        count = loc.count()
        if count != 1:
            raise ValueError(f"selector matched {count} elements, need exactly 1")
        loc.fill(text, timeout=timeout_ms)
        return {"filled": target, "text_len": len(text)}

    if cmd == "press":
        key = params.get("key", "")
        page.keyboard.press(key)
        return {"pressed": key}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            rid = req.get("id")
            result = handle(req.get("cmd", ""), req.get("params", {}) or {})
            sys.stdout.write(json.dumps({"id": rid, "ok": True, "result": result}) + "\n")
        except Exception as exc:
            try:
                rid = json.loads(line).get("id")
            except Exception:
                rid = None
            sys.stdout.write(json.dumps({"id": rid, "ok": False, "error": str(exc)}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
