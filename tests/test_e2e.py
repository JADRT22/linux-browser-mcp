import base64
import json
import select
import shutil
import subprocess

import pytest

IMAGE = "linux-browser-mcp-driver:1.49.0"
DRIVER_HOST_DIR = "/home/fernando/linux-browser-mcp/driver"

needs_docker = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker ausente")


def _req(cmd, params=None, rid=1):
    return json.dumps({"id": rid, "cmd": cmd,
                       "params": params or {}}) + "\n"


def _readline(proc, timeout=90):
    r, _, _ = select.select([proc.stdout], [], [], timeout)
    assert r, "driver stdout timed out"
    line = proc.stdout.readline()
    assert line, "driver stdout EOF"
    return json.loads(line)


@needs_docker
@pytest.mark.slow
def test_e2e_navigate_snapshot_screenshot():
    proc = subprocess.Popen(
        ["docker", "run", "--rm", "-i",
         "--user", "pwuser",
         "--cap-drop=ALL",
         "--security-opt=no-new-privileges:true",
         "--pids-limit=256",
         "--shm-size=256m",
         "-m", "512m", "--cpus=1",
         "--pull=missing", "-v", DRIVER_HOST_DIR + ":/driver:ro",
         IMAGE, "python", "-u", "/driver/driver.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, bufsize=1)
    try:
        proc.stdin.write(_req("goto", {"url": "https://example.com"}, 1))
        proc.stdin.flush()
        r1 = _readline(proc)
        assert r1["ok"] is True
        assert "Example" in r1["result"].get("title", "")

        proc.stdin.write(_req("snapshot", {}, 2))
        proc.stdin.flush()
        r2 = _readline(proc)
        assert r2["ok"] is True
        assert isinstance(r2["result"].get("elements"), list)

        proc.stdin.write(_req("screenshot", {}, 3))
        proc.stdin.flush()
        r3 = _readline(proc)
        assert r3["ok"] is True
        raw = base64.b64decode(r3["result"]["png_base64"])
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        try:
            proc.stdin.write(_req("close", {}, 99))
            proc.stdin.flush()
        except Exception:
            pass
        try:
            proc.communicate(timeout=30)
        except Exception:
            proc.kill()
            proc.wait(timeout=30)
