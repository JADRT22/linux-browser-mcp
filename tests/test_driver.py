import importlib.util

_DRIVER = "/home/fernando/linux-browser-mcp/driver/driver.py"


def _load():
    spec = importlib.util.spec_from_file_location("driver", _DRIVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gate_allows_public():
    d = _load()
    assert d.is_blocked_url("https://example.com/") is False


def test_gate_blocks_schemes():
    d = _load()
    assert d.is_blocked_url("file:///etc/passwd") is True
    assert d.is_blocked_url("ftp://example.com/x") is True


def test_gate_blocks_literal_private():
    d = _load()
    assert d.is_blocked_url("http://127.0.0.1:8080/") is True
    assert d.is_blocked_url("http://10.0.0.1/") is True
    assert d.is_blocked_url("http://169.254.169.254/") is True


def test_gate_blocks_localhost_variants():
    d = _load()
    assert d.is_blocked_url("http://localhost/") is True
    assert d.is_blocked_url("http://localhost./") is True
    assert d.is_blocked_url("http://foo.localhost/") is True


def test_gate_blocks_ambiguous_numeric():
    d = _load()
    assert d.is_blocked_url("http://0x7f.0.0.1/") is True
    assert d.is_blocked_url("http://2130706433/") is True
    assert d.is_blocked_url("http://127.1/") is True


def test_gate_resolves_dns_and_blocks_private():
    d = _load()
    # localhost resolves to loopback on any sane system
    assert d.is_blocked_url("http://localhost/") is True


def test_unknown_cmd():
    d = _load()
    try:
        d.handle("bogus-cmd", {})
    except ValueError as exc:
        assert "unknown cmd" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_clamp_timeout():
    d = _load()
    assert d._clamp_timeout_ms(-5, 30000) == 1000
    assert d._clamp_timeout_ms("abc", 30000) == 30000
    assert d._clamp_timeout_ms(999999, 30000) == 60000
    assert d._clamp_timeout_ms(5000, 30000) == 5000


def test_stale_ref_rejected():
    d = _load()

    class FakeLoc:
        def count(self):
            return 1

    class FakePage:
        def locator(self, sel):
            return FakeLoc()

    d._snap_gen = 7
    try:
        d._resolve_locator(FakePage(), "s3-e0")
    except ValueError as exc:
        assert "stale" in str(exc)
    else:
        raise AssertionError("expected ValueError for stale ref")
    loc = d._resolve_locator(FakePage(), "s7-e0")
    assert loc is not None
