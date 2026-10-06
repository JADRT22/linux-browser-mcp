import importlib.util
import json

_SERVER = "/home/fernando/linux-browser-mcp/server.py"


def _load():
    spec = importlib.util.spec_from_file_location("lbm_server", _SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_server_tools_list_names():
    s = _load()
    assert s.TOOLS == ["browser_navigate", "browser_snapshot", "browser_screenshot",
                       "browser_click", "browser_type", "browser_key", "browser_close"]


def test_server_redacts_typed_text():
    s = _load()
    entry = s.audit_entry("browser_type", {"text": "s3cr3t"}, ok=True, salt="abc")
    assert "s3cr3t" not in json.dumps(entry)
    assert entry["text_len"] == 6


def test_server_redacts_url_query():
    s = _load()
    entry = s.audit_entry("browser_navigate",
                          {"url": "https://x.example/?token=topsecret"}, ok=False,
                          err="blocked url: 'https://x.example/?token=topsecret'")
    blob = json.dumps(entry)
    assert "topsecret" not in blob
    assert entry["url"].startswith("https://x.example/")


def test_server_logs_url_target():
    s = _load()
    entry = s.audit_entry("browser_click", {"target": "s1-e2"}, ok=True)
    assert entry["target"] == "s1-e2"


def test_server_rejects_unknown_method_with_id():
    s = _load()
    resp = s.handle_request({"jsonrpc": "2.0", "id": 9,
                             "method": "prompts/list", "params": {}})
    assert resp["error"]["code"] == -32601


def test_server_validates_params():
    s = _load()
    try:
        s._validated_params("browser_navigate", {})
    except ValueError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    try:
        s._validated_params("browser_navigate",
                            {"url": "https://example.com", "nope": 1})
    except ValueError as exc:
        assert "unexpected" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    clean = s._validated_params("browser_navigate",
                               {"url": "https://example.com",
                                "timeout_ms": 999999})
    assert clean["timeout_ms"] == 60000
