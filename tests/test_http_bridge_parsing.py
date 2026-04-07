import pytest

import rust_ext
from client.kemtls_http_client import KEMTLSHttpClient
from kemtls._http_bridge import parse_http_request


def _run_with_python_fallback(monkeypatch, fn, *args):
    original_core = rust_ext._core
    original_flag = rust_ext.HAS_RUST_BACKEND
    monkeypatch.setattr(rust_ext, "_core", None)
    monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", False)
    try:
        return fn(*args)
    finally:
        monkeypatch.setattr(rust_ext, "_core", original_core)
        monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", original_flag)


def test_parse_http_request_headers_and_body():
    raw_request = (
        b"POST /authorize?x=1 HTTP/1.1\r\n"
        b"Host: auth.local\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Test: Value\r\n"
        b"\r\n"
        b'{"grant":"code"}'
    )

    parsed = parse_http_request(raw_request)

    assert parsed["method"] == "POST"
    assert parsed["path"] == "/authorize?x=1"
    assert parsed["version"] == "HTTP/1.1"
    assert parsed["headers"]["host"] == "auth.local"
    assert parsed["headers"]["content-type"] == "application/json"
    assert parsed["headers"]["x-test"] == "Value"
    assert parsed["body"] == b'{"grant":"code"}'


def test_parse_http_request_rejects_malformed_request_line():
    with pytest.raises(ValueError):
        parse_http_request(b"BROKEN\r\nHost: test\r\n\r\n")


def test_parse_http_request_rust_matches_python_fallback(monkeypatch):
    raw_request = (
        b"GET /openid-configuration HTTP/1.1\r\n"
        b"Host: issuer.local\r\n"
        b"Accept: application/json\r\n"
        b"\r\n"
    )

    rust_parsed = parse_http_request(raw_request)
    py_parsed = _run_with_python_fallback(monkeypatch, parse_http_request, raw_request)

    assert rust_parsed == py_parsed


def test_parse_http_response_json_and_text_and_malformed(monkeypatch):
    client = KEMTLSHttpClient(expected_identity="server")

    raw_json = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"status":"ok"}'
    )
    parsed_json = client._parse_response(raw_json)
    assert parsed_json["status"] == 200
    assert parsed_json["status_text"] == "OK"
    assert parsed_json["headers"]["Content-Type"] == "application/json"
    assert parsed_json["body"] == {"status": "ok"}

    raw_text = (
        b"HTTP/1.1 404 Not Found\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"not found"
    )
    parsed_text = client._parse_response(raw_text)
    assert parsed_text["status"] == 404
    assert parsed_text["body"] == "not found"

    with pytest.raises(ValueError):
        client._parse_response(b"HTTP/1.1 BAD\r\n\r\n")

    # parity checks against forced Python fallback
    py_json = _run_with_python_fallback(monkeypatch, client._parse_response, raw_json)
    py_text = _run_with_python_fallback(monkeypatch, client._parse_response, raw_text)

    assert parsed_json == py_json
    assert parsed_text == py_text
