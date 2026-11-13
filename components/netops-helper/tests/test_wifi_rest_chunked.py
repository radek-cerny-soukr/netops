"""FortiOS Wi-Fi REST: chunked framing through the real http.client parser (CVE-2026-103995).

Only TLS and the socket are replaced (a socketpair); http.client, the chunk-size
reader and the JSON/sanitiser path of `wifi_rest.get` are the production code.
Python's own reader accepts `+61` and `6_1` through int(..., 16); wifi_rest must not.
"""
import json
import socket
import threading

import pytest

from netops_helper import engine, wifi_rest as r
from test_wifi_rest import CERT, auth, fixture

PATH = r.MONITOR + "client"
HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"


class _Tls:
    """Stands in for the TLS layer only: certificate bytes plus the raw socket."""

    def __init__(self, raw):
        self._raw = raw

    def do_handshake(self):
        pass

    def getpeercert(self, binary_form=False):
        return CERT

    def __getattr__(self, name):
        return getattr(self._raw, name)


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    r._rates.clear()


@pytest.fixture
def arm(monkeypatch):
    """Serve `wire` to the next connection a production Wi-Fi REST read opens."""
    cleanup = []

    def start(wire):
        left, right = socket.socketpair()

        class Context:
            minimum_version = None

            def wrap_socket(self, sock, **kw):
                return _Tls(sock)

        monkeypatch.setattr(r.ssl, "SSLContext", lambda *a: Context())
        monkeypatch.setattr(r.socket, "create_connection", lambda *a, **k: left)

        def peer():
            try:
                right.recv(65536)
                right.sendall(wire)
            except OSError:
                pass
            finally:
                right.close()

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        cleanup.append((left, thread))

    yield start
    for left, thread in cleanup:
        left.close()
        thread.join(5)
        assert not thread.is_alive()


@pytest.fixture
def serve(arm):
    def call(wire, path=PATH):
        arm(wire)
        return r.get(auth(), path)
    return call


def _document():
    return fixture("monitor_wifi_client")


def _body():
    return json.dumps(_document()).encode()


def _chunks(body, size_field=None, parts=1, upper=False, extension=b"", trailer=b""):
    """Whole-response wire form; `size_field` overrides the first chunk's size text."""
    step = -(-len(body) // parts)
    pieces = [body[i:i + step] for i in range(0, len(body), step)]
    wire = b""
    for index, piece in enumerate(pieces):
        digits = b"%X" % len(piece) if upper else b"%x" % len(piece)
        wire += (size_field if index == 0 and size_field is not None else digits) + (extension if index == 0 else b"") + b"\r\n" + piece + b"\r\n"
    return HEAD + wire + b"0\r\n" + trailer + b"\r\n"


@pytest.mark.parametrize("variant", ["lower", "upper", "extension", "several", "trailer"])
def test_valid_fortios_chunk_framing_passes(serve, variant):
    body = _body()
    wire = _chunks(body, upper=variant == "upper", extension=b";name=value" if variant == "extension" else b"",
                   parts=7 if variant == "several" else 1,
                   trailer=b"X-Checksum: abc\r\n" if variant == "trailer" else b"")
    assert serve(wire) == _document()


def test_valid_chunk_content_is_parsed_like_an_unchunked_response(serve):
    records = r.parse(PATH, serve(_chunks(_body(), parts=3)))
    assert records and records[0]["mac"] == "00:00:5e:00:53:81"


@pytest.mark.parametrize("spelling", ["plus", "underscore", "hex_prefix", "leading_space", "minus_zero", "empty"])
def test_non_hex_chunk_size_is_refused_not_decoded(serve, spelling):
    body = _body()
    digits = b"%x" % len(body)
    size_field = {"plus": b"+" + digits, "underscore": digits[:1] + b"_" + digits[1:],
                  "hex_prefix": b"0x" + digits, "leading_space": b" " + digits,
                  "minus_zero": b"-0", "empty": b""}[spelling]
    with pytest.raises(r.RestError) as caught:
        serve(_chunks(body, size_field=size_field))
    assert caught.value.code == "transport_error"
    assert "status" not in str(caught.value)


def test_refused_chunk_size_through_engine_is_a_structured_failure(arm):
    body = _body()
    arm(_chunks(body, size_field=b"+" + b"%x" % len(body)))
    answer = engine._wifi_rest_result(auth(), (("records", PATH),))
    assert answer["ok"] is False and answer["error_code"] == "transport_error"
    assert "records" not in answer


def test_engine_reads_valid_chunked_clients(arm):
    arm(_chunks(_body(), parts=4, extension=b";x=1"))
    answer = engine._wifi_rest_result(auth(), (("records", PATH),))
    assert answer["ok"] is True and answer["records"][0]["mac"] == "00:00:5e:00:53:81"
