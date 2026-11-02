import netops_helper.engine as engine

PROMPT = b"FortiADC-VM # "
HCV = "execute health-check-verify health-check HC_HTTP_APP dest-address member1 count 2"
TLS = "execute ssl-handshake-n-record-statistics show virtual-server VS_APP_HTTP"
HCV_BODY = "recv hc state is UP(check service successfully, status code 200), rtt = 0.7 ms\n\n2 checks completed"
TLS_BODY = "VS client-side SSL statistics:\n\t# of succeeded HANDSHAKEs: 0, average latency 0(us)"


def _wire(echo, body):
    return echo.encode() + b"\r\n" + body.replace("\n", "\r\n").encode() + b"\r\n" + PROMPT


def test_wrapped_echo_of_health_check_verify_is_the_typed_command():
    raw = _wire("execute health-check-verify health-check HC_HTTP_APP dest-address \x08 member1 count 2", HCV_BODY)
    assert engine._pty_body(raw, HCV, PROMPT) == HCV_BODY


def test_wrapped_echo_of_tls_handshake_stats_is_the_typed_command():
    raw = _wire("execute ssl-handshake-n-record-statistics show virtual-server VS_ \x08APP_HTTP", TLS_BODY)
    assert engine._pty_body(raw, TLS, PROMPT) == TLS_BODY


def test_backspace_erases_the_previous_character_and_never_the_line_break():
    raw = b"ab \x08c\r\n\x08x\r\n" + PROMPT
    assert engine._pty_body(raw, "none", PROMPT) == "abc\nx"
    assert "\x08" not in engine._pty_body(b"\x08\x08ok\r\n" + PROMPT, "none", PROMPT)
