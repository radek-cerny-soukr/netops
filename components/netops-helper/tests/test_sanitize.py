#!/usr/bin/env python3
"""Dependency-free regression tests for contextual secret redaction."""

from __future__ import annotations

import pytest

from netops_helper.sanitize import redact


def test_log_language_is_preserved() -> None:
    source = "sshd: Failed password for invalid user admin from host.invalid"
    assert redact(source) == source


def test_snmp_status_redacts_the_value_not_the_neighboring_word() -> None:
    source = "SNMP community string configured: public"
    cleaned = redact(source)
    assert cleaned == "SNMP community string configured: <REDACTED>"
    assert "public" not in cleaned


def test_legacy_whitespace_community_value_is_redacted() -> None:
    cleaned = redact("community private-community")
    assert cleaned == "community <REDACTED>"
    assert "private-community" not in cleaned


def test_structured_and_cli_secrets_are_redacted() -> None:
    source = (
        'password=hunter2 token: abc "secret": "quoted value"\n'
        "enable secret 5 hashvalue\n"
        "username reader password 7 encoded\n"
        "snmp-server community public RO"
    )
    cleaned = redact(source)
    for hidden in ("hunter2", "abc", "quoted value", "hashvalue", "encoded", "public"):
        assert hidden not in cleaned
    for context in ("password=", "token:", '"secret":', "enable secret 5", "username reader"):
        assert context in cleaned


def test_exact_injected_secrets_and_diagnostic_context() -> None:
    from netops_helper.proxy_sanitize import sanitize_text

    source = (
        "time=10:23:45 host=host.invalid serial=DEVICE123 "
        "credential material-is-secret\n"
        "      128-length passwd            : enabled\n"
    )
    for sanitize in (redact, sanitize_text):
        cleaned = sanitize(source, secrets=("material-is-secret",))
        for visible in ("10:23:45", "host.invalid", "DEVICE123",
                        "      128-length passwd            : enabled\n"):
            assert visible in cleaned
        assert "material-is-secret" not in cleaned


def test_redaction_limit_is_still_enforced() -> None:
    try:
        redact("x" * 20, limit=10)
    except ValueError as exc:
        assert "explicit limit" in str(exc)
    else:
        raise AssertionError("redaction limit was not enforced")


def test_community_and_bearer_do_not_cross_line_breaks() -> None:
    source = 'config system snmp community\n    edit 1\n        set name "public"'
    assert redact(source) == 'config system snmp community\n    edit 1\n        set name <REDACTED:credential#1>'
    neighbor = "Neighbor 192.0.2.1 community\nlocalpref 100"
    assert redact(neighbor) == neighbor
    bearer = "The bearer\nof this packet"
    assert redact(bearer) == bearer


def test_type7_and_preshared_secrets_are_redacted() -> None:
    cleaned = redact(
        "radius-server host 192.0.2.9 key 7 0A1B2C\n"
        "ip ospf message-digest-key 1 md5 7 0A1B2C\n"
        "key-string 7 0A1B2C\n"
        "user reader password 7 0822455D0A16\n"
        "set psksecret ENC-free-value\n"
        "pre-shared-key: \"abc def\"\n"
        "wpa-passphrase=abc\n"
    )
    assert "0A1B2C" not in cleaned
    assert "0822455D0A16" not in cleaned
    assert "ENC-free-value" not in cleaned
    assert "abc def" not in cleaned
    assert "wpa-passphrase=<REDACTED>" in cleaned
    assert "radius-server host 192.0.2.9 key 7 <REDACTED>" in cleaned


def main() -> int:
    test_log_language_is_preserved()
    test_snmp_status_redacts_the_value_not_the_neighboring_word()
    test_legacy_whitespace_community_value_is_redacted()
    test_structured_and_cli_secrets_are_redacted()
    test_exact_injected_secrets_and_diagnostic_context()
    test_redaction_limit_is_still_enforced()
    test_community_and_bearer_do_not_cross_line_breaks()
    test_type7_and_preshared_secrets_are_redacted()
    print("sanitize_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


PEM_BODY = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"
PEM_FORMS = {
    "rsa": "RSA PRIVATE KEY", "ec": "EC PRIVATE KEY", "openssh": "OPENSSH PRIVATE KEY",
    "pkcs8": "PRIVATE KEY", "pkcs8-encrypted": "ENCRYPTED PRIVATE KEY",
    "dsa": "DSA PRIVATE KEY", "pgp": "PGP PRIVATE KEY BLOCK",
}


def test_every_private_key_pem_form_is_redacted_by_server_and_proxy() -> None:
    from netops_helper.proxy_sanitize import sanitize_text

    public = "-----BEGIN PUBLIC KEY-----\n" + PEM_BODY + "-----END PUBLIC KEY-----"
    certificate = "-----BEGIN CERTIFICATE-----\n" + PEM_BODY + "-----END CERTIFICATE-----"
    for clean in (redact, sanitize_text):
        assert clean("before\n" + public + "\nafter") == "before\n" + public + "\nafter"
        assert clean(certificate) == certificate
        for name, label in sorted(PEM_FORMS.items()):
            document = f"-----BEGIN {label}-----\n{PEM_BODY}-----END {label}-----"
            cleaned = clean(f"key {name}:\n{document}\nshow done")
            assert cleaned == f"key {name}:\n<PRIVATE-KEY-REDACTED>\nshow done", (clean, name)
        for name, label in sorted(PEM_FORMS.items()):
            truncated = clean(f"key {name}:\n-----BEGIN {label}-----\n{PEM_BODY[:40]}")
            assert truncated == f"key {name}:\n<PRIVATE-KEY-REDACTED>", (clean, name)
        assert clean("before\n" + public + "\nafter") == "before\n" + public + "\nafter"


def test_secret_length_threshold_is_three_utf8_bytes() -> None:
    from netops_helper.proxy_sanitize import sanitize_text

    for clean in (redact, sanitize_text):
        assert clean("device says abc here", ["abc"]) == "device says <REDACTED> here"
        for secret in ("žž", "éé", "ž1", "€"):
            cleaned = clean(f"device says {secret} here", [secret])
            assert cleaned == "device says <REDACTED> here", (clean, secret)
        for short in ("ab", "ž", "7"):
            assert clean(f"device says {short} here", [short]) == f"device says {short} here"
        assert clean("device says abc here", ["abc"]) == "device says <REDACTED> here"


QUOTED_SECRET_CASES = {
    "assigned-double": ('password="SYNTHHEAD\\" SYNTHTAIL42" user=reader', "user=reader"),
    "assigned-single": ("token: 'SYNTHHEAD\\' SYNTHTAIL42' user=reader", "user=reader"),
    "assigned-double-odd-backslashes": ('password="SYNTHHEAD\\\\\\" SYNTHTAIL42" user=reader', "user=reader"),
    "assigned-double-trailing-backslash-pair": ('password="SYNTHHEAD\\" SYNTHTAIL42\\\\" user=reader', "user=reader"),
    "assigned-double-unclosed": ('password="SYNTHHEAD SYNTHTAIL42\nuser=reader', "user=reader"),
    "assigned-single-unclosed": ("token: 'SYNTHHEAD SYNTHTAIL42\nuser=reader", "user=reader"),
    "assigned-double-unclosed-trailing-backslash": ('password="SYNTHHEAD SYNTHTAIL42\\\nuser=reader', "user=reader"),
    "cli-option-double": ('--password "SYNTHHEAD\\" SYNTHTAIL42" --host=sw1', "--host=sw1"),
    "cli-option-single": ("--token 'SYNTHHEAD\\' SYNTHTAIL42' --host=sw1", "--host=sw1"),
    "cli-option-double-trailing-backslash-pair": ('--password "SYNTHHEAD\\" SYNTHTAIL42\\\\" --host=sw1', "--host=sw1"),
    "cli-option-double-unclosed": ('--password "SYNTHHEAD SYNTHTAIL42\n--host=sw1', "--host=sw1"),
    "cli-option-single-unclosed": ("--token 'SYNTHHEAD SYNTHTAIL42\n--host=sw1", "--host=sw1"),
    "preshared-double": ('set psksecret "SYNTHHEAD\\" SYNTHTAIL42" ssid=lab', "ssid=lab"),
    "preshared-double-trailing-backslash-pair": ('set psksecret "SYNTHHEAD\\" SYNTHTAIL42\\\\" ssid=lab', "ssid=lab"),
    "preshared-double-unclosed": ('set psksecret "SYNTHHEAD SYNTHTAIL42\nset ssid=lab', "set ssid=lab"),
    "preshared-single": ("set psksecret 'SYNTHHEAD\\' SYNTHTAIL42' ssid=lab", "ssid=lab"),
    "preshared-single-trailing-backslash-pair": ("set psksecret 'SYNTHHEAD\\' SYNTHTAIL42\\\\' ssid=lab", "ssid=lab"),
    "preshared-single-unclosed": ("set psksecret 'SYNTHHEAD SYNTHTAIL42\nset ssid=lab", "set ssid=lab"),
    "snmp-cli-double": ('snmp-server community "SYNTHHEAD\\" SYNTHTAIL42" RO', "RO"),
    "snmp-cli-double-trailing-backslash-pair": ('set community "SYNTHHEAD\\" SYNTHTAIL42\\\\" RO', None),
    "snmp-cli-single": ("snmp-server community 'SYNTHHEAD\\' SYNTHTAIL42' RO", "RO"),
    "snmp-cli-single-trailing-backslash-pair": ("set community 'SYNTHHEAD\\' SYNTHTAIL42\\\\' RO", None),
    "snmp-cli-single-unclosed": ("snmp-server community 'SYNTHHEAD SYNTHTAIL42\nsnmp-server host 192.0.2.1", "snmp-server host 192.0.2.1"),
    "snmp-cli-double-unclosed": ('snmp-server community "SYNTHHEAD SYNTHTAIL42\nsnmp-server host 192.0.2.1', "snmp-server host 192.0.2.1"),
}


@pytest.mark.parametrize("source,public", QUOTED_SECRET_CASES.values(), ids=QUOTED_SECRET_CASES.keys())
def test_quoted_secret_leaves_no_fragment_in_the_output(source: str, public: str | None) -> None:
    cleaned = redact(source)
    assert "SYNTH" not in cleaned
    assert "TAIL42" not in cleaned
    assert "<REDACTED>" in cleaned
    if public is None:
        # set community carries the complete remaining line under the O1 policy.
        assert cleaned == "set community <REDACTED>"
    else:
        assert public in cleaned


def test_quoted_secret_without_escapes_keeps_the_neighboring_value() -> None:
    assert redact('password="plain value" user=reader') == "password=<REDACTED> user=reader"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
def test_closed_quoted_secret_with_a_token_keyword_keeps_the_neighboring_value(keyword: str) -> None:
    assert redact(f'password="{keyword} value" user=reader') == "password=<REDACTED> user=reader"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
def test_unclosed_quoted_secret_with_a_token_keyword_is_redacted_to_the_end_of_the_line(keyword: str) -> None:
    assert redact(f'password="{keyword} value user=reader\nnext=public') == "password=<REDACTED>\nnext=public"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("punctuation", [",", "}", "]"])
def test_token_with_an_inner_quote_and_punctuation_is_redacted_whole(keyword: str, quote: str, punctuation: str) -> None:
    token = f"SYNTHHEAD{quote}{punctuation}SYNTHTAIL42"
    assert redact(f"{keyword} {token}") == f"{keyword} <REDACTED>"
    cleaned = redact(f"{keyword} {token} {keyword} SECONDSECRET")
    assert cleaned == f"{keyword} <REDACTED> {keyword} <REDACTED>"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
@pytest.mark.parametrize("quote", ['"', "'"])
def test_escaped_quote_after_a_token_keyword_does_not_end_the_quoted_secret(keyword: str, quote: str) -> None:
    source = f"password={quote}{keyword} SYNTHHEAD\\{quote} SYNTHTAIL42{quote} user=reader"
    assert redact(source) == "password=<REDACTED> user=reader"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
def test_closed_quoted_secret_with_only_a_token_keyword_keeps_the_neighboring_value(keyword: str) -> None:
    assert redact(f'password="{keyword} " user=reader') == "password=<REDACTED> user=reader"


@pytest.mark.parametrize("keyword", ["ENC", "bearer"])
def test_token_keyword_does_not_shift_the_next_quoted_secret(keyword: str) -> None:
    source = f'password="{keyword} value" token="SYNTHHEAD SYNTHTAIL42"'
    assert redact(source) == "password=<REDACTED> token=<REDACTED>"
