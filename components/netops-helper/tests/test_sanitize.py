#!/usr/bin/env python3
"""Dependency-free regression tests for contextual secret redaction."""

from __future__ import annotations

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
    source = (
        "time=10:23:45 host=host.invalid serial=DEVICE123 "
        "credential material-is-secret"
    )
    cleaned = redact(source, secrets=("material-is-secret",))
    for visible in ("10:23:45", "host.invalid", "DEVICE123"):
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
    assert redact(source) == source
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
