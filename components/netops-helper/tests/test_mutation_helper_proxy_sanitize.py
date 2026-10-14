"""Text redaction in the proxy keeps the label and drops only the secret."""

from __future__ import annotations

from netops_helper.proxy_sanitize import sanitize_text


def test_a_shadow_hash_is_hidden_and_the_account_name_kept() -> None:
    text = "root:$6$salt$hashvalue-x:19000:0:99999:7:::\nbob:!locked-hash:19001::\n"
    cleaned = sanitize_text(text)
    assert "hashvalue-x" not in cleaned and "locked-hash" not in cleaned
    assert "root:<REDACTED>:19000:" in cleaned
    assert "bob:<REDACTED>:19001:" in cleaned


def test_a_cisco_secret_is_hidden_and_its_command_kept() -> None:
    text = "enable secret 5 $1$abcd$cisco-hash-x\n password 7 0822455D0A16FF\n"
    cleaned = sanitize_text(text)
    assert "cisco-hash-x" not in cleaned and "0822455D0A16FF" not in cleaned
    assert "enable secret 5 <REDACTED>" in cleaned
    assert " password 7 <REDACTED>" in cleaned


def test_a_labelled_secret_field_keeps_the_label_and_drops_the_value() -> None:
    text = 'login ok, password: hunter2-value, "token"="tok-value-x"}'
    cleaned = sanitize_text(text)
    assert "hunter2-value" not in cleaned and "tok-value-x" not in cleaned
    assert 'password: "<REDACTED>"' in cleaned
    assert '"token"="<REDACTED>"' in cleaned
    assert cleaned.startswith("login ok, ")
