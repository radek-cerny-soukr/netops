"""1.0.12 EXOS summary fixes (task 691): real captures through the real Helper read path, fake SSH transport only."""

import hashlib
import json
from pathlib import Path

import pytest

from netops_helper import engine
from test_g38_ports import ordinary_port_outputs, transport as port_transport
from test_g40_exos_health import LEGACY_LOGS, PROFILE, public  # noqa: F401  (public is a fixture)
from test_ios_exos_522_r2 import ssh_read as wire_ssh_read

FIXTURES = Path(__file__).parent / "fixtures"
REAL = FIXTURES / "real/exos"
EXOSVM_LOG = (REAL / "exosvm_33.6.1.14/log_messages.txt").read_text().splitlines()
EXOSVM_WARNINGS = (REAL / "exosvm_33.6.1.14/log_warnings.txt").read_text().splitlines()
X435_LOG = (REAL / "x435-8p-4s_33.7.1.6/log_messages.txt").read_text().splitlines()
X435_WARNINGS = (REAL / "x435-8p-4s_33.7.1.6/log_warnings.txt").read_text().splitlines()


def real_row(rows, needle):
    return next(row for row in rows if needle in row)


# Rows measured on a booting EXOS-VM and on an X435 (anonymized captures kept in the repository).
BENIGN_ROWS = [
    real_row(EXOSVM_LOG, "Existing host key with fingerprint"),
    real_row(EXOSVM_LOG, "Generating RSA-2048 public key"),
    real_row(EXOSVM_LOG, "Loaded Private Key of size"),
    real_row(X435_WARNINGS, 'Missing component "inlets"'),
    real_row(X435_WARNINGS, 'Missing component "telegraf"'),
]


@pytest.mark.parametrize("query", sorted(LEGACY_LOGS))
def test_common_operational_log_rows_are_not_withheld(public, query):  # noqa: F811
    """Booting and telemetry-agent rows are ordinary; they must not make every log read incomplete."""
    public[1][LEGACY_LOGS[query]] = "\n".join(BENIGN_ROWS) + "\n"
    result = public[0]("ssh_read", platform=PROFILE, query=query)
    assert result.get("ok") is True, result
    assert result["untrusted_device_output"].splitlines() == BENIGN_ROWS
    assert result["status"] != "incomplete" and result.get("complete") is not False, result


@pytest.mark.parametrize("query", sorted(LEGACY_LOGS))
@pytest.mark.parametrize("event", ["AAA.authFail", "AAA.LogSsh", "exsshd.KeyAuthFail"])
def test_failed_ssh_login_redacts_attempted_user_before_output_and_hash(public, query, event):  # noqa: F811
    if event == "AAA.authFail":
        rows = EXOSVM_LOG if query == "log_messages" else EXOSVM_WARNINGS
        row = real_row(rows, "<Warn:AAA.authFail>")
        captured_user = "******"
    elif event == "exsshd.KeyAuthFail":
        row = real_row(X435_WARNINGS, "<Warn:exsshd.KeyAuthFail>")
        captured_user = "user02"
    else:
        # Derived from the X435 diagnostic using the allowlisted failure wording.
        row = real_row(X435_LOG, "<Info:AAA.LogSsh> Msg from Master : Login passed for user ")
        row = row.replace("Login passed", "Login failed", 1)
        captured_user = "user01"

    attempted_user = "Fixture.Pass-42@Lab"
    assert f"for user {captured_user} " in row
    public[1][LEGACY_LOGS[query]] = row.replace(captured_user, attempted_user, 1) + "\n"
    expected = row.replace(captured_user, "<user-redacted>", 1) + "\n"
    result = public[0]("ssh_read", platform=PROFILE, query=query)

    assert result.get("ok") is True
    assert result.get("complete") is not False and result["status"] != "incomplete"
    user_redacted = attempted_user not in json.dumps(result)
    safe_digest = result["content_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
    assert (user_redacted, safe_digest) == (True, True)
    assert result["untrusted_device_output"] == expected


def test_successful_ssh_login_and_logout_keep_account_names(public):  # noqa: F811
    rows = [
        real_row(X435_LOG, "Msg from Master : Login passed for user "),
        real_row(EXOSVM_LOG, ":AAA.authPass>").replace("******", "user01"),
        real_row(EXOSVM_LOG, ":AAA.logout>").replace("******", "user01"),
    ]
    expected = "\n".join(rows) + "\n"
    public[1][LEGACY_LOGS["log_messages"]] = expected
    result = public[0]("ssh_read", platform=PROFILE, query="log_messages")

    assert result.get("ok") is True
    assert result["untrusted_device_output"] == expected
    assert result["content_sha256"] == hashlib.sha256(expected.encode()).hexdigest()


@pytest.mark.parametrize("tail", [" secret ~q", "; community ~q", " password: ~q"])
def test_extended_log_rows_still_withhold_anything_else(public, tail):  # noqa: F811
    """The new rows are exact shapes; a variant carrying extra text stays withheld."""
    rows = [row + tail for row in BENIGN_ROWS]
    public[1][LEGACY_LOGS["log_messages"]] = "\n".join(rows) + "\n"
    result = public[0]("ssh_read", platform=PROFILE, query="log_messages")
    assert result.get("ok") is True, result
    assert "~q" not in str(result)
    assert result["status"] == "incomplete" or result.get("complete") is False, result


def test_access_list_counter_without_counters_is_an_empty_read(public):  # noqa: F811
    """`show access-list counter` prints nothing when no ACL has counters (measured rc 0 on VM, X435, X440 x3)."""
    blank = (REAL / "x435-8p-4s_33.7.1.6/access_list_counters.txt").read_text()
    assert not blank.strip()
    public[1]["show access-list counter"] = blank
    result = public[0]("ssh_read", platform=PROFILE, query="access_list_counters", enabled=["access_list_counters"])
    assert result.get("ok") is True, result
    assert result["status"] == "empty" and result["normalized"]["records"] == [], result


def test_access_list_counter_empty_read_still_fails_on_cli_refusal(public):  # noqa: F811
    public[1]["show access-list counter"] = (0, "This user does not have permissions for this command.\n")
    result = public[0]("ssh_read", platform=PROFILE, query="access_list_counters", enabled=["access_list_counters"])
    assert result.get("ok") is False and result["status"] == "permission_denied", result


@pytest.mark.parametrize("stderr", [b"Error: Permission denied\n",
                                    b"Error: Permission denied\nSSH diagnostic\n"])
@pytest.mark.parametrize("with_stdout", [False, True], ids=["stderr-only", "both-streams"])
def test_exos_permission_denied_on_stderr_has_the_denied_status(wire, monkeypatch, stderr, with_stdout):
    table = json.loads((FIXTURES / "tables/extreme_exos.json").read_text())
    stdout = table["mac_entry"].encode() if with_stdout else b""
    result = wire_ssh_read(monkeypatch, "extreme_exos", "mac_table", stdout, stderr=stderr)
    assert result["ok"] is False and result["status"] == "permission_denied", result
    assert result["error_code"] == "device_cli_error"
    assert "SSH diagnostic" not in result.get("untrusted_device_output", "")


@pytest.mark.parametrize("state", ["BLOCKING", "DISCARDING", "LEARNING", "LISTENING"])
def test_port_triage_reports_every_non_forwarding_stp_state(monkeypatch, state):
    outputs = ordinary_port_outputs()
    assert "Port State        : FORWARDING" in outputs["stp_port_detail"]
    outputs["stp_port_detail"] = outputs["stp_port_detail"].replace("Port State        : FORWARDING",
                                                                     "Port State        : " + state)
    auth, _ = port_transport(monkeypatch, outputs)
    result = engine.triage_port(auth, "1")
    assert {"code": "stp_not_forwarding", "source": "stp_port_detail"} in result["findings"], result


def test_port_triage_does_not_flag_a_forwarding_stp_port(monkeypatch):
    auth, _ = port_transport(monkeypatch, ordinary_port_outputs())
    result = engine.triage_port(auth, "1")
    assert not [item for item in result["findings"] if item["code"] == "stp_not_forwarding"], result
