from __future__ import annotations

from types import SimpleNamespace

import pytest

from netops_admin import access, exec_exos, exec_fortios


class Shell:
    def __init__(self, answers):
        self.pending = answers.pop(0)
        self.answers = answers
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def discard(self, data):
        return len(data)

    def send(self, line):
        self.sent.append(line)
        self.pending += self.answers.pop(0) if self.answers else b""

    def expect(self, patterns, timeout):
        best = None
        for index, pattern in enumerate(patterns):
            found = self.pending.find(pattern)
            if found >= 0 and (best is None or found < best[1]):
                best = (index, found, pattern)
        if best is None:
            raise access.session.SessionError("timed out waiting for %r" % patterns)
        end = best[1] + len(best[2])
        data, self.pending = self.pending[:end], self.pending[end:]
        return best[0], data


def device_access(shell):
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(legacy_ssh=None)
    handle._session = lambda: shell
    return handle


def test_fortios_prompt_right_after_login_is_found():
    shell = Shell([b"FortiGate-60F $ ",
                   b"config firewall address\r\nFortiGate-60F (address) $ ",
                   b"end\r\nFortiGate-60F $ "])
    spec = exec_fortios.prompt_spec("FortiGate-60F")
    assert device_access(shell).apply(["config firewall address", "end"], spec) == 2


def test_exos_unsaved_marker_is_read_from_the_login_prompt():
    spec = exec_exos.prompt_spec("sw-lab")
    assert device_access(Shell([b"\r\n* sw-lab.1 # "])).login_prefix(spec) == b"*"
    assert device_access(Shell([b"\r\nsw-lab.1 # "])).login_prefix(spec) == b""


def test_exos_profile_body_and_prompted_save_are_sent_as_steps():
    spec = exec_exos.prompt_spec("sw-lab")
    shell = Shell([b"sw-lab.1 # ",
                   b"create upm profile p\r\nStart typing the profile\r\n",
                   b"delete vlan guest\r\n",
                   b".\r\n* sw-lab.2 # ",
                   b"save configuration\r\noverwrite it? (y/N) ",
                   b"Yes\r\nConfiguration saved.\r\nsw-lab.3 # "])
    steps = [("ask", "create upm profile p", b"Start typing"), ("raw", "delete vlan guest"), ".",
             ("ask", "save configuration", b"(y/N)"), "y"]
    assert device_access(shell).apply(steps, spec) == 5
    assert shell.sent == ["create upm profile p", "delete vlan guest", ".", "save configuration", "y"]


def test_exos_error_answer_stops_the_session():
    spec = exec_exos.prompt_spec("sw-lab")
    shell = Shell([b"sw-lab.1 # ",
                   b"delete vlan guest\r\n        ^\r\n%% Invalid input detected at '^' marker.\r\nsw-lab.2 # ",
                   b"never sent"])
    try:
        device_access(shell).apply(["delete vlan guest", "create vlan other tag 5"], spec)
    except access.AccessError as error:
        assert error.accepted_lines == 0 and "line 1" in str(error)
    else:
        raise AssertionError("an error answer must stop the session")
    assert shell.sent == ["delete vlan guest"]


@pytest.mark.parametrize("send_fails", [False, True])
def test_line_sent_reports_a_successful_send_even_without_a_reply(send_fails):
    class WriteShell(Shell):
        def send(self, line):
            if send_fails:
                raise access.session.SessionError("session closed before the line was sent")
            super().send(line)

    shell = WriteShell([b"sw-lab.1 # "])
    handle = device_access(shell)
    sent = []
    handle.line_sent = sent.append
    with pytest.raises(access.AccessError) as failure:
        handle.apply(["delete vlan guest"], exec_exos.prompt_spec("sw-lab"))
    assert failure.value.accepted_lines == 0
    assert sent == ([] if send_fails else [1])
    assert shell.sent == ([] if send_fails else ["delete vlan guest"])


def test_fortios_refusal_names_the_object_the_line_and_the_device_answer():
    spec = exec_fortios.prompt_spec("fw-lab")
    shell = Shell([b"fw-lab $ ",
                   b"config system accprofile\r\nfw-lab (accprofile) $ ",
                   b'edit "netops-sg-x-p"\r\nnew entry \'netops-sg-x-p\' added\r\nfw-lab (netops-sg-x-p) $ ',
                   b"set fwgrp read-write\r\nfw-lab (netops-sg-x-p) $ ",
                   b"next\r\nobject set operator error, -672 discard the setting\r\nCommand fail. Return code -672\r\n"
                   b"fw-lab (netops-sg-x-p) $ ",
                   b"never sent"])
    lines = ["config system accprofile", 'edit "netops-sg-x-p"', "set fwgrp read-write", "next", "end"]
    try:
        device_access(shell).apply(lines, spec)
    except access.AccessError as error:
        assert error.accepted_lines == 3
        assert str(error) == ('line 4 (config system accprofile, edit "netops-sg-x-p") was refused by the device:'
                              " object set operator error, -672 discard the setting | Command fail. Return code -672")
    else:
        raise AssertionError("an error answer must stop the session")
    assert shell.sent == lines[:4]


def test_the_check_account_uses_its_own_management_address(monkeypatch):
    calls, scans = [], []

    def run_command(address, port, login, credential, host_key_line, command, **options):
        calls.append((address, credential.login, host_key_line))
        return SimpleNamespace(rc=250 if credential.login == "netops-check" else 0, stdout=b"Port:\t10\n")

    def scan(address, port, pin, timeout, legacy=None):
        scans.append(address)
        return "%s ssh-rsa AAAA" % address

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    monkeypatch.setattr(access.hostkey, "scan", scan)
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(address="192.0.2.1", check_address="198.51.100.1", port=22,
                                    host_key_fingerprint="SHA256:x", legacy_ssh=None, platform="exos")
    handle.credential = SimpleNamespace(login="netops-rw")
    handle.check_credential = SimpleNamespace(login="netops-check")
    handle._host_key_lines = {}
    handle.check_query("show ports 10 information detail")
    handle.query("show switch")
    assert calls[0][:2] == ("198.51.100.1", "netops-check") and calls[0][2].startswith("198.51.100.1 ")
    assert calls[1][:2] == ("192.0.2.1", "netops-rw") and calls[1][2].startswith("192.0.2.1 ")
    assert scans == ["198.51.100.1", "192.0.2.1"]


def test_query_status_gives_the_exit_status_of_a_port_without_poe(monkeypatch):
    """Measured (ref 171): show inline-power info ports N of a port without PoE ends with exit status 250."""
    answers = {"show inline-power info ports 13": (250, b"Port 13 is not inline-power capable\n", b""),
               "show inline-power info ports 10": (0, b"Port  State\n", b"")}

    def run_command(address, port, login, credential, host_key_line, command, **options):
        rc, stdout, stderr = answers[command]
        return SimpleNamespace(rc=rc, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    monkeypatch.setattr(access.hostkey, "scan", lambda address, port, pin, timeout, legacy=None: "%s ssh-rsa AAAA" % address)
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(address="192.0.2.1", check_address=None, port=22,
                                    host_key_fingerprint="SHA256:x", legacy_ssh=None, platform="exos")
    handle.credential = SimpleNamespace(login="netops-rw")
    handle._host_key_lines = {}
    handle.read_seconds = None
    rc, text = handle.query_status("show inline-power info ports 13")
    assert rc == 250 and "Port 13 is not inline-power capable" in text
    assert handle.query_status("show inline-power info ports 10")[0] == 0
    try:
        handle.query("show inline-power info ports 13")
    except access.AccessError as error:
        assert "exit status 250" in str(error)
    else:
        raise AssertionError("the plain query must keep refusing a non-zero exit status")


# measured (ref admin-exos-184 N01, x440-refusal-diagnostic.jsonl): the OpenSSH client of the runtime image writes
# this warning to stderr of every exec call to the X440
SSH_PQ_WARNING = (b"** WARNING: connection is not using a post-quantum key exchange algorithm.\r\n"
                  b"** This session may be vulnerable to \"store now, decrypt later\" attacks.\r\n"
                  b"** The server may need to be upgraded. See https://openssh.com/pq.html\r\n")


def stderr_access(monkeypatch, answers, platform="exos"):
    def run_command(address, port, login, credential, host_key_line, command, **options):
        rc, stdout, stderr = answers[command]
        return access.ssh.Result(rc=rc, stdout=stdout, said="", started_at="a", finished_at="b", stderr=stderr)

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    monkeypatch.setattr(access.hostkey, "scan", lambda address, port, pin, timeout, legacy=None: "%s ssh-rsa AAAA" % address)
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(address="192.0.2.1", check_address=None, port=22,
                                    host_key_fingerprint="SHA256:x", legacy_ssh=None, platform=platform)
    handle.credential = SimpleNamespace(login="netops-rw")
    handle.check_credential = SimpleNamespace(login="netops-check")
    handle._host_key_lines = {}
    return handle


def test_ssh_client_warning_on_stderr_keeps_the_poe_not_capable_code(monkeypatch):
    """N01: rc 250, the single stdout line and the SSH client warning on stderr give poe_not_capable."""
    import pytest
    from netops_admin import exos
    command = "show inline-power info ports 13"
    handle = stderr_access(monkeypatch, {command: (250, b"Port 13 is not inline-power capable\n", SSH_PQ_WARNING)})
    rc, text = handle.query_status(command)
    assert rc == 250 and text.split() == "Port 13 is not inline-power capable".split()
    assert "post-quantum" in handle.last_stderr and "post-quantum" not in text
    plan = {"key": "13", "prechecks": []}
    with pytest.raises(exos.NotInlinePower) as refused:
        exec_exos._poe_prechecks(handle, None, plan, "")
    assert refused.value.reason_codes == ["poe_not_capable"]
    assert plan["prechecks"] == []


def test_ssh_client_warning_on_stderr_does_not_reach_the_inline_power_table(monkeypatch):
    command = "show inline-power info ports 10"
    table = (b"Port      State            Class     Volts   Curr  Power  Fault\n"
             b"                                            (mA)   (Watts)\n"
             b"10        searching        ------     0.0      0   0.00  None\n")
    handle = stderr_access(monkeypatch, {command: (0, table, SSH_PQ_WARNING)})
    rc, text = handle.query_status(command)
    assert rc == 0 and "WARNING" not in text and "Port" in text


def test_stderr_only_answers_stay_joined_for_the_readers_that_need_them(monkeypatch):
    handle = stderr_access(monkeypatch, {"show switch": (0, b"", b"answer on stderr\n"),
                                         "show accounts": (0, b"", b"admin\n")})
    assert "answer on stderr" in handle.diagnose_query("show switch")
    assert "admin" in handle.own_query("show accounts")


# task 441 (B02): the refusal exactly as the runtime engine image received it live on 2026-11-17 from X440 port 13 and
# X435 port 9 over ai-login (EXOS 33.7.1.6-patch1-11): stdout "Port N is not inline-power capable", exit status 250,
# and the OpenSSH post-quantum warning on stderr. The replay goes through DeviceAccess._query, as the live call did.
def _replay(name):
    from pathlib import Path
    base = Path(__file__).resolve().parent / "fixtures" / "exos_port_poe" / name
    return (base.with_suffix(".stdout").read_bytes(), base.with_suffix(".stderr").read_bytes())



@pytest.mark.parametrize(("name", "port"), [("x440__441-ip-nopoe-exec", "13"), ("x435__441-ip-nopoe-exec", "9")])
def test_live_refusal_with_ssh_warning_replays_as_poe_not_capable(monkeypatch, name, port):
    from netops_admin import exos
    stdout, stderr = _replay(name)
    assert b"post-quantum" in stderr and stdout.strip() == ("Port %s is not inline-power capable" % port).encode()
    command = "show inline-power info ports %s" % port
    handle = stderr_access(monkeypatch, {command: (250, stdout, stderr)})
    rc, text = handle.query_status(command)
    assert rc == 250 and exos.poe_not_capable_answer(rc, text, port)
    plan = {"key": port, "prechecks": []}
    with pytest.raises(exos.NotInlinePower) as refused:
        exec_exos._poe_prechecks(handle, None, plan, "")
    assert refused.value.reason_codes == ["poe_not_capable"] and plan["prechecks"] == []
    # root cause of N01 (task 184, source 72c1fca): the answer joined with stderr is not the single measured line,
    # so the detector refused it and the precheck fell through to the generic refusal
    joined = handle._query(handle.credential, command, any_status=True, with_stderr=True)
    assert not exos.poe_not_capable_answer(250, joined, port)


@pytest.mark.parametrize("name", ["x440__441-ip-nopoe-exec", "x435__441-ip-nopoe-exec"])
def test_live_refusal_with_another_exit_status_keeps_the_generic_refusal(monkeypatch, name):
    from netops_admin import exos
    stdout, stderr = _replay(name)
    port = stdout.split()[1].decode()
    command = "show inline-power info ports %s" % port
    handle = stderr_access(monkeypatch, {command: (254, stdout, stderr)})
    with pytest.raises(Exception) as caught:
        exec_exos._poe_prechecks(handle, None, {"key": port, "prechecks": []}, "")
    assert not isinstance(caught.value, exos.NotInlinePower)
