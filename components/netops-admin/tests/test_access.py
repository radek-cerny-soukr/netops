from __future__ import annotations

from types import SimpleNamespace

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
