import os
import stat

import pytest

from netops_core import ssh as ssh_module
from netops_core.ssh import ASKPASS_PROGRAM_ENV, ASKPASS_SCRIPT, SshError

LOGIN = "audit-ro"
PASSWORD = "KANARCI-HESLO-NESMI-UNIKNOUT"
PROGRAM = "#!/bin/sh\ncat \"$NETOPS_ASKPASS_FILE\"\n"


class FakeCredential:
    kind = "password"
    login = LOGIN
    name = "fw-a-ro"

    def use(self):
        return PASSWORD


def _workspace(tmp_path):
    path = tmp_path / "workspace"
    path.mkdir(mode=0o700)
    return str(path)


def _installed(tmp_path, mode=0o755, body=PROGRAM):
    path = tmp_path / "netops-askpass"
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def test_without_the_variable_the_program_is_written_into_the_workspace(tmp_path, monkeypatch):
    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    workspace = _workspace(tmp_path)
    identity, environment = ssh_module._prepared(workspace, "password", FakeCredential())

    assert identity is None
    written = environment["SSH_ASKPASS"]
    assert os.path.dirname(written) == workspace
    assert open(written, encoding="utf-8").read() == ASKPASS_SCRIPT
    assert stat.S_IMODE(os.stat(written).st_mode) == 0o700
    assert open(environment["NETOPS_ASKPASS_FILE"], "rb").read() == b"%s\n" % PASSWORD.encode()


def test_the_variable_names_the_program_and_nothing_is_written_beside_the_secret(
    tmp_path, monkeypatch,
):
    program = _installed(tmp_path)
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(program))
    workspace = _workspace(tmp_path)
    _, environment = ssh_module._prepared(workspace, "password", FakeCredential())

    assert environment["SSH_ASKPASS"] == str(program)
    assert environment["SSH_ASKPASS_REQUIRE"] == "force"
    assert sorted(os.listdir(workspace)) == ["secret"]
    assert os.path.dirname(environment["NETOPS_ASKPASS_FILE"]) == workspace


def test_a_program_that_cannot_be_executed_is_refused_naming_the_variable(tmp_path, monkeypatch):
    program = _installed(tmp_path, mode=0o644)
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(program))
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    assert ASKPASS_PROGRAM_ENV in str(caught.value)
    assert "cannot execute" in str(caught.value)


def test_a_program_writable_by_others_is_refused(tmp_path, monkeypatch):
    program = _installed(tmp_path, mode=0o757)
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(program))
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    assert "writable by group or other" in str(caught.value)


def test_a_program_that_is_not_there_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(tmp_path / "missing"))
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    assert ASKPASS_PROGRAM_ENV in str(caught.value)


def test_a_program_that_is_a_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(tmp_path))
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    assert "not a regular file" in str(caught.value)


def test_a_workspace_that_cannot_execute_is_refused_with_the_remedy(tmp_path, monkeypatch):
    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    workspace = _workspace(tmp_path)
    real = os.access

    def refuse(path, mode, **rest):
        if mode == os.X_OK and os.path.dirname(path) == workspace:
            return False
        return real(path, mode, **rest)

    monkeypatch.setattr(ssh_module.os, "access", refuse)
    with pytest.raises(SshError) as caught:
        ssh_module._prepared(workspace, "password", FakeCredential())
    assert "cannot be executed" in str(caught.value)
    assert ASKPASS_PROGRAM_ENV in str(caught.value)


def test_a_key_call_never_looks_for_an_askpass_program(tmp_path, monkeypatch):
    monkeypatch.setenv(ASKPASS_PROGRAM_ENV, str(tmp_path / "missing"))

    class Key(FakeCredential):
        kind = "ssh-key"

        def use(self):
            return "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n"

    workspace = _workspace(tmp_path)
    identity, environment = ssh_module._prepared(workspace, "ssh-key", Key())

    assert identity == os.path.join(workspace, "identity")
    assert "SSH_ASKPASS" not in environment


def test_the_packaged_program_answers_with_the_secret_file(tmp_path):
    from netops_core import askpass as askpass_module

    secret = tmp_path / "secret"
    secret.write_bytes(b"%s\n" % PASSWORD.encode())
    source = os.path.abspath(askpass_module.__file__)

    assert stat.S_IMODE(os.stat(source).st_mode) & 0o111

    import subprocess
    import sys

    answer = subprocess.run(
        [sys.executable, source],
        capture_output=True,
        env={"NETOPS_ASKPASS_FILE": str(secret), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert answer.returncode == 0
    assert answer.stdout == b"%s\n" % PASSWORD.encode()
