import os
import stat
import sys

import pytest

from netops_core import ssh as ssh_module
from netops_core.ssh import ASKPASS_PROGRAM_ENV, ASKPASS_SCRIPT, SshError

LOGIN = "audit-ro"
PASSWORD = "CANARY-PASSWORD-MUST-NOT-LEAK"
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
    text = __import__('pathlib').Path(written).read_text(encoding="utf-8")
    assert text.splitlines()[0] == "#!%s -I" % sys.executable
    assert text.partition("\n")[2] == ASKPASS_SCRIPT.partition("\n")[2]
    assert stat.S_IMODE(os.stat(written).st_mode) == 0o700
    assert __import__('pathlib').Path(environment["NETOPS_ASKPASS_FILE"]).read_bytes() == b"%s\n" % PASSWORD.encode()


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
        [sys.executable, source, "Password: "],
        capture_output=True,
        env={"NETOPS_ASKPASS_FILE": str(secret), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert answer.returncode == 0
    assert answer.stdout == b"%s\n" % PASSWORD.encode()


@pytest.mark.parametrize("packaged", [False, True], ids=["fallback", "packaged"])
@pytest.mark.parametrize("prompt", [
    "Password: ", "password:", "PASSWORD: ", "(netops-ro@switch) Password: ",
    "netops-ro@switch's password: ",
])
def test_password_prompts_answer_once_per_connection(tmp_path, monkeypatch, packaged, prompt):
    import subprocess
    from netops_core import askpass

    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    if packaged:
        monkeypatch.setenv(ASKPASS_PROGRAM_ENV, os.path.abspath(askpass.__file__))
    workspace = _workspace(tmp_path)
    _, environment = ssh_module._prepared(workspace, "password", FakeCredential())
    program = environment["SSH_ASKPASS"]
    first = subprocess.run([program, prompt], env=environment, capture_output=True)
    assert first.returncode == 0
    assert first.stdout == PASSWORD.encode() + b"\n"
    assert first.stderr == b""
    second = subprocess.run([program, prompt], env=environment, capture_output=True)
    assert second.returncode != 0
    assert second.stdout == b""
    assert PASSWORD.encode() not in second.stderr
    # A fresh connection has a fresh attempt, with the same credential.
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    _, fresh = ssh_module._prepared(str(other), "password", FakeCredential())
    assert subprocess.run([fresh["SSH_ASKPASS"], prompt], env=fresh, capture_output=True).stdout == first.stdout


@pytest.mark.parametrize("packaged", [False, True], ids=["fallback", "packaged"])
@pytest.mark.parametrize("prompts", [
    [], ["OTP: "], ["Verification code: "], ["Passcode: "],
    ["New password: "], ["passwordless: "], ["Token's password: "], ["Password: \nOTP: "],
    ["Are you sure you want to continue connecting (yes/no/[fingerprint])? "],
])
def test_other_prompts_fail_without_disclosing_or_logging_password(tmp_path, monkeypatch, packaged, prompts):
    import subprocess
    from netops_core import askpass

    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    if packaged:
        monkeypatch.setenv(ASKPASS_PROGRAM_ENV, os.path.abspath(askpass.__file__))
    _, environment = ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    program = environment["SSH_ASKPASS"]
    rejected = subprocess.run([program, *prompts], env=environment, capture_output=True)
    assert rejected.returncode != 0
    assert rejected.stdout == b""
    assert b"ssh_auth_method_unsupported" in rejected.stderr
    assert PASSWORD.encode() not in rejected.stderr
    assert b"yes" not in rejected.stdout
    # A server cannot turn an unsupported exchange into a later password attempt.
    retry = subprocess.run([program, "Password: "], env=environment, capture_output=True)
    assert retry.returncode != 0
    assert retry.stdout == b""


@pytest.mark.parametrize("packaged", [False, True], ids=["fallback", "packaged"])
def test_concurrent_password_prompts_disclose_only_once(tmp_path, monkeypatch, packaged):
    import subprocess
    from netops_core import askpass

    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    if packaged:
        monkeypatch.setenv(ASKPASS_PROGRAM_ENV, os.path.abspath(askpass.__file__))
    _, environment = ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    children = [subprocess.Popen([environment["SSH_ASKPASS"], "Password: "],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    answers = [child.communicate(timeout=10) for child in children]
    assert sum(child.returncode == 0 for child in children) == 1
    assert sum(out == PASSWORD.encode() + b"\n" for out, err in answers) == 1
    assert all(PASSWORD.encode() not in err for out, err in answers)


@pytest.mark.parametrize("packaged", [False, True], ids=["fallback", "packaged"])
def test_otp_after_an_accepted_password_is_unsupported_not_a_refusal(tmp_path, monkeypatch, packaged):
    import subprocess
    from netops_core import askpass

    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    if packaged:
        monkeypatch.setenv(ASKPASS_PROGRAM_ENV, os.path.abspath(askpass.__file__))
    _, environment = ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    program = environment["SSH_ASKPASS"]
    assert subprocess.run([program, "Password: "], env=environment, capture_output=True).returncode == 0
    otp = subprocess.run([program, "(u@h) Verification code: "], env=environment, capture_output=True)
    assert otp.returncode != 0 and otp.stdout == b""
    assert b"ssh_auth_method_unsupported" in otp.stderr
    again = subprocess.run([program, "Password: "], env=environment, capture_output=True)
    assert b"already requested" in again.stderr and again.stdout == b""


def test_temporary_askpass_runs_without_python_on_path(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.delenv(ASKPASS_PROGRAM_ENV, raising=False)
    _, environment = ssh_module._prepared(_workspace(tmp_path), "password", FakeCredential())
    environment = dict(environment, PATH="/nonexistent")
    answer = subprocess.run([environment["SSH_ASKPASS"], "Password: "], env=environment, capture_output=True)
    assert answer.stdout == PASSWORD.encode() + b"\n"
