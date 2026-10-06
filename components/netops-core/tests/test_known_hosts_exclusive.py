import shutil
import subprocess

import pytest

from netops_core import session, sftp, ssh

PIN = "/w/known_hosts"
IDENTITY = "/w/identity"
HOST = "fw-a.example.invalid"

pytestmark = pytest.mark.skipif(
    shutil.which("ssh") is None, reason="the OpenSSH client is needed to read the argument vector"
)


def resolved(line):
    arguments = ["ssh", "-G"] + ["-p" if item == "-P" else item for item in line[1:]]
    answer = subprocess.run(arguments, capture_output=True, text=True, timeout=30, check=True)
    settings = {}
    for row in answer.stdout.splitlines():
        name, _, value = row.partition(" ")
        settings[name] = value
    return settings


def built(kind, identity, legacy):
    if kind == "ssh":
        return ssh.argv(HOST, 22, "admin", PIN, "true", identity=identity, legacy=legacy)[:-1]
    if kind == "sftp":
        return sftp.argv(HOST, 22, "admin", PIN, identity=identity, legacy=legacy)
    return session.argv(HOST, 22, "admin", PIN, identity=identity, legacy=legacy)


@pytest.mark.parametrize("legacy", (None, "rsa-sha1", "rsa-sha1-dh14"))
@pytest.mark.parametrize("identity", (IDENTITY, None))
@pytest.mark.parametrize("kind", ("ssh", "sftp", "session"))
def test_the_pin_is_the_only_known_hosts_file_ssh_reads(kind, identity, legacy):
    settings = resolved(built(kind, identity, legacy))
    assert settings["userknownhostsfile"] == PIN
    assert settings["globalknownhostsfile"] == "/dev/null"
    assert settings["stricthostkeychecking"] == "true"
    assert "knownhostscommand" not in settings
