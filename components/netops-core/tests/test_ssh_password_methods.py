import pytest

from netops_core import session, sftp, ssh


def client_argv(transport, identity):
    arguments = ("127.0.0.1", 2222, "synthetic", "/tmp/pin")
    if transport is ssh:
        arguments += ("true",)
    return transport.argv(*arguments, identity=identity)


def options(argv):
    return dict(argv[index + 1].split("=", 1) for index, value in enumerate(argv) if value == "-o")


@pytest.mark.parametrize("transport", (ssh, session, sftp))
def test_password_uses_one_authentication_method(transport):
    selected = options(client_argv(transport, None))
    assert selected.get("PreferredAuthentications") == "password"
    assert selected.get("KbdInteractiveAuthentication") == "no"
    assert selected["NumberOfPasswordPrompts"] == "1"
    assert selected["PubkeyAuthentication"] == "no"
    assert selected["BatchMode"] == "no"
    assert selected["StrictHostKeyChecking"] == "yes"


@pytest.mark.parametrize("transport", (ssh, session, sftp))
def test_password_method_selection_does_not_change_key_lane(transport):
    argv = client_argv(transport, "/tmp/identity")
    selected = options(argv)
    assert selected["BatchMode"] == "yes"
    assert selected["IdentitiesOnly"] == "yes"
    assert "PreferredAuthentications" not in selected
    assert "KbdInteractiveAuthentication" not in selected
    assert argv[argv.index("-i") + 1] == "/tmp/identity"
