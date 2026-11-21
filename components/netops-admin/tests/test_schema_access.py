from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from netops_admin import access
from netops_admin.access import DeviceAccess, SchemaAccess
from netops_admin.errors import Rejected


def context(monkeypatch, inventory="known", current="root", bad_exit=False):
    value = object.__new__(SchemaAccess)
    value.device = SimpleNamespace(platform="fortios", address="192.0.2.1", check_address=None, port=22,
                                   legacy_ssh=None, schema={"vdoms": ["root", "VD1", "missing"]})
    value.credential = SimpleNamespace(login="write")
    value.check_credential = SimpleNamespace(login="check")
    value.spec = SimpleNamespace(anchor=b"fixture")
    value.base = object.__new__(DeviceAccess)
    value.base.device = value.device
    value.base.credential = value.credential
    value.base.check_credential = value.check_credential
    domains = {"root", "VD1"}
    sent = []
    created = []
    opened = []

    class Shell:
        context = None
        _closed = False

        def close(self):
            self._closed = True

        def run(self, line, **_limits):
            assert not self._closed
            sent.append(line)
            body, rc = "", 0
            if line.startswith("config "):
                self.context = line.split()[1]
            elif line.startswith("edit "):
                self.context = line.removeprefix("edit ").strip('"')
                if self.context not in domains:
                    domains.add(self.context)
                    created.append(self.context)
            elif line == "end":
                if not bad_exit:
                    self.context = None
            elif line == "get system status":
                body = f"Current virtual domain: {current}\n"
            elif line == "show full-configuration system vdom-property":
                assert self.context == "global"
                if inventory == "unreadable":
                    rc = 1
                elif inventory == "malformed":
                    body = "config system vdom-property\n"
                elif inventory == "wrong-table":
                    body = "config system global\nend\n"
                else:
                    names = sorted(domains) if inventory == "known" else []
                    entries = "".join(f'    edit "{name}"\n    next\n' for name in names)
                    body = f"config system vdom-property\n{entries}end\n"
            elif line == "show":
                body = "config firewall address\nend\n"
            return SimpleNamespace(rc=rc, stdout=body.encode(), continuation=False, context=self.context)

    @contextmanager
    def open_shell(_device, credential, **_options):
        opened.append(credential.login)
        shell = Shell()
        try:
            yield shell
        finally:
            shell.close()

    monkeypatch.setattr(access.session, "fortinet_session", open_shell)
    monkeypatch.setattr(access.fortinet_cli, "has_hostname", lambda _shell, _name: True)
    monkeypatch.setattr(access.fortinet_cli, "dialog", lambda shell, command, *_args, **_options: shell.run(command))
    return value, sent, created, opened


def test_missing_declared_vdom_is_refused_before_any_edit(monkeypatch):
    value, sent, created, _ = context(monkeypatch)
    with pytest.raises(Rejected):
        value._context("missing", "show")
    assert created == []
    assert not any(line.startswith("edit ") for line in sent)


@pytest.mark.parametrize("inventory", ["empty", "malformed", "wrong-table", "unreadable"])
def test_vdom_navigation_requires_complete_readable_inventory(monkeypatch, inventory):
    value, sent, created, _ = context(monkeypatch, inventory=inventory)
    with pytest.raises(Rejected):
        value._context("VD1", "show")
    assert created == []
    assert not any(line.startswith("edit ") for line in sent)


def test_vdom_outside_binding_is_refused_before_transport(monkeypatch):
    value, sent, created, _ = context(monkeypatch)
    with pytest.raises(Rejected):
        value._context("outside", "show")
    assert sent == created == []


def test_existing_vdom_is_verified_before_context_navigation(monkeypatch):
    value, sent, created, opened = context(monkeypatch)
    with value.base.operation():
        assert "config firewall address" in value._context("VD1", "show")
        value._context("root", "show")
    assert sent == ["config global", "show full-configuration system vdom-property", "end",
                    "config vdom", 'edit "VD1"', "show", "end",
                    "config global", "show full-configuration system vdom-property", "end",
                    "config vdom", 'edit "root"', "show", "end"]
    assert created == [] and opened == ["write"]


def test_independent_reader_in_current_vdom_avoids_edit_but_checks_inventory(monkeypatch):
    value, sent, created, opened = context(monkeypatch, current="VD1")
    with value.base.operation():
        assert "config firewall address" in value._context("VD1", "show", True)
        value._context("VD1", "show", True)
    assert sent == ["config global", "show full-configuration system vdom-property", "end",
                    "get system status", "show"] * 2
    assert created == [] and opened == ["write", "check"]


def test_global_read_leaves_verified_context_without_selecting_vdom(monkeypatch):
    value, sent, created, _ = context(monkeypatch)
    value._context(None, "show")
    assert sent == ["config global", "show", "end"] and created == []


def test_failed_context_exit_discards_answer_and_connection(monkeypatch):
    value, sent, _, opened = context(monkeypatch, bad_exit=True)
    with value.base.operation(), pytest.raises(Rejected, match="CLI context"):
        value._context(None, "show")
    assert sent == ["config global", "show", "end"] and opened == ["write"]
