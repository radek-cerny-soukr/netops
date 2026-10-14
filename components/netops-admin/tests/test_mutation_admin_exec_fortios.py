from types import SimpleNamespace

import pytest

from netops_admin import exec_fortios, fortios
from netops_admin.errors import Rejected

ADMINS = 'config system admin\n edit "operator"\n set accprofile "ops-profile"\n next\nend\n'
PROFILE = 'config system accprofile\n edit "ops-profile"\n set fwgrp read\n next\nend\n'
HEADER = "#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0:vdom=0:user=example\n"
GLOBAL = HEADER + 'config system global\n set hostname "fw-example"\nend\n'


class Access:
    def __init__(self, table=ADMINS, login="operator"):
        self.table = table
        self.credential = SimpleNamespace(login=login)
        self.queries = []

    def query(self, command):
        self.queries.append(command)
        return self.table


def device(*accounts):
    return SimpleNamespace(accounts=tuple(accounts))


def test_the_account_fingerprint_follows_the_access_profile_in_the_snapshot():
    before = exec_fortios.accounts_check(Access(), device("operator"), GLOBAL + PROFILE)
    same = exec_fortios.accounts_check(Access(), device("operator"), GLOBAL + PROFILE)
    widened = exec_fortios.accounts_check(Access(), device("operator"), GLOBAL + PROFILE.replace("read", "read-write"))
    assert before == same
    assert widened != before
    assert before != fortios.admin_fingerprint(ADMINS)


def test_an_access_profile_missing_from_the_snapshot_refuses_the_account_check():
    with pytest.raises(Rejected) as caught:
        exec_fortios.accounts_check(Access(), device("operator"), GLOBAL)
    assert caught.value.reasons == ["an administrator access profile is not visible in the snapshot"]


def test_other_visible_administrators_are_refused_with_their_count():
    table = ADMINS.replace("end\n", ' edit "intruder"\n next\nend\n')
    access = Access(table)
    with pytest.raises(Rejected) as caught:
        exec_fortios.accounts_check(access, device("operator"), GLOBAL + PROFILE)
    assert caught.value.reasons == ["the write account sees other administrators than the configured ones (2 accounts)"]
    assert access.queries == [fortios.QUERY_ADMINS]


@pytest.mark.parametrize("body", ["config firewall address\nend\n", "config system global\n set timezone 28\nend\n"])
def test_a_snapshot_without_a_hostname_is_refused_by_name(body):
    with pytest.raises(Rejected) as caught:
        exec_fortios.hostname(None, HEADER + body)
    assert caught.value.reasons == ["the snapshot does not name the device hostname"]


def test_the_hostname_comes_from_system_global():
    assert exec_fortios.hostname(None, GLOBAL) == "fw-example"


def test_the_fortios_prompt_ends_on_dollar_or_hash_and_continues_on_an_angle():
    spec = exec_fortios.prompt_spec("fw-example")
    assert spec.anchor == b"\nfw-example"
    assert spec.ends == (b"$ ", b"# ")
    assert spec.continuation == b"\n> "
    assert spec.error is fortios.cli_error
