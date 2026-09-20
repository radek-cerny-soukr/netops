import hashlib
import os
import re
from pathlib import Path
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

import pytest

from netops_auditor.collect import (
    CHANNEL_FILE,
    EMPTY_SHA256,
    ChannelEvent,
    CollectError,
    Snapshot,
    collect_file,
    completeness_finding,
    missing_sections,
)
from netops_auditor.findings import EVIDENCE_TYPES, Finding
from netops_core import prompt

CANARY = "KANARCI-RETEZEC-NESMI-UNIKNOUT"
DEVICE = "fw-example"
PLATFORM = "fortios"
PROFILE = "audit-readonly"
MOMENT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REQUIRED = ("system global", "system interface", "firewall policy", "firewall address")
EXOS_PLATFORM = "exos"
EXOS_REQUIRED = ("devmgr", "vlan", "stp", "poe")


@dataclass(frozen=True)
class InventoryEntry:
    device: str
    platform: str
    profile: str
    required_sections: tuple


def entry(profile=PROFILE, device=DEVICE):
    return InventoryEntry(device=device, platform=PLATFORM, profile=profile, required_sections=REQUIRED)


def collect_entry(record, source, now=None):
    return collect_file(record.device, record.platform, str(source), record.profile, now=now)


def config_text(canary=False):
    description = '        set description "%s"\n' % CANARY if canary else ""
    return (
        "config system global\n"
        '    set hostname "fw-example"\n'
        "end\n"
        "config system interface\n"
        '    edit "wan1"\n'
        "        set ip 192.0.2.10 255.255.255.0\n"
        "        set allowaccess ping\n"
        "%s"
        "    next\n"
        "end\n"
        "config firewall address\n"
        '    edit "lan-net"\n'
        "        set subnet 198.51.100.0 255.255.255.0\n"
        "    next\n"
        "end\n"
        "config firewall policy\n"
        "    edit 1\n"
        '        set srcintf "lan"\n'
        '        set comments "hub example.invalid"\n'
        "    next\n"
        "end\n"
    ) % description


def exos_config_text():
    return (
        "#\n"
        "# Module devmgr configuration.\n"
        "#\n"
        'configure snmp sysLocation "example-site"\n'
        "configure timezone name UTC\n"
        "#\n"
        "# Module vlan configuration.\n"
        "#\n"
        'create vlan "Mgmt"\n'
        "configure vlan Mgmt tag 10\n"
        "#\n"
        "# Module stp configuration.\n"
        "#\n"
        "disable stpd s0\n"
    )


def config_lines(text, minimum=12):
    return tuple(sorted({line.strip() for line in text.splitlines() if len(line.strip()) >= minimum}))


def write_config(directory, text, name="device.conf"):
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def event_values(event):
    return tuple(str(getattr(event, item.name)) for item in fields(event))


def clock_of(*moments):
    ticks = list(moments)

    def tick():
        return ticks.pop(0) if len(ticks) > 1 else ticks[0]

    return tick


def test_snapshot_and_event_describe_the_same_read(tmp_path):
    text = config_text()
    path = write_config(tmp_path, text)
    snapshot, event = collect_entry(entry(), path)
    assert isinstance(snapshot, Snapshot)
    assert isinstance(event, ChannelEvent)
    assert snapshot.device == DEVICE
    assert snapshot.platform == PLATFORM
    assert snapshot.channel == CHANNEL_FILE
    assert snapshot.source == str(path)
    assert snapshot.profile == PROFILE
    assert snapshot.text == text
    assert event.device == DEVICE
    assert event.channel == CHANNEL_FILE
    assert event.request == str(path)
    assert event.outcome == "ok"
    assert event.response_sha256 == snapshot.sha256
    assert event.response_bytes == snapshot.size_bytes
    assert snapshot.collected_at == event.finished_at


def test_channel_event_never_carries_the_configuration(tmp_path):
    text = config_text(canary=True)
    path = write_config(tmp_path, text)
    snapshot, event = collect_entry(entry(), path)
    assert CANARY in snapshot.text
    assert "text" not in {item.name for item in fields(ChannelEvent)}
    assert CANARY not in repr(event)
    for value in event_values(event):
        assert CANARY not in value
    for line in config_lines(text):
        assert line not in repr(event)
        for value in event_values(event):
            assert line not in value
    assert CANARY not in repr(snapshot)


def test_failed_event_never_carries_the_configuration(tmp_path):
    path = write_config(tmp_path, config_text(canary=True), name="device.bin")
    path.write_bytes(path.read_bytes() + b"\xff\xfe")
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(), path)
    event = caught.value.event
    assert event.outcome == "failed"
    assert CANARY not in repr(event)
    assert CANARY not in str(caught.value)
    for value in event_values(event):
        assert CANARY not in value


def test_missing_sections_keeps_the_order_of_the_request():
    text = "config system global\nend\n"
    assert missing_sections(text, REQUIRED, PLATFORM) == ("system interface", "firewall policy", "firewall address")


def test_missing_sections_ignores_indentation():
    text = "        config firewall policy\n        end\n"
    assert missing_sections(text, ("firewall policy",), PLATFORM) == ()


def test_missing_sections_matches_the_whole_section_name():
    text = "config system interface\nend\n"
    assert missing_sections(text, ("system",), PLATFORM) == ("system",)
    assert missing_sections(text, ("system interface",), PLATFORM) == ()


def test_missing_sections_returns_nothing_for_a_complete_snapshot():
    assert missing_sections(config_text(), REQUIRED, PLATFORM) == ()


def test_missing_sections_reports_each_section_once():
    text = "config system global\nend\n"
    assert missing_sections(text, ("firewall policy", "firewall policy"), PLATFORM) == ("firewall policy",)


def test_missing_sections_refuses_nonsense_input():
    with pytest.raises(CollectError):
        missing_sections(config_text(), ("",), PLATFORM)
    with pytest.raises(CollectError):
        missing_sections(None, REQUIRED, PLATFORM)


def test_missing_sections_needs_a_platform_it_knows():
    with pytest.raises(CollectError) as caught:
        missing_sections(config_text(), REQUIRED, "junos")
    assert "fortios, exos" in str(caught.value)
    assert "'junos'" in str(caught.value)
    with pytest.raises(CollectError):
        missing_sections(config_text(), REQUIRED, None)


def test_missing_sections_reads_the_module_headers_of_an_exos_dump():
    text = exos_config_text()
    assert missing_sections(text, ("devmgr", "vlan", "stp"), EXOS_PLATFORM) == ()
    assert missing_sections(text, EXOS_REQUIRED, EXOS_PLATFORM) == ("poe",)


def test_missing_sections_takes_only_the_header_line_on_exos():
    text = exos_config_text()
    assert missing_sections(text, ("Mgmt",), EXOS_PLATFORM) == ("Mgmt",)
    assert missing_sections(text, ("stpd s0",), EXOS_PLATFORM) == ("stpd s0",)
    assert missing_sections(text, ("configuration.",), EXOS_PLATFORM) == ("configuration.",)


def test_missing_sections_needs_the_whole_header_on_exos():
    text = exos_config_text() + "# Module poe\n"
    assert missing_sections(text, ("poe",), EXOS_PLATFORM) == ("poe",)


def test_missing_sections_measures_by_platform_and_does_not_guess():
    assert missing_sections(exos_config_text(), ("vlan",), PLATFORM) == ("vlan",)
    assert missing_sections(config_text(), ("system global",), EXOS_PLATFORM) == ("system global",)


def test_missing_sections_refuses_a_section_written_as_a_fortios_header():
    with pytest.raises(CollectError) as caught:
        missing_sections(config_text(), ("config system global",), PLATFORM)
    said = str(caught.value)
    assert "'config system global'" in said
    assert "config <section>" in said
    assert "'system global'" in said


def test_missing_sections_refuses_a_section_written_as_an_exos_header():
    with pytest.raises(CollectError) as caught:
        missing_sections(exos_config_text(), ("# Module vlan configuration.",), EXOS_PLATFORM)
    said = str(caught.value)
    assert "# Module <section> configuration." in said
    assert "'vlan'" in said


def test_missing_sections_refuses_a_half_written_exos_header():
    with pytest.raises(CollectError) as caught:
        missing_sections(exos_config_text(), ("# Module vlan",), EXOS_PLATFORM)
    assert "'vlan'" in str(caught.value)


def test_a_prefixed_section_is_refused_instead_of_reported_as_missing():
    for platform, section in ((PLATFORM, "config firewall policy"), (EXOS_PLATFORM, "# Module vlan")):
        with pytest.raises(CollectError):
            missing_sections(config_text() + exos_config_text(), (section,), platform)


def test_completeness_finding_has_the_shape_the_engine_takes():
    finding = completeness_finding(DEVICE, ("firewall policy", "system interface"))
    assert set(finding) == {"object_key", "section", "line", "evidence"}
    assert finding["line"] == 0
    assert finding["section"] == "snapshot"
    assert DEVICE in finding["object_key"]
    assert finding["evidence"] == {"missing_count": 2, "missing_sections": "firewall policy, system interface"}
    for value in finding["evidence"].values():
        assert isinstance(value, EVIDENCE_TYPES)
    built = Finding(
        rule_id="fortios.snapshot.incomplete",
        rule_version=1,
        device=DEVICE,
        object_key=finding["object_key"],
        severity="high",
        rule_class="fakt",
        section=finding["section"],
        line=finding["line"],
        evidence=tuple(sorted(finding["evidence"].items())),
    )
    assert built.as_dict()["line"] == 0


def test_completeness_finding_evidence_carries_no_configuration(tmp_path):
    text = config_text(canary=True)
    path = write_config(tmp_path, text)
    snapshot, _ = collect_entry(entry(), path)
    missing = missing_sections(snapshot.text, REQUIRED + ("vpn ipsec phase1-interface",), snapshot.platform)
    finding = completeness_finding(DEVICE, missing)
    assert finding["evidence"]["missing_count"] == 1
    assert CANARY not in repr(finding)
    for line in config_lines(text):
        assert line not in repr(finding)


def test_completeness_finding_is_none_when_nothing_is_missing():
    assert completeness_finding(DEVICE, ()) is None
    assert completeness_finding(DEVICE, missing_sections(config_text(), REQUIRED, PLATFORM)) is None


def test_missing_file_fails_but_leaves_a_trace(tmp_path):
    path = tmp_path / "nowhere.conf"
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(), path)
    event = caught.value.event
    assert event.outcome == "failed"
    assert event.channel == CHANNEL_FILE
    assert event.request == str(path)
    assert event.response_bytes == 0
    assert event.response_sha256 == EMPTY_SHA256
    assert MOMENT.match(event.started_at) and MOMENT.match(event.finished_at)


def test_directory_instead_of_a_file_fails_but_leaves_a_trace(tmp_path):
    target = tmp_path / "snapshots"
    target.mkdir()
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(), target)
    assert caught.value.event.outcome == "failed"
    assert caught.value.event.response_bytes == 0


def test_unreadable_file_fails_but_leaves_a_trace(tmp_path):
    path = write_config(tmp_path, config_text())
    path.chmod(0o000)
    try:
        with open(path, "rb"):
            readable = True
    except OSError:
        readable = False
    if readable:
        path.chmod(0o644)
        pytest.skip("this process reads a file with mode 000")
    try:
        with pytest.raises(CollectError) as caught:
            collect_entry(entry(), path)
    finally:
        path.chmod(0o644)
    assert caught.value.event.outcome == "failed"
    assert caught.value.event.request == str(path)
    assert caught.value.event.response_bytes == 0


def test_invalid_utf8_fails_and_the_trace_keeps_hash_and_length(tmp_path):
    path = tmp_path / "device.conf"
    data = b"config system global\n    set hostname \xff\xfe\nend\n"
    path.write_bytes(data)
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(), path)
    event = caught.value.event
    assert event.outcome == "failed"
    assert event.response_bytes == len(data)
    assert event.response_sha256 == hashlib.sha256(data).hexdigest()


def test_empty_file_is_a_successful_read(tmp_path):
    path = tmp_path / "device.conf"
    path.write_bytes(b"")
    snapshot, event = collect_entry(entry(), path)
    assert event.outcome == "ok"
    assert event.response_bytes == 0
    assert snapshot.sha256 == EMPTY_SHA256
    assert snapshot.text == ""


@pytest.mark.parametrize("profile", ["", "   ", None, 0])
def test_snapshot_without_a_profile_is_refused(tmp_path, profile):
    path = write_config(tmp_path, config_text())
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(profile=profile), path)
    assert caught.value.event is None


@pytest.mark.parametrize("device", ["", None])
def test_snapshot_without_a_device_is_refused(tmp_path, device):
    path = write_config(tmp_path, config_text())
    with pytest.raises(CollectError) as caught:
        collect_entry(entry(device=device), path)
    assert caught.value.event is None


def test_moments_are_iso_8601_utc_with_second_precision(tmp_path):
    path = write_config(tmp_path, config_text())
    snapshot, event = collect_entry(entry(), path)
    for value in (snapshot.collected_at, event.started_at, event.finished_at):
        assert MOMENT.match(value)
    assert event.finished_at >= event.started_at


def test_moments_are_converted_to_utc(tmp_path):
    path = write_config(tmp_path, config_text())
    local = datetime(2026, 9, 12, 12, 20, 30, 999999, tzinfo=timezone(timedelta(hours=2)))
    snapshot, event = collect_entry(entry(), path, now=clock_of(local))
    assert event.started_at == "2026-09-12T10:20:30Z"
    assert snapshot.collected_at == "2026-09-12T10:20:30Z"


def test_finished_at_is_never_before_started_at(tmp_path):
    path = write_config(tmp_path, config_text())
    started = datetime(2026, 9, 12, 10, 20, 30, tzinfo=timezone.utc)
    backwards = clock_of(started, started - timedelta(minutes=5))
    snapshot, event = collect_entry(entry(), path, now=backwards)
    assert event.started_at == "2026-09-12T10:20:30Z"
    assert event.finished_at == event.started_at
    assert snapshot.collected_at == event.finished_at


def test_naive_clock_is_refused(tmp_path):
    path = write_config(tmp_path, config_text())
    with pytest.raises(CollectError):
        collect_entry(entry(), path, now=clock_of(datetime(2026, 9, 12, 10, 20, 30)))


def test_sha256_is_taken_from_the_bytes_on_disk(tmp_path):
    path = tmp_path / "device.conf"
    data = b"config system global\r\n    set hostname \xc5\xbe\r\nend\r\n"
    path.write_bytes(data)
    snapshot, event = collect_entry(entry(), path)
    assert snapshot.sha256 == hashlib.sha256(data).hexdigest()
    assert snapshot.sha256 != hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    assert snapshot.size_bytes == len(data) == os.stat(path).st_size
    assert "\r\n" in snapshot.text
    assert event.response_sha256 == snapshot.sha256


def test_incomplete_snapshot_from_a_weaker_profile_is_reported(tmp_path):
    weak = "config system global\n    set hostname \"fw-example\"\nend\n"
    path = write_config(tmp_path, weak)
    record = entry(profile="read-only-limited")
    snapshot, event = collect_entry(record, path)
    assert event.outcome == "ok"
    assert snapshot.profile == "read-only-limited"
    missing = missing_sections(snapshot.text, record.required_sections, snapshot.platform)
    finding = completeness_finding(snapshot.device, missing)
    assert finding["evidence"]["missing_count"] == 3
    assert finding["evidence"]["missing_sections"] == "system interface, firewall policy, firewall address"


import ssl
import stat
import subprocess
from pathlib import Path

from netops_auditor.collect import (
    CHANNEL_REST,
    CHANNEL_SSH,
    PLATFORM_FORTIOS,
    REST_METHOD,
    REST_TARGET,
    REST_TIMEOUT_SECONDS,
    SSH_STEPS,
    SSH_TIMEOUT_SECONDS,
    collect_fortios_rest,
    collect_ssh,
)
from netops_core.hostkey import PREFIX as HOST_KEY_PREFIX
from netops_core.legacy_ssh import OPENSSH_OPTIONS, PROFILES
from netops_core.ssh import SAID_CHARS

CANARY_TOKEN = "KANARCI-TOKEN-NESMI-UNIKNOUT"
CANARY_KEY = "KANARCI-PRIVATNI-KLIC-NESMI-UNIKNOUT"
CANARY_PASSWORD = "KANARCI-HESLO-NESMI-UNIKNOUT"
HOST = "192.0.2.10"
LOGIN = "audit-ro"
REST_SOURCE = "https://192.0.2.10"
REST_URL = REST_SOURCE + REST_TARGET
REST_REQUEST = "%s %s" % (REST_METHOD, REST_URL)
SSH_SOURCE = "%s@%s" % (LOGIN, HOST)
PREFLIGHT_COMMAND = SSH_STEPS["fortios"][0].command
SSH_COMMAND = SSH_STEPS["fortios"][1].command
SSH_REQUEST = "%s %s" % (SSH_SOURCE, SSH_COMMAND)
PREFLIGHT_REQUEST = "%s %s" % (SSH_SOURCE, PREFLIGHT_COMMAND)
PIN = "0123456789abcdef" * 4
OTHER_PIN = "fedcba9876543210" * 4
KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIEdTwaiTIgcu/hVdAGf/B5Tu8i3/vYtTyb3SkSvXkYIi"
KEY_PIN = "SHA256:ainTqLVboX+ve469siLf72rOminn3mGxWCUt89zwYxc"
OTHER_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAINR23xHSURVIE0oubEpDDe9x6/dhC2YhG8K9mQ4EKU0T"
OTHER_KEY_PIN = "SHA256:ekSe0E/s7//Umlqy0NuwAdT1o4BqdTDGd3f2+hFgkoM"
BAD_PINS = (PIN[:-1], PIN + "a", PIN.replace("a", "g"), "", "   ", 0, 1, True, [PIN], {"sha256": PIN})
BAD_KEY_PINS = (
    None,
    KEY_PIN[len(HOST_KEY_PREFIX):],
    KEY_PIN[:-1],
    KEY_PIN + "A",
    "sha256:" + KEY_PIN[len(HOST_KEY_PREFIX):],
    HOST_KEY_PREFIX + "!" * 43,
    "",
    "   ",
    0,
    True,
    [KEY_PIN],
)
BAD_TIMEOUTS = (0, 0.0, -1, -0.5, None, "30", "", float("inf"), float("nan"), True, False, [30], {})


class FakeCredential:
    def __init__(self, secret=CANARY_TOKEN):
        self._secret = secret
        self.uses = 0

    def use(self):
        self.uses += 1
        return self._secret

    def __repr__(self):
        return "<FakeCredential>"

    def __str__(self):
        return "<FakeCredential>"


class FakeConnection:
    def __init__(self, log, fingerprint, status, body, error):
        self.log = log
        self._fingerprint = fingerprint
        self._status = status
        self._body = body
        self._error = error

    def fingerprint(self):
        self.log.append(("fingerprint",))
        if isinstance(self._fingerprint, Exception):
            raise self._fingerprint
        return self._fingerprint

    def request(self, method, target, headers):
        self.log.append(("request", method, target, dict(headers)))
        if self._error is not None:
            raise self._error
        return self._status, self._body

    def close(self):
        self.log.append(("close",))

    def __repr__(self):
        return "<FakeConnection>"


class FakeOpener:
    def __init__(self, fingerprint=PIN, status=200, body=None, error=None, refuse=None):
        self.fingerprint = fingerprint
        self.status = status
        self.body = config_text().encode("utf-8") if body is None else body
        self.error = error
        self.refuse = refuse
        self.calls = []
        self.log = []

    def __call__(self, host, port, timeout, pinned):
        self.calls.append({"host": host, "port": port, "timeout": timeout, "pinned": pinned})
        if self.refuse is not None:
            raise self.refuse
        return FakeConnection(self.log, self.fingerprint, self.status, self.body, self.error)

    def targets(self):
        return tuple(entry[2] for entry in self.log if entry[0] == "request")

    def headers(self):
        return tuple(entry[3] for entry in self.log if entry[0] == "request")

    def steps(self):
        return tuple(entry[0] for entry in self.log)


def rest_call(opener, credential=None, host=HOST, fingerprint=None, **kwargs):
    holder = FakeCredential() if credential is None else credential
    return collect_fortios_rest(
        DEVICE, host, holder, PROFILE, tls_fingerprint=fingerprint, opener=opener, **kwargs
    )


def rest_failure(opener, credential=None, **kwargs):
    with pytest.raises(CollectError) as caught:
        rest_call(opener, credential=credential, **kwargs)
    return caught.value


def test_rest_snapshot_and_event_describe_the_same_read():
    text = config_text()
    snapshot, event = rest_call(FakeOpener(body=text.encode("utf-8")))
    assert isinstance(snapshot, Snapshot) and isinstance(event, ChannelEvent)
    assert snapshot.device == DEVICE
    assert snapshot.platform == PLATFORM_FORTIOS
    assert snapshot.channel == CHANNEL_REST
    assert snapshot.source == REST_SOURCE
    assert snapshot.profile == PROFILE
    assert snapshot.text == text
    assert snapshot.sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert snapshot.size_bytes == len(text.encode("utf-8"))
    assert event.device == DEVICE
    assert event.channel == CHANNEL_REST
    assert event.request == REST_REQUEST
    assert event.outcome == "ok"
    assert event.response_sha256 == snapshot.sha256
    assert event.response_bytes == snapshot.size_bytes
    assert snapshot.collected_at == event.finished_at
    assert MOMENT.match(event.started_at) and event.finished_at >= event.started_at


def test_rest_url_never_carries_the_token():
    opener = FakeOpener()
    credential = FakeCredential()
    _, event = rest_call(opener, credential=credential)
    assert opener.targets() == (REST_TARGET,)
    assert REST_TARGET == "/api/v2/monitor/system/config/backup?scope=global"
    assert event.request == "POST https://192.0.2.10/api/v2/monitor/system/config/backup?scope=global"
    for target in opener.targets():
        assert CANARY_TOKEN not in target
        assert "access_token" not in target
        assert target.split("?", 1)[1] == "scope=global"
    assert CANARY_TOKEN not in event.request
    assert opener.headers() == ({"Authorization": "Bearer %s" % CANARY_TOKEN, "Accept": "text/plain"},)
    assert credential.uses == 1


def test_rest_token_never_leaks_from_a_successful_call():
    credential = FakeCredential()
    snapshot, event = rest_call(FakeOpener(), credential=credential)
    assert CANARY_TOKEN not in repr(event)
    assert CANARY_TOKEN not in repr(snapshot)
    assert CANARY_TOKEN not in repr(credential)
    assert CANARY_TOKEN not in snapshot.text
    for value in event_values(event):
        assert CANARY_TOKEN not in value


@pytest.mark.parametrize(
    "opener",
    (
        FakeOpener(refuse=ssl.SSLCertVerificationError("certificate verify failed")),
        FakeOpener(refuse=TimeoutError("timed out")),
        FakeOpener(refuse=OSError("no route to host")),
        FakeOpener(fingerprint=OTHER_PIN),
        FakeOpener(fingerprint=None),
        FakeOpener(fingerprint=RuntimeError("no certificate")),
        FakeOpener(error=TimeoutError("timed out")),
        FakeOpener(error=ssl.SSLError("record layer failure")),
        FakeOpener(status=401),
        FakeOpener(status=403),
        FakeOpener(status=500),
        FakeOpener(body=b"\xff\xfe"),
        FakeOpener(body="not bytes"),
        FakeOpener(status=None),
    ),
)
def test_rest_token_never_leaks_when_the_call_fails(opener):
    credential = FakeCredential()
    error = rest_failure(opener, credential=credential, fingerprint=PIN)
    assert CANARY_TOKEN not in str(error)
    assert CANARY_TOKEN not in repr(error)
    assert error.event is not None
    assert error.event.outcome == "failed"
    assert error.event.channel == CHANNEL_REST
    assert error.event.request == REST_REQUEST
    assert CANARY_TOKEN not in repr(error.event)
    for value in event_values(error.event):
        assert CANARY_TOKEN not in value


def test_rest_fingerprint_mismatch_never_sends_the_token():
    opener = FakeOpener(fingerprint=OTHER_PIN)
    credential = FakeCredential()
    error = rest_failure(opener, credential=credential, fingerprint=PIN)
    assert credential.uses == 0
    assert opener.targets() == ()
    assert opener.headers() == ()
    assert opener.steps() == ("fingerprint", "close")
    assert "does not match the pinned fingerprint" in str(error)
    assert CANARY_TOKEN not in str(error)
    assert error.event.outcome == "failed"
    assert error.event.response_bytes == 0
    assert error.event.response_sha256 == EMPTY_SHA256


def test_rest_verifies_the_certificate_before_it_sends_anything():
    opener = FakeOpener(fingerprint=PIN)
    credential = FakeCredential()
    snapshot, _ = rest_call(opener, credential=credential, fingerprint=PIN)
    assert opener.steps() == ("fingerprint", "request", "close")
    assert opener.calls == [{"host": HOST, "port": 443, "timeout": REST_TIMEOUT_SECONDS, "pinned": True}]
    assert credential.uses == 1
    assert snapshot.channel == CHANNEL_REST


def test_rest_pin_comparison_ignores_case():
    assert rest_call(FakeOpener(fingerprint=PIN.upper()), fingerprint=PIN)[1].outcome == "ok"
    assert rest_call(FakeOpener(fingerprint=PIN), fingerprint=PIN.upper())[1].outcome == "ok"


def test_rest_without_a_pin_leaves_the_chain_to_the_tls_stack():
    opener = FakeOpener()
    snapshot, event = rest_call(opener, fingerprint=None)
    assert opener.calls == [{"host": HOST, "port": 443, "timeout": REST_TIMEOUT_SECONDS, "pinned": False}]
    assert opener.steps() == ("request", "close")
    assert event.outcome == "ok" and snapshot.channel == CHANNEL_REST


@pytest.mark.parametrize("fingerprint", BAD_PINS)
def test_rest_refuses_a_broken_pin(fingerprint):
    opener = FakeOpener()
    with pytest.raises(CollectError) as caught:
        rest_call(opener, fingerprint=fingerprint)
    assert caught.value.event is None
    assert opener.calls == []
    assert "tls_fingerprint must be the sha256 certificate fingerprint" in str(caught.value)


def test_rest_answer_is_never_logged():
    text = config_text(canary=True)
    snapshot, event = rest_call(FakeOpener(body=text.encode("utf-8")), fingerprint=PIN)
    assert CANARY in snapshot.text
    assert CANARY not in repr(event)
    for value in event_values(event):
        assert CANARY not in value
    for line in config_lines(text):
        assert line not in repr(event)
        for value in event_values(event):
            assert line not in value
    assert event.response_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert event.response_bytes == len(text.encode("utf-8"))


@pytest.mark.parametrize("status", (201, 204, 301, 400, 401, 403, 404, 424, 500, 502, 503))
def test_rest_http_status_other_than_200_fails_with_an_event(status):
    body = b'{"status": "error"}'
    error = rest_failure(FakeOpener(status=status, body=body))
    assert "returned http status %d" % status in str(error)
    assert error.event.outcome == "failed"
    assert error.event.response_sha256 == hashlib.sha256(body).hexdigest()
    assert error.event.response_bytes == len(body)
    assert body.decode("utf-8") not in str(error)


def test_rest_failed_answer_is_never_logged():
    text = config_text(canary=True)
    error = rest_failure(FakeOpener(status=500, body=text.encode("utf-8")))
    assert CANARY not in str(error)
    assert CANARY not in repr(error.event)
    for value in event_values(error.event):
        assert CANARY not in value


def test_rest_timeout_of_the_device_fails_with_an_event():
    error = rest_failure(FakeOpener(error=TimeoutError("timed out")))
    assert error.event.outcome == "failed"
    assert "TimeoutError" in str(error)
    assert error.event.response_bytes == 0
    assert error.event.response_sha256 == EMPTY_SHA256


def test_rest_tls_failure_fails_with_an_event():
    error = rest_failure(FakeOpener(refuse=ssl.SSLCertVerificationError("certificate verify failed")))
    assert error.event.outcome == "failed"
    assert "cannot open %s" % REST_SOURCE in str(error)
    assert error.event.request == REST_REQUEST
    assert MOMENT.match(error.event.started_at) and MOMENT.match(error.event.finished_at)


def test_rest_non_utf8_answer_keeps_hash_and_length():
    body = b"config system global\n    set hostname \xff\xfe\nend\n"
    error = rest_failure(FakeOpener(body=body))
    assert error.event.outcome == "failed"
    assert error.event.response_bytes == len(body)
    assert error.event.response_sha256 == hashlib.sha256(body).hexdigest()
    assert "not valid UTF-8" in str(error)


def test_rest_default_timeout_is_finite_and_reaches_the_opener():
    assert 0 < REST_TIMEOUT_SECONDS < float("inf")
    opener = FakeOpener()
    collect_fortios_rest(DEVICE, HOST, FakeCredential(), PROFILE, opener=opener)
    assert opener.calls[0]["timeout"] == REST_TIMEOUT_SECONDS
    opener = FakeOpener()
    rest_call(opener, timeout=5)
    assert opener.calls[0]["timeout"] == 5.0


@pytest.mark.parametrize("timeout", BAD_TIMEOUTS)
def test_rest_refuses_a_timeout_that_is_not_a_positive_number(timeout):
    opener = FakeOpener()
    with pytest.raises(CollectError) as caught:
        rest_call(opener, timeout=timeout)
    assert caught.value.event is None
    assert opener.calls == []
    assert "timeout must be a positive number of seconds" in str(caught.value)


@pytest.mark.parametrize("credential", (CANARY_TOKEN, CANARY_TOKEN.encode("utf-8"), None, 1, object()))
def test_rest_refuses_anything_but_a_credential_store_handle(credential):
    opener = FakeOpener()
    with pytest.raises(CollectError) as caught:
        collect_fortios_rest(DEVICE, HOST, credential, PROFILE, opener=opener)
    assert caught.value.event is None
    assert opener.calls == []
    assert CANARY_TOKEN not in str(caught.value)
    assert "credential must be a credential store handle" in str(caught.value)


@pytest.mark.parametrize(
    "host,name,port,source",
    (
        ("192.0.2.10", "192.0.2.10", 443, "https://192.0.2.10"),
        ("https://192.0.2.10", "192.0.2.10", 443, "https://192.0.2.10"),
        ("https://192.0.2.10/", "192.0.2.10", 443, "https://192.0.2.10"),
        ("HTTPS://192.0.2.10", "192.0.2.10", 443, "https://192.0.2.10"),
        ("  192.0.2.10  ", "192.0.2.10", 443, "https://192.0.2.10"),
        ("192.0.2.10:8443", "192.0.2.10", 8443, "https://192.0.2.10:8443"),
        ("https://192.0.2.10:443", "192.0.2.10", 443, "https://192.0.2.10:443"),
        ("fw-a.example.invalid", "fw-a.example.invalid", 443, "https://fw-a.example.invalid"),
    ),
)
def test_rest_source_is_the_host_without_any_credentials(host, name, port, source):
    opener = FakeOpener()
    snapshot, event = rest_call(opener, host=host)
    assert snapshot.source == source
    assert event.request == "%s %s%s" % (REST_METHOD, source, REST_TARGET)
    assert opener.calls[0]["host"] == name
    assert opener.calls[0]["port"] == port
    assert "@" not in snapshot.source and CANARY_TOKEN not in snapshot.source


@pytest.mark.parametrize(
    "host",
    (
        "admin:%s@192.0.2.10" % CANARY_TOKEN,
        "https://admin:%s@192.0.2.10" % CANARY_TOKEN,
        "http://192.0.2.10",
        "ssh://192.0.2.10",
        "192.0.2.10/api/v2",
        "192.0.2.10?access_token=x",
        "192.0.2.10#fragment",
        "192.0.2.10:0",
        "192.0.2.10:99999",
        "192.0.2.10:api",
        ":443",
        "",
        "   ",
        None,
        1,
    ),
)
def test_rest_refuses_a_host_that_is_not_a_bare_host(host):
    opener = FakeOpener()
    with pytest.raises(CollectError) as caught:
        rest_call(opener, host=host)
    assert caught.value.event is None
    assert opener.calls == []
    assert CANARY_TOKEN not in str(caught.value)


@pytest.mark.parametrize(
    "opener",
    (
        FakeOpener(),
        FakeOpener(fingerprint=OTHER_PIN),
        FakeOpener(status=500),
        FakeOpener(error=TimeoutError("timed out")),
        FakeOpener(body=b"\xff\xfe"),
    ),
)
def test_rest_closes_the_connection_on_every_path(opener):
    try:
        rest_call(opener, fingerprint=PIN)
    except CollectError:
        pass
    assert opener.steps()[-1] == "close"
    assert opener.steps().count("close") == 1


@pytest.mark.parametrize("profile", ["", "   ", None, 0])
def test_rest_without_a_profile_is_refused(profile):
    opener = FakeOpener()
    with pytest.raises(CollectError) as caught:
        collect_fortios_rest(DEVICE, HOST, FakeCredential(), profile, opener=opener)
    assert caught.value.event is None
    assert opener.calls == []


def test_rest_moments_come_from_the_injected_clock():
    local = datetime(2026, 9, 12, 12, 20, 30, 999999, tzinfo=timezone(timedelta(hours=2)))
    snapshot, event = rest_call(FakeOpener(), now=clock_of(local))
    assert event.started_at == "2026-09-12T10:20:30Z"
    assert snapshot.collected_at == event.finished_at == "2026-09-12T10:20:30Z"


def test_rest_snapshot_feeds_the_completeness_check():
    weak = "config system global\n    set hostname \"fw-example\"\nend\n"
    snapshot, event = rest_call(FakeOpener(body=weak.encode("utf-8")), fingerprint=PIN)
    missing = missing_sections(snapshot.text, REQUIRED, snapshot.platform)
    assert missing == ("system interface", "firewall policy", "firewall address")
    assert completeness_finding(snapshot.device, missing)["evidence"]["missing_count"] == 3
    assert event.channel == CHANNEL_REST


CONSOLE_STANDARD = (
    "mode                : line\n"
    "baudrate            : 9600\n"
    "output              : standard\n"
    "login               : standard\n"
).encode("utf-8")
CONSOLE_MORE = CONSOLE_STANDARD.replace(b"output              : standard", b"output              : more")
CONSOLE_WITHOUT_OUTPUT = b"mode                : line\nbaudrate            : 9600\n"
EXOS_CONFIG = (
    "#\n"
    "# Module devmgr configuration.\n"
    "#\n"
    "configure snmp sysName \"example-switch\"\n"
    "configure vlan default delete ports all\n"
).encode("utf-8")
WRITE_MARKERS = ("config system console", "set output", "config ", "set ", "execute ")
KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
KEY_FOOTER = "-----END " + "OPENSSH PRIVATE KEY-----"
PRIVATE_KEY = "%s\n%s\n%s\n" % (KEY_HEADER, CANARY_KEY, KEY_FOOTER)
MANDATED_KEY_OPTIONS = (
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "IdentitiesOnly=yes",
    "ClearAllForwardings=yes",
    "ProxyCommand=none",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
)
MANDATED_PASSWORD_OPTIONS = (
    "BatchMode=no",
    "StrictHostKeyChecking=yes",
    "NumberOfPasswordPrompts=1",
    "PubkeyAuthentication=no",
)


class FakeResult:
    def __init__(self, returncode, stdout, stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class SshCredential:
    def __init__(self, secret=PRIVATE_KEY, kind="ssh-key", login=LOGIN):
        self.kind = kind
        self.login = login
        self._secret = secret
        self.uses = 0

    def use(self):
        self.uses += 1
        return self._secret

    def __repr__(self):
        return "<SshCredential>"

    def __str__(self):
        return "<SshCredential>"


class FakeRunner:
    def __init__(
        self,
        platform=PLATFORM,
        blob=KEY_BLOB,
        scan=None,
        scan_code=0,
        scan_error=None,
        console=None,
        console_code=0,
        console_error=None,
        code=0,
        stdout=None,
        stderr=b"",
        error=None,
    ):
        self.steps = SSH_STEPS[platform]
        self.scan = ("%s ssh-ed25519 %s\n" % (HOST, blob)).encode("utf-8") if scan is None else scan
        self.scan_code = scan_code
        self.scan_error = scan_error
        self.console = CONSOLE_STANDARD if console is None else console
        self.console_code = console_code
        self.console_error = console_error
        self.code = code
        self.stdout = config_text().encode("utf-8") if stdout is None else stdout
        self.stderr = stderr
        self.error = error
        self.calls = []
        self.known_hosts = None
        self.identity = None
        self.identity_mode = None
        self.secret = None
        self.secret_mode = None
        self.workspace = None

    def __call__(self, argv, **options):
        environment = options.get("env")
        self.calls.append(
            {
                "argv": list(argv),
                "timeout": options.get("timeout"),
                "env": None if environment is None else dict(environment),
            }
        )
        if argv[0] == "ssh-keyscan":
            if self.scan_error is not None:
                raise self.scan_error
            return FakeResult(self.scan_code, self.scan)
        self._look(argv, environment or {})
        if self.steps[0].field and argv[-1] == self.steps[0].command:
            if self.console_error is not None:
                raise self.console_error
            return FakeResult(self.console_code, self.console)
        if self.error is not None:
            raise self.error
        return FakeResult(self.code, self.stdout, self.stderr)

    def _look(self, argv, environment):
        for item in argv:
            if item.startswith("UserKnownHostsFile="):
                known_hosts = item.split("=", 1)[1]
                self.known_hosts = Path(known_hosts).read_text(encoding="utf-8")
                self.workspace = os.path.dirname(known_hosts)
        if "-i" in argv:
            identity = argv[argv.index("-i") + 1]
            self.identity = Path(identity).read_bytes()
            self.identity_mode = stat.S_IMODE(os.stat(identity).st_mode)
        held = environment.get("NETOPS_ASKPASS_FILE")
        if held:
            self.secret = Path(held).read_bytes()
            self.secret_mode = stat.S_IMODE(os.stat(held).st_mode)

    def argv(self, index=-1):
        return self.calls[index]["argv"]

    def env(self, index=-1):
        return self.calls[index]["env"]

    def commands(self):
        return [call["argv"][0] if call["argv"][0] != "ssh" else call["argv"][-1] for call in self.calls]


def ssh_call(
    runner,
    credential=None,
    platform=PLATFORM,
    address=HOST,
    port=22,
    pin=KEY_PIN,
    **kwargs
):
    holder = SshCredential() if credential is None else credential
    return collect_ssh(
        DEVICE, platform, address, port, holder, pin, run=runner, keyscan=runner, **kwargs
    )


def ssh_failure(runner, credential=None, **kwargs):
    with pytest.raises(CollectError) as caught:
        ssh_call(runner, credential=credential, **kwargs)
    return caught.value


def algorithm_options(argv):
    return [item for item in argv if item.startswith(ALGORITHM_OPTION_PREFIXES)]


ALGORITHM_OPTION_PREFIXES = (
    "HostKeyAlgorithms=",
    "PubkeyAcceptedAlgorithms=",
    "KexAlgorithms=",
    "Ciphers=",
    "MACs=",
    "HostbasedAcceptedAlgorithms=",
)
LEGACY_PROFILE = "rsa-sha1"
LEGACY_OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")


def test_ssh_steps_are_a_table_per_platform():
    assert tuple(SSH_STEPS) == ("fortios", "exos")
    assert [step.command for step in SSH_STEPS["fortios"]] == ["get system console", "show"]
    assert [step.command for step in SSH_STEPS["exos"]] == ["show configuration"]
    assert (SSH_STEPS["fortios"][0].field, SSH_STEPS["fortios"][0].expect) == ("output", "standard")
    assert (SSH_STEPS["exos"][0].field, SSH_STEPS["exos"][0].expect) == ("", "")
    assert [step.snapshot for step in SSH_STEPS["fortios"]] == [False, True]
    assert [step.snapshot for step in SSH_STEPS["exos"]] == [True]
    assert [step.prompt for step in SSH_STEPS["fortios"]] == [True, True]
    assert [step.prompt for step in SSH_STEPS["exos"]] == [True]
    for steps in SSH_STEPS.values():
        assert sum(1 for step in steps if step.snapshot) == 1


@pytest.mark.parametrize(
    "platform",
    ("fortiswitch", "ios", "junos", "FortiOS", "EXOS", "", "   ", None, 1, True, ["exos"]),
)
def test_ssh_refuses_a_platform_without_a_step_table(platform):
    runner = FakeRunner()
    with pytest.raises(CollectError) as caught:
        ssh_call(runner, platform=platform)
    assert caught.value.event is None
    assert runner.calls == []
    assert "platform must be one of fortios, exos" in str(caught.value)


def test_ssh_snapshot_and_events_describe_the_same_read():
    text = config_text()
    snapshot, events = ssh_call(FakeRunner(stdout=text.encode("utf-8")))
    preflight, event = events
    assert isinstance(snapshot, Snapshot)
    assert isinstance(preflight, ChannelEvent) and isinstance(event, ChannelEvent)
    assert snapshot.device == DEVICE
    assert snapshot.platform == PLATFORM
    assert snapshot.channel == CHANNEL_SSH
    assert snapshot.source == SSH_SOURCE
    assert snapshot.text == text
    assert snapshot.sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert event.channel == preflight.channel == CHANNEL_SSH
    assert preflight.request == PREFLIGHT_REQUEST
    assert event.request == SSH_REQUEST
    assert preflight.outcome == event.outcome == "ok"
    assert event.response_sha256 == snapshot.sha256
    assert event.response_bytes == snapshot.size_bytes
    assert snapshot.collected_at == event.finished_at


def test_the_snapshot_profile_is_the_login_of_the_credential():
    snapshot, _ = ssh_call(FakeRunner(), credential=SshCredential(login="audit-ro-2"))
    assert snapshot.profile == "audit-ro-2"
    assert snapshot.source == "audit-ro-2@%s" % HOST


def test_ssh_fortios_asks_the_console_before_it_reads_the_configuration():
    runner = FakeRunner()
    ssh_call(runner)
    assert runner.commands() == ["ssh-keyscan", "get system console", "show"]
    assert len(runner.calls) == 3


def test_ssh_exos_reads_the_configuration_with_no_preamble():
    runner = FakeRunner(platform="exos", stdout=EXOS_CONFIG)
    snapshot, events = ssh_call(runner, platform="exos")
    assert runner.commands() == ["ssh-keyscan", "show configuration"]
    assert snapshot.platform == "exos"
    assert snapshot.text == EXOS_CONFIG.decode("utf-8")
    assert [event.request for event in events] == ["%s show configuration" % SSH_SOURCE]
    assert [event.outcome for event in events] == ["ok"]


def test_ssh_exos_still_needs_a_configuration_to_come_back():
    runner = FakeRunner(platform="exos", stdout=b"")
    error = ssh_failure(runner, platform="exos")
    assert "returned an empty answer" in str(error)
    assert error.event.request == "%s show configuration" % SSH_SOURCE
    assert error.event.outcome == "failed"


def test_ssh_fortios_pager_stops_the_collection_and_changes_nothing():
    runner = FakeRunner(console=CONSOLE_MORE)
    credential = SshCredential()
    error = ssh_failure(runner, credential=credential)
    assert "the auditor does not change device configuration" in str(error)
    assert "set console output to standard first" in str(error)
    assert "'more'" in str(error)
    assert runner.commands() == ["ssh-keyscan", "get system console"]
    for call in runner.calls:
        for item in call["argv"]:
            for marker in WRITE_MARKERS:
                assert marker not in item
    assert error.event.request == PREFLIGHT_REQUEST
    assert error.event.outcome == "failed"
    assert error.event.response_sha256 == hashlib.sha256(CONSOLE_MORE).hexdigest()
    assert CANARY_KEY not in str(error)


def test_ssh_console_answer_without_the_output_field_stops_the_collection():
    runner = FakeRunner(console=CONSOLE_WITHOUT_OUTPUT)
    error = ssh_failure(runner)
    assert "cannot read output of" in str(error)
    assert runner.commands() == ["ssh-keyscan", "get system console"]
    assert error.event.request == PREFLIGHT_REQUEST
    assert error.event.outcome == "failed"
    assert error.event.response_bytes == len(CONSOLE_WITHOUT_OUTPUT)


@pytest.mark.parametrize(
    "runner",
    (
        FakeRunner(console_code=1),
        FakeRunner(console="not bytes"),
        FakeRunner(console_error=subprocess.TimeoutExpired(["ssh"], 1)),
        FakeRunner(console_error=OSError("ssh binary not found")),
    ),
)
def test_ssh_preflight_failure_fails_with_an_event(runner):
    error = ssh_failure(runner)
    assert error.event is not None
    assert error.event.outcome == "failed"
    assert error.event.channel == CHANNEL_SSH
    assert error.event.request == PREFLIGHT_REQUEST
    assert runner.commands() == ["ssh-keyscan", "get system console"]


def test_ssh_console_answer_is_never_logged():
    runner = FakeRunner()
    _, events = ssh_call(runner)
    assert "standard" not in repr(events[0])
    for value in event_values(events[0]):
        assert "baudrate" not in value


@pytest.mark.parametrize("platform", ("fortios", "exos"))
def test_ssh_argv_binds_every_mandated_option(platform):
    runner = FakeRunner(platform=platform, stdout=EXOS_CONFIG)
    ssh_call(runner, platform=platform)
    for index, step in enumerate(SSH_STEPS[platform], start=1):
        argv = runner.argv(index)
        assert argv[0] == "ssh"
        assert argv[1:3] == ["-F", "/dev/null"]
        for option in MANDATED_KEY_OPTIONS:
            assert argv.count(option) == 1
            assert argv[argv.index(option) - 1] == "-o"
        assert not [
            item
            for item in argv
            if item.startswith("StrictHostKeyChecking=") and item != "StrictHostKeyChecking=yes"
        ]
        assert argv[-2] == "%s@%s" % (LOGIN, HOST)
        assert argv[-1] == step.command


def test_ssh_argv_points_at_a_known_hosts_file_with_the_pinned_key():
    runner = FakeRunner()
    ssh_call(runner)
    argv = runner.argv()
    pointed = [item for item in argv if item.startswith("UserKnownHostsFile=")]
    assert len(pointed) == 1
    assert argv[argv.index(pointed[0]) - 1] == "-o"
    assert runner.known_hosts == "%s ssh-ed25519 %s\n" % (HOST, KEY_BLOB)


def test_ssh_key_never_reaches_argv_or_the_environment():
    runner = FakeRunner()
    credential = SshCredential()
    ssh_call(runner, credential=credential)
    for call in runner.calls:
        for item in call["argv"]:
            assert CANARY_KEY not in item
        for value in (call["env"] or {}).values():
            assert CANARY_KEY not in value
    assert set(runner.env().keys()) == {"PATH", "HOME", "LC_ALL"}
    assert runner.identity.startswith(KEY_HEADER.encode("utf-8"))
    assert CANARY_KEY.encode("utf-8") in runner.identity
    assert runner.identity_mode == 0o600
    assert credential.uses == len(runner.calls) - 1
    assert "-i" in runner.argv()


def test_ssh_password_authenticates_and_never_reaches_argv_or_the_environment():
    runner = FakeRunner()
    credential = SshCredential(secret=CANARY_PASSWORD, kind="password")
    snapshot, events = ssh_call(runner, credential=credential)
    assert snapshot.profile == LOGIN
    assert [event.outcome for event in events] == ["ok", "ok"]
    for call in runner.calls:
        for item in call["argv"]:
            assert CANARY_PASSWORD not in item
        for value in (call["env"] or {}).values():
            assert CANARY_PASSWORD not in value
    for option in MANDATED_PASSWORD_OPTIONS:
        assert runner.argv().count(option) == 1
    assert "BatchMode=yes" not in runner.argv()
    assert "-i" not in runner.argv()
    assert runner.secret.startswith(CANARY_PASSWORD.encode("utf-8"))
    assert runner.secret_mode == 0o600
    assert runner.env()["SSH_ASKPASS_REQUIRE"] == "force"
    assert runner.env()["NETOPS_ASKPASS_FILE"].startswith(runner.workspace)
    assert CANARY_PASSWORD not in repr(snapshot)


def test_ssh_refuses_a_credential_of_another_kind():
    runner = FakeRunner()
    error = ssh_failure(runner, credential=SshCredential(kind="api-token", login=None))
    assert "kind password or ssh-key" in str(error)
    assert error.event.outcome == "failed"
    assert runner.commands() == ["ssh-keyscan"]


@pytest.mark.parametrize(
    "runner",
    (
        FakeRunner(blob=OTHER_BLOB),
        FakeRunner(scan=b""),
        FakeRunner(scan=b"# 192.0.2.10:22 SSH-2.0-OpenSSH\n"),
        FakeRunner(scan_error=OSError("ssh-keyscan not found")),
        FakeRunner(scan_error=subprocess.TimeoutExpired(["ssh-keyscan"], 1)),
        FakeRunner(console=CONSOLE_MORE),
        FakeRunner(console_code=1),
        FakeRunner(console_error=OSError("ssh binary not found")),
        FakeRunner(code=255),
        FakeRunner(code=1),
        FakeRunner(stdout=b""),
        FakeRunner(stdout=b"\xff\xfe"),
        FakeRunner(stdout="not bytes"),
        FakeRunner(error=subprocess.TimeoutExpired(["ssh"], 1)),
        FakeRunner(error=OSError("ssh binary not found")),
    ),
)
def test_ssh_credential_never_leaks_when_the_call_fails(runner):
    credential = SshCredential()
    error = ssh_failure(runner, credential=credential)
    assert CANARY_KEY not in str(error)
    assert CANARY_KEY not in repr(error)
    assert error.event is not None
    assert error.event.outcome == "failed"
    assert error.event.channel == CHANNEL_SSH
    assert error.event.request in (PREFLIGHT_REQUEST, SSH_REQUEST)
    for value in event_values(error.event):
        assert CANARY_KEY not in value


def test_ssh_credential_never_leaks_from_a_successful_call():
    credential = SshCredential()
    snapshot, events = ssh_call(FakeRunner(), credential=credential)
    assert CANARY_KEY not in repr(snapshot)
    assert CANARY_KEY not in repr(credential)
    assert CANARY_KEY not in snapshot.text
    for event in events:
        assert CANARY_KEY not in repr(event)
        for value in event_values(event):
            assert CANARY_KEY not in value


def test_ssh_host_key_mismatch_stops_before_the_connection():
    runner = FakeRunner(blob=OTHER_BLOB)
    credential = SshCredential()
    error = ssh_failure(runner, credential=credential)
    assert credential.uses == 0
    assert len(runner.calls) == 1
    assert runner.calls[0]["argv"][0] == "ssh-keyscan"
    assert runner.identity is None
    assert "no offered host key matches the pinned fingerprint" in str(error)
    assert KEY_PIN in str(error)
    assert error.event.outcome == "failed"
    assert error.event.request == PREFLIGHT_REQUEST
    assert error.event.response_bytes == 0
    assert error.event.response_sha256 == EMPTY_SHA256


def test_ssh_host_key_scan_is_bounded_and_targets_the_device():
    runner = FakeRunner()
    ssh_call(runner, timeout=17)
    scan = runner.calls[0]["argv"]
    assert scan[0] == "ssh-keyscan"
    assert scan[-1] == HOST
    assert ["-T", "17"] == scan[1:3]
    assert ["-p", "22"] == scan[3:5]
    assert [call["timeout"] for call in runner.calls] == [17.0, 17.0, 17.0]


def test_ssh_workspace_is_removed_after_the_call():
    runner = FakeRunner()
    ssh_call(runner)
    assert runner.workspace and "netops-core-" in runner.workspace
    assert not os.path.exists(runner.workspace)
    runner = FakeRunner(code=255)
    ssh_failure(runner)
    assert not os.path.exists(runner.workspace)
    runner = FakeRunner(console=CONSOLE_MORE)
    ssh_failure(runner)
    assert not os.path.exists(runner.workspace)


@pytest.mark.parametrize("pin", BAD_KEY_PINS)
def test_ssh_refuses_a_broken_or_missing_host_key_pin(pin):
    runner = FakeRunner()
    with pytest.raises(CollectError) as caught:
        ssh_call(runner, pin=pin)
    assert runner.calls == []
    assert caught.value.event.outcome == "failed"
    assert "host_key_fingerprint must hold the sha256 host key fingerprint" in str(caught.value)


def test_ssh_nonzero_exit_fails_with_an_event():
    runner = FakeRunner(code=255, stdout=b"Permission denied (publickey).\n")
    error = ssh_failure(runner)
    assert "failed with exit code 255" in str(error)
    assert str(error).startswith(SSH_REQUEST)
    assert error.event.outcome == "failed"
    assert error.event.request == SSH_REQUEST
    assert error.event.response_sha256 == EMPTY_SHA256


def test_ssh_empty_answer_fails_with_an_event():
    error = ssh_failure(FakeRunner(stdout=b""))
    assert "returned an empty answer" in str(error)
    assert error.event.outcome == "failed"
    assert error.event.response_bytes == 0
    assert error.event.response_sha256 == EMPTY_SHA256


def test_ssh_timeout_fails_with_an_event():
    error = ssh_failure(FakeRunner(error=subprocess.TimeoutExpired(["ssh"], 120)))
    assert error.event.outcome == "failed"
    assert "did not finish within" in str(error)
    assert error.event.response_bytes == 0


def test_ssh_non_utf8_answer_keeps_hash_and_length():
    body = b"config system global\n    set hostname \xff\xfe\nend\n"
    error = ssh_failure(FakeRunner(stdout=body))
    assert "not valid UTF-8" in str(error)
    assert error.event.outcome == "failed"
    assert error.event.response_bytes == len(body)
    assert error.event.response_sha256 == hashlib.sha256(body).hexdigest()


def test_ssh_answer_is_never_logged():
    text = config_text(canary=True)
    snapshot, events = ssh_call(FakeRunner(stdout=text.encode("utf-8")))
    event = events[1]
    assert CANARY in snapshot.text
    assert CANARY not in repr(event)
    for value in event_values(event):
        assert CANARY not in value
    for line in config_lines(text):
        assert line not in repr(event)
        for value in event_values(event):
            assert line not in value
    assert event.response_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_ssh_default_timeout_is_finite_and_reaches_the_runner():
    assert 0 < SSH_TIMEOUT_SECONDS < float("inf")
    runner = FakeRunner()
    collect_ssh(DEVICE, PLATFORM, HOST, 22, SshCredential(), KEY_PIN, run=runner, keyscan=runner)
    assert [call["timeout"] for call in runner.calls] == [SSH_TIMEOUT_SECONDS] * 3


@pytest.mark.parametrize("timeout", BAD_TIMEOUTS)
def test_ssh_refuses_a_timeout_that_is_not_a_positive_number(timeout):
    runner = FakeRunner()
    with pytest.raises(CollectError) as caught:
        ssh_call(runner, timeout=timeout)
    assert caught.value.event is None
    assert runner.calls == []
    assert "timeout must be a positive number of seconds" in str(caught.value)


@pytest.mark.parametrize("credential", (CANARY_KEY, CANARY_KEY.encode("utf-8"), None, 1, object()))
def test_ssh_refuses_anything_but_a_credential_store_handle(credential):
    runner = FakeRunner()
    with pytest.raises(CollectError) as caught:
        collect_ssh(DEVICE, PLATFORM, HOST, 22, credential, KEY_PIN, run=runner, keyscan=runner)
    assert caught.value.event is None
    assert runner.calls == []
    assert CANARY_KEY not in str(caught.value)


@pytest.mark.parametrize(
    "address,port,source",
    (
        ("192.0.2.10", 22, "audit-ro@192.0.2.10"),
        ("192.0.2.10", 2222, "audit-ro@192.0.2.10:2222"),
        ("fw-a.example.invalid", 22, "audit-ro@fw-a.example.invalid"),
    ),
)
def test_ssh_source_is_the_login_and_the_address_of_the_device(address, port, source):
    runner = FakeRunner(scan=("[%s]:%d ssh-ed25519 %s\n" % (address, port, KEY_BLOB)).encode("utf-8"))
    snapshot, events = ssh_call(runner, address=address, port=port)
    assert snapshot.source == source
    assert events[0].request == "%s get system console" % source
    assert events[1].request == "%s show" % source
    assert runner.argv()[-2] == "%s@%s" % (LOGIN, address)
    assert ["-p", str(port)] == runner.argv()[-4:-2]
    assert runner.calls[0]["argv"][-1] == address


@pytest.mark.parametrize(
    "address",
    ("audit-ro@192.0.2.10", "-oProxyCommand=touch /tmp/pwned", "ssh://192.0.2.10", "192.0.2.10/x", "", None, 1),
)
def test_ssh_refuses_an_address_that_is_not_a_bare_host(address):
    runner = FakeRunner()
    with pytest.raises(CollectError):
        ssh_call(runner, address=address)
    assert runner.calls == []


@pytest.mark.parametrize("port", (0, 65536, None, "22", True, -1))
def test_ssh_refuses_a_port_outside_the_range(port):
    runner = FakeRunner()
    with pytest.raises(CollectError):
        ssh_call(runner, port=port)
    assert runner.calls == []


@pytest.mark.parametrize(
    "login",
    ("-oProxyCommand=touch /tmp/pwned", "audit ro", "audit@ro", "audit:ro", "", "   ", None, 1),
)
def test_ssh_refuses_a_login_that_could_become_an_option(login):
    runner = FakeRunner()
    error = ssh_failure(runner, credential=SshCredential(login=login))
    assert "login" in str(error)
    assert runner.commands() == ["ssh-keyscan"]


@pytest.mark.parametrize("platform", ("fortios", "exos"))
def test_ssh_sends_the_commands_of_the_table_verbatim(platform):
    runner = FakeRunner(platform=platform, stdout=EXOS_CONFIG)
    _, events = ssh_call(runner, platform=platform)
    sent = [call["argv"][-1] for call in runner.calls[1:]]
    assert sent == [step.command for step in SSH_STEPS[platform]]
    assert [event.request for event in events] == [
        "%s %s" % (SSH_SOURCE, step.command) for step in SSH_STEPS[platform]
    ]


def test_ssh_moments_come_from_the_injected_clock():
    local = datetime(2026, 9, 12, 12, 20, 30, 999999, tzinfo=timezone(timedelta(hours=2)))
    snapshot, events = ssh_call(FakeRunner(), now=clock_of(local))
    assert events[0].started_at == "2026-09-12T10:20:30Z"
    assert events[1].started_at == "2026-09-12T10:20:30Z"
    assert snapshot.collected_at == events[1].finished_at == "2026-09-12T10:20:30Z"


def test_ssh_snapshot_feeds_the_completeness_check():
    weak = "config system global\n    set hostname \"fw-example\"\nend\n"
    snapshot, events = ssh_call(FakeRunner(stdout=weak.encode("utf-8")))
    missing = missing_sections(snapshot.text, REQUIRED, snapshot.platform)
    assert missing == ("system interface", "firewall policy", "firewall address")
    assert completeness_finding(snapshot.device, missing)["evidence"]["missing_count"] == 3
    assert events[1].channel == CHANNEL_SSH


def test_ssh_talks_only_through_the_injected_runners():
    runner = FakeRunner()
    ssh_call(runner)
    assert [call["argv"][0] for call in runner.calls] == ["ssh-keyscan", "ssh", "ssh"]
    assert len(runner.calls) == 3


CONSOLE_PROMPTED = (
    "FortiGate-80F # output              : standard \n"
    "login               : enable \n"
    "fortiexplorer       : enable \n"
    "\n"
    "FortiGate-80F #"
).encode("utf-8")
CONFIG_BODY = (
    "#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0\n"
    "config system global\n"
    '    set hostname "fw-example"\n'
    "end\n"
    "config system interface\n"
    '    edit "wan1"\n'
    "        set ip 192.0.2.10 255.255.255.0\n"
    "    next\n"
    "end\n"
    "config firewall address\n"
    '    edit "lan-net"\n'
    "        set subnet 198.51.100.0 255.255.255.0\n"
    "    next\n"
    "end\n"
    "config firewall policy\n"
    "    edit 1\n"
    '        set srcintf "lan"\n'
    "    next\n"
    "end\n"
)
CONFIG_PROMPTED = ("FortiGate-80F # " + CONFIG_BODY + "FortiGate-80F #").encode("utf-8")
HASH_BODY = (
    "#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0\n"
    "config firewall address\n"
    '    edit "net # 42"\n'
    '        set comment "sprava # 42"\n'
    "    next\n"
    "end\n"
    "# a comment line that starts with a hash\n"
    "config system global\n"
    '    set alias "FortiGate-80F #"\n'
    "end\n"
)
HASH_PROMPTED = ("FortiGate-80F # " + HASH_BODY + "FortiGate-80F #").encode("utf-8")
VDOM_PROMPTED = ("FortiGate-80F (global) # " + CONFIG_BODY + "FortiGate-80F (global) #").encode("utf-8")
EXOS_BODY = (
    "#\n"
    "# Module devmgr configuration.\n"
    "#\n"
    'configure snmp sysName "example-switch"\n'
    'configure ports 1 display-string "uplink # 3"\n'
)
EXOS_PROMPTED = ("* example-switch.5 # " + EXOS_BODY + "* example-switch.5 #").encode("utf-8")


def test_ssh_preflight_reads_the_field_through_the_prompt():
    runner = FakeRunner(console=CONSOLE_PROMPTED)
    snapshot, events = ssh_call(runner)
    assert runner.commands() == ["ssh-keyscan", "get system console", "show"]
    assert events[0].outcome == "ok"
    assert snapshot.channel == CHANNEL_SSH


def test_ssh_preflight_still_sees_a_pager_through_the_prompt():
    prompted = CONSOLE_PROMPTED.replace(b": standard ", b": more ")
    error = ssh_failure(FakeRunner(console=prompted))
    assert "the auditor does not change device configuration" in str(error)
    assert "'more'" in str(error)
    assert error.event.request == PREFLIGHT_REQUEST


def test_ssh_snapshot_drops_the_prompt_from_both_ends():
    runner = FakeRunner(console=CONSOLE_PROMPTED, stdout=CONFIG_PROMPTED)
    snapshot, _ = ssh_call(runner)
    assert snapshot.text == CONFIG_BODY
    assert snapshot.text.startswith("#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0\n")
    assert snapshot.text.endswith("end\n")
    assert "FortiGate-80F" not in snapshot.text
    assert missing_sections(snapshot.text, REQUIRED, snapshot.platform) == ()


def test_ssh_event_hashes_the_raw_answer_and_the_snapshot_the_clean_text():
    runner = FakeRunner(console=CONSOLE_PROMPTED, stdout=CONFIG_PROMPTED)
    snapshot, events = ssh_call(runner)
    event = events[1]
    assert event.response_sha256 == hashlib.sha256(CONFIG_PROMPTED).hexdigest()
    assert event.response_bytes == len(CONFIG_PROMPTED)
    assert snapshot.sha256 == hashlib.sha256(CONFIG_BODY.encode("utf-8")).hexdigest()
    assert snapshot.size_bytes == len(CONFIG_BODY.encode("utf-8"))
    assert event.response_bytes - snapshot.size_bytes == len("FortiGate-80F # ") + len("FortiGate-80F #")


def test_ssh_cleanup_keeps_every_hash_inside_the_configuration():
    runner = FakeRunner(console=CONSOLE_PROMPTED, stdout=HASH_PROMPTED)
    snapshot, _ = ssh_call(runner)
    assert snapshot.text == HASH_BODY
    assert '    edit "net # 42"' in snapshot.text
    assert "# a comment line that starts with a hash" in snapshot.text
    assert snapshot.text.count("#") == HASH_BODY.count("#")


def test_ssh_cleanup_handles_a_prompt_with_a_vdom():
    runner = FakeRunner(console=CONSOLE_PROMPTED, stdout=VDOM_PROMPTED)
    snapshot, _ = ssh_call(runner)
    assert snapshot.text == CONFIG_BODY
    assert "(global)" not in snapshot.text


def test_ssh_cleanup_leaves_output_without_a_prompt_alone():
    raw = CONFIG_BODY.encode("utf-8")
    runner = FakeRunner(stdout=raw)
    snapshot, events = ssh_call(runner)
    assert snapshot.text == CONFIG_BODY
    assert snapshot.sha256 == events[1].response_sha256 == hashlib.sha256(raw).hexdigest()


def test_ssh_cleanup_never_eats_a_leading_comment_line():
    raw = b"#config-version=FGT80F-8.0.0-FW-build0167-260420:opmode=0\nconfig system global\nend\n"
    snapshot, _ = ssh_call(FakeRunner(stdout=raw))
    assert snapshot.text == raw.decode("utf-8")


READ_ONLY_PROMPTED = ("FortiGate-80F $ " + CONFIG_BODY + "FortiGate-80F $").encode("utf-8")
READ_ONLY_CONSOLE = CONSOLE_PROMPTED.replace(b"FortiGate-80F #", b"FortiGate-80F $")


def test_ssh_reads_the_preflight_and_the_snapshot_through_a_read_only_prompt():
    runner = FakeRunner(console=READ_ONLY_CONSOLE, stdout=READ_ONLY_PROMPTED)
    snapshot, events = ssh_call(runner)
    assert snapshot.text == CONFIG_BODY
    assert "FortiGate-80F" not in snapshot.text
    assert events[1].response_sha256 == hashlib.sha256(READ_ONLY_PROMPTED).hexdigest()
    assert snapshot.sha256 == hashlib.sha256(CONFIG_BODY.encode("utf-8")).hexdigest()
    assert events[1].response_bytes - snapshot.size_bytes == len("FortiGate-80F $ ") + len(
        "FortiGate-80F $"
    )


def test_the_auditor_cleans_prompts_through_the_core_and_holds_no_copy():
    import netops_auditor.collect as collect

    source = Path(collect.__file__).read_text(encoding="utf-8")
    assert "PROMPT_PREFIX" not in source
    assert "def _cleaned" not in source
    assert collect.prompt is prompt


def test_ssh_exos_cleans_the_prompt_with_the_same_mechanism():
    runner = FakeRunner(platform="exos", stdout=EXOS_PROMPTED)
    snapshot, events = ssh_call(runner, platform="exos")
    assert snapshot.text == EXOS_BODY
    assert "example-switch.5 #" not in snapshot.text
    assert events[0].response_sha256 == hashlib.sha256(EXOS_PROMPTED).hexdigest()
    assert snapshot.sha256 == hashlib.sha256(EXOS_BODY.encode("utf-8")).hexdigest()


def test_ssh_without_a_legacy_profile_binds_no_algorithm_option():
    runner = FakeRunner()
    ssh_call(runner)
    for call in runner.calls:
        assert algorithm_options(call["argv"]) == []


def test_the_family_holds_the_options_behind_the_profile_name():
    assert PROFILES == (LEGACY_PROFILE,)
    assert OPENSSH_OPTIONS[LEGACY_PROFILE] == LEGACY_OPTIONS


@pytest.mark.parametrize("platform", ("fortios", "exos"))
def test_legacy_profile_adds_its_options_behind_the_bound_ones(platform):
    runner = FakeRunner(platform=platform, stdout=EXOS_CONFIG)
    ssh_call(runner, platform=platform, legacy_ssh=LEGACY_PROFILE)
    for index, step in enumerate(SSH_STEPS[platform], start=1):
        argv = runner.argv(index)
        assert algorithm_options(argv) == list(LEGACY_OPTIONS)
        for option in LEGACY_OPTIONS:
            assert argv.count(option) == 1
            assert argv[argv.index(option) - 1] == "-o"
        for option in MANDATED_KEY_OPTIONS:
            assert argv.index(option) < argv.index(LEGACY_OPTIONS[0])
        assert argv[-1] == step.command


def test_legacy_profile_stays_out_of_the_host_key_scan():
    runner = FakeRunner()
    ssh_call(runner, legacy_ssh=LEGACY_PROFILE)
    scan = runner.argv(0)
    assert scan[0] == "ssh-keyscan"
    assert algorithm_options(scan) == []
    assert "-o" not in scan


@pytest.mark.parametrize(
    "profile",
    (
        "ssh-rsa",
        "HostKeyAlgorithms=+ssh-rsa",
        "rsa-sha1,diffie-hellman-group14-sha1",
        "RSA-SHA1",
        " rsa-sha1",
        "-oProxyCommand=touch /tmp/pwned",
        "",
        "   ",
        1,
        True,
        [],
        {},
        ["rsa-sha1"],
    ),
)
def test_ssh_refuses_a_legacy_profile_the_family_does_not_name(profile):
    runner = FakeRunner()
    with pytest.raises(CollectError) as caught:
        ssh_call(runner, legacy_ssh=profile)
    assert caught.value.event is None
    assert runner.calls == []
    assert "legacy_ssh must be null for a device that speaks current algorithms" in str(caught.value)


def test_ssh_exit_code_carries_a_recognized_reason_and_not_the_client_words():
    runner = FakeRunner(
        code=255,
        stdout=b"",
        stderr=b"Unable to negotiate with 192.0.2.10 port 22:"
        b" no matching host key type found. Their offer: ssh-rsa\n",
    )
    error = ssh_failure(runner)
    assert "failed with exit code 255" in str(error)
    assert "share no algorithm the client accepts" in str(error)
    assert "Their offer: ssh-rsa" not in str(error)
    assert error.event.outcome == "failed"


def test_words_a_device_writes_on_standard_error_stay_out_of_the_collect_error():
    canary = "KANARCI-TAJEMSTVI-OD-PROTISTRANY"
    noise = ("\x1b[31mbanner\x1b[0m\r\n\x00Permission denied. key=%s\n" % canary).encode("utf-8")
    error = ssh_failure(FakeRunner(code=255, stdout=b"", stderr=noise))
    assert canary not in str(error)
    assert canary not in repr(error)
    assert "the device refused the credential" in str(error)
    for character in str(error):
        assert character.isprintable()


NEGOTIATION_STDERR = (
    b"Unable to negotiate with 192.0.2.10 port 22:"
    b" no matching host key type found. Their offer: ssh-rsa\n"
)


def test_a_refused_negotiation_names_the_target_and_how_to_write_the_exception_down():
    error = ssh_failure(FakeRunner(code=255, stdout=b"", stderr=NEGOTIATION_STDERR))
    said = str(error)
    assert HOST in said
    assert "offers only algorithms this client refuses" in said
    assert "legacy_ssh" in said
    assert "rsa-sha1" in said
    assert "there is no global switch" in said


def test_the_remedy_stays_out_when_the_device_already_has_its_profile():
    error = ssh_failure(
        FakeRunner(code=255, stdout=b"", stderr=NEGOTIATION_STDERR), legacy_ssh=LEGACY_PROFILE
    )
    assert "share no algorithm the client accepts" in str(error)
    assert "legacy_ssh" not in str(error)


def test_the_remedy_stays_out_of_a_failure_that_is_not_a_negotiation():
    error = ssh_failure(
        FakeRunner(code=255, stdout=b"", stderr=b"Permission denied (publickey,password).\n")
    )
    assert "the device refused the credential" in str(error)
    assert "legacy_ssh" not in str(error)


def test_a_snapshot_command_that_reports_a_nonzero_exit_status_is_refused():
    runner = FakeRunner(code=250)
    error = ssh_failure(runner)
    assert "exit status 250" in str(error)
    assert error.event.outcome == "failed"
    assert config_text() not in str(error)
