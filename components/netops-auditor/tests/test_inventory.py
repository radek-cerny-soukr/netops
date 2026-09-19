import json

import pytest

from netops_auditor.inventory import (
    CHANNELS,
    FILE_VERSION,
    SECTION_FIELDS,
    AuditorSection,
    InventoryError,
    device,
    load,
    section,
)

NAME = "fw-a.example.invalid"
PLATFORM = "fortios"
ADDRESS = "192.0.2.10"
PORT = 22
ROLE = "perimetr"
CREDENTIAL = "fw-a-audit-ro"
FILE_SOURCE = "/var/lib/netops/fw-a.conf"
REST_SOURCE = "https://192.0.2.10:443"
SECTIONS = ["system interface", "firewall policy"]
TLS_FINGERPRINT = "0123456789abcdef" * 4
HOST_KEY = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
NOT_TEXT = (None, 1, True, [], {}, "", "   ")
KEPT = object()


def auditor(
    channel="file",
    source=FILE_SOURCE,
    required_sections=KEPT,
    tls_fingerprint=None,
):
    return {
        "channel": channel,
        "source": source,
        "required_sections": list(SECTIONS) if required_sections is KEPT else required_sections,
        "tls_fingerprint": tls_fingerprint,
    }


def item(
    name=NAME,
    platform=PLATFORM,
    address=None,
    port=None,
    role=ROLE,
    credential=None,
    host_key_fingerprint=None,
    legacy_ssh=None,
    auditor_section=None,
    helper=None,
):
    return {
        "name": name,
        "platform": platform,
        "address": address,
        "port": port,
        "role": role,
        "credential": credential,
        "host_key_fingerprint": host_key_fingerprint,
        "legacy_ssh": legacy_ssh,
        "auditor": auditor() if auditor_section is None else auditor_section,
        "helper": helper,
    }


def file_item(**overrides):
    return item(**overrides)


def rest_item(**overrides):
    values = {
        "name": "fw-b.example.invalid",
        "address": "192.0.2.20",
        "port": 443,
        "credential": "fw-b-audit-ro",
        "auditor_section": auditor(
            channel="fortios-rest", source=REST_SOURCE, tls_fingerprint=TLS_FINGERPRINT
        ),
    }
    values.update(overrides)
    return item(**values)


def ssh_item(**overrides):
    values = {
        "name": "fw-c.example.invalid",
        "address": "198.51.100.10",
        "port": PORT,
        "credential": "fw-c-audit-ro",
        "host_key_fingerprint": HOST_KEY,
        "auditor_section": auditor(channel="ssh", source=None),
    }
    values.update(overrides)
    return item(**values)


def write(tmp_path, items, version=FILE_VERSION, name="inventory.json"):
    path = tmp_path / name
    path.write_text(
        json.dumps({"version": version, "devices": items}, ensure_ascii=False), encoding="utf-8"
    )
    return path


def loaded_section(tmp_path, entry, name="inventory.json"):
    return section(device(load(write(tmp_path, [entry], name=name)), entry["name"]))


def refusal(tmp_path, entry, fragment, name="inventory.json"):
    path = write(tmp_path, [entry], name=name)
    with pytest.raises(InventoryError, match=fragment):
        load(path)


def test_file_device_carries_its_whole_section(tmp_path):
    one = loaded_section(tmp_path, file_item())
    assert isinstance(one, AuditorSection)
    assert one.channel == "file"
    assert one.source == FILE_SOURCE
    assert one.required_sections == ("system interface", "firewall policy")
    assert one.tls_fingerprint is None


def test_rest_device_carries_the_pinned_certificate(tmp_path):
    one = loaded_section(tmp_path, rest_item())
    assert one.channel == "fortios-rest"
    assert one.source == REST_SOURCE
    assert one.tls_fingerprint == TLS_FINGERPRINT


def test_ssh_device_is_reached_by_the_common_address(tmp_path):
    path = write(tmp_path, [ssh_item()])
    entry = device(load(path), "fw-c.example.invalid")
    assert entry.address == "198.51.100.10"
    assert entry.port == PORT
    assert entry.host_key_fingerprint == HOST_KEY
    assert section(entry).source is None
    assert section(entry).channel == "ssh"


def test_the_section_is_immutable(tmp_path):
    one = loaded_section(tmp_path, file_item())
    with pytest.raises(AttributeError):
        one.channel = "ssh"
    with pytest.raises(AttributeError):
        one.source = "/etc/passwd"


def test_a_version_1_inventory_is_refused_naming_version_2(tmp_path):
    path = write(tmp_path, [file_item()], version=1)
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "unknown inventory file version 1" in message
    assert "expected %d" % FILE_VERSION in message
    assert FILE_VERSION == 2


def test_a_device_of_the_helper_alone_is_not_measured_by_the_auditor(tmp_path):
    entry = item(name="sw-a.example.invalid", auditor_section=None, helper={"account_role": "ro"})
    entry["auditor"] = None
    loaded = load(write(tmp_path, [entry]))
    assert loaded[0].auditor is None
    assert loaded[0].helper == {"account_role": "ro"}


def test_a_broken_section_of_a_helper_device_is_not_the_auditors_business(tmp_path):
    entry = item(name="sw-a.example.invalid", helper={"account_role": "ro"})
    entry["auditor"] = None
    entry["helper"] = {"channel": "nonsense"}
    assert load(write(tmp_path, [entry]))[0].helper == {"channel": "nonsense"}


@pytest.mark.parametrize("field", SECTION_FIELDS)
def test_a_missing_section_field_names_the_device_and_the_field(tmp_path, field):
    entry = file_item()
    del entry["auditor"][field]
    refusal(tmp_path, entry, "device %s: auditor section: missing fields: %s" % (NAME, field))


@pytest.mark.parametrize("field", ("consumer", "role", "legacy_ssh", "Channel"))
def test_an_unknown_section_field_names_the_device_and_the_field(tmp_path, field):
    entry = file_item()
    entry["auditor"][field] = "x"
    refusal(tmp_path, entry, "device %s: auditor section: unknown fields: %s" % (NAME, field))


@pytest.mark.parametrize("value", ("nonsense", 1, True, [], "", []))
def test_a_section_that_is_not_an_object_is_refused(tmp_path, value):
    entry = file_item()
    entry["auditor"] = value
    path = write(tmp_path, [entry])
    with pytest.raises(InventoryError, match="must be null or an object"):
        load(path)


@pytest.mark.parametrize("channel", CHANNELS)
def test_every_channel_from_the_enum_loads(tmp_path, channel):
    entry = {"file": file_item(), "fortios-rest": rest_item(), "ssh": ssh_item()}[channel]
    assert loaded_section(tmp_path, entry).channel == channel


@pytest.mark.parametrize(
    "channel", ("https", "telnet", "rest", "fortios_rest", "SSH", "File") + NOT_TEXT
)
def test_channel_must_come_from_the_enum(tmp_path, channel):
    entry = file_item(auditor_section=auditor(channel=channel))
    refusal(tmp_path, entry, "channel must be one of file, fortios-rest, ssh")


@pytest.mark.parametrize("source", (FILE_SOURCE, "/srv/dumps/fw-a.conf"))
def test_the_file_channel_takes_the_path_of_the_dump(tmp_path, source):
    assert loaded_section(tmp_path, file_item(auditor_section=auditor(source=source))).source == source


@pytest.mark.parametrize("source", NOT_TEXT)
def test_the_file_channel_needs_a_source(tmp_path, source):
    entry = file_item(auditor_section=auditor(source=source))
    refusal(tmp_path, entry, "source must be a non-empty string for channel file")


@pytest.mark.parametrize("source", ("192.0.2.20", "http://192.0.2.20", "ftp://192.0.2.20", ""))
def test_the_rest_channel_needs_an_https_source(tmp_path, source):
    entry = rest_item(
        auditor_section=auditor(
            channel="fortios-rest", source=source, tls_fingerprint=TLS_FINGERPRINT
        )
    )
    refusal(tmp_path, entry, "source must")


@pytest.mark.parametrize("source", ("198.51.100.10", "198.51.100.10:22", "", 1, True, []))
def test_an_ssh_device_with_a_source_is_refused(tmp_path, source):
    entry = ssh_item(auditor_section=auditor(channel="ssh", source=source))
    refusal(tmp_path, entry, "source must be null for channel ssh")


@pytest.mark.parametrize(
    "sections", (["system interface"], ["system interface", "firewall policy", "system admin"])
)
def test_required_sections_holds_what_the_entry_lists(tmp_path, sections):
    entry = file_item(auditor_section=auditor(required_sections=sections))
    assert loaded_section(tmp_path, entry).required_sections == tuple(sections)


@pytest.mark.parametrize("sections", ([], None, "system interface", {}, 1, True))
def test_required_sections_must_be_a_non_empty_list(tmp_path, sections):
    entry = file_item(auditor_section=auditor(required_sections=sections))
    refusal(tmp_path, entry, "required_sections must be a non-empty list")


@pytest.mark.parametrize("value", ("", "   ", None, 1, True, [], {}))
def test_required_sections_must_hold_non_empty_strings(tmp_path, value):
    entry = file_item(auditor_section=auditor(required_sections=["system interface", value]))
    refusal(tmp_path, entry, r"required_sections\[1\] must be a non-empty string")


def test_the_tls_fingerprint_is_normalized_to_lowercase(tmp_path):
    entry = rest_item(
        auditor_section=auditor(
            channel="fortios-rest", source=REST_SOURCE, tls_fingerprint=TLS_FINGERPRINT.upper()
        )
    )
    assert loaded_section(tmp_path, entry).tls_fingerprint == TLS_FINGERPRINT


@pytest.mark.parametrize(
    "fingerprint",
    (
        None,
        TLS_FINGERPRINT[:-1],
        TLS_FINGERPRINT + "a",
        TLS_FINGERPRINT.replace("a", "g"),
        "sha256:" + TLS_FINGERPRINT,
        "",
        "   ",
        1,
        True,
        [TLS_FINGERPRINT],
    ),
)
def test_the_rest_channel_demands_a_usable_tls_fingerprint(tmp_path, fingerprint):
    entry = rest_item(
        auditor_section=auditor(
            channel="fortios-rest", source=REST_SOURCE, tls_fingerprint=fingerprint
        )
    )
    refusal(tmp_path, entry, "tls_fingerprint must hold the sha256 certificate")


@pytest.mark.parametrize("fingerprint", (TLS_FINGERPRINT, "nonsense", 1, True, []))
def test_the_file_channel_forbids_a_tls_fingerprint(tmp_path, fingerprint):
    entry = file_item(auditor_section=auditor(tls_fingerprint=fingerprint))
    refusal(tmp_path, entry, "tls_fingerprint must be null for channel file")


@pytest.mark.parametrize("fingerprint", (TLS_FINGERPRINT, "nonsense", 1, True, []))
def test_the_ssh_channel_forbids_a_tls_fingerprint(tmp_path, fingerprint):
    entry = ssh_item(auditor_section=auditor(channel="ssh", source=None, tls_fingerprint=fingerprint))
    refusal(tmp_path, entry, "tls_fingerprint must be null for channel ssh")


@pytest.mark.parametrize("credential", (CREDENTIAL, "fw-a-api"))
def test_a_file_device_with_a_credential_is_refused(tmp_path, credential):
    entry = file_item(credential=credential)
    refusal(tmp_path, entry, "credential must be null for channel file")


def test_a_file_device_needs_neither_address_nor_port(tmp_path):
    one = loaded_section(tmp_path, file_item(address=None, port=None))
    assert one.channel == "file"


def test_a_file_device_may_still_carry_an_address(tmp_path):
    one = loaded_section(tmp_path, file_item(address=ADDRESS, port=PORT))
    assert one.channel == "file"


def test_a_rest_device_without_a_credential_is_refused(tmp_path):
    entry = rest_item(credential=None)
    refusal(tmp_path, entry, "credential must name a record in the credential store")


def test_a_rest_device_with_a_host_key_fingerprint_is_refused(tmp_path):
    entry = rest_item(host_key_fingerprint=HOST_KEY)
    refusal(tmp_path, entry, "host_key_fingerprint must be null for channel fortios-rest")


def test_an_ssh_device_without_a_credential_is_refused(tmp_path):
    entry = ssh_item(credential=None)
    refusal(tmp_path, entry, "credential must name a record in the credential store")


def test_an_ssh_device_without_an_address_is_refused(tmp_path):
    entry = ssh_item(address=None, port=None, host_key_fingerprint=None)
    refusal(tmp_path, entry, "address must name the device for channel ssh")


def test_an_ssh_device_without_a_host_key_fingerprint_is_refused(tmp_path):
    entry = ssh_item(host_key_fingerprint=None)
    refusal(tmp_path, entry, "host_key_fingerprint must pin the host key for channel ssh")


def test_an_ssh_device_takes_the_legacy_profile_of_the_common_part(tmp_path):
    path = write(tmp_path, [ssh_item(legacy_ssh="rsa-sha1")])
    assert device(load(path), "fw-c.example.invalid").legacy_ssh == "rsa-sha1"


def test_a_legacy_profile_the_family_does_not_know_is_refused(tmp_path):
    entry = ssh_item(legacy_ssh="ssh-rsa")
    refusal(tmp_path, entry, "legacy_ssh must be null")


def test_every_refusal_names_the_device(tmp_path):
    entry = ssh_item(name="sw-b.example.invalid", host_key_fingerprint=None)
    refusal(tmp_path, entry, "device sw-b.example.invalid: auditor section")


def test_load_returns_every_device_in_file_order(tmp_path):
    loaded = load(write(tmp_path, [file_item(), ssh_item(), rest_item()]))
    assert [one.name for one in loaded] == [
        NAME,
        "fw-c.example.invalid",
        "fw-b.example.invalid",
    ]


def test_device_returns_the_named_entry(tmp_path):
    loaded = load(write(tmp_path, [file_item(), ssh_item()]))
    assert device(loaded, NAME) is loaded[0]
    assert device(loaded, "fw-c.example.invalid") is loaded[1]


@pytest.mark.parametrize("name", ("fw-z.example.invalid", "FW-A.EXAMPLE.INVALID", "", None, 1))
def test_device_rejects_an_unknown_name(tmp_path, name):
    loaded = load(write(tmp_path, [file_item()]))
    with pytest.raises(InventoryError, match="unknown device"):
        device(loaded, name)


def test_a_broken_common_part_is_refused_by_the_shared_loader(tmp_path):
    entry = file_item(role="dmz")
    refusal(tmp_path, entry, "role must be one of perimetr, interni, lab")


def test_a_secret_field_name_is_refused_by_the_shared_loader(tmp_path):
    entry = file_item()
    entry["password"] = "do-not-put-me-here"
    refusal(tmp_path, entry, "secrets do not belong in the inventory")


def test_a_duplicate_name_is_refused(tmp_path):
    path = write(tmp_path, [file_item(), rest_item(name=NAME)])
    with pytest.raises(InventoryError, match="duplicate name"):
        load(path)


def test_a_missing_file_is_an_inventory_error(tmp_path):
    with pytest.raises(InventoryError, match="cannot read inventory file"):
        load(tmp_path / "nothing-here.json")
