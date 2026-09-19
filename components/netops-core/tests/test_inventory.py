from __future__ import annotations

import json

import pytest

from netops_core.inventory import (
    CONSUMERS,
    DEVICE_FIELDS,
    DOCUMENT_FIELDS,
    ROLES,
    Device,
    InventoryError,
    device,
    for_consumer,
    load,
)
from netops_core.legacy_ssh import PROFILES
from netops_core.platforms import ALIASES, PLATFORMS

NAME = "fw-a.example.invalid"
OTHER = "sw-a.example.invalid"
PLATFORM = "fortios"
ADDRESS = "192.0.2.10"
OTHER_ADDRESS = "192.0.2.20"
PORT = 22
ROLE = "perimetr"
CREDENTIAL = "fw-a-ro"
PIN = "SHA256:" + "A" * 43
OTHER_PIN = "SHA256:" + "B" * 43
AUDITOR_SECTION = {"channel": "ssh", "required_sections": ["system global"]}
HELPER_SECTION = {"account_role": "read-only"}

EXAMPLE = {
    "version": 2,
    "devices": [
        {
            "name": NAME,
            "platform": "fortios",
            "address": ADDRESS,
            "port": 22,
            "role": "perimetr",
            "credential": CREDENTIAL,
            "host_key_fingerprint": PIN,
            "legacy_ssh": None,
            "auditor": AUDITOR_SECTION,
            "helper": None,
        },
        {
            "name": OTHER,
            "platform": "exos",
            "address": OTHER_ADDRESS,
            "port": 22,
            "role": "interni",
            "credential": "sw-a-ro",
            "host_key_fingerprint": OTHER_PIN,
            "legacy_ssh": "rsa-sha1",
            "auditor": None,
            "helper": HELPER_SECTION,
        },
    ],
}

SECRET_FIELDS = (
    "password",
    "Password",
    "PASSWORD",
    "passwd",
    "passphrase",
    "token",
    "TOKEN",
    "api_key",
    "api-key",
    "API-KEY",
    "Api_Key",
    "apikey",
    "secret",
    "Secret",
    "psk",
    "PSK",
    "private_key",
    "private-key",
    "PRIVATE-KEY",
    "Private Key",
    "privatekey",
    "admin_password",
    "ssh-password",
    "bearer_token",
    "wifi-psk",
    "client_secret",
)

NOT_TEXT = (None, 1, True, [], {}, "", "   ")
NOT_SECTION = (1, 0, True, False, "ssh", "", [], [{"channel": "ssh"}], 1.5)
BAD_PINS = (
    PIN[len("SHA256:"):],
    PIN[:-1],
    PIN + "A",
    "sha256:" + "A" * 43,
    "SHA256:" + "!" * 43,
    "MD5:" + "A" * 43,
    "SHA256:",
    "",
    "   ",
    0,
    1,
    True,
    [PIN],
    {"sha256": PIN},
)


def item(
    name=NAME,
    platform=PLATFORM,
    address=ADDRESS,
    port=PORT,
    role=ROLE,
    credential=CREDENTIAL,
    host_key_fingerprint=PIN,
    legacy_ssh=None,
    auditor=None,
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
        "auditor": dict(AUDITOR_SECTION) if auditor is None and helper is None else auditor,
        "helper": helper,
    }


def helper_item(**overrides):
    values = {
        "name": OTHER,
        "platform": "exos",
        "address": OTHER_ADDRESS,
        "credential": "sw-a-ro",
        "host_key_fingerprint": OTHER_PIN,
        "auditor": None,
        "helper": dict(HELPER_SECTION),
    }
    values.update(overrides)
    return item(**values)


def offline_item(**overrides):
    values = {
        "address": None,
        "port": None,
        "credential": None,
        "host_key_fingerprint": None,
    }
    values.update(overrides)
    return item(**values)


def without(field, **overrides):
    entry = item(**overrides)
    del entry[field]
    return entry


def plus(extra, **overrides):
    entry = item(**overrides)
    entry.update(extra)
    return entry


def write(tmp_path, items, version=2, extra=None, name="inventory.json"):
    document = {"version": version, "devices": items}
    if extra is not None:
        document.update(extra)
    path = tmp_path / name
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def write_raw(tmp_path, text, name="inventory.json"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def fleet(tmp_path):
    return load(
        write(
            tmp_path,
            [
                item(),
                helper_item(),
                item(
                    name="fw-b.example.invalid",
                    role="lab",
                    auditor=dict(AUDITOR_SECTION),
                    helper=dict(HELPER_SECTION),
                ),
            ],
        )
    )


def test_example_document_from_the_specification_loads(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    loaded = load(path)
    assert [one.name for one in loaded] == [NAME, OTHER]
    assert loaded[0].platform == "fortios"
    assert loaded[0].address == ADDRESS
    assert loaded[0].port == 22
    assert loaded[0].role == "perimetr"
    assert loaded[0].credential == CREDENTIAL
    assert loaded[0].host_key_fingerprint == PIN
    assert loaded[0].legacy_ssh is None
    assert loaded[0].auditor == AUDITOR_SECTION
    assert loaded[0].helper is None
    assert loaded[0].consumers() == ("auditor",)
    assert loaded[1].platform == "exos"
    assert loaded[1].legacy_ssh == "rsa-sha1"
    assert loaded[1].helper == HELPER_SECTION
    assert loaded[1].consumers() == ("helper",)


def test_valid_device_loads_every_field(tmp_path):
    path = write(tmp_path, [item()])
    loaded = load(path)
    assert len(loaded) == 1
    one = loaded[0]
    assert isinstance(one, Device)
    assert one.name == NAME
    assert one.platform == PLATFORM
    assert one.address == ADDRESS
    assert one.port == PORT
    assert one.role == ROLE
    assert one.credential == CREDENTIAL
    assert one.host_key_fingerprint == PIN
    assert one.legacy_ssh is None
    assert one.auditor == AUDITOR_SECTION
    assert one.helper is None
    assert load(str(path)) == loaded


def test_loaded_devices_are_immutable_and_keep_file_order(tmp_path):
    loaded = fleet(tmp_path)
    assert isinstance(loaded, tuple)
    assert [one.name for one in loaded] == [NAME, OTHER, "fw-b.example.invalid"]
    with pytest.raises(AttributeError):
        loaded[0].role = "lab"
    with pytest.raises(AttributeError):
        loaded[0].credential = "somewhere-else"
    with pytest.raises(AttributeError):
        loaded[0].host_key_fingerprint = OTHER_PIN


def test_empty_device_list_loads_to_nothing(tmp_path):
    assert load(write(tmp_path, [])) == ()


def test_device_fields_are_the_ten_of_the_schema():
    assert DEVICE_FIELDS == (
        "name",
        "platform",
        "address",
        "port",
        "role",
        "credential",
        "host_key_fingerprint",
        "legacy_ssh",
        "auditor",
        "helper",
    )
    assert CONSUMERS == ("auditor", "helper")
    for consumer in CONSUMERS:
        assert consumer in DEVICE_FIELDS


@pytest.mark.parametrize("field", SECRET_FIELDS)
def test_secret_field_in_a_device_is_an_error(tmp_path, field):
    path = write(tmp_path, [plus({field: "do-not-put-me-here"})])
    with pytest.raises(InventoryError, match="secrets do not belong in the inventory"):
        load(path)


@pytest.mark.parametrize("field", ("password", "API-KEY", "private_key", "psk"))
def test_secret_field_in_the_document_is_an_error(tmp_path, field):
    path = write(tmp_path, [item()], extra={field: "do-not-put-me-here"})
    with pytest.raises(InventoryError, match="secrets do not belong in the inventory"):
        load(path)


def test_secret_check_names_every_offending_field(tmp_path):
    path = write(tmp_path, [plus({"token": "x", "admin-password": "y"})])
    with pytest.raises(InventoryError, match="remove fields: admin-password, token"):
        load(path)


def test_secret_check_runs_before_missing_and_unknown_fields(tmp_path):
    path = write(tmp_path, [{"password": "do-not-put-me-here"}])
    with pytest.raises(InventoryError, match="secrets do not belong in the inventory"):
        load(path)
    path = write(tmp_path, [plus({"vdom": "root", "psk": "do-not-put-me-here"})])
    with pytest.raises(InventoryError, match="secrets do not belong in the inventory"):
        load(path)


def test_secret_check_looks_at_device_field_names_not_at_values_or_sections(tmp_path):
    loaded = load(
        write(
            tmp_path,
            [
                item(
                    credential="fw-a-api-key-record",
                    auditor={"required_sections": ["system password-policy"]},
                ),
                helper_item(helper={"secret_store": "vault", "password_policy": "checked"}),
            ],
        )
    )
    assert loaded[0].credential == "fw-a-api-key-record"
    assert loaded[0].auditor == {"required_sections": ["system password-policy"]}
    assert loaded[1].helper == {"secret_store": "vault", "password_policy": "checked"}


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_platform_from_the_enum_loads(tmp_path, platform):
    assert load(write(tmp_path, [item(platform=platform)]))[0].platform == platform


@pytest.mark.parametrize("alias", sorted(ALIASES))
def test_platform_alias_is_stored_canonical(tmp_path, alias):
    assert load(write(tmp_path, [item(platform=alias)]))[0].platform == ALIASES[alias]


def test_platform_fortinet_is_normalised_to_fortios(tmp_path):
    assert load(write(tmp_path, [item(platform="fortinet")]))[0].platform == "fortios"
    assert load(write(tmp_path, [item(platform=" FortiNet ")]))[0].platform == "fortios"


@pytest.mark.parametrize(
    "platform", ("fortiswitch", "ios", "junos", "eos", "forti os", "extreme") + NOT_TEXT
)
def test_platform_must_be_a_known_name_or_alias(tmp_path, platform):
    path = write(tmp_path, [item(platform=platform)])
    with pytest.raises(InventoryError, match="platform must be one of fortios"):
        load(path)


@pytest.mark.parametrize("role", ROLES)
def test_every_role_from_the_enum_loads(tmp_path, role):
    assert load(write(tmp_path, [item(role=role)]))[0].role == role


@pytest.mark.parametrize(
    "role", ("dmz", "Perimetr", "perimetr ", " lab", "internal", "perimetr/lab") + NOT_TEXT
)
def test_role_must_come_from_the_enum(tmp_path, role):
    path = write(tmp_path, [item(role=role)])
    with pytest.raises(InventoryError, match="role must be one of perimetr, interni, lab"):
        load(path)


@pytest.mark.parametrize(
    "address",
    ("192.0.2.10", "198.51.100.1", "203.0.113.255", "203.0.113.1", "198.51.100.254"),
)
def test_canonical_ipv4_address_loads(tmp_path, address):
    assert load(write(tmp_path, [item(address=address)]))[0].address == address


@pytest.mark.parametrize(
    "address",
    (
        "fw-a.example.invalid",
        "example.invalid",
        "sw-a-1.lab.example.invalid",
        "replace-me",
        "a" * 63 + ".example.invalid",
    ),
)
def test_lowercase_dns_name_loads(tmp_path, address):
    assert load(write(tmp_path, [item(address=address)]))[0].address == address


@pytest.mark.parametrize(
    "address", ("2001:db8::1", "::1", "2001:db8:0:0:0:0:0:1", "::ffff:192.0.2.1")
)
def test_ipv6_address_is_refused(tmp_path, address):
    path = write(tmp_path, [item(address=address)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "IPv6 targets are not supported" in message
    assert repr(address) in message


@pytest.mark.parametrize("address", ("192.0.2.010", "192.000.2.10", "192.0.2.10.", "192.0.2.10.5"))
def test_ipv4_address_must_be_canonical(tmp_path, address):
    path = write(tmp_path, [item(address=address)])
    with pytest.raises(InventoryError, match="address must"):
        load(path)


@pytest.mark.parametrize(
    "address",
    (
        "FW-A.EXAMPLE.INVALID",
        "Fw-a.example.invalid",
        "fw-a.example.invalid.",
        "-fw-a.example.invalid",
        "fw-a-.example.invalid",
        "fw_a.example.invalid",
        "fw a.example.invalid",
        "fw-a..example.invalid",
        "a" * 64 + ".example.invalid",
        ("a" * 63 + ".") * 4 + "invalid",
        "https://192.0.2.10",
        "192.0.2.10:22",
        1,
        True,
        [],
        {},
        "",
        "   ",
    ),
)
def test_address_must_be_null_an_ipv4_literal_or_a_dns_name(tmp_path, address):
    path = write(tmp_path, [item(address=address)])
    with pytest.raises(InventoryError, match="address must be null"):
        load(path)


@pytest.mark.parametrize("port", (1, 22, 443, 8443, 65535))
def test_port_in_range_loads(tmp_path, port):
    assert load(write(tmp_path, [item(port=port)]))[0].port == port


@pytest.mark.parametrize("port", (0, -1, 65536, 99999, True, False, 22.0, "22", [], {}))
def test_port_must_be_an_integer_in_range(tmp_path, port):
    path = write(tmp_path, [item(port=port)])
    with pytest.raises(InventoryError, match="port must be null or an integer between 1 and 65535"):
        load(path)


def test_device_without_address_and_port_loads(tmp_path):
    loaded = load(write(tmp_path, [offline_item()]))
    assert loaded[0].address is None
    assert loaded[0].port is None
    assert loaded[0].host_key_fingerprint is None


def test_address_without_port_is_refused(tmp_path):
    path = write(tmp_path, [item(address=ADDRESS, port=None, host_key_fingerprint=None)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "address and port must be both null or both set" in message
    assert repr(ADDRESS) in message


def test_port_without_address_is_refused(tmp_path):
    path = write(tmp_path, [item(address=None, port=PORT, host_key_fingerprint=None)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "address and port must be both null or both set" in message
    assert "port 22" in message


def test_credential_may_be_null(tmp_path):
    assert load(write(tmp_path, [item(credential=None)]))[0].credential is None


def test_credential_names_a_record(tmp_path):
    assert load(write(tmp_path, [item(credential="fw-a-ro")]))[0].credential == "fw-a-ro"


@pytest.mark.parametrize("credential", ("", "   ", 1, True, [], {}))
def test_credential_must_be_null_or_a_name(tmp_path, credential):
    path = write(tmp_path, [item(credential=credential)])
    with pytest.raises(
        InventoryError, match="credential must be null or name a record in the credential store"
    ):
        load(path)


def test_pinned_device_keeps_the_fingerprint_as_written(tmp_path):
    loaded = load(write(tmp_path, [item(host_key_fingerprint=PIN)]))
    assert loaded[0].host_key_fingerprint == PIN
    assert loaded[0].host_key_fingerprint.startswith("SHA256:")


@pytest.mark.parametrize("pin", BAD_PINS)
def test_host_key_fingerprint_must_be_a_usable_pin(tmp_path, pin):
    path = write(tmp_path, [item(host_key_fingerprint=pin)])
    with pytest.raises(InventoryError, match="host_key_fingerprint must hold the sha256 host key"):
        load(path)


def test_host_key_fingerprint_without_address_is_refused(tmp_path):
    path = write(tmp_path, [item(address=None, port=None, host_key_fingerprint=PIN)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "host_key_fingerprint" in message
    assert "must be null for a device without an address" in message


def test_device_without_a_pin_loads_when_nothing_demands_it(tmp_path):
    assert load(write(tmp_path, [item(host_key_fingerprint=None)]))[0].host_key_fingerprint is None


@pytest.mark.parametrize("profile", PROFILES)
def test_named_legacy_profile_loads_with_a_pin(tmp_path, profile):
    loaded = load(write(tmp_path, [item(legacy_ssh=profile)]))
    assert loaded[0].legacy_ssh == profile


def test_legacy_ssh_without_host_key_fingerprint_is_refused(tmp_path):
    path = write(tmp_path, [item(host_key_fingerprint=None, legacy_ssh="rsa-sha1")])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "legacy_ssh" in message
    assert "requires host_key_fingerprint" in message
    assert "not pinned" in message


@pytest.mark.parametrize(
    "profile",
    (
        "ssh-rsa",
        "HostKeyAlgorithms=+ssh-rsa",
        "RSA-SHA1",
        "rsa_sha1",
        " rsa-sha1",
        "-oProxyCommand=touch /somewhere/pwned",
        1,
        True,
        [],
        {},
        ["rsa-sha1"],
        "",
        "   ",
    ),
)
def test_legacy_ssh_takes_a_named_profile_and_never_free_text(tmp_path, profile):
    path = write(tmp_path, [item(legacy_ssh=profile)])
    with pytest.raises(InventoryError, match="legacy_ssh must be null for a device that speaks"):
        load(path)


def test_sections_are_stored_as_given(tmp_path):
    section = {"channel": "ssh", "required_sections": ["system global"], "depth": {"a": [1, 2]}}
    loaded = load(write(tmp_path, [item(auditor=section)]))
    assert loaded[0].auditor == section


def test_device_can_serve_both_consumers(tmp_path):
    loaded = load(
        write(tmp_path, [item(auditor=dict(AUDITOR_SECTION), helper=dict(HELPER_SECTION))])
    )
    assert loaded[0].consumers() == ("auditor", "helper")


def test_empty_section_object_still_counts_as_a_consumer(tmp_path):
    loaded = load(write(tmp_path, [item(auditor={}, helper=None)]))
    assert loaded[0].auditor == {}
    assert loaded[0].consumers() == ("auditor",)


def test_device_with_both_sections_null_is_refused(tmp_path):
    path = write(tmp_path, [dict(item(), auditor=None, helper=None)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "at least one of auditor, helper must be an object" in message
    assert "no component consumes" in message


@pytest.mark.parametrize("section", NOT_SECTION)
@pytest.mark.parametrize("consumer", CONSUMERS)
def test_section_must_be_null_or_an_object(tmp_path, consumer, section):
    entry = dict(item(), auditor=dict(AUDITOR_SECTION), helper=dict(HELPER_SECTION))
    entry[consumer] = section
    path = write(tmp_path, [entry])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "%s must be null or an object" % consumer in message
    assert repr(section) in message


def test_duplicate_name_is_an_error(tmp_path):
    path = write(tmp_path, [item(), helper_item(name=NAME)])
    with pytest.raises(InventoryError) as caught:
        load(path)
    message = str(caught.value)
    assert "duplicate name" in message
    assert NAME in message
    assert "device 0" in message


def test_different_names_are_fine(tmp_path):
    loaded = load(write(tmp_path, [item(), helper_item()]))
    assert [one.name for one in loaded] == [NAME, OTHER]


@pytest.mark.parametrize("name", NOT_TEXT)
def test_name_must_be_a_non_empty_string(tmp_path, name):
    path = write(tmp_path, [item(name=name)])
    with pytest.raises(InventoryError, match="name must be a non-empty string"):
        load(path)


@pytest.mark.parametrize("field", ("vdom", "comment", "Name", "source", "channel", "consumer"))
def test_unknown_field_in_a_device_is_an_error(tmp_path, field):
    path = write(tmp_path, [plus({field: "x"})])
    with pytest.raises(InventoryError, match="unknown fields: %s" % field):
        load(path)


@pytest.mark.parametrize("field", ("tenant", "Devices", "defaults"))
def test_unknown_field_in_the_document_is_an_error(tmp_path, field):
    path = write(tmp_path, [item()], extra={field: "x"})
    with pytest.raises(InventoryError, match="unknown document fields: %s" % field):
        load(path)


@pytest.mark.parametrize("field", DEVICE_FIELDS)
def test_missing_device_field_is_an_error(tmp_path, field):
    path = write(tmp_path, [without(field)])
    with pytest.raises(InventoryError, match="missing fields: %s" % field):
        load(path)


@pytest.mark.parametrize("field", DOCUMENT_FIELDS)
def test_missing_document_field_is_an_error(tmp_path, field):
    document = {"version": 2, "devices": [item()]}
    del document[field]
    path = write_raw(tmp_path, json.dumps(document))
    with pytest.raises(InventoryError, match="missing document fields: %s" % field):
        load(path)


@pytest.mark.parametrize("version", (1, 3, 0, -1, "2", True, None, 2.5, [2], {}))
def test_version_must_be_two(tmp_path, version):
    path = write(tmp_path, [item()], version=version)
    with pytest.raises(InventoryError, match="unknown inventory file version") as caught:
        load(path)
    assert "expected 2" in str(caught.value)


def test_missing_file_is_an_inventory_error(tmp_path):
    with pytest.raises(InventoryError, match="cannot read inventory file"):
        load(tmp_path / "nothing-here.json")


def test_broken_json_is_an_inventory_error(tmp_path):
    path = write_raw(tmp_path, '{"version": 2, "devices": [}')
    with pytest.raises(InventoryError, match="is not valid JSON"):
        load(path)


@pytest.mark.parametrize("document", ("[]", '"inventory"', "1", "null"))
def test_document_must_be_an_object(tmp_path, document):
    path = write_raw(tmp_path, document)
    with pytest.raises(InventoryError, match="must hold an object"):
        load(path)


@pytest.mark.parametrize("devices", ({}, "fw-a", 1, None))
def test_devices_must_be_a_list(tmp_path, devices):
    path = write_raw(tmp_path, json.dumps({"version": 2, "devices": devices}))
    with pytest.raises(InventoryError, match="devices must be a list"):
        load(path)


@pytest.mark.parametrize("entry", ("fw-a", 1, None, []))
def test_device_entry_must_be_an_object(tmp_path, entry):
    path = write(tmp_path, [entry])
    with pytest.raises(InventoryError, match="device 0: must be an object"):
        load(path)


def test_device_returns_the_named_entry(tmp_path):
    loaded = fleet(tmp_path)
    assert device(loaded, NAME) is loaded[0]
    assert device(loaded, OTHER) is loaded[1]


@pytest.mark.parametrize("name", ("fw-z.example.invalid", "FW-A.EXAMPLE.INVALID", "", None, 1))
def test_device_rejects_an_unknown_name(tmp_path, name):
    loaded = fleet(tmp_path)
    with pytest.raises(InventoryError, match="unknown device"):
        device(loaded, name)


def test_device_on_an_empty_inventory_is_an_error(tmp_path):
    loaded = load(write(tmp_path, []))
    with pytest.raises(InventoryError, match="no devices"):
        device(loaded, NAME)


def test_consumers_follow_the_order_of_the_enum(tmp_path):
    loaded = load(
        write(
            tmp_path,
            [
                item(auditor=dict(AUDITOR_SECTION), helper=dict(HELPER_SECTION)),
                helper_item(),
                item(name="fw-b.example.invalid", auditor=dict(AUDITOR_SECTION)),
            ],
        )
    )
    assert loaded[0].consumers() == ("auditor", "helper")
    assert loaded[1].consumers() == ("helper",)
    assert loaded[2].consumers() == ("auditor",)


def test_for_consumer_filters_and_keeps_order(tmp_path):
    loaded = fleet(tmp_path)
    auditor = for_consumer(loaded, "auditor")
    helper = for_consumer(loaded, "helper")
    assert isinstance(auditor, tuple)
    assert [one.name for one in auditor] == [NAME, "fw-b.example.invalid"]
    assert [one.name for one in helper] == [OTHER, "fw-b.example.invalid"]
    assert auditor[0] is loaded[0]


def test_for_consumer_can_return_nothing(tmp_path):
    loaded = load(write(tmp_path, [item()]))
    assert for_consumer(loaded, "helper") == ()


@pytest.mark.parametrize("consumer", ("reporter", "Auditor", "", None, 1, True, ["auditor"]))
def test_for_consumer_rejects_an_unknown_consumer(tmp_path, consumer):
    loaded = fleet(tmp_path)
    with pytest.raises(InventoryError, match="consumer must be one of auditor, helper"):
        for_consumer(loaded, consumer)
