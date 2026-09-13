import json

import pytest

from netops_auditor.collect import LEGACY_SSH_OPTIONS
from netops_auditor.inventory import (
    CHANNELS,
    CONSUMERS,
    DEVICE_FIELDS,
    DOCUMENT_FIELDS,
    LEGACY_SSH_PROFILES,
    PLATFORMS,
    ROLES,
    Device,
    InventoryError,
    device,
    for_consumer,
    load,
)

NAME = "fw-a.example.invalid"
PLATFORM = "fortios"
FILE_SOURCE = "/var/lib/netops/fw-a.conf"
REST_SOURCE = "https://192.0.2.10:443"
SSH_SOURCE = "198.51.100.10"
ROLE = "perimetr"
CONSUMER = "auditor"
CREDENTIAL = "fw-a-audit-ro"
SECTIONS = ["system interface", "firewall policy"]
TLS_FINGERPRINT = "0123456789abcdef" * 4
HOST_KEY = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

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


def item(
    name=NAME,
    platform=PLATFORM,
    channel="file",
    source=FILE_SOURCE,
    role=ROLE,
    consumer=CONSUMER,
    credential=None,
    required_sections=SECTIONS,
    tls_fingerprint=None,
    host_key_fingerprint=None,
    legacy_ssh=None,
):
    return {
        "name": name,
        "platform": platform,
        "channel": channel,
        "source": source,
        "role": role,
        "consumer": consumer,
        "credential": credential,
        "required_sections": required_sections,
        "tls_fingerprint": tls_fingerprint,
        "host_key_fingerprint": host_key_fingerprint,
        "legacy_ssh": legacy_ssh,
    }


def rest_item(**overrides):
    values = {
        "name": "fw-b.example.invalid",
        "channel": "fortios-rest",
        "source": REST_SOURCE,
        "credential": "fw-b-audit-ro",
        "tls_fingerprint": TLS_FINGERPRINT,
    }
    values.update(overrides)
    return item(**values)


def ssh_item(**overrides):
    values = {
        "name": "fw-c.example.invalid",
        "channel": "ssh",
        "source": SSH_SOURCE,
        "credential": "fw-c-audit-ro",
        "host_key_fingerprint": HOST_KEY,
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


def write(tmp_path, items, version=1, extra=None, name="inventory.json"):
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
                ssh_item(role="interni", consumer="helper"),
                rest_item(role="lab", consumer="auditor"),
            ],
        )
    )


def test_valid_file_device_loads_every_field(tmp_path):
    path = write(tmp_path, [item()])
    loaded = load(path)
    assert len(loaded) == 1
    one = loaded[0]
    assert isinstance(one, Device)
    assert one.name == NAME
    assert one.platform == PLATFORM
    assert one.channel == "file"
    assert one.source == FILE_SOURCE
    assert one.role == ROLE
    assert one.consumer == CONSUMER
    assert one.credential is None
    assert one.required_sections == ("system interface", "firewall policy")
    assert load(str(path)) == loaded


def test_loaded_devices_are_immutable_and_keep_file_order(tmp_path):
    loaded = fleet(tmp_path)
    assert isinstance(loaded, tuple)
    assert [one.name for one in loaded] == [
        NAME,
        "fw-c.example.invalid",
        "fw-b.example.invalid",
    ]
    assert isinstance(loaded[0].required_sections, tuple)
    assert len({loaded[0], loaded[0]}) == 1
    with pytest.raises(AttributeError):
        loaded[0].role = "lab"
    with pytest.raises(AttributeError):
        loaded[0].credential = "somewhere-else"


def test_empty_device_list_loads_to_nothing(tmp_path):
    assert load(write(tmp_path, [])) == ()


def test_credential_names_a_record_for_remote_channels(tmp_path):
    loaded = load(write(tmp_path, [rest_item(), ssh_item()]))
    assert loaded[0].channel == "fortios-rest"
    assert loaded[0].credential == "fw-b-audit-ro"
    assert loaded[1].channel == "ssh"
    assert loaded[1].credential == "fw-c-audit-ro"


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


def test_secret_check_looks_at_field_names_not_at_values(tmp_path):
    loaded = load(
        write(
            tmp_path,
            [
                item(required_sections=["system password-policy", "system interface"]),
                rest_item(credential="fw-b-api-key-record"),
                ssh_item(
                    source="/var/lib/netops/secret-place/fw-c.conf",
                    channel="file",
                    credential=None,
                    host_key_fingerprint=None,
                ),
            ],
        )
    )
    assert loaded[0].required_sections == ("system password-policy", "system interface")
    assert loaded[1].credential == "fw-b-api-key-record"
    assert loaded[2].source == "/var/lib/netops/secret-place/fw-c.conf"


@pytest.mark.parametrize("role", ROLES)
def test_every_role_from_the_enum_loads(tmp_path, role):
    assert load(write(tmp_path, [item(role=role)]))[0].role == role


@pytest.mark.parametrize(
    "role",
    ("dmz", "DMZ", "Perimetr", "perimetr ", " lab", "internal", "wan", "perimetr/lab") + NOT_TEXT,
)
def test_role_must_come_from_the_enum(tmp_path, role):
    path = write(tmp_path, [item(role=role)])
    with pytest.raises(InventoryError, match="role must be one of perimetr, interni, lab"):
        load(path)


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_every_consumer_from_the_enum_loads(tmp_path, consumer):
    assert load(write(tmp_path, [item(consumer=consumer)]))[0].consumer == consumer


@pytest.mark.parametrize(
    "consumer",
    ("reporter", "Auditor", "auditor ", "helper,auditor", "both") + NOT_TEXT,
)
def test_consumer_must_come_from_the_enum(tmp_path, consumer):
    path = write(tmp_path, [item(consumer=consumer)])
    with pytest.raises(InventoryError, match="consumer must be one of auditor, helper"):
        load(path)


@pytest.mark.parametrize("channel", CHANNELS)
def test_every_channel_from_the_enum_loads(tmp_path, channel):
    entry = item(
        channel=channel,
        credential=None if channel == "file" else CREDENTIAL,
        tls_fingerprint=TLS_FINGERPRINT if channel == "fortios-rest" else None,
        host_key_fingerprint=HOST_KEY if channel == "ssh" else None,
    )
    assert load(write(tmp_path, [entry]))[0].channel == channel


@pytest.mark.parametrize(
    "channel",
    ("https", "telnet", "rest", "fortios_rest", "SSH", "File") + NOT_TEXT,
)
def test_channel_must_come_from_the_enum(tmp_path, channel):
    path = write(tmp_path, [item(channel=channel)])
    with pytest.raises(InventoryError, match="channel must be one of file, fortios-rest, ssh"):
        load(path)


@pytest.mark.parametrize("credential", (CREDENTIAL, "", "   ", 1, True, [], {}))
def test_file_channel_forbids_a_credential(tmp_path, credential):
    path = write(tmp_path, [item(channel="file", credential=credential)])
    with pytest.raises(InventoryError, match="credential must be null for channel file"):
        load(path)


@pytest.mark.parametrize("channel", ("fortios-rest", "ssh"))
@pytest.mark.parametrize("credential", (None, "", "   ", 1, True, [], {}))
def test_remote_channels_require_a_credential_name(tmp_path, channel, credential):
    path = write(tmp_path, [item(channel=channel, source=SSH_SOURCE, credential=credential)])
    with pytest.raises(InventoryError, match="credential must name a record in the credential store"):
        load(path)


@pytest.mark.parametrize(
    "sections",
    (["system interface"], ["system interface", "firewall policy", "system admin"]),
)
def test_required_sections_holds_the_listed_sections(tmp_path, sections):
    assert load(write(tmp_path, [item(required_sections=sections)]))[0].required_sections == tuple(sections)


@pytest.mark.parametrize("sections", ([], None, "system interface", {}, 1, True))
def test_required_sections_must_be_a_non_empty_list(tmp_path, sections):
    path = write(tmp_path, [item(required_sections=sections)])
    with pytest.raises(InventoryError, match="required_sections must be a non-empty list"):
        load(path)


@pytest.mark.parametrize("section", ("", "   ", None, 1, True, [], {}))
def test_required_sections_must_hold_non_empty_strings(tmp_path, section):
    path = write(tmp_path, [item(required_sections=["system interface", section])])
    with pytest.raises(InventoryError, match=r"required_sections\[1\] must be a non-empty string"):
        load(path)


def test_duplicate_name_is_an_error(tmp_path):
    path = write(tmp_path, [item(), rest_item(name=NAME)])
    with pytest.raises(InventoryError, match="duplicate name"):
        load(path)


def test_different_names_are_fine(tmp_path):
    loaded = load(write(tmp_path, [item(), rest_item()]))
    assert [one.name for one in loaded] == [NAME, "fw-b.example.invalid"]


@pytest.mark.parametrize("field", ("vdom", "comment", "Name", "required-sections", "sections"))
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
    document = {"version": 1, "devices": [item()]}
    del document[field]
    path = write_raw(tmp_path, json.dumps(document))
    with pytest.raises(InventoryError, match="missing document fields: %s" % field):
        load(path)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_platform_from_the_enum_loads(tmp_path, platform):
    assert load(write(tmp_path, [item(platform=platform)]))[0].platform == platform


@pytest.mark.parametrize(
    "platform",
    ("ios", "FortiOS", "junos", "eos", "fortios ", "fortiswitch") + NOT_TEXT,
)
def test_platform_must_be_fortios(tmp_path, platform):
    path = write(tmp_path, [item(platform=platform)])
    with pytest.raises(InventoryError, match="platform must be one of fortios"):
        load(path)


@pytest.mark.parametrize("version", (2, 0, -1, "1", True, None, 1.5, [1], {}))
def test_version_must_be_one(tmp_path, version):
    path = write(tmp_path, [item()], version=version)
    with pytest.raises(InventoryError, match="unknown inventory file version"):
        load(path)


@pytest.mark.parametrize("name", NOT_TEXT)
def test_name_must_be_a_non_empty_string(tmp_path, name):
    path = write(tmp_path, [item(name=name)])
    with pytest.raises(InventoryError, match="name must be a non-empty string"):
        load(path)


@pytest.mark.parametrize("source", NOT_TEXT)
def test_source_must_be_a_non_empty_string(tmp_path, source):
    path = write(tmp_path, [item(source=source)])
    with pytest.raises(InventoryError, match="source must be a non-empty string"):
        load(path)


def test_missing_file_is_an_inventory_error(tmp_path):
    with pytest.raises(InventoryError, match="cannot read inventory file"):
        load(tmp_path / "nothing-here.json")


def test_broken_json_is_an_inventory_error(tmp_path):
    path = write_raw(tmp_path, '{"version": 1, "devices": [}')
    with pytest.raises(InventoryError, match="is not valid JSON"):
        load(path)


@pytest.mark.parametrize("document", ("[]", '"inventory"', "1", "null"))
def test_document_must_be_an_object(tmp_path, document):
    path = write_raw(tmp_path, document)
    with pytest.raises(InventoryError, match="must hold an object"):
        load(path)


@pytest.mark.parametrize("devices", ({}, "fw-a", 1, None))
def test_devices_must_be_a_list(tmp_path, devices):
    path = write_raw(tmp_path, json.dumps({"version": 1, "devices": devices}))
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
    assert device(loaded, "fw-c.example.invalid") is loaded[1]
    assert device(loaded, "fw-b.example.invalid") is loaded[2]


@pytest.mark.parametrize("name", ("fw-z.example.invalid", "FW-A.EXAMPLE.INVALID", "", None, 1))
def test_device_rejects_an_unknown_name(tmp_path, name):
    loaded = fleet(tmp_path)
    with pytest.raises(InventoryError, match="unknown device"):
        device(loaded, name)


def test_device_on_an_empty_inventory_is_an_error(tmp_path):
    loaded = load(write(tmp_path, []))
    with pytest.raises(InventoryError, match="no devices"):
        device(loaded, NAME)


def test_for_consumer_filters_and_keeps_order(tmp_path):
    loaded = fleet(tmp_path)
    auditor = for_consumer(loaded, "auditor")
    helper = for_consumer(loaded, "helper")
    assert isinstance(auditor, tuple)
    assert [one.name for one in auditor] == [NAME, "fw-b.example.invalid"]
    assert [one.name for one in helper] == ["fw-c.example.invalid"]
    assert auditor[0] is loaded[0]


def test_for_consumer_can_return_nothing(tmp_path):
    loaded = load(write(tmp_path, [item(consumer="auditor")]))
    assert for_consumer(loaded, "helper") == ()


@pytest.mark.parametrize("consumer", ("reporter", "Auditor", "", None, 1, True, ["auditor"]))
def test_for_consumer_rejects_an_unknown_consumer(tmp_path, consumer):
    loaded = fleet(tmp_path)
    with pytest.raises(InventoryError, match="consumer must be one of auditor, helper"):
        for_consumer(loaded, consumer)


from netops_auditor.inventory import CHANNEL_REST, CHANNEL_SSH

COLON_FORM = ":".join(
    TLS_FINGERPRINT[index:index + 2] for index in range(0, len(TLS_FINGERPRINT), 2)
)
BAD_TLS_FINGERPRINTS = (
    None,
    TLS_FINGERPRINT[:-1],
    TLS_FINGERPRINT + "a",
    TLS_FINGERPRINT.replace("a", "g"),
    TLS_FINGERPRINT[:-2] + "zz",
    COLON_FORM,
    "sha256:" + TLS_FINGERPRINT,
    " " + TLS_FINGERPRINT[:-1],
    "",
    "   ",
    0,
    1,
    True,
    [TLS_FINGERPRINT],
    {"sha256": TLS_FINGERPRINT},
)
BAD_HOST_KEYS = (
    None,
    HOST_KEY[len("SHA256:"):],
    HOST_KEY[:-1],
    HOST_KEY + "A",
    "sha256:" + HOST_KEY[len("SHA256:"):],
    "SHA256:" + "!" * 43,
    "MD5:" + HOST_KEY[len("SHA256:"):],
    "SHA256:",
    "",
    "   ",
    0,
    1,
    True,
    [HOST_KEY],
    {"sha256": HOST_KEY},
)


def test_rest_device_carries_the_pinned_certificate(tmp_path):
    loaded = load(write(tmp_path, [rest_item()]))
    assert loaded[0].channel == CHANNEL_REST
    assert loaded[0].tls_fingerprint == TLS_FINGERPRINT
    assert loaded[0].host_key_fingerprint is None


def test_ssh_device_carries_the_pinned_host_key(tmp_path):
    loaded = load(write(tmp_path, [ssh_item()]))
    assert loaded[0].channel == CHANNEL_SSH
    assert loaded[0].host_key_fingerprint == HOST_KEY
    assert loaded[0].tls_fingerprint is None


def test_file_device_pins_nothing(tmp_path):
    loaded = load(write(tmp_path, [item()]))
    assert loaded[0].tls_fingerprint is None
    assert loaded[0].host_key_fingerprint is None


def test_tls_fingerprint_is_normalized_to_lowercase(tmp_path):
    loaded = load(write(tmp_path, [rest_item(tls_fingerprint=TLS_FINGERPRINT.upper())]))
    assert loaded[0].tls_fingerprint == TLS_FINGERPRINT


def test_host_key_fingerprint_keeps_its_case(tmp_path):
    loaded = load(write(tmp_path, [ssh_item()]))
    assert loaded[0].host_key_fingerprint == HOST_KEY
    assert loaded[0].host_key_fingerprint.startswith("SHA256:")
    assert loaded[0].host_key_fingerprint != HOST_KEY.lower()


@pytest.mark.parametrize("fingerprint", BAD_TLS_FINGERPRINTS)
def test_rest_channel_demands_a_usable_tls_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [rest_item(tls_fingerprint=fingerprint)])
    with pytest.raises(InventoryError, match="tls_fingerprint must hold the sha256 certificate"):
        load(path)


@pytest.mark.parametrize("fingerprint", BAD_HOST_KEYS)
def test_ssh_channel_demands_a_usable_host_key_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [ssh_item(host_key_fingerprint=fingerprint)])
    with pytest.raises(InventoryError, match="host_key_fingerprint must hold the sha256 host key"):
        load(path)


@pytest.mark.parametrize("fingerprint", (TLS_FINGERPRINT, TLS_FINGERPRINT.upper(), "", "nonsense", 1, True, [], {}))
def test_file_channel_forbids_a_tls_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [item(tls_fingerprint=fingerprint)])
    with pytest.raises(InventoryError, match="tls_fingerprint must be null for channel file"):
        load(path)


@pytest.mark.parametrize("fingerprint", (TLS_FINGERPRINT, "nonsense", 1, True, [], {}))
def test_ssh_channel_forbids_a_tls_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [ssh_item(tls_fingerprint=fingerprint)])
    with pytest.raises(InventoryError, match="tls_fingerprint must be null for channel ssh"):
        load(path)


@pytest.mark.parametrize("fingerprint", (HOST_KEY, "nonsense", 1, True, [], {}))
def test_file_channel_forbids_a_host_key_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [item(host_key_fingerprint=fingerprint)])
    with pytest.raises(InventoryError, match="host_key_fingerprint must be null for channel file"):
        load(path)


@pytest.mark.parametrize("fingerprint", (HOST_KEY, "nonsense", 1, True, [], {}))
def test_rest_channel_forbids_a_host_key_fingerprint(tmp_path, fingerprint):
    path = write(tmp_path, [rest_item(host_key_fingerprint=fingerprint)])
    with pytest.raises(
        InventoryError, match="host_key_fingerprint must be null for channel fortios-rest"
    ):
        load(path)


def test_both_pins_are_required_fields(tmp_path):
    assert DEVICE_FIELDS[-3:] == ("tls_fingerprint", "host_key_fingerprint", "legacy_ssh")
    for field in ("tls_fingerprint", "host_key_fingerprint", "legacy_ssh"):
        path = write(tmp_path, [without(field)])
        with pytest.raises(InventoryError, match="missing fields: %s" % field):
            load(path)


def test_pin_fields_are_not_taken_for_secrets(tmp_path):
    loaded = load(write(tmp_path, [rest_item(), ssh_item()]))
    assert loaded[0].tls_fingerprint == TLS_FINGERPRINT
    assert loaded[1].host_key_fingerprint == HOST_KEY


def test_pinned_devices_stay_immutable(tmp_path):
    loaded = load(write(tmp_path, [rest_item(), ssh_item()]))
    with pytest.raises(AttributeError):
        loaded[0].tls_fingerprint = TLS_FINGERPRINT.replace("0", "1")
    with pytest.raises(AttributeError):
        loaded[1].host_key_fingerprint = HOST_KEY.replace("0", "1")


@pytest.mark.parametrize("profile", LEGACY_SSH_PROFILES)
def test_ssh_channel_takes_a_named_legacy_profile(tmp_path, profile):
    loaded = load(write(tmp_path, [ssh_item(legacy_ssh=profile)]))
    assert loaded[0].legacy_ssh == profile


def test_ssh_channel_without_a_legacy_profile_stays_on_current_algorithms(tmp_path):
    loaded = load(write(tmp_path, [ssh_item()]))
    assert loaded[0].legacy_ssh is None


@pytest.mark.parametrize(
    "profile",
    (
        "ssh-rsa",
        "HostKeyAlgorithms=+ssh-rsa",
        "rsa-sha1,diffie-hellman-group14-sha1",
        "RSA-SHA1",
        "rsa_sha1",
        " rsa-sha1",
        "rsa-sha1 ",
        "-oProxyCommand=touch /tmp/pwned",
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
    path = write(tmp_path, [ssh_item(legacy_ssh=profile)])
    with pytest.raises(InventoryError, match="legacy_ssh must be null for a device that speaks"):
        load(path)


@pytest.mark.parametrize("profile", LEGACY_SSH_PROFILES + ("ssh-rsa", "", 1, True, [], {}))
def test_file_channel_forbids_a_legacy_profile(tmp_path, profile):
    path = write(tmp_path, [item(legacy_ssh=profile)])
    with pytest.raises(InventoryError, match="legacy_ssh must be null for channel file"):
        load(path)


@pytest.mark.parametrize("profile", LEGACY_SSH_PROFILES + ("ssh-rsa", "", 1, True, [], {}))
def test_rest_channel_forbids_a_legacy_profile(tmp_path, profile):
    path = write(tmp_path, [rest_item(legacy_ssh=profile)])
    with pytest.raises(InventoryError, match="legacy_ssh must be null for channel fortios-rest"):
        load(path)


def test_every_legacy_profile_is_one_the_collector_can_expand():
    assert LEGACY_SSH_PROFILES == tuple(sorted(LEGACY_SSH_OPTIONS))
    for profile in LEGACY_SSH_PROFILES:
        assert LEGACY_SSH_OPTIONS[profile]
