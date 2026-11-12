import importlib.util
import ipaddress
import json
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "support/anonymize_fixture.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL = FIXTURES / "real"


def _load():
    spec = importlib.util.spec_from_file_location("anonymize_fixture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


anonymize = _load()


def run(text, **options):
    engine = anonymize.Anonymizer(**options)
    return engine.text(text), engine


# The inputs below stand for raw device output, so they must be outside the documentation ranges. The source privacy
# gate refuses such literals in tracked files, therefore every one of them is synthetic and built at run time.
def _mac(*octets, sep=":"):
    return sep.join(f"{octet:02x}" for octet in octets)


def _ipv4(*octets):
    return ".".join(str(octet) for octet in octets)


def _ipv6(*groups):
    return str(ipaddress.IPv6Address(":".join(f"{group:x}" for group in groups)))


SITE = (0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F)          # a synthetic locally administered unicast MAC
OTHER = (0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x60)
SITE_MAC = _mac(*SITE)
SITE_HEX = SITE_MAC.replace(":", "")
SITE_DOT = ".".join(SITE_HEX[i:i + 4] for i in range(0, 12, 4))
LAN = (172, 31, 133)                                # a synthetic private /24
WELL_KNOWN = " ".join((_mac(0x01, 0x80, 0xC2, 0, 0, 0x0E), _mac(*[0xFF] * 6), _mac(*[0] * 6),
                       _mac(0x01, 0x00, 0x5E, 0, 0, 0xFB), _mac(0x00, 0xE0, 0x2B, 0, 0, 0)))
GLOBAL6 = _ipv6(0x2A00, 0x1234, 0x5678, 1, 0, 0, 0, 7)
LINK6 = _ipv6(0xFE80, 0, 0, 0, 0x0819, 0x2CFF, 0xFE3D, 0x4E5F)


def test_mac_spellings_map_consistently_and_keep_their_format():
    text = (f"{SITE_MAC} {_mac(*SITE, sep='-').upper()} {SITE_DOT} {SITE_HEX.upper()}\n"
            f"{SITE_MAC.upper()} {_mac(*OTHER)}\n")
    result, _ = run(text)
    first = result.split()
    assert first[0] == "00:00:5e:00:53:01"
    assert first[1] == "00-00-5E-00-53-01"
    assert first[2] == "0000.5e00.5301"
    assert first[4] == "00:00:5E:00:53:01"            # same address, original upper case
    assert first[5] == "00:00:5e:00:53:02"
    assert SITE_HEX not in result.lower().replace(":", "").replace("-", "").replace(".", "")


def test_group_and_well_known_addresses_are_kept():
    text = WELL_KNOWN + "\n"
    assert run(text)[0] == text


def test_bridge_id_keeps_priority_and_maps_the_mac_like_the_system_mac():
    text = f"System MAC: {SITE_MAC}\nBridgeID: 80:00:{SITE_MAC}\nRegion: {SITE_HEX} id 8000{SITE_HEX}\n"
    result, _ = run(text)
    assert "System MAC: 00:00:5e:00:53:01" in result
    assert "BridgeID: 80:00:00:00:5e:00:53:01" in result
    assert "Region: 00005e005301 id 800000005e005301" in result


def test_ipv4_keeps_subnet_relations_and_host_octet():
    text = f"gw {_ipv4(*LAN, 1)} host {_ipv4(*LAN, 111)} other {_ipv4(10, 9, 8, 7)} net {_ipv4(*LAN, 0)}/24\n"
    result, _ = run(text)
    addresses = re.findall(r"\d+\.\d+\.\d+\.\d+", result)
    assert addresses[0].endswith(".1") and addresses[1].endswith(".111") and addresses[3].endswith(".0")
    assert addresses[0].rsplit(".", 1)[0] == addresses[1].rsplit(".", 1)[0] == addresses[3].rsplit(".", 1)[0]
    assert addresses[2].rsplit(".", 1)[0] != addresses[0].rsplit(".", 1)[0]
    assert addresses[0].startswith("192.0.2.")
    assert all(any(ipaddress.ip_address(a) in ipaddress.ip_network(net + ".0/24") for net in anonymize.DOC_NETS)
               for a in addresses)


def test_masks_loopback_multicast_and_versions_stay():
    text = ("mask 255.255.255.0 wildcard 0.0.0.255 any 0.0.0.0 lo 127.0.0.1 grp 224.0.0.5 bcast 255.255.255.255\n"
            "Primary ver:      33.7.1.6\nImage : ExtremeXOS version 33.7.1.6 33.7.1.6-patch1-11\nBootROM : Default 1.0.1.9  Alternate 1.0.1.9\n")
    assert run(text)[0] == text


def test_ipv6_maps_into_documentation_space_and_keeps_multicast():
    text = f"{GLOBAL6} {LINK6} ff02::1 ::1 {GLOBAL6}\n"
    result, _ = run(text)
    mapped = result.split()
    assert mapped[0].startswith("2001:db8:") and mapped[0] == mapped[4]
    assert mapped[1].startswith("fe80::") and "819" not in mapped[1]
    assert mapped[2:4] == ["ff02::1", "::1"]


@pytest.mark.parametrize("order", [(0, 1), (1, 0)])
def test_ipv6_never_maps_two_addresses_to_one(order):
    addresses = [_ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0x1234, 0x5678), _ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0, 0x10)]
    result, _ = run(" ".join(addresses[i] for i in order) + "\n")
    mapped = result.split()
    assert len(set(mapped)) == 2 and all(item.startswith("2001:db8:1::") for item in mapped)
    # the short host part is kept whenever it is free: only the colliding one moves
    assert result.split()[order.index(1)] != result.split()[order.index(0)]


def test_ipv6_many_addresses_in_one_prefix_stay_distinct():
    addresses = ([_ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0, n) for n in range(0x8, 0x40)]
                 + [_ipv6(0x2001, 0x4860, 1, 0, 0, 0, n, n) for n in range(1, 40)])
    mapped = run(" ".join(addresses) + "\n")[0].split()
    assert len(set(mapped)) == len(addresses)


def test_loading_a_map_that_merges_two_addresses_is_refused():
    net = str(int(ipaddress.IPv6Address(_ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0, 0))) >> 64)
    ten, ninety_nine = _ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0, 0x10), _ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0, 0x99)
    engine = anonymize.Anonymizer()
    engine.load({"ipv6net": {net: 1}, "ipv6": {ten: 0x10}})
    broken = anonymize.Anonymizer()
    with pytest.raises(ValueError):
        broken.load({"ipv6net": {net: 1}, "ipv6": {ten: 0x10, _ipv6(0x2001, 0x4860, 1, 0, 0, 0, 0x1234, 0x5678): 0x10}})
    follow, _ = (engine.text(f"{ten} {ninety_nine}\n"), None)
    assert follow.split() == ["2001:db8:1::10", "2001:db8:1::99"]


def test_mapping_is_deterministic_and_can_be_reloaded():
    text = f"a {_ipv4(*LAN, 5)} b {SITE_MAC} c {_ipv6(0xFE80, 0, 0, 0, 1, 2, 3, 4)}\n"
    one, engine = run(text)
    assert run(text)[0] == one
    again = anonymize.Anonymizer()
    again.load(engine.dump())
    assert again.text(text) == one


def test_column_alignment_is_kept_when_the_replacement_has_another_length():
    text = (f"{_ipv4(*LAN, 111)}  /24   up\n"
            f"{_ipv4(*LAN, 1)}    /24   up\n"
            f"{_mac(*OTHER)}   x\n")
    result, _ = run(text)
    rows = result.splitlines()
    assert rows[0].index("/24") == rows[1].index("/24") == text.splitlines()[0].index("/24")
    assert rows[2].endswith("x")
    line = f"Name: {_ipv4(10, 177, 133, 111)}          next\n"
    long_to_short, _ = run(line)
    assert long_to_short.index("next") == line.index("next")


def test_names_serials_ssids_users_and_descriptions():
    text = ("SysName:          SW-Core-7\nSysLocation:      Rack-B\nChassis : 800614-00-22 2135N-41490 Rev 22\n"
            "SSID: LabNet\nlink to switch SW-Core-7 port 3 desc Printer-R2\n")
    result, engine = run(text, descriptions=["Printer-R2"], users=[])
    assert "SW-Core-7" not in result and "Rack-B" not in result and "2135N-41490" not in result
    assert "LabNet" not in result and "Printer-R2" not in result
    assert re.search(r"SysName:\s+host01\b", result)
    assert "800614-00-22" in result                    # part number is not an identifier
    assert re.search(r"\d{4}S-\d{5}", result)          # serial keeps its shape and length
    assert len(re.search(r"Chassis : \S+ (\S+)", result)[1]) == len("2135N-41490")
    assert not engine.residual(result)


def test_truncated_display_strings_are_mapped_consistently():
    text = "Uplink-S>VR-Default E A\n3 Uplink-SW3 x\n"
    result, _ = run(text, descriptions=["Uplink-SW3"])
    first, second = result.splitlines()
    assert first.startswith("port-des>VR-Default") and "Uplink" not in result
    assert second.split()[1].startswith("port-des")


def test_host_name_equal_to_the_model_is_replaced_but_the_model_stays():
    text = ("SysName:          X440G2-12p-10G4\nSystem Type:      X440G2-12p-10G4\n"
            "Port    Chassis ID         Port ID            TTL     Age     System Name\n"
            "=====================================================================\n"
            "13      00:00:5E:00:53:02  13                 120     7       X440G2-12p-10G4\n"
            "=====================================================================\n"
            "    - System Name: \"X440G2-12p-10G4\"\n"
            "    - System Description: \"ExtremeXOS (X440G2-12p-10G4) version 33.7.1.6\"\n"
            "* X440G2-12p-10G4.7 # show switch\nX440G2-12p-10G4.8 # \n")
    result, engine = run(text)
    assert re.search(r"SysName:\s+host01\n", result) and re.search(r"System Type:\s+X440G2-12p-10G4\n", result)
    assert re.search(r"120     7       host01\n", result) and '- System Name: "host01"' in result
    assert "ExtremeXOS (X440G2-12p-10G4) version" in result
    assert "* host01.7 # show switch" in result and "\nhost01.8 # " in result
    assert not engine.residual(result)
    assert any(item.startswith("SysName ") for item in engine.residual("SysName: X440G2-12p-10G4\nSystem Type: X440G2-12p-10G4\n"))


def test_lldp_hex_dump_bytes_are_blanked():
    text = "    - Unknown organizational specific TLV: Length=4 bytes, OUI=00A0C5\n      HEX Dump [000]: 00 A0 C5 02 0A 47 53 31\n"
    result, _ = run(text)
    assert "HEX Dump [000]: 00 00 00 00 00 00 00 00" in result
    assert "OUI=00A0C5" in result


def test_residual_reports_what_is_left():
    engine = anonymize.Anonymizer(names=["secret-host"])
    assert engine.residual(f"host secret-host at {SITE_MAC} and {_ipv4(*LAN, 5)}") == [
        f"mac {SITE_MAC}", f"ipv4 {_ipv4(*LAN, 5)}", "name secret-host"]
    assert engine.residual("00:00:5e:00:53:01 192.0.2.5 2001:db8::1") == []


@pytest.mark.parametrize("text,kind", [
    (f"addr {_ipv6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)} up", "ipv6"),
    (f"addr {GLOBAL6}", "ipv6"),
    (f"lladdr {LINK6}", "ipv6"),
    (f"BridgeID: 80:00:{SITE_MAC}", "bridge id"),
    (f"Region: {SITE_HEX} id", "bare mac"),
    (f"Region: 8000{SITE_HEX} id", "bare mac"),
    (f"neighbor {SITE_DOT}", "mac"),
    (f"neighbor {_mac(*SITE, sep='-').upper()}", "mac"),
    (f"former fallback {_ipv4(198, 18, 0, 5)}", "ipv4"),
    (f"old placeholder {_mac(0x02, 0x00, 0x5E, 0, 0, 1)}", "mac"),
    ("SysName:          anything-real", "SysName"),
    ('    - System Name: "anything-real"', "System Name"),
    ("anything-real.3 # show switch", "prompt"),
    ("Cisco IOS Software, Version 15.9\nprivate-router uptime is 5 days", "IOS hostname"),
    ("Device ID: private-router", "Device ID"),
    ("Device ID: private-router(SYNTHETIC)", "Device ID"),
    ("Hostname: private-router", "Hostname"),
    ("FQDN: private-router.example", "FQDN"),
])
def test_residual_finds_real_identifiers_in_every_spelling(text, kind):
    found = anonymize.Anonymizer().residual(text + "\n")
    assert found and found[0].startswith(kind), found


@pytest.mark.parametrize("text", [
    "addr 2001:db8:1::10 fe80::10 ff02::1 ::1 :: 2001:DB8::ABCD",
    f"BridgeID: 80:00:00:00:5e:00:53:01 Region: 00005e005301 id 800000005e005301 {_mac(0x01, 0x80, 0xC2, 0, 0, 0x0E)}",
    "SysName:          host01\nSysLocation:      None\n    - System Name: \"host02\"\nhost03.7 # show switch\n",
    "22:50:57.50 version 33.7.1.6 mask 255.255.255.0 gw 192.0.2.1 198.51.100.7 203.0.113.9",
    "host01 uptime is 5 days\nDevice ID: host02(SYNTHETIC)\nHostname: host03\nFQDN: host03\n",
    "Kernel uptime is 0 day(s), 2 hour(s), 40 minute(s), 53 second(s)\nntp uptime is 107500 (1/100 of seconds), resolution is 4000\n",
])
def test_residual_accepts_documentation_ranges_placeholders_and_constants(text):
    assert anonymize.Anonymizer().residual(text + "\n") == []


def test_command_line_writes_copies_and_checks(tmp_path):
    source = tmp_path / "raw" / "arp.txt"
    source.parent.mkdir()
    source.write_text(f"{_ipv4(*LAN, 7)}     {SITE_MAC}  NO\n")
    mapping = tmp_path / "map.json"
    assert anonymize.main([str(source), "--out", str(tmp_path / "out"), "--map", str(mapping), "--check"]) == 0
    assert (tmp_path / "out" / "arp.txt").read_text().startswith("192.0.2.7")
    assert mapping.stat().st_mode & 0o077 == 0


def _json_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)
    elif isinstance(value, str):
        yield value


def _fixture_text(path):
    """CLI text of a fixture; a JSON fixture contributes its decoded strings (escaped line feeds hide addresses)."""
    text = path.read_text(errors="replace")
    if path.suffix == ".json":
        try:
            return "\n".join(_json_strings(json.loads(text)))
        except ValueError:
            return text
    return text


def _fixture_residuals(root):
    leftovers = []
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        text = path.read_text(errors="replace")
        leftovers += [f"{path.relative_to(root)}: {kind}" for kind in anonymize.Anonymizer.credential_markers(text)]
    for directory in sorted({path.parent for path in root.rglob("*") if path.suffix in (".txt", ".json")}):
        texts = {path: _fixture_text(path) for path in sorted(directory.iterdir()) if path.suffix in (".txt", ".json")}
        engine = anonymize.Anonymizer()
        for text in texts.values():
            engine.prime(text)
        for path, text in texts.items():
            leftovers += [f"{path.relative_to(root)}: {item}" for item in engine.residual(text)
                          if not _synthetic_name(item)]
    return leftovers


# Host names of the vendor documentation and synthetic fixtures (docs/, tables/, identity/) and the serial-shaped
# placeholders of the anonymised FortiGate captures. They name no site; each is listed so that any other name fails.
SYNTHETIC_NAMES = frozenset((
    "leaf2", "core-sw", "SEP00005E0053B0.example.net", "phone-1", "lab-ios", "lab-xe", "lab-isr", "lab-ios-router",
    "lab-mx480", "lab-junos", "lab-els", "lab-vc", "FGT80FTK00000000", "FGT80F0000001111", "FGT80F0000002222"))
NAME_FINDINGS = ("name ", "SysName ", "System Name ", "Hostname ", "IOS hostname ", "Device ID ", "FQDN ", "prompt ")


def _synthetic_name(item):
    return item.startswith(NAME_FINDINGS) and item.rsplit(" ", 1)[-1] in SYNTHETIC_NAMES


@pytest.mark.parametrize("text,kind", [
    ("$6$test$0123456789", "credential:crypt"),
    ("$1$test$0123456789", "credential:crypt"),
    ("username demo secret 5 X", "credential:username-secret"),
    ("username demo secret 9 X", "credential:username-secret"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "credential:private-key"),
    ("-----BEGIN RSA PRIVATE KEY-----", "credential:private-key"),
    ("-----BEGIN EC PRIVATE KEY-----", "credential:private-key"),
    ("-----BEGIN PRIVATE KEY-----", "credential:private-key"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "credential:private-key"),
], ids=["sha512", "md5", "ios-type5", "ios-type9", "openssh", "rsa", "ec", "pkcs8", "encrypted-pkcs8"])
@pytest.mark.parametrize("filename", ["capture.txt", "index.json", "nested/capture.bin"])
def test_every_forbidden_credential_type_fails_the_fixture_guard_without_disclosing_values(tmp_path, text, kind, filename):
    source = tmp_path / filename
    source.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"output": text}).encode() if source.suffix == ".json" else b"\xff\n" + text.encode() + b"\n"
    source.write_bytes(payload)
    assert anonymize.Anonymizer().residual(text) == [kind]
    findings = _fixture_residuals(tmp_path)
    assert findings and all(item == f"{filename}: {kind}" for item in findings)
    assert text not in " ".join(findings)


def test_committed_fixtures_hold_no_site_identifiers():
    """Every committed fixture, not only the real captures: credential markers in every file; MAC/IP and host-name
    fields in CLI text and in the strings of JSON fixtures. Reports contain only file names and finding types for
    credentials, never their values."""
    assert REAL.is_dir() and (FIXTURES / "fortios_80f_802_routing_arp.txt").is_file()
    leftovers = _fixture_residuals(FIXTURES)
    assert leftovers == []


def test_the_fixture_check_reads_json_strings_and_only_listed_synthetic_names_pass(tmp_path):
    (tmp_path / "capture.json").write_text(json.dumps({"output": "Address\n" + _ipv4(*LAN, 9) + "  NO\n"}))
    (tmp_path / "status.txt").write_text("Hostname: leaf2\nHostname: branch-office-7\n")
    findings = _fixture_residuals(tmp_path)
    assert f"capture.json: ipv4 {_ipv4(*LAN, 9)}" in findings
    assert any(item.startswith("status.txt: ") and item.endswith("branch-office-7") for item in findings)
    assert not any(item.endswith(" leaf2") for item in findings)


@pytest.mark.parametrize('profile,directory,query', [
    ('cisco_nxos', 'nexus9300v_9.3.12', 'version'),
    ('cisco_xe', 'iolxe_17.18.2', 'ntp_status'),
])
def test_system_uptime_subject_is_not_a_hostname(profile, directory, query):
    text = (REAL / profile / directory / (query + '.txt')).read_text()
    engine = anonymize.Anonymizer()
    assert engine.residual(text) == []
    assert list(engine._ios_hostnames(text)) == []
    assert engine.text(text) == text


@pytest.mark.parametrize('banner', ['Cisco IOS Software, Version 15.9',
                                   'Cisco IOS Software [IOSXE], Version 17.18.2',
                                   'Cisco IOS XE Software, Version 17.12'])
@pytest.mark.parametrize('hostname', ['private-router', 'Kernel', 'ntp'])
def test_ios_identity_hostname_is_detected_and_anonymized(banner, hostname):
    text = banner + '\n' + hostname + ' uptime is 5 days\n'
    engine = anonymize.Anonymizer()
    assert engine.residual(text) == ['IOS hostname ' + hostname]
    clean = engine.text(text)
    assert re.search(r'(?m)^host01[ \t]+uptime is 5 days$', clean)
    assert engine.residual(clean) == []
