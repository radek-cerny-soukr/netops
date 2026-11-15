"""Public ssh_read path of Arista EOS `mlag_interfaces` (`show mlag interfaces`) and its `mlag_members` key.

Path: Proxy.request -> TargetAuth.decode -> engine.ssh_read with the real catalog, policy, redaction and
`switch_mlag_eos.payload`; only the physical SSH transport and the audit record are replaced.

Data labels:
* DOC     - tests/fixtures/docs/arista_eos/mlag_interfaces.txt: the `show mlag interfaces` example of the official
            Arista ATD lab guide 2026.2 (https://labguides.testdrive.arista.com/2026.2/data_center/vxlan/) without
            its prompt-and-echo line.  A documentation example, not a measurement and no EOS firmware or hardware
            qualification.
* DERIVED - unrecognized text and an empty capture, made only to exercise the public path.
The members are reported device data, never a health, forwarding or consistency verdict.
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
DOC = (HERE / "fixtures/docs/arista_eos/mlag_interfaces.txt").read_text()
MLAG_DETAIL = (HERE / "fixtures/real/arista_eos/ceos_4.36.1F/mlag_detail.txt").read_text()
NXOS_DIR = HERE / "fixtures/real/cisco_nxos/nexus9300v_9.3.12"
IDENTITY = {"cisco_nxos": NXOS_DIR / "version.txt", "arista_eos": HERE / "fixtures/identity/arista_eos.txt"}
EOS_QUERIES = ("version", "mlag_detail", "mlag_interfaces", "mlag_config_sanity")
DOC_MEMBER = {"id": 5, "description": "MLAG - HOST2", "state": "active-full", "local_port": "Po5",
              "remote_port": "Po5", "local_status": "up", "remote_status": "up", "missing_fields": []}
UNRECOGNIZED = "NEW UNRECOGNIZED OUTPUT\n"  # DERIVED
VERDICT_WORDS = ("health", "healthy", "consistent", "consistency", "verdict", "operable")


def _gateway(tmp_path, monkeypatch, outputs, platform="arista_eos", queries=EOS_QUERIES, rc=0):
    import test_proxy_contracts as contracts
    from netops_helper import engine
    module = contracts._load_proxy()
    inventory, _, _, _ = contracts._configure(module, tmp_path)
    section = contracts._section()
    section.update(ssh_platform=platform, device_types=["switch"], enabled_queries=list(queries), read_inventory={})
    section["egress"]["tcp_ports"].append(22)
    contracts._write(inventory, contracts._inventory(contracts._device(section, platform)))
    gateway = module.Proxy()
    calls = []

    def transport(auth, platform_name, command, **kwargs):
        calls.append(command)
        if command == "show version":
            return 0, IDENTITY[platform_name].read_text()
        return rc, outputs[command]
    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)
    engine._SSH_PAGE_CACHE.clear()
    return contracts, gateway, calls


def _ssh_read(contracts, gateway, index, platform="arista_eos", **arguments):
    from netops_helper import engine
    from netops_helper.auth import TargetAuth
    forwarded = gateway.request(contracts._request(index, "ssh_read", {"target": "device-a", "platform": platform, **arguments}))
    assert forwarded is not None
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    return engine.ssh_read(auth, args["platform"], args["query"], args.get("parameters"), args.get("offset", 0),
                           args.get("max_bytes", 48_000), args.get("content_sha256"))


def _summarize(text, capture_state="ok"):
    from netops_helper import switch_mlag_eos_interfaces
    return switch_mlag_eos_interfaces.summarize(text, capture_state)


def _no_verdict(answer):
    keys = set(answer) | set(answer.get("mlag_members", {}))
    assert not any(word in key.lower() for key in keys for word in VERDICT_WORDS), keys


def test_public_doc_fixture_gives_one_measured_member(tmp_path, monkeypatch):
    contracts, gateway, calls = _gateway(tmp_path, monkeypatch, {"show mlag interfaces": DOC})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_interfaces", offset=0)
    assert answer["ok"] is True and answer["complete"], answer
    assert calls.count("show mlag interfaces") == 1
    assert answer["untrusted_device_output"] == DOC
    assert answer["mlag_members"] == _summarize(DOC)
    assert answer["mlag_members"] == {"state": "measured", "members": [DOC_MEMBER], "missing_fields": []}
    (member,) = answer["mlag_members"]["members"]
    assert (member["id"], member["local_port"], member["remote_port"]) == (5, "Po5", "Po5")
    assert "mlag" not in answer
    _no_verdict(answer)


def test_public_unrecognized_output_is_unparsed(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag interfaces": UNRECOGNIZED})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_interfaces", offset=0)
    assert answer["ok"] is True and answer["untrusted_device_output"] == UNRECOGNIZED
    assert answer["mlag_members"] == {"state": "unparsed", "members": [], "missing_fields": ["table", "members"]}
    _no_verdict(answer)


def test_empty_output_is_unparsed_and_the_public_path_reports_no_member_key(tmp_path, monkeypatch):
    from netops_helper import switch_mlag_eos
    for text in ("", "\n", "  \r\n"):
        assert switch_mlag_eos.payload("arista_eos", "mlag_interfaces", text, "ok") == {
            "mlag_members": {"state": "unparsed", "members": [], "missing_fields": ["table", "members"]}}
    # The engine answers an empty capture before any summary: no result was read, so no members key at all.
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show mlag interfaces": ""})
    answer = _ssh_read(contracts, gateway, 1, query="mlag_interfaces", offset=0)
    assert answer["ok"] is False and answer["error_code"] == "empty"
    assert "mlag_members" not in answer and "mlag" not in answer


def test_public_mlag_detail_keeps_only_mlag_and_mlag_interfaces_only_mlag_members(tmp_path, monkeypatch):
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch,
                                     {"show mlag detail": MLAG_DETAIL, "show mlag interfaces": DOC})
    detail = _ssh_read(contracts, gateway, 1, query="mlag_detail", offset=0)
    assert detail["ok"] is True and "mlag" in detail and "mlag_members" not in detail
    members = _ssh_read(contracts, gateway, 2, query="mlag_interfaces", offset=0)
    assert members["ok"] is True and "mlag_members" in members and "mlag" not in members
    version = _ssh_read(contracts, gateway, 3, query="version", offset=0)
    assert version["ok"] is True and "mlag_members" not in version and "mlag" not in version


def test_public_other_profile_gets_no_mlag_members(tmp_path, monkeypatch):
    from netops_helper import switch_mlag_eos
    nxos = (NXOS_DIR / "vpc_status.txt").read_text()
    contracts, gateway, _ = _gateway(tmp_path, monkeypatch, {"show vpc brief": nxos}, platform="cisco_nxos",
                                     queries=("version", "vpc_status"))
    answer = _ssh_read(contracts, gateway, 1, platform="cisco_nxos", query="vpc_status", offset=0)
    assert answer["ok"] and "vpc" in answer and "mlag_members" not in answer
    for platform in ("cisco_nxos", "extreme_exos", "cisco_ios", "juniper_junos", "fortinet"):
        assert switch_mlag_eos.payload(platform, "mlag_interfaces", DOC, "ok") == {}
