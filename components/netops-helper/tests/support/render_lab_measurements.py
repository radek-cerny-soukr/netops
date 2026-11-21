#!/usr/bin/env python3
"""Render the GNS3 lab measurement tables of the IOS, IOS XE, NX-OS, EOS and Junos vendor notes from tests/fixtures/real.

Every cell is derived from the stored output (`index.json` gives the SSH exit status and the account):
what the read-only account got, and, where the account was refused, what the admin account got
(`<query>.admin.txt`). A template no stored device could answer is `verified: docs-only`.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
REAL = ROOT / "tests/fixtures/real"
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(ROOT.parent / "netops-core/src"))
sys.path.insert(0, str(ROOT.parents[1] / "src"))

TARGETS = {
    "docs/vendor-cli-references/cisco.md": (
        ("cisco_ios", "Cisco IOS", (("iosv_15.9.3M12", "IOSv 15.9(3)M12 (router)"), ("iosvl2_15.2.20200924", "IOSvL2 15.2(20200924)"))),
        ("cisco_xe", "Cisco IOS XE", (("iolxe_17.18.2", "IOL XE 17.18.2 (router)"),)),
        ("cisco_nxos", "Cisco NX-OS", (("nexus9300v_9.3.12", "Nexus 9300v 9.3(12)"),)),
    ),
    "docs/vendor-cli-references/arista-eos.md": (("arista_eos", "Arista EOS", (("ceos_4.36.1F", "cEOS 4.36.1F"),)),),
    "docs/vendor-cli-references/juniper-junos.md": (("juniper_junos_els", "Junos OS (ELS)", (("vjunosswitch_26.2R1.7", "vJunos-switch 26.2R1.7"),)),),
}
def markers(profile: str) -> tuple[str, str]:
    """The first block of a note (IOS, EOS, Junos) keeps the plain markers; later blocks of the same note carry the profile."""
    suffix = "" if profile in ("cisco_ios", "arista_eos", "juniper_junos_els") else f" {profile}"
    return f"<!-- lab-measurements:begin{suffix} -->", f"<!-- lab-measurements:end{suffix} -->"

REFUSED = re.compile(r'Line has invalid autocommand|privileged mode required|% Invalid input|% Unavailable command|% Ambiguous|% Incomplete')
DENIED = re.compile(r'% Permission denied for the role|error: permission denied')
ABSENT = re.compile(r'Syntax error while parsing|error: unknown command|error: syntax error|subsystem (?:is )?not running')
FAILED = re.compile(r'(?mi)^(?:ERROR:|Cmd exec error\.)')
NOT_CONFIGURED = re.compile(r'% BGP (?:not active|inactive)|IPv6 routing not enabled|BGP is not running|OSPF3 process does not exist in vrf |Spanning-tree is not enabled at global level|No spanning tree instances? exists?|No VRF named |IP routing table vrf .* does not exist')



NXOS_G92_CAPTURES = {
    "stp_detail": "2255-stp-detail",
    "stp_interface_detail": "2255-stp-port",
    "stp_mst": "2255-stp-mst",
    "port_channel_database": "2261-lag-database",
    "lacp_interface": "2261-lacp-port-compact",
    "port_channel_load_balance": "2261-lag-load",
    "vpc_member_consistency": "2261-vpc-member",
    "vpc_interface_consistency": "2261-vpc-interface-compact",
    "lldp_neighbor_interface": "2255-lldp-mgmt-compact",
    "cdp_neighbor_interface": "2261-cdp-port",
}

def cisco_operational_capture(image: str, query: str) -> tuple[str, bool] | None:
    if query == "vrf_cef_lookup":
        capture = {
            "iosv_15.9.3M12": REAL / "cisco_ios/g59/d-iosv/vrf_cef",
            "iolxe_17.18.2": REAL / "cisco_xe/g77/d-iolxe/vrf_cef",
        }.get(image)
        if capture is not None:
            return capture.read_text(), False
    node = {"iosv_15.9.3M12": "iosv", "iolxe_17.18.2": "iolxe"}.get(image)
    if node is None:
        return None
    captures = REAL / "cisco_ios" / "g57" / node
    if node == "iolxe" and query == "qos_queues":
        captures = REAL / "cisco_ios_xe" / "g75" / "lab"
    read_only = captures / f"ro_{query}.out"
    if not read_only.is_file():
        return None
    text = read_only.read_text()
    admin = captures / f"{query}.out"
    admin_answered = admin.is_file() and not REFUSED.search(admin.read_text())
    return text, admin_answered


XE_G72_CAPTURES = {
    "log_history": "log_messages",
    "hsrp_detail": "hsrp_detail",
    "vrrp_detail": "vrrp_detail",
    "ip_sla_statistics": "ip_sla_statistics",
    "object_tracking": "object_tracking",
}

IOS_XE_G73_ROUTER_CAPTURES = {
    "arp_lookup": "router-arp_global",
    "arp_lookup_vrf": "router-arp_vrf",
    "arp_table_vrf": "router-arp_vrf_table",
    "ipv6_neighbors_interface": "router-nd_port",
    "ipv6_neighbors_vrf": "router-nd_vrf",
    "ipv6_neighbors_interface_vrf": "router-nd_vrf_port",
    "dhcp_server_bindings": "router-lease",
    "dhcp_server_binding_address": "router-lease_address",
    "dhcp_server_pools": "router-pool",
    "dhcp_server_conflicts": "router-conflict",
    "dhcp_server_statistics": "router-stats",
}

def cell(directory: Path, name: str, index: dict) -> str:
    entry = index.get(name)
    groups = {"ceos_4.36.1F": ("g117_ceos_4.36.1F", "g118_ceos_4.36.1F", "g119_ceos_4.36.1F",
                                       "g120_ceos_4.36.1F"),
              "vjunosswitch_26.2R1.7": ("g132_vjunosswitch_26.2R1.7", "g133_vjunosswitch_26.2R1.7",
                                      "g135_vjunosswitch_26.2R1.7")}.get(directory.name)
    if entry is None and groups:
        # Recent groups keep both accounts in separate fixture directories.
        for group in groups:
            capture = directory.with_name(group)
            measured = json.loads((capture / "index.json").read_text())
            entry = measured.get(name + "_ro")
            if entry is None and group.startswith("g133_"):
                entry = measured.get(name + "_admin")
            if entry is not None:
                text = entry["text"] if "text" in entry else (capture / entry["file"]).read_text()
                admin = name + "_admin" in measured and measured[name + "_admin"]["rc"] == 0
                if "error: unknown command" in text and admin:
                    # G132 probes: the Junos read-only class lacks the network permission; admin answers.
                    return "refused to the read-only account, answered to admin"
                break
        else:
            return "-"
    elif entry is None and directory.name == "nexus9300v_9.3.12" and name in NXOS_G92_CAPTURES:
        capture = directory.with_name("g92_nexus9300v_9.3.12")
        key = NXOS_G92_CAPTURES[name]
        for filename in ("index.json", "index-extra.json"):
            entry = json.loads((capture / filename).read_text())["captures"].get(key)
            if entry is not None:
                break
        text = (capture / (key + ".out")).read_text()
        admin = False
    elif entry is None and directory.name == "nexus9300v_9.3.12":
        capture = directory.with_name("g97") / "lab"
        entry = json.loads((capture / "index.json").read_text()).get(name)
        if entry is None:
            return "-"
        text = (capture / f"{name}.out").read_text()
        admin = False
    elif entry is None and (operational := cisco_operational_capture(directory.name, name)) is not None:
        text, admin = operational
        entry = {"rc": 0}
    elif entry is None and directory.name == "iolxe_17.18.2" and name in XE_G72_CAPTURES:
        capture = directory.with_name("iolxe_17.18.2_g72")
        source = XE_G72_CAPTURES[name]
        text = (capture / f"d-iolxe-ro-{source}.out").read_text()
        admin = (capture / f"d-iolxe-admin-{source}.out").is_file()
        entry = {"rc": 0}
    elif entry is None and directory.name == "iolxe_17.18.2":
        for group in ("iolxe_17.18.2_g69", "iolxe_17.18.2_g70"):
            capture = directory.with_name(group) / (name + ".out")
            if capture.is_file():
                break
        else:
            filename = IOS_XE_G73_ROUTER_CAPTURES.get(name)
            if filename is None:
                return "-"
            capture = directory.with_name("iolxe_17.18.2_g73") / (filename + ".out")
        read_only_capture = capture.with_name("ro_" + capture.name)
        admin = read_only_capture.is_file()
        text = (read_only_capture if admin else capture).read_text()
        entry = {"rc": 0}
    elif entry is None:
        return "-"
    else:
        text = (directory / f"{name}.txt").read_text()
        admin = (directory / f"{name}.admin.txt").exists()
    if REFUSED.search(text) or DENIED.search(text):
        if admin:
            return "refused to the read-only account, answered to admin"
        return "refused to the read-only account" if DENIED.search(text) else "not supported by the image"
    if entry.get("account") == "network" and "not needed by configuration" in text:
        return "not configured"
    if ABSENT.search(text):
        return "feature off or not supported by the image"
    if NOT_CONFIGURED.search(text):
        return "not configured"
    if FAILED.search(text):
        status = f", exit status {entry['rc']}" if entry["rc"] else ""
        return "command failed" + status
    if not text.strip():
        return "empty"
    lines = len(text.splitlines())
    status = f", exit status {entry['rc']}" if entry["rc"] else ""
    return f"ok, {lines} line{'s' if lines != 1 else ''}{status}"


def render(profile: str, devices) -> str:
    begin, end = markers(profile)
    from netops_helper.query_catalog import READ_QUERIES
    rows = []
    for name, query in READ_QUERIES[profile].items():
        cells, answered = [], False
        for directory, _ in devices:
            path = REAL / profile / directory
            index = json.loads((path / "index.json").read_text())
            value = cell(path, name, index)
            cells.append(value)
            answered = answered or value.startswith(("ok", "empty", "not configured", "refused", "command failed"))
        rows.append((name, query.command, cells, "live" if answered else "docs-only"))
    head = "| Template | Command | " + " | ".join(label for _, label in devices) + " | verified |"
    rule = "|---|---|" + "---|" * len(devices) + "---|"
    # GFM splits a cell at every unescaped pipe, also inside a code span
    body = [f"| `{n}` | `" + c.replace("|", "\\|") + "` | " + " | ".join(cells) + f" | {v} |" for n, c, cells, v in rows]
    return "\n".join([begin, "", head, rule, *body, "", end])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    status = 0
    for relative, blocks in TARGETS.items():
        path = ROOT / relative
        text = path.read_text()
        new = text
        for profile, label, devices in blocks:
            begin, end = markers(profile)
            block = render(profile, devices)
            if begin in new:
                new = re.sub(re.escape(begin) + ".*?" + re.escape(end), lambda m: block, new, flags=re.S)
            elif begin.endswith("begin -->"):
                new = new.rstrip("\n") + "\n\n## Lab measurements (GNS3 lab, 2026-11-08/09)\n\nEvery template was run on the lab images with the read-only account; the stored outputs are in `tests/fixtures/real`. Regenerated by `tests/support/render_lab_measurements.py`.\n\n### " + label + "\n\n" + block + "\n"
            else:
                new = new.rstrip("\n") + "\n\n### " + label + "\n\n" + block + "\n"
        if args.check:
            if new != text:
                print(f"lab_measurements=stale {relative}")
                status = 1
        else:
            path.write_text(new)
    if args.check and not status:
        print("lab_measurements=passed")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
