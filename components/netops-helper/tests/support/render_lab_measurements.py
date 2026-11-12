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
NOT_CONFIGURED = re.compile(r'% BGP (?:not active|inactive)|IPv6 routing not enabled|BGP is not running|Spanning-tree is not enabled at global level|No spanning tree instances? exists?')


def cell(directory: Path, name: str, index: dict) -> str:
    entry = index.get(name)
    if entry is None:
        return "-"
    text = (directory / f"{name}.txt").read_text()
    admin = (directory / f"{name}.admin.txt").exists()
    if REFUSED.search(text) or DENIED.search(text):
        if admin:
            return "refused to the read-only account, answered to admin"
        return "refused to the read-only account" if DENIED.search(text) else "not supported by the image"
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
    body = [f"| `{n}` | `{c}` | " + " | ".join(cells) + f" | {v} |" for n, c, cells, v in rows]
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
