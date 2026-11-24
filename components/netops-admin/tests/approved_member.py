"""Test helper: the deprecated FortiADC pool member commands write only with the plan_sha256 of their own preview.

`fortiadc.run`, `fortiadc_member.add` and `fortiadc_member.remove` refuse a write without the approved hash before the
device is contacted. Tests that exercise what happens after that gate run the command as an operator does: first its
preview (no write), then the write with the preview's plan_sha256. A preview refusal is the refusal the write would
meet (the preview runs the same reads and checks), so it propagates unchanged.
"""
from __future__ import annotations

import json


# The configured identity of the device a direct (non-CLI) call targets; the CLI passes fortiadc.member_target(device).
TARGET = {"device": "adc", "address": "192.0.2.40", "port": 22, "host_key_fingerprint": "SHA256:" + "A" * 43}


def approved_member(function, access, *args):
    previewed = function(access, *args, target=TARGET, preview=True)
    assert previewed["result"] in ("ready", "unchanged"), previewed
    return function(access, *args, target=TARGET, expected_plan_sha256=previewed["plan_sha256"])


def approved_cli(main, argv, capsys):
    """cli.main of a pool member command: --preview, then the write with its plan_sha256 (a refused preview is returned)."""
    code = main(argv + ["--preview"])
    previewed = json.loads(capsys.readouterr().out)
    if previewed.get("result") not in ("ready", "unchanged"):
        return code, previewed
    code = main(argv + ["--expect-plan-sha256", previewed["plan_sha256"]])
    return code, json.loads(capsys.readouterr().out)
