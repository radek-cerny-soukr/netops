"""Synthetic, offline role data for upgrade-check; run only in its scratch instance."""
import json
import sys
from pathlib import Path

DEVICE = "upgrade-fw"
ADC_DEVICE = "upgrade-adc"
REQUEST = "upgrade-check-request"
CHANGE = "a" * 32


def admin_input(secret_path):
    secret = Path(secret_path).read_text()
    device = {"platform": "fortios", "address": "192.0.2.11", "port": 22,
              "host_key_fingerprint": "SHA256:" + "A" * 43,
              "credential": "upgrade-write", "check_credential": "upgrade-check"}
    credentials = {name: {"kind": "password", "login": login, "value": secret}
                   for name, login in (("upgrade-write", "synthetic-write"), ("upgrade-check", "synthetic-check"))}
    return {"config": {"version": 1, "devices": {DEVICE: device}},
            "vault": {"version": 2, "credentials": credentials}}


def seed_auditor(root):
    from netops_auditor.findings import Finding
    from netops_auditor.store import Store
    finding = Finding(rule_id="fortios.ref.dangling", rule_version=1, tenant="default",
                      device=DEVICE, object_key="firewall policy/1", severity="high",
                      rule_class="fakt", section="firewall policy", line=1,
                      evidence=(("attribute", "srcaddr"), ("value", "upgrade-object")))
    with Store(root / "auditor/store.sqlite") as store:
        run = store.record_run("default", DEVICE, "b" * 64, "upgrade-synthetic.conf",
                               "fortios:1:" + "c" * 64, (finding,),
                               started_at="2026-01-01T00:00:00Z",
                               rule_status={finding.rule_id: {"status": "evaluated", "reason": "", "required": True}})
        assert store.findings_for_run("default", run)
        # A FortiADC run with the inherent coverage gap (factory certificate provenance) and an
        # actionable one (collector visibility), so that the upgrade carries both kinds of gaps.
        statuses = {
            "fortiadc.tls.factory-certificate": {"status": "not-evaluated", "reason": "factory-provenance-unproven",
                                                 "required": True},
            "fortiadc.lb.pool-no-health-check": {"status": "not-evaluated", "reason": "visibility:networking",
                                                 "required": True},
            "fortiadc.mgmt.trusted-hosts-open": {"status": "evaluated", "reason": "", "required": True},
        }
        store.record_run("default", ADC_DEVICE, "e" * 64, "upgrade-synthetic-adc.conf",
                         "fortiadc:1:" + "f" * 64, (), started_at="2026-01-01T00:00:00Z", rule_status=statuses)


def seed_admin(root):
    from netops_admin.state import Store
    store = Store(root / "admin/changes")
    store.save({"change_id": CHANGE, "request_id": REQUEST, "device": DEVICE,
                "status": "finished", "result": "confirmed", "reason": None,
                "audit_delivery": "acknowledged", "notification": "not-required",
                "created_at_epoch": 1767225600, "finished_at_epoch": 1767225601,
                "plan": {"table": "firewall address", "op": "create", "key": "upgrade-object", "commands": []},
                "steps": [{"step": "verified"}]})
    store.remember_request(REQUEST, CHANGE, "d" * 64, DEVICE)
    assert store.request(REQUEST)["change_id"] == CHANGE
    assert store.operation(CHANGE)["status"] == "finished"


if __name__ == "__main__":
    if sys.argv[1] == "admin-input":
        print(json.dumps(admin_input(sys.argv[2])))
    elif sys.argv[1] == "auditor":
        seed_auditor(Path("/var/lib/netops"))
    elif sys.argv[1] == "admin":
        seed_admin(Path("/var/lib/netops"))
    else:
        raise SystemExit("unknown population mode")
