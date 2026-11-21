"""IOS (switch image, G60) and IOS XE (G78) VLAN database lifecycle with compensating return, because vlan.dat is outside config rollback.

Admin readback or failure returns the inverse in the same run; loss of process/path needs recover.
Only unused VLANs are changed. No new timer or scheduler is installed on the device.
"""
import re

from netops_admin import exec_ios, ios
from netops_admin.errors import Rejected

COMPENSATING = True
AUDIT_RULES = False
AUDIT_NOT_RUN = ("ios.vlan", "not-evaluated",
                 "VLAN database lifecycle has no dedicated auditor rules; unused VLAN and management checks run before writing")
RETURN_MECHANISM = "compensating VLAN inverse; Admin/path loss requires recover (no VLAN database revert timer)"
FIRING_OBSERVED = True
prompt_spec = exec_ios.prompt_spec
hostname = exec_ios.hostname
accounts_check = exec_ios.accounts_check
prechecks = exec_ios.prechecks
ports = exec_ios.ports
leftovers = exec_ios.leftovers
foreign_sessions = exec_ios.foreign_sessions
persist = exec_ios.persist
safeguard_label = exec_ios.safeguard_label


def plan_prechecks(access, device, plan, snapshot_text=""):
    snapshot = ios.load(snapshot_text, device.firmware)
    snapshot.platform = device.platform
    if not ios.version(exec_ios._query(access, "show version", "version"))["switch"]:
        raise Rejected(["VLAN lifecycle requires a switch image"], reason_codes=["port_routed"])
    _, management_vlans = exec_ios._management(access, snapshot)
    if plan["key"] in management_vlans:
        raise Rejected(["management VLAN cannot be changed"], reason_codes=["port_management_vlan"])
    if snapshot.references("vlan", plan["key"]):
        raise Rejected(["VLAN is used by an interface or trunk; only unused VLANs may change"])
    # A dynamically negotiated trunk is not visible as mode trunk in running-config.
    # Inspect potential dynamic ports; the measured non-trunk operational states are down / static access.
    for name in snapshot.interfaces:
        lines = snapshot.interface_lines(name)
        if not ios.ETHERNET.fullmatch(name) or "no switchport" in lines or any(
                line in ("switchport mode access", "switchport mode trunk") for line in lines):
            continue
        answer = exec_ios._query(access, "show interfaces %s switchport" % name, "dynamic port use")
        shown = ios.switchport(answer, name)
        operational = re.findall(r"^Operational Mode: (.+)$", answer.replace("\r", ""), re.MULTILINE)
        if shown is None or len(operational) != 1 or operational[0] not in ("down", "static access"):
            raise Rejected(["port %s may be a negotiated trunk; unused VLAN cannot be established" % name])
    plan["prechecks"].append(RETURN_MECHANISM)
    return []


def observe(access, plan):
    listing = ios.vlan_database(access.check_query("show vlan brief"))
    row = listing.get(plan["key"])
    if row is None:
        return None
    if row[1] != "active":
        raise Rejected(["VLAN is not active"])
    return {"name": row[0]}


def install_safeguard(access, record, plan, device, spec):
    return []


def remove_safeguard(access, record, spec):
    return True


def safeguard_absent(access, record):
    return exec_ios.pending(access) is None


def remove_remaining(access, record, spec):
    return safeguard_absent(access, record)


def safeguard_disarmed(access, record):
    return False


def safeguard_fired(access, record):
    return False
