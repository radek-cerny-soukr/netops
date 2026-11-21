"""Pinned file operations and operational checks for ExtremeXOS ingress ACLs."""
from __future__ import annotations

import hashlib
import re

from netops_admin import exos, exos_acl as acl, membership
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin import exec_exos
from netops_admin.exec_exos import accounts_check, foreign_sessions, hostname, prechecks, prompt_spec
from netops_core.sftp import SftpError, put_exos_policy, read_exos_policy, remove_exos_policy, rename_exos_policy

COMPENSATING = True
RETURN_MECHANISM = "pinned-sftp-compensation"
AUDIT_NOT_RUN = ("exos-acl-file", "not-evaluated", "standalone policy file before an ACL is attached")


def _transfer(access, function, *args):
    device = access.device
    try:
        return function(device.address, device.port, access.credential, access._host_key(),
                        device.legacy_ssh, *args)
    except (SftpError, AccessError):
        acl.unreadable("ExtremeXOS policy SFTP operation could not be verified")


def read_file(access, name):
    return _transfer(access, read_exos_policy, name)


def _checked_file(access, name, *, writer=False):
    query = access.query_status if writer else access.check_query_status
    try:
        rc, text = query(f"check policy {name} access-list")
    except AccessError:
        acl.unreadable("ExtremeXOS policy syntax check is unavailable")
    if rc == 0 and text.strip() == "Policy file check successful.":
        return True
    if rc == 250 and " ".join(text.split()) == f"Error: Policy {name} does not exist on file":
        return False
    if rc == 250 and text.strip().startswith("Error:"):
        acl.invalid()
    acl.unreadable("ExtremeXOS policy syntax check was incomplete or refused")


def _data(value):
    if value is None:
        return None
    return acl.content(value[acl.CONTENT]).encode("ascii")


def _unused(access, name):
    try:
        acl.require_unused(access.query("show policy"), name)
    except AccessError:
        acl.unreadable("ExtremeXOS policy client usage could not be read")


class FileAccess:
    """Extend the Admin snapshot with an independently transferred file, including proven absence."""

    def __init__(self, access, name):
        if not acl.EXOS_POLICY_NAME.fullmatch(name):
            acl.invalid()
        self.access = access
        self.name = name
        self.plan = None

    def __getattr__(self, name):
        return getattr(self.access, name)

    def snapshot(self):
        return acl.snapshot_line(self.name, read_file(self.access, self.name)) + self.access.snapshot()

    def bind_plan(self, plan):
        self.plan = plan

    def _stage(self):
        return f"{self.name[:15]}-{self.plan['safeguard_id'][:12]}"

    def _remove_stage(self, *policies):
        stage = self._stage()
        current = read_file(self.access, stage)
        if current is not None:
            if not any(policy is not None and policy.startswith(current) for policy in policies):
                acl.unsafe("ExtremeXOS staging file contains bytes outside this operation")
            _transfer(self.access, remove_exos_policy, stage)
            if read_file(self.access, stage) is not None:
                acl.unreadable("ExtremeXOS staging file removal could not be verified")

    def recover_stage(self):
        self._remove_stage(*(_data(side) for side in self.plan["predicted"].values()))

    def apply(self, steps, spec):
        plan = self.plan
        before, after = (_data(plan["predicted"][side]) for side in ("before", "after"))
        if steps == plan["inverse"]:
            before, after = after, before
        elif steps != plan["commands"]:
            acl.unsafe("ExtremeXOS file operation differs from the approved plan")
        _unused(self.access, self.name)
        if read_file(self.access, self.name) != before:
            acl.unsafe("ExtremeXOS policy file changed outside this operation")
        if after is None:
            _transfer(self.access, remove_exos_policy, self.name)
            return 1
        stage = self._stage()
        if read_file(self.access, stage) is not None:
            acl.unsafe("ExtremeXOS policy staging filename is already occupied")
        try:
            _transfer(self.access, put_exos_policy, stage, after)
            if read_file(self.access, stage) != after or not _checked_file(self.access, stage, writer=True):
                acl.invalid()
            _unused(self.access, self.name)
            if read_file(self.access, self.name) != before:
                acl.unsafe("ExtremeXOS policy file changed outside this operation")
            _transfer(self.access, rename_exos_policy, stage, self.name)
        finally:
            self._remove_stage(after)
        return 1


def wrap_access(access, key):
    return FileAccess(access, key)


def ports(access, table):
    return None


def leftovers(access):
    remaining = exec_exos.leftovers(access)
    if access.plan is not None:
        stage = access._stage()
        if read_file(access, stage) is not None:
            remaining.append(stage + ".pol")
    return remaining


def safeguard_label(change_id):
    return "acl-file-" + change_id[:12]


def safeguard_absent(access, record):
    return True


def persist(access, spec):
    return False


def plan_prechecks(access, device, plan, snapshot_text):
    name = plan["key"]
    if exos.load(snapshot_text, device.firmware).in_use(name):
        acl.unsafe("ExtremeXOS policy has a running configuration reference")
    _unused(access, name)
    plan["prechecks"].append("policy is unused and the original file and its inverse can be verified")
    return []


def observe(access, plan):
    name = plan["key"]
    current = read_file(access, name)
    if _checked_file(access, name) != (current is not None):
        acl.unreadable("ExtremeXOS policy file presence differs between SSH and SFTP")
    if current is None:
        return None
    try:
        return {acl.CONTENT: acl.content(current.decode("ascii"))}
    except UnicodeError:
        acl.invalid()


def _binding_state(access):
    try:
        rc, text = access.check_query_status("show access-list")
    except AccessError:
        acl.unreadable("ExtremeXOS ACL attachments could not be read")
    if rc != 0:
        acl.unreadable("ExtremeXOS operational ACL table was refused")
    return acl.active_bindings(text)


def _policy_bytes(access, name):
    data = read_file(access, name)
    if data is None:
        acl.unsafe("ExtremeXOS attachment requires an existing .pol file")
    try:
        acl.content(data.decode("ascii"))
    except UnicodeError:
        acl.invalid()
    if not _checked_file(access, name):
        acl.unreadable("ExtremeXOS attachment file presence is inconsistent")
    return data


def _tokens(text):
    return re.findall(r"[{};]|[^\s{};]+", text)


def _verify_active_rules(access, key, data, rules):
    kind, name = acl.selector(key)
    command = f"show access-list {'port' if kind == 'ports' else 'vlan'} {name} ingress detail"
    try:
        rc, text = access.check_query_status(command)
    except AccessError:
        acl.unreadable("ExtremeXOS active ACL rules could not be read")
    if rc or not text.startswith("#Policy Entries\n"):
        acl.unreadable("ExtremeXOS active ACL rules are incomplete")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    expected = _tokens(data.decode("ascii"))
    if expected.count("entry") != rules or _tokens(body.replace("if match all", "if")) != expected:
        acl.unreadable("ExtremeXOS active ACL rules differ from the approved file")


def observe_binding(access, plan):
    key = plan["key"]
    state = plan["predicted"]
    name = (state["after"] or state["before"])["policy"]
    data = _policy_bytes(access, name)
    if hashlib.sha256(data).hexdigest() != plan["exos_acl_file_sha256"]:
        acl.unsafe("ExtremeXOS attachment file changed after preview")
    row = _binding_state(access).get(key.casefold())
    if row is None:
        return None
    if row[0] != name or row[2]:
        acl.unsafe("ExtremeXOS operational attachment differs from the approved policy")
    rules = row[1]
    _verify_active_rules(access, key, data, rules)
    return {"policy": name}


def _scope(access, device, plan, snapshot):
    key = plan["key"]
    kind, name = acl.selector(key)
    policy = device.audit_policy or {}
    protected_ports = set(device.protected.get("ports", ())) | set(policy.get("protected_ports", ()))
    management = {item.casefold() for item in policy.get("management_vlans", ())} | {"mgmt"}
    guarded_vlans = management | {item.casefold() for item in device.protected.get("vlan", ())}
    if not exos.vlan_module_closed(snapshot):
        acl.unreadable("ExtremeXOS VLAN configuration module is incomplete")
    snapshot.inventory = frozenset(plan.get("ports", ()))
    vlans, members, _descriptions = membership.model(snapshot)
    vlan_active = False
    if kind == "vlan":
        if name.casefold() in guarded_vlans or name.casefold() == "default":
            acl.unsafe("ExtremeXOS VLAN is a protected, management or default VLAN")
        if name not in vlans:
            acl.unsafe("ExtremeXOS VLAN name was not found with that spelling")
        text = access.check_query(f"show vlan {name}")
        if exos.shown_vlan(text, name) is None:
            acl.unreadable("ExtremeXOS could not independently identify the target VLAN")
        shown = exos.shown_vlan_ports(text)
        scope = {port for port, modes in members.items() if any(name in names for names in modes.values())}
        if scope != set(" ".join(shown.values()).split()):
            acl.unreadable("ExtremeXOS VLAN membership differs between running and operational state")
        vlan_active = bool(re.search(r"\(Number of active ports=[1-9][0-9]*\)|(?m:^\s+Loopback:[ \t]+Enabled\s*$)", text))
    else:
        if name not in snapshot.inventory:
            acl.unsafe("ExtremeXOS target is outside the physical port inventory")
        scope = {name}
    if scope & (protected_ports | membership.lag_ports(snapshot)):
        acl.unsafe("ExtremeXOS attachment affects a protected or aggregated port")
    names = {name.casefold()} if kind == "vlan" else set()
    for port in scope:
        modes = members.get(port, {})
        names.update(vlan.casefold() for values in modes.values() for vlan in values)
        names.update(vlan.casefold() for values in policy.get("port_vlans", {}).get(port, {}).values()
                     for vlan in values)
        if modes.get("tagged"):
            acl.unsafe("ExtremeXOS attachment affects a tagged port")
    if names & guarded_vlans:
        acl.unsafe("ExtremeXOS attachment affects a protected or management VLAN")
    return scope, names, vlan_active


def _check_endpoint_impact(access, snapshot, plan, scope, names, vlan_active):
    active = vlan_active
    if scope:
        learned = exos.lldp_ports(access.query(exos.QUERY_LLDP)) | exos.fdb_ports(access.query(exos.QUERY_FDB))
        active = active or bool(scope & learned)
    for port in sorted(scope, key=exos.port_order):
        command = f"show ports {port} configuration no-refresh"
        shown = exos.port_configuration(access.check_query(command), port)
        if shown is None or shown["link_state"] not in exos.LINK_STATES.values():
            acl.unreadable("ExtremeXOS link state could not be established")
        if shown["link_state"] not in ("active", "ready"):
            acl.unsafe("ExtremeXOS attachment affects an unavailable port")
        active = active or shown["link_state"] == "active"
    if scope or vlan_active:
        exec_exos._management_path(access, snapshot, scope, names, whole_vlan=plan["key"].startswith("vlan:"))
    if active and plan.get("endpoint_impact") != plan["key"]:
        raise Rejected(["an active ExtremeXOS ACL attachment target requires endpoint_impact naming the port or VLAN"],
                       reason_codes=["endpoint_impact_required"])


def binding_prechecks(access, device, plan, snapshot_text):
    snapshot = exos.load(snapshot_text, device.firmware)
    key = plan["key"]
    before, after = plan["predicted"]["before"], plan["predicted"]["after"]
    name = (before or after)["policy"]
    if name.casefold() in {value.casefold() for value in device.protected.get(acl.POLICY, ())}:
        acl.unsafe("ExtremeXOS attachment uses a protected policy")
    try:
        scope, names, vlan_active = _scope(access, device, plan, snapshot)
        _check_endpoint_impact(access, snapshot, plan, scope, names, vlan_active)
        active = _binding_state(access)
        overlap = {"any:*"} | {f"port:{port}" for port in scope} | {f"vlan:{vlan}" for vlan in names}
        if (overlap - {key.casefold()}).intersection(active) or active.get(key.casefold(), (None, 0, 0))[2]:
            acl.unsafe("ExtremeXOS attachment overlaps an existing ACL")
        if (active.get(key.casefold()) or (None,))[0] != (before or {}).get("policy"):
            acl.unreadable("ExtremeXOS ingress attachment differs between running and operational state")
        if any(row[0].casefold() == name.casefold() and target != key.casefold()
               for target, row in active.items()):
            acl.unsafe("ExtremeXOS policy is already attached to a different ingress scope")
        data = _policy_bytes(access, name)
    except AccessError:
        acl.unreadable("ExtremeXOS attachment preflight data could not be read")
    plan["exos_acl_file_sha256"] = hashlib.sha256(data).hexdigest()
    plan["prechecks"].append("ingress scope and endpoint impact checked; the policy file is readable and syntax-checked")
