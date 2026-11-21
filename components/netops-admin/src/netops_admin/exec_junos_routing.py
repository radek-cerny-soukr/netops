"""Junos routing preflight and independent operational readback."""

from __future__ import annotations

import ipaddress
import json
import re

from . import junos_routing as routing
from .access import AccessError
from .errors import Rejected


def _unreadable(what):
    return Rejected(["Junos %s readback is incomplete or unrecognised" % what],
                    reason_codes=["junos_routing_readback_unreadable"])


def _read_failure(exc, what):
    if isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("timeout", "timed out")):
        raise Rejected(["Junos %s timed out" % what], reason_codes=["junos_routing_read_timeout"]) from None
    raise _unreadable(what) from None


def _data(record, key):
    item, = record[key]
    return item["data"]


def _one(document, key):
    item, = document[key]
    if not isinstance(item, dict):
        raise ValueError("invalid Junos record")
    return item


def _document(text):
    # Some versions put the pending-commit banner on a line before the JSON response.
    from .junos import answer_rows

    result = json.loads("\n".join(answer_rows(text)))
    if not isinstance(result, dict) or any(key.endswith(":error") or key == "error" for key in result):
        raise ValueError("invalid Junos response")
    return result


def _ospf_rows(text, protocol, kind):
    document = _document(text)
    if "output" in document:
        if _data(document, "output") == "OSPF instance is not running":
            return []
        raise ValueError("unexpected OSPF notice")
    records = _one(document, f"{protocol}-{kind}-information").get(f"{protocol}-{kind}", [])
    if not isinstance(records, list):
        raise ValueError("invalid OSPF rows")
    return records


def _config(access, plan, table, key):
    from . import junos

    if table in routing.OSPF:
        protocol = routing.OSPF[table]
        match = f"^set protocols {protocol} area [^ ]+ interface {re.escape(key)}( |$)"
        path = f'protocols {protocol} | display set | match "{match}"'
    else:
        path = routing._path(table, key, {}) + " | display set"
    text = access.query("show configuration " + path + " | no-more")
    rows = junos.answer_rows(text)
    if (text and not text.endswith("\n")) or any(not row.startswith("set ") for row in rows):
        raise _unreadable("configuration")
    scoped = junos.load("set version " + plan["firmware"] + "\n" + "".join(row + "\n" for row in rows), None)
    entry = scoped.entries(table).get(key)
    if (rows and entry is None) or (entry is not None and entry.unsupported):
        raise _unreadable("configuration")
    return None if entry is None else entry.attributes


def _management_read(access, command):
    from .junos import refused_answer

    answer = access.query(command)
    if refused_answer(answer):
        raise _unreadable("management path")
    return answer


def _checked(access, command):
    return access.check_query(command + " | no-more")


def _ospf(access, plan):
    table, key = plan["table"], plan["key"]
    protocol = routing.OSPF[table]
    # Operational cost is effective, so the writer's scoped read distinguishes a default from an explicit metric.
    state = _config(access, plan, table, key)
    rows = _ospf_rows(_checked(access, f"show {protocol} interface {key} detail | display json"), protocol, "interface")
    if not rows:
        if state is None:
            return None
        raise _unreadable("configured OSPF interface")
    row, = rows
    if state is None or _data(row, "interface-name") != key:
        raise _unreadable("OSPF interface identity")
    area = str(ipaddress.IPv4Address(_data(row, "ospf-area")))
    passive = "passive" in row
    if passive and _data(row, "passive") != "Passive":
        raise ValueError("unrecognised OSPF passive flag")
    cost = str(int(_data(row, "interface-cost")))
    if area != state["area"] or passive != (state.get("passive") == "yes"):
        raise _unreadable("OSPF area or passive mode")
    if "metric" in state and state["metric"] != cost:
        raise _unreadable("OSPF metric")
    if passive:
        neighbors = _ospf_rows(_checked(access, f"show {protocol} neighbor | display json"), protocol, "neighbor")
        if int(_data(row, "adj-count")) != 0 or any(_data(other, "interface-name") == key for other in neighbors):
            raise _unreadable("passive OSPF adjacency")
    return state


def _policy_names(access):
    document = _document(_checked(access, "show policy | display json"))
    rows = _one(document, "policy-information").get("policy", [])
    if not isinstance(rows, list):
        raise ValueError("invalid routing policy list")
    names = [_data(row, "policy-name") for row in rows]
    if len(names) != len(set(names)):
        raise ValueError("ambiguous routing policy name")
    return set(names)


def _policy(access, plan):
    key = plan["key"]
    if key not in _policy_names(access):
        return None
    document = _document(_checked(access, f"show policy {key} | display json"))
    row = _one(_one(document, "policy-information"), "policy")
    if _data(row, "policy-name") != key:
        raise _unreadable("policy identity")
    terms = {}
    for term in row["term"]:
        name = _data(term, "name")
        action_keys = set(_one(term, "then")) - {"attributes"}
        action, = action_keys
        if action not in ("accept", "reject") or name in terms:
            raise ValueError("unrecognised or duplicate term")
        prefix = "-"
        if "from" in term:
            match = _one(term, "from")
            if set(match) != {"attributes", "prefix-list", "route-filter-information"}:
                raise ValueError("unrecognised policy match")
            prefix = _data(match, "prefix-list")
            if not re.fullmatch(routing.NAME, prefix):
                raise ValueError("invalid readback prefix list name")
            filters = _one(match, "route-filter-information")["route-filter"]
            if any(_data(item, "flags") != "exact" for item in filters):
                raise ValueError("unrecognised prefix filter")
            seen = routing._prefixes(" ".join(_data(item, "address") for item in filters))
            if _config(access, plan, routing.PREFIX_LIST, prefix) != {"prefixes": seen}:
                raise _unreadable("expanded policy prefixes")
        terms[name] = f"{name}:{prefix}:{action}"
    result = {"terms": " ".join(terms.values())}
    routing._terms(result["terms"])
    return result


def _prefix_list(access, plan):
    # A standalone prefix list has no show policy object. Pin the control account to the device,
    # then read the single list by writer. The control account verifies every prefix when a term uses it.
    from .exec_junos import _check_identity, _read

    rows = _read(access, 'show configuration system host-name | display set | no-more')
    _check_identity(access, rows.splitlines())
    return _config(access, plan, routing.PREFIX_LIST, plan["key"])


_PEER = re.compile(r"^Peer: (\S+?)(?:\+\d+)?\s+AS ([0-9]+)\s+Local:", re.M)
_GROUP = re.compile(r"^(?:Group Type:|Group:)\s*(Internal|External)\s+AS(?: number)?:\s*([0-9]+)", re.M | re.I)
_BGP_WARNING = "Warning: License key missing; requires 'BGP' license"
_BGP_STATES = r"Idle|Active|Connect|OpenSent|OpenConfirm|Established"


def _bgp_answer(text):
    from .junos import answer_rows, refused_answer

    rows = [row for row in answer_rows(text) if row.strip() != _BGP_WARNING]
    answer = "\n".join(rows)
    if answer.strip() == "BGP is not running":
        return None
    if not rows or refused_answer(answer) or "(more" in answer.lower():
        raise _unreadable("BGP")
    return answer


def _bgp_policies(text):
    policies = {}
    for field in routing.POLICY_FIELDS:
        labels = list(re.finditer(rf"(?:^|\s){field.title()}:", text))
        if not labels:
            continue
        value = re.match(r"\s*\[([^\[\]\n]*)\]", text[labels[0].end():])
        if len(labels) != 1 or not value or not routing._names(value[1].split()):
            raise ValueError("invalid BGP policy list")
        policies[field] = " ".join(value[1].split())
    return policies


def _bgp_neighbor(access, address, group):
    output = _bgp_answer(_checked(access, "show bgp neighbor " + address))
    if output is None:
        return None
    peers = list(_PEER.finditer(output))
    if len(peers) != 1 or str(ipaddress.ip_address(peers[0][1])) != address:
        raise _unreadable("BGP neighbor address")
    if not re.search(rf"^\s*Group:\s*{re.escape(group)}\s+Routing-Instance:\s*master\s*$", output, re.M):
        raise _unreadable("BGP neighbor group or routing instance")
    status = re.search(rf"\bState:\s*({_BGP_STATES})\b", output)
    if status is None:
        raise _unreadable("BGP neighbor state")
    return {"peer-as": peers[0][2], **_bgp_policies(output)}, status[1]


def _bgp_group(access, group):
    output = _bgp_answer(_checked(access, "show bgp group " + group))
    if output is None:
        return None
    if not re.search(rf"(?:^|\s)Name:\s*{re.escape(group)}(?:\s|$)", output):
        raise _unreadable("BGP group name")
    groups = list(_GROUP.finditer(output))
    if len(groups) != 1:
        raise _unreadable("BGP group type or AS")
    return {"type": groups[0][1].lower(), "peer-as": groups[0][2], **_bgp_policies(output)}


def _bgp_absent(access, table, key):
    group, _, address = key.partition("@")
    command = "show bgp group summary" if table == routing.GROUP else "show bgp summary"
    output = _bgp_answer(_checked(access, command))
    if output is None:
        return True
    rows = output.splitlines()
    counts = [re.search(r"\bGroups:\s*(\d+)\s+Peers:\s*(\d+)", row) for row in rows]
    (count,) = [item for item in counts if item]
    if table == routing.GROUP:
        names = [match[1] for row in rows if (
            match := re.fullmatch(r"\s*(\S+)\s+(?:Internal|External)\s+\d+\s+\d+(?:\s+.*)?", row)
        )]
        if len(names) != int(count[1]) or not any(row.split()[:3] == ["Group", "Type", "Peers"] for row in rows):
            raise _unreadable("BGP group summary")
        return group not in names
    addresses = []
    for row in rows:
        fields = row.split()
        if len(fields) >= 8 and fields[1].isdigit():
            try:
                addresses.append(str(ipaddress.ip_address(fields[0])))
            except ValueError:
                continue
    if len(addresses) != int(count[2]) or not any(row.split()[:2] == ["Peer", "AS"] for row in rows):
        raise _unreadable("BGP neighbor summary")
    return address not in addresses


def _inherited_bgp_policies(access, plan, group, wanted):
    prefix = f"set protocols bgp group {group} neighbor "
    command = (f'show configuration protocols bgp group {group} | display set '
               f'| match "^{prefix}" | no-more')
    rows = access.query(command).splitlines()
    if any(not row.startswith(prefix) for row in rows):
        raise _unreadable("BGP group members")
    addresses = {str(ipaddress.ip_address(row[len(prefix):].split()[0])) for row in rows}
    verified = set()
    for address in sorted(addresses):
        peer = _config(access, plan, routing.NEIGHBOR, f"{group}@{address}")
        if peer is None:
            raise _unreadable("BGP group member configuration")
        inherited = set(wanted) - set(peer)
        if not inherited:
            continue
        observed = _bgp_neighbor(access, address, group)
        if observed is None or any(observed[0].get(field) != wanted[field] for field in inherited):
            raise _unreadable("BGP group policy inherited by a neighbor")
        verified.update(inherited)
    if any(policy is not None and field not in verified for field, policy in wanted.items()):
        raise _unreadable("BGP group policy without an inheriting neighbor")


def _bgp(access, plan, operational):
    table, key = plan["table"], plan["key"]
    group, _, address = key.partition("@")
    configured = _config(access, plan, table, key)
    if configured is None:
        if _bgp_absent(access, table, key):
            return None
        raise _unreadable("BGP object still present")
    if table == routing.GROUP:
        observed = _bgp_group(access, group)
        if observed is None or any(configured.get(field) != observed.get(field) for field in ("type", "peer-as")
                                   if field in configured):
            raise _unreadable("BGP group type or AS")
        wanted = {}
        for field in routing.POLICY_FIELDS:
            if field in observed:
                if observed[field] != configured.get(field):
                    raise _unreadable("BGP group policy")
            elif field in configured or any(field in (state or {}) for state in plan["predicted"].values()):
                wanted[field] = configured.get(field)
        if wanted:
            _inherited_bgp_policies(access, plan, group, wanted)
        return configured
    observed = _bgp_neighbor(access, address, group)
    if observed is None:
        raise _unreadable("BGP neighbor presence")
    group_state = _config(access, plan, routing.GROUP, group)
    if group_state is None:
        raise _unreadable("BGP neighbor inheritance")
    effective = {name: configured.get(name, group_state.get(name)) for name in ("peer-as", *routing.POLICY_FIELDS)}
    fields, status = observed
    if any(value != fields.get(name) for name, value in effective.items()
           if value is not None or name in routing.POLICY_FIELDS):
        raise _unreadable("BGP neighbor effective AS or policies")
    if operational and status == "Established":
        for direction in ("advertising-protocol", "receive-protocol"):
            answer = _checked(access, f"show route {direction} bgp {address} | display json")
            _one(_document(answer), "route-information")
    return configured


def observe(access, plan, operational):
    table = plan["table"]
    try:
        if table in routing.OSPF:
            return _ospf(access, plan)
        if table == routing.POLICY:
            return _policy(access, plan)
        if table == routing.PREFIX_LIST:
            return _prefix_list(access, plan)
        return _bgp(access, plan, operational)
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "routing readback")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise _unreadable("operational") from None


def _active_paths(text, peer):
    document = _document(text)
    candidates = []
    for table in _one(document, "route-information")["route-table"]:
        name = _data(table, "table-name")
        if name not in ("inet.0", "inet6.0", "mgmt_junos.inet.0", "mgmt_junos.inet6.0"):
            continue
        for route in table["rt"]:
            network = ipaddress.ip_network(_data(route, "rt-destination"))
            if peer not in network:
                continue
            for entry in route["rt-entry"]:
                if _data(entry, "active-tag") != "*":
                    continue
                protocol = _data(entry, "protocol-name").casefold()
                selected = [hop for hop in entry["nh"] if "selected-next-hop" in hop]
                hops = [_data(hop, "via") for hop in selected or entry["nh"]]
                if not hops:
                    raise ValueError("missing management next hop")
                candidates.append((protocol, hops))
    if not candidates:
        raise ValueError("missing active management route")
    return candidates


def prechecks(access, device, plan, snapshot_text):
    from . import junos
    from .exec_junos import DEDICATED_MANAGEMENT, SSH_CONNECTIONS, _interface_addresses, _ssh_connections

    table, key = plan["table"], plan["key"]
    if table in (routing.PREFIX_LIST, routing.POLICY):
        # The planner only permits changes to definitions with no external references.
        return []
    try:
        snapshot = junos.load(snapshot_text, plan["firmware"])
        ports = {line.split()[-1] for line in snapshot.lines
                 if re.fullmatch(r"set system services ssh port [0-9]+", line)}
        if len(ports) > 1:
            raise ValueError("ambiguous SSH port")
        port = next(iter(ports), "22")
        sockets = _ssh_connections(_management_read(access, SSH_CONNECTIONS), port)
        if device.check_address and device.check_address != device.address:
            sockets.update(_ssh_connections(access.check_query(SSH_CONNECTIONS), port))
        if not sockets:
            raise ValueError("no management connection")
        if table in routing.OSPF:
            family = "inet6" if routing.OSPF[table] == "ospf3" else "inet"
            rows = junos.answer_rows(_management_read(access, f"show interfaces {key} terse | no-more"))
            if not rows or not rows[0].startswith("Interface "):
                raise ValueError("invalid interface listing")
            matching = [row.split() for row in rows[1:] if row.split()[0] == key]
            if not matching or family not in matching[0][3:4]:
                # Other families can appear as indented continuations.
                state = _config(access, plan, table, key)
                if plan["predicted"]["after"] is not None and not any(
                    row.split()[0] == family for row in rows[1:] if row[0].isspace()
                ):
                    raise Rejected(["the OSPF interface needs operational family %s" % family],
                                   reason_codes=["junos_routing_dependency"])
                if not matching and state is not None:
                    raise ValueError("configured interface is missing")
            local_text = _management_read(access, "show interfaces terse | no-more")
            if not local_text.startswith("Interface ") or "(more" in local_text.lower():
                raise ValueError("invalid local interface addresses")
            local = _interface_addresses(local_text)
            if any(address not in local for address, _peer in sockets):
                raise ValueError("missing local SSH address")
            if any(key in local[address] for address, _peer in sockets):
                raise Rejected(["the OSPF interface terminates a management connection"],
                               reason_codes=["junos_routing_management"])
        else:
            group, _, address = key.partition("@")
            peers = ({ipaddress.ip_address(address)} if address else
                     {ipaddress.ip_address(name.split("@", 1)[1]) for name in snapshot.entries(routing.NEIGHBOR)
                      if name.startswith(group + "@")})
            if any(peers.intersection(socket) for socket in sockets):
                raise Rejected(["a BGP neighbor is a management endpoint"],
                               reason_codes=["junos_routing_management"])
        for peer in sorted({peer for _address, peer in sockets}, key=str):
            command = f"show route {peer} active-path | display json | no-more"
            paths = _active_paths(_management_read(access, command), peer)
            protected = any(
                (table in routing.OSPF and key in hops)
                or (protocol not in {"direct", "local"} and (protocol != "static"
                    or any(not DEDICATED_MANAGEMENT.fullmatch(hop) for hop in hops)))
                for protocol, hops in paths
            )
            if protected:
                raise Rejected(["the routing change could affect an active management path"],
                               reason_codes=["junos_routing_management"])
    except (AccessError, TimeoutError) as exc:
        _read_failure(exc, "management preflight")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise Rejected(["the Junos management path could not be established"],
                       reason_codes=["junos_routing_readback_unreadable"]) from None
    plan["prechecks"].append("active SSH return routes and local management endpoints are outside the routing change")
    return []
