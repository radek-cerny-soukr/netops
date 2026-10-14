import hashlib
import json
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from netops_core import schema

from netops_auditor import cli, engine, inventory, scoped_fortios, suppressions
from netops_auditor.engine import CATALOG_DIR, CatalogError, load_catalog
from netops_auditor.findings import Finding, fingerprint_of, fingerprint_v1
from netops_auditor.store import Store

COMPONENT = Path(__file__).resolve().parents[1]
FIXTURES = COMPONENT / "tests" / "fixtures"
CLEAN = FIXTURES / "fortios_clean.conf"
EMPTY_VLAN = FIXTURES / "rules" / "exos.management.vlan-empty"
SEPARATOR = "\x1f"
ODD = "a" + SEPARATOR + "b"
REFUSAL = "holds U+001F, the separator of the finding fingerprint"
TENANT = "tenant-a"
DEVICE = "fw-a.example.invalid"
RULE = "fortios.mgmt.wan-admin-access"
OBJECT = "system interface/port1"
COMPONENTS = ("rule_id", "rule_version", "tenant", "device", "object_key")
VERSION_ONE_COMPONENTS = ("rule_id", "rule_version", "device", "object_key")
SCOPED = json.dumps([None, "system interface/wan" + SEPARATOR + "1"], ensure_ascii=True, separators=(",", ":"))
VECTORS = (
    ((RULE, 1, TENANT, DEVICE, OBJECT), "2aa12a59e584e7c28ed33cf55508fa350f8415652984bdaa18dc7ddc072a80d6"),
    (("exos.management.vlan-empty", 1, "tenant-\xe9", "sw-\xfc.example.invalid", "vlan/caf\xe9"),
     "340f226032bcdccb26340a0f84a2ae6ceee07b8ddd1de3d8593b407027be066a"),
    (("fortios.ref.dangling", 2, "tenant\x1eb", "fw\tb.example.invalid", "firewall policy/1/srcaddr/lan net"),
     "c93c8b3c63f711483c7941b70b24d76eaa6cb17348275a13c742bd0941f99565"),
    ((RULE, 1, TENANT, DEVICE, SCOPED), "77d2396dd88670b0c7d6c3ce272c4bf0607c407e2ed6515e44c2cb90562bb8e6"),
)
VERSION_ONE = ((RULE, 1, DEVICE, OBJECT), "33ada9e38cd292f102d92833ae24ae3366f45eb5462f307b9edd31f6993034a1")
SCOPED_TEXT = """config global
 config system global
  set strong-crypto enable
 end
end
config vdom
 edit root
  config firewall policy
   edit 1
    set srcaddr "lan%snet"
    set dstaddr all
    set service HTTPS
    set schedule always
   next
  end
 next
end
""" % SEPARATOR


def _refused(name):
    return "^%s %s$" % (re.escape(name), re.escape(REFUSAL))


def _joined(*values):
    return hashlib.sha256(SEPARATOR.join(values).encode("utf-8")).hexdigest()


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tables(path):
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    try:
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return {name: [dict(row) for row in connection.execute("SELECT * FROM %s ORDER BY rowid" % name)]
                for name in names}
    finally:
        connection.close()


def _written(path, document):
    path.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
    return path


def _cli(capsys, *argv):
    code = cli.main([str(item) for item in argv])
    out, err = capsys.readouterr()
    return code, out, err


def _run(config, store, *extra, platform="fortios", tenant=TENANT, device=DEVICE):
    return ("run", "--platform", platform, "--tenant", tenant, "--device", device, "--config", config,
            "--store", store, *extra)


def _device(name, source, auditor=True):
    section = {"channel": "file", "source": str(source), "required_sections": ["system global"],
               "tls_fingerprint": None}
    return {
        "name": name,
        "platform": "fortios",
        "address": None,
        "port": None,
        "role": "perimetr",
        "credential": None,
        "host_key_fingerprint": None,
        "legacy_ssh": None,
        "auditor": section if auditor else None,
        "helper": None if auditor else {},
    }


def _waiver(rule_id=RULE, device=DEVICE, object_key=OBJECT, tenant=TENANT):
    return {
        "fingerprint": _joined(rule_id, "1", tenant, device, object_key),
        "rule_id": rule_id,
        "rule_version": 1,
        "device": device,
        "object_key": object_key,
        "reason": "accepted for the test",
        "author": "operator@example.invalid",
        "created": "2026-01-01T00:00:00Z",
        "expires": "2036-01-01T00:00:00Z",
    }


def _library():
    nodes = {path: {"kind": "table", "scope": "vdom", "available": True, "attrs": {}}
             for path in set(scoped_fortios.PRIMARY_PATHS.values())}
    for path in ("system interface", "system global", "system admin", "system auto-install"):
        nodes[path]["scope"] = "global"
    nodes["system interface"]["scope"] = "global+vdom"
    nodes["system interface"]["attrs"] = {"vdom": {"type": "string", "default": "root"}}
    return schema.Library({"format": 1, "platform": "fortios", "hardware": "FortiGate-VM64-KVM",
                           "os_version": "8.0.0", "build": "0167", "config": nodes})


def _schema_check(directory, text, tenant=TENANT, device=DEVICE):
    library = _library()
    source = _written(directory / "schema.json", library._document)
    snapshot = _written(directory / "snapshot.conf", text)
    return ("schema-check", "--library", source, "--hardware", library.identity[0], "--os-version",
            library.identity[1], "--build", library.identity[2], "--config", snapshot, "--tenant", tenant,
            "--device", device, "--full-snapshot", "--catalog-vdoms")


@pytest.fixture
def world(tmp_path, capsys):
    store = tmp_path / "store.sqlite"
    code, _out, err = _cli(capsys, *_run(CLEAN, store))
    assert code == 0, err
    return SimpleNamespace(
        directory=tmp_path,
        store=store,
        inventory=_written(tmp_path / "inventory.json", {"version": 2, "devices": [_device(DEVICE, CLEAN)]}),
        old=_written(tmp_path / "old.json", {"version": 1, "suppressions": [
            dict(_waiver(), fingerprint=_joined(RULE, "1", DEVICE, OBJECT))]}),
        new=tmp_path / "new.json",
    )


def _argv(command, world, tenant, device):
    if command == "run":
        return _run(CLEAN, world.store, tenant=tenant, device=device)
    if command == "collect":
        return ("collect", "--inventory", world.inventory, "--device", device, "--tenant", tenant,
                "--store", world.store)
    if command == "status":
        return ("status", "--tenant", tenant, "--device", device, "--store", world.store)
    if command == "schema-check":
        return _schema_check(world.directory, SCOPED_TEXT.replace(SEPARATOR, ""), tenant, device)
    return ("migrate-suppressions", "--input", world.old, "--output", world.new, "--tenant", tenant)


@pytest.mark.parametrize("components,expected", VECTORS)
def test_a_fingerprint_without_the_separator_keeps_its_bytes(components, expected):
    assert fingerprint_of(*components) == expected


def test_the_fingerprint_of_a_finding_keeps_its_bytes():
    finding = Finding(rule_id=RULE, rule_version=1, tenant=TENANT, device=DEVICE, object_key=OBJECT,
                      severity="high", rule_class="fakt", section="system interface", line=10)
    assert finding.fingerprint() == VECTORS[0][1]
    assert finding.as_dict()["fingerprint"] == VECTORS[0][1]


def test_a_version_one_fingerprint_keeps_its_bytes():
    assert fingerprint_v1(*VERSION_ONE[0]) == VERSION_ONE[1]


@pytest.mark.parametrize("position", range(len(COMPONENTS)))
def test_fingerprint_of_refuses_the_separator_in_every_component(position):
    components = [RULE, "1", TENANT, DEVICE, OBJECT]
    components[position] += SEPARATOR
    with pytest.raises(ValueError, match=_refused(COMPONENTS[position])):
        fingerprint_of(*components)


@pytest.mark.parametrize("position", range(len(VERSION_ONE_COMPONENTS)))
def test_fingerprint_v1_refuses_the_separator_in_every_component(position):
    components = [RULE, "1", DEVICE, OBJECT]
    components[position] = SEPARATOR + components[position]
    with pytest.raises(ValueError, match=_refused(VERSION_ONE_COMPONENTS[position])):
        fingerprint_v1(*components)


@pytest.mark.parametrize("command,name", [(command, name) for command in ("run", "collect", "status", "schema-check")
                                          for name in ("tenant", "device")] + [("migrate-suppressions", "tenant")])
def test_every_command_refuses_the_separator_in_tenant_and_device_before_the_store(world, capsys, command, name):
    values = {"tenant": TENANT, "device": DEVICE, name: ODD}
    before = _digest(world.store)
    code, out, err = _cli(capsys, *_argv(command, world, values["tenant"], values["device"]))
    assert (code, out, err) == (2, "", "error: argument %s %s\n" % (name, REFUSAL))
    assert _digest(world.store) == before
    assert not world.new.exists()


@pytest.mark.parametrize("command", ("run", "collect"))
def test_a_refused_identity_creates_no_store(world, capsys, command):
    world.store = world.directory / "fresh.sqlite"
    code, out, err = _cli(capsys, *_argv(command, world, ODD, DEVICE))
    assert (code, out, err) == (2, "", "error: argument tenant %s\n" % REFUSAL)
    assert not world.store.exists()


@pytest.mark.parametrize("tenant", (ODD, TENANT + SEPARATOR))
def test_the_mcp_configuration_refuses_the_separator_in_the_tenant(world, tenant):
    from netops_auditor import mcp_server

    values = {
        mcp_server.STORE_VARIABLE: str(world.store),
        mcp_server.TENANT_VARIABLE: tenant,
        mcp_server.CATALOG_VARIABLE: "fortios",
    }
    mcp_server._CONFIGURATION = None
    try:
        with pytest.raises(mcp_server.ConfigurationError, match=_refused(mcp_server.TENANT_VARIABLE)):
            mcp_server.configure(values)
        assert mcp_server._CONFIGURATION is None
        assert mcp_server.configure(dict(values, **{mcp_server.TENANT_VARIABLE: TENANT})).tenant == TENANT
    finally:
        mcp_server._CONFIGURATION = None


@pytest.mark.parametrize("field", ("rule_id", "device", "object_key"))
def test_a_suppression_refuses_the_separator_in_a_fingerprint_component(tmp_path, field):
    path = _written(tmp_path / "waivers.json",
                    {"version": 2, "tenant": TENANT, "suppressions": [_waiver(**{field: ODD})]})
    with pytest.raises(suppressions.SuppressionError, match=_refused("suppression 0: " + field)):
        suppressions.load(path, TENANT)


@pytest.mark.parametrize("bound,asked,name", (
    (ODD, ODD, "tenant"),
    (TENANT, ODD, "tenant"),
    (ODD, TENANT, "suppression file {path}: tenant"),
))
def test_a_suppression_file_refuses_the_separator_in_the_tenant(tmp_path, bound, asked, name):
    path = _written(tmp_path / "waivers.json",
                    {"version": 2, "tenant": bound, "suppressions": [_waiver(tenant=bound)]})
    with pytest.raises(suppressions.SuppressionError, match=_refused(name.format(path=path))):
        suppressions.load(path, asked)


def test_run_refuses_a_suppression_with_the_separator_before_the_store(world, capsys):
    path = _written(world.directory / "waivers.json",
                    {"version": 2, "tenant": TENANT, "suppressions": [_waiver(device=DEVICE + SEPARATOR)]})
    before = _digest(world.store)
    code, out, err = _cli(capsys, *_run(CLEAN, world.store, "--suppressions", path))
    assert (code, out, err) == (2, "", "error: suppressions: suppression 0: device %s\n" % REFUSAL)
    assert _digest(world.store) == before


def test_migrate_suppressions_refuses_an_item_with_the_separator(world, capsys):
    item = dict(_waiver(device=DEVICE + SEPARATOR), fingerprint=_joined(RULE, "1", DEVICE + SEPARATOR, OBJECT))
    old = _written(world.directory / "old-separator.json", {"version": 1, "suppressions": [item]})
    code, out, err = _cli(capsys, "migrate-suppressions", "--input", old, "--output", world.new, "--tenant", TENANT)
    assert (code, out, err) == (2, "", "error: suppressions: suppression 0: device %s\n" % REFUSAL)
    assert not world.new.exists()


def test_collect_refuses_an_inventory_whose_auditor_device_name_holds_the_separator(world, capsys):
    odd = "fw" + SEPARATOR + "b.example.invalid"
    path = _written(world.directory / "odd-inventory.json",
                    {"version": 2, "devices": [_device(DEVICE, CLEAN), _device(odd, CLEAN)]})
    before = _digest(world.store)
    code, out, err = _cli(capsys, "collect", "--inventory", path, "--device", DEVICE, "--tenant", TENANT,
                          "--store", world.store)
    assert (code, out, err) == (2, "", "error: inventory: device %r: name %s\n" % (odd, REFUSAL))
    assert _digest(world.store) == before
    with pytest.raises(inventory.InventoryError, match=re.escape(REFUSAL)):
        inventory.load(path)


def test_a_device_the_auditor_does_not_read_may_hold_the_separator(world, capsys):
    path = _written(world.directory / "helper-inventory.json", {"version": 2, "devices": [
        _device(DEVICE, CLEAN), _device("fw" + SEPARATOR + "b.example.invalid", CLEAN, auditor=False)]})
    code, _out, err = _cli(capsys, "collect", "--inventory", path, "--device", DEVICE, "--tenant", TENANT, "--json")
    assert code == 0, err


def test_a_catalog_rule_id_with_the_separator_is_refused(world, capsys, monkeypatch):
    document = json.loads((CATALOG_DIR / "fortios.json").read_text(encoding="utf-8"))
    odd = document["rules"][0]["id"] + SEPARATOR
    document["rules"][0]["id"] = odd
    directory = world.directory / "catalog"
    directory.mkdir()
    _written(directory / "fortios.json", document)
    monkeypatch.setattr(engine, "CATALOG_DIR", directory)
    with pytest.raises(CatalogError, match="^%s$" % re.escape("%r: id %s" % (odd, REFUSAL))):
        load_catalog("fortios")
    expected = (2, "", "error: catalog fortios: %r: id %s\n" % (odd, REFUSAL))
    before = _digest(world.store)
    assert _cli(capsys, *_run(CLEAN, world.store)) == expected
    assert _digest(world.store) == before
    assert _cli(capsys, *_schema_check(world.directory, SCOPED_TEXT.replace(SEPARATOR, ""))) == expected


def _object_cases(directory):
    fortios = CLEAN.read_text(encoding="utf-8").replace("set allowaccess ping\n", "set allowaccess ping https ssh\n", 1)
    fortios = _written(directory / "fortios.conf", fortios.replace('edit "wan1"', 'edit "wan%s1"' % SEPARATOR))
    exos = (EMPTY_VLAN / "positive.conf").read_text(encoding="utf-8").replace("guest", "gu%sest" % SEPARATOR)
    exos = _written(directory / "exos.conf", exos)
    return {
        "fortios": ((fortios,), {}, "rule fortios.mgmt.wan-admin-access, line 10"),
        "exos": ((exos, "--policy", EMPTY_VLAN / "positive.policy.json"), {"platform": "exos"},
                 "rule exos.management.vlan-empty, line 0"),
    }


@pytest.mark.parametrize("platform", ("fortios", "exos"))
def test_a_configuration_whose_finding_object_holds_the_separator_is_refused(world, capsys, platform):
    (config, *extra), keywords, where = _object_cases(world.directory)[platform]
    store = world.directory / ("%s.sqlite" % platform)
    code, out, err = _cli(capsys, *_run(config, store, *extra, **keywords))
    assert (code, out) == (2, "")
    assert err == "error: cannot parse configuration: %s: object_key %s\n" % (where, REFUSAL)
    assert not store.exists()


def test_collect_refuses_a_snapshot_whose_finding_object_holds_the_separator(world, capsys):
    (config,), _keywords, where = _object_cases(world.directory)["fortios"]
    path = _written(world.directory / "object-inventory.json", {"version": 2, "devices": [_device(DEVICE, config)]})
    before = _tables(world.store)
    code, out, err = _cli(capsys, "collect", "--inventory", path, "--device", DEVICE, "--tenant", TENANT,
                          "--store", world.store)
    assert (code, out, err) == (2, "", "error: cannot parse configuration: %s: object_key %s\n" % (where, REFUSAL))
    after = _tables(world.store)
    added = after.pop("channel_events")[len(before.pop("channel_events")):]
    assert after == before
    assert [(row["run_id"], row["channel"], row["request"], row["outcome"]) for row in added] == [
        (None, "file", str(config), "ok")]


def test_the_separator_outside_every_finding_object_still_audits(world, capsys):
    text = CLEAN.read_text(encoding="utf-8").replace('set comment "site', 'set comment "si%ste' % SEPARATOR)
    config = _written(world.directory / "comment.conf", text)
    code, out, err = _cli(capsys, *_run(config, world.store, "--json"))
    assert code == 0, err
    assert json.loads(out)["findings"] == []


def test_a_scoped_object_carries_the_separator_escaped(world, capsys):
    code, out, err = _cli(capsys, *_schema_check(world.directory, SCOPED_TEXT))
    assert code == 1, err
    keys = [item["object_key"] for item in json.loads(out)["findings"] if item["rule_id"] == "fortios.ref.dangling"]
    assert keys == [json.dumps(["root", "firewall policy/1/srcaddr/lan" + SEPARATOR + "net"], ensure_ascii=True,
                               separators=(",", ":"))]


def test_migrate_store_refuses_a_version_one_finding_with_the_separator(tmp_path, capsys):
    path = tmp_path / "v1.sqlite"
    with Store(path):
        pass
    connection = sqlite3.connect(str(path), isolation_level=None)
    run_id = connection.execute(
        "INSERT INTO runs (tenant, device, started_at, snapshot_sha256, snapshot_source, rules_version)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (ODD, DEVICE, "2026-01-01T00:00:00Z", "0" * 64, "fw.conf", "fortios:1:x"),
    ).lastrowid
    connection.execute(
        'INSERT INTO findings (run_id, fingerprint, rule_id, rule_version, device, object_key, severity, "class",'
        " section, line, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, _joined(RULE, "1", DEVICE, OBJECT), RULE, 1, DEVICE, OBJECT, "high", "fakt", "system interface", 10,
         "{}"),
    )
    connection.execute("PRAGMA user_version = 0")
    connection.close()
    before = _digest(path)
    code, out, err = _cli(capsys, "migrate-store", "--store", path)
    assert (code, out, err) == (2, "", "error: store: finding 1 cannot be migrated: tenant %s\n" % REFUSAL)
    assert _digest(path) == before
