import json

import pytest

from netops_auditor import engine, platforms, l1_cli


def test_registry_reserves_platforms_and_inventory_aliases():
    assert set(platforms.PLATFORMS) == {
        "arista-eos", "cisco-ios", "cisco-nxos", "exos", "fortiadc", "fortios", "juniper-junos",
    }
    assert platforms.catalog_key("cisco_ios") == platforms.catalog_key("cisco_xe") == "cisco-ios"
    assert platforms.catalog_key("juniper_junos_els") == "juniper-junos"
    expected = tuple(key for key in platforms.PLATFORMS if engine.catalog_path(key).is_file())
    assert engine.available_platforms() == expected


def test_missing_optional_and_empty_catalog_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "CATALOG_DIR", tmp_path)
    with pytest.raises(engine.CatalogError, match="catalog is missing"):
        engine.load_catalog("cisco-ios")
    with pytest.raises(engine.CatalogError, match="unknown Auditor catalog"):
        engine.load_catalog("../fortios")
    (tmp_path / "fortios.json").write_text(json.dumps({"rules": []}))
    with pytest.raises(engine.CatalogError, match="no rule definitions"):
        engine.load_catalog("fortios")


def test_corrupt_catalog_is_skipped_with_a_diagnostic(tmp_path, monkeypatch, caplog):
    for path in engine.CATALOG_DIR.glob("*.json"):
        (tmp_path / path.name).write_bytes(path.read_bytes())
    (tmp_path / "arista-eos.json").write_text("{")
    monkeypatch.setattr(engine, "CATALOG_DIR", tmp_path)
    assert engine.available_platforms() == tuple(key for key in platforms.PLATFORMS if key != "arista-eos")
    assert "Auditor catalog arista-eos is unavailable: catalog is not readable JSON" in caplog.text
    with pytest.raises(engine.CatalogError, match="not readable JSON"):
        engine.available_platforms(require_all=True)


def test_cli_parser_keeps_vrf_indentation_modes_and_repeated_values():
    tree = l1_cli.parse(
        "banner motd ^C\ninterface fake\n^C\n!\nmanagement ssh\n   vrf default\n"
        "      no shutdown\n      default shutdown\n!\nlogging host 192.0.2.1\nlogging host 192.0.2.2\n"
    )
    assert tree.section("interface") is None
    commands = tree.matching("shutdown")
    assert [item.mode for item in commands] == ["no", "default"]
    assert [item.line for item in commands] == [7, 8]
    assert commands[0].parents == (("management", "ssh"), ("vrf", "default"))
    assert len(tree.section("logging")) == 2


def test_unavailable_rules_prevent_healthy_cli_audit(tmp_path, monkeypatch, capsys):
    from netops_auditor import cli
    monkeypatch.setattr(engine, "CATALOG_DIR", tmp_path)
    config = tmp_path / "input.conf"
    config.write_text("version 15.9\n")
    store = tmp_path / "audit.sqlite"
    rc = cli.main(["run", "--platform", "cisco-ios", "--device", "example", "--tenant", "example",
                   "--config", str(config), "--store", str(store), "--json"])
    out, err = capsys.readouterr()
    assert rc == cli.EXIT_ERROR
    assert "rules are unavailable" in err
    assert not out and not store.exists()
