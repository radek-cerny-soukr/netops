import json
import sqlite3

from netops_auditor import cli

TENANT = "tenant-a"
DEVICE = "fw-example"
COMPLETE = 'config system global\n    set hostname "fw-example"\nend\n'
VDOM = "config vdom\n    edit root\n    next\nend\n" + COMPLETE
UNEVALUATED = "cannot accept a baseline from an unevaluated audit"
NO_RUN = "no run was recorded"
LOCK_WAIT_SECONDS = 0.2


def write(directory, name, text):
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def run_cli(capsys, config, database, accept=True):
    argv = ["run", "--platform", "fortios", "--tenant", TENANT, "--device", DEVICE,
            "--config", str(config), "--store", str(database), "--json"]
    if accept:
        argv += ["--baseline-accept", "--accepted-by", "operator", "--note", "first review"]
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def collect_cli(capsys, tmp_path, config, database):
    inventory = write(tmp_path, "inventory.json", json.dumps({"version": 2, "devices": [{
        "name": DEVICE, "platform": "fortios", "address": None, "port": None, "role": "lab",
        "credential": None, "host_key_fingerprint": None, "legacy_ssh": None,
        "auditor": {"channel": "file", "source": str(config), "required_sections": ["system global"],
                    "tls_fingerprint": None},
        "helper": None,
    }]}))
    code = cli.main(["collect", "--inventory", str(inventory), "--device", DEVICE, "--tenant", TENANT,
                     "--store", str(database), "--baseline-accept", "--accepted-by", "operator",
                     "--note", "first review"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def counts(database):
    connection = sqlite3.connect(str(database))
    try:
        return tuple(
            connection.execute("SELECT count(*) FROM %s" % table).fetchone()[0]
            for table in ("runs", "findings", "baseline", "rule_status")
        )
    finally:
        connection.close()


def events(database):
    connection = sqlite3.connect(str(database))
    try:
        return connection.execute("SELECT channel, outcome, run_id FROM channel_events ORDER BY id").fetchall()
    finally:
        connection.close()


def status(capsys, database):
    code = cli.main(["status", "--tenant", TENANT, "--device", DEVICE, "--store", str(database), "--json"])
    return code, json.loads(capsys.readouterr().out)["state"]


def test_an_accepted_complete_run_records_the_run_and_its_baseline(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    code, out, err = run_cli(capsys, write(tmp_path, "ok.conf", COMPLETE), database)
    findings = len(json.loads(out)["findings"])
    assert code == cli.EXIT_OK
    assert err == "baseline: accepted %d of %d findings\n" % (findings, findings)
    assert counts(database)[:3] == (1, findings, findings)


def test_a_refused_baseline_acceptance_records_nothing(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    code, out, err = run_cli(capsys, write(tmp_path, "vdom.conf", VDOM), database)
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert counts(database) == (0, 0, 0, 0)
    assert UNEVALUATED in err and NO_RUN in err
    assert err.count("\n") == 1
    assert status(capsys, database) == (cli.EXIT_STALE, "never")


def test_a_refused_acceptance_leaves_the_history_of_the_device_as_it_was(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    complete = write(tmp_path, "ok.conf", COMPLETE)
    assert run_cli(capsys, complete, database)[0] == cli.EXIT_OK
    before = counts(database)
    code, _, err = run_cli(capsys, write(tmp_path, "vdom.conf", VDOM), database)
    assert code == cli.EXIT_ERROR and UNEVALUATED in err
    assert counts(database) == before
    assert status(capsys, database) == (cli.EXIT_OK, "fresh")
    code, out, _ = run_cli(capsys, complete, database, accept=False)
    report = json.loads(out)
    assert code == cli.EXIT_OK
    assert report["gone"] == [] and report.get("not_evaluated", []) == []
    assert {item["state"] for item in report["findings"]} <= {"open-known"}
    assert counts(database)[0] == before[0] + 1


def test_a_collect_refused_at_acceptance_keeps_only_the_events_of_its_collection(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    code, out, err = collect_cli(capsys, tmp_path, write(tmp_path, "vdom.conf", VDOM), database)
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert counts(database) == (0, 0, 0, 0)
    assert UNEVALUATED in err and NO_RUN in err
    assert "stayed unrecorded" not in err
    assert events(database) == [("file", "ok", None)]
    code, _, err = collect_cli(capsys, tmp_path, write(tmp_path, "ok.conf", COMPLETE), database)
    assert code == cli.EXIT_OK
    run_id = counts(database)[0]
    assert run_id == 1
    assert events(database) == [("file", "ok", None), ("file", "ok", run_id)]


def test_a_store_locked_while_the_baseline_is_written_records_no_run(tmp_path, capsys, monkeypatch):
    database = tmp_path / "audit.sqlite"
    real_connect = sqlite3.connect
    holders, seen = [], []

    def lock(statement):
        if statement.startswith("INSERT OR IGNORE INTO baseline"):
            seen.append(statement)
        if statement == "COMMIT" and seen and not holders:
            holder = real_connect(str(database), isolation_level=None)
            holder.execute("BEGIN")
            holder.execute("SELECT count(*) FROM runs").fetchone()
            holders.append(holder)

    def connect(*args, **keywords):
        keywords["timeout"] = LOCK_WAIT_SECONDS
        connection = real_connect(*args, **keywords)
        connection.set_trace_callback(lock)
        return connection

    config = write(tmp_path, "ok.conf", COMPLETE)
    with monkeypatch.context() as patched:
        patched.setattr(sqlite3, "connect", connect)
        try:
            code, out, err = run_cli(capsys, config, database)
        finally:
            for holder in holders:
                holder.execute("ROLLBACK")
                holder.close()
    assert holders and seen
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert counts(database) == (0, 0, 0, 0)
    assert err.startswith("error: store ") and err.count("\n") == 1
    assert "database is locked" in err and NO_RUN in err
    code, _, err = run_cli(capsys, config, database)
    assert code == cli.EXIT_OK and err.startswith("baseline: accepted ")
    assert counts(database)[0] == 1
