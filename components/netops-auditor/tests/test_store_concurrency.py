import multiprocessing
import sqlite3
import threading
from contextlib import closing

import pytest

from netops_auditor import cli
from netops_auditor.store import SCHEMA_VERSION, Store
from test_cli import dirty_text, invoke, run_args, status_args, write_config

OPENERS = 8
ROUNDS = 20
LOCK_WAIT_SECONDS = 0.3
PAUSE_SECONDS = 1.0


def _user_version(path):
    with closing(sqlite3.connect(str(path))) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0]


def _open_in_thread(path, barrier, errors):
    barrier.wait()
    try:
        Store(path).close()
    except Exception as error:
        errors.append(repr(error))


def _open_in_process(path, barrier, errors):
    barrier.wait()
    try:
        Store(path).close()
    except Exception as error:
        errors.put(repr(error))


def test_threads_opening_one_empty_store_together_all_succeed(tmp_path):
    for round_number in range(ROUNDS):
        path = tmp_path / ("audit-%d.sqlite" % round_number)
        barrier, errors = threading.Barrier(OPENERS), []
        threads = [threading.Thread(target=_open_in_thread, args=(path, barrier, errors)) for _ in range(OPENERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        assert errors == []
        assert _user_version(path) == SCHEMA_VERSION


def test_processes_opening_one_empty_store_together_all_succeed(tmp_path):
    context = multiprocessing.get_context("fork")
    for round_number in range(ROUNDS // 4):
        path = tmp_path / ("audit-%d.sqlite" % round_number)
        barrier, errors = context.Barrier(OPENERS), context.Queue()
        workers = [context.Process(target=_open_in_process, args=(path, barrier, errors)) for _ in range(OPENERS)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        assert [worker.exitcode for worker in workers] == [0] * OPENERS
        found = []
        while not errors.empty():
            found.append(errors.get())
        assert found == []
        assert _user_version(path) == SCHEMA_VERSION


def test_an_opener_never_sees_the_schema_another_opener_is_still_writing(tmp_path, monkeypatch):
    path = tmp_path / "audit.sqlite"
    real_connect = sqlite3.connect
    paused, resumed = threading.Event(), threading.Event()

    def hold(statement):
        if "CREATE TABLE IF NOT EXISTS findings" in statement and not paused.is_set():
            paused.set()
            resumed.wait(PAUSE_SECONDS)

    def connect(*args, **keywords):
        connection = real_connect(*args, **keywords)
        if threading.current_thread().name == "first-opener":
            connection.set_trace_callback(hold)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    outcome = {}

    def first():
        try:
            Store(path).close()
            outcome["first"] = "ok"
        except Exception as error:
            outcome["first"] = repr(error)

    thread = threading.Thread(target=first, name="first-opener")
    thread.start()
    assert paused.wait(30)
    try:
        Store(path).close()
        outcome["second"] = "ok"
    except Exception as error:
        outcome["second"] = repr(error)
    finally:
        resumed.set()
        thread.join(30)
    assert outcome == {"first": "ok", "second": "ok"}
    assert _user_version(path) == SCHEMA_VERSION


def _corrupt_table(path, table):
    with closing(sqlite3.connect(str(path))) as connection:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        root = connection.execute(
            "SELECT rootpage FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()[0]
    with open(path, "r+b") as stream:
        stream.seek((root - 1) * page_size)
        stream.write(b"\xff" * page_size)


def _audited_store(tmp_path, capsys):
    database = tmp_path / "audit.sqlite"
    config = write_config(tmp_path, dirty_text())
    code, _, err = invoke(capsys, run_args(config, store=database))
    assert code == 0, err
    return database, config


def test_status_over_a_store_with_a_corrupted_page_ends_with_a_store_error(tmp_path, capsys):
    database, _ = _audited_store(tmp_path, capsys)
    _corrupt_table(database, "findings")
    code, out, err = invoke(capsys, status_args(database))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith("error: store ")
    assert "malformed" in err
    assert err.count("\n") == 1


def test_run_against_a_store_locked_by_another_writer_ends_with_a_store_error(tmp_path, capsys, monkeypatch):
    database, config = _audited_store(tmp_path, capsys)
    real_connect = sqlite3.connect
    holders = []

    def lock(statement):
        if statement == "BEGIN IMMEDIATE" and not holders:
            holder = real_connect(str(database), isolation_level=None)
            holder.execute("BEGIN IMMEDIATE")
            holders.append(holder)

    def connect(*args, **keywords):
        keywords.setdefault("timeout", LOCK_WAIT_SECONDS)
        connection = real_connect(*args, **keywords)
        connection.set_trace_callback(lock)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    try:
        code, out, err = invoke(capsys, run_args(config, store=database))
    finally:
        for holder in holders:
            holder.execute("ROLLBACK")
            holder.close()
    assert holders
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith("error: store ")
    assert "database is locked" in err
    assert err.count("\n") == 1
