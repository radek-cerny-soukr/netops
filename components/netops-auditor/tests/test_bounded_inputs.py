import json
import os
import resource
import subprocess
import sys
from pathlib import Path

import pytest

from netops_auditor import cli
from test_cli import TENANT, clean_text, file_inventory, run_args, write_config

COMPONENT = Path(__file__).resolve().parents[1]
SUPPRESSIONS_LIMIT = 4 * 1024 * 1024
MEMORY_CAP = 768 * 1024 * 1024
SECONDS = 30
ZERO = "/dev/zero"

needs_zero = pytest.mark.skipif(not Path(ZERO).exists(), reason="needs /dev/zero")


def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_CAP, MEMORY_CAP))


def _cli(argv):
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
        (str(COMPONENT / "src"), str(COMPONENT.parent / "netops-core" / "src"))))
    try:
        return subprocess.run(
            [sys.executable, "-B", "-m", "netops_auditor"] + [str(part) for part in argv],
            capture_output=True, text=True, timeout=SECONDS, env=environment, preexec_fn=_limited,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the command was still reading after %d seconds: %s" % (SECONDS, argv))


def _refused(result, words):
    assert result.returncode == cli.EXIT_ERROR, result.stderr[-400:]
    assert result.stdout == ""
    assert words in result.stderr
    assert "Traceback" not in result.stderr


def _fifo(directory, name):
    path = directory / name
    os.mkfifo(path)
    return path


@needs_zero
def test_suppressions_from_dev_zero_are_refused(tmp_path):
    config = write_config(tmp_path, clean_text())
    _refused(_cli(run_args(config) + ["--suppressions", ZERO]), "not a regular file")


def test_suppressions_from_a_fifo_without_a_writer_are_refused_without_blocking(tmp_path):
    config = write_config(tmp_path, clean_text())
    fifo = _fifo(tmp_path, "suppressions.fifo")
    _refused(_cli(run_args(config) + ["--suppressions", fifo]), "not a regular file")


def test_suppressions_over_the_limit_are_refused(tmp_path):
    config = write_config(tmp_path, clean_text())
    document = json.dumps({"version": 2, "tenant": TENANT, "suppressions": []})
    path = tmp_path / "suppressions.json"
    path.write_text(document + " " * (SUPPRESSIONS_LIMIT + 1 - len(document)), encoding="utf-8")
    _refused(_cli(run_args(config) + ["--suppressions", path]), "larger than %d bytes" % SUPPRESSIONS_LIMIT)


def test_suppressions_at_the_limit_are_read(tmp_path):
    config = write_config(tmp_path, clean_text())
    document = json.dumps({"version": 2, "tenant": TENANT, "suppressions": []})
    path = tmp_path / "suppressions.json"
    path.write_text(document + " " * (SUPPRESSIONS_LIMIT - len(document)), encoding="utf-8")
    result = _cli(run_args(config) + ["--suppressions", path])
    assert result.returncode == cli.EXIT_OK, result.stderr[-400:]


@needs_zero
def test_configuration_from_dev_zero_is_refused(tmp_path):
    _refused(_cli(run_args(ZERO)), "not a regular file")


def test_configuration_from_a_fifo_without_a_writer_is_refused_without_blocking(tmp_path):
    _refused(_cli(run_args(_fifo(tmp_path, "device.fifo"))), "not a regular file")


@needs_zero
def test_inventory_from_dev_zero_is_refused(tmp_path):
    argv = ["collect", "--inventory", ZERO, "--device", "fw-example", "--tenant", TENANT]
    _refused(_cli(argv), "not a regular file")


def test_inventory_from_a_fifo_without_a_writer_is_refused_without_blocking(tmp_path):
    fifo = _fifo(tmp_path, "inventory.fifo")
    argv = ["collect", "--inventory", fifo, "--device", "fw-example", "--tenant", TENANT]
    _refused(_cli(argv), "not a regular file")


def test_file_channel_from_a_fifo_without_a_writer_is_refused_without_blocking(tmp_path):
    inventory = file_inventory(tmp_path, str(_fifo(tmp_path, "device.fifo")))
    argv = ["collect", "--inventory", inventory, "--device", "fw-example", "--tenant", TENANT]
    _refused(_cli(argv), "not a regular file")


@needs_zero
def test_sarif_from_dev_zero_is_refused(tmp_path):
    _refused(_cli(["merge-sarif", "--output", tmp_path / "merged.sarif", ZERO]), "not a regular file")


def test_policy_from_a_fifo_without_a_writer_is_refused_without_blocking(tmp_path):
    config = write_config(tmp_path, clean_text())
    _refused(_cli(run_args(config) + ["--policy", _fifo(tmp_path, "policy.fifo")]), "not a regular file")


def test_suppressions_that_are_not_utf_8_are_refused(tmp_path):
    config = write_config(tmp_path, clean_text())
    path = tmp_path / "suppressions.json"
    path.write_bytes(b'{"version": 2, "tenant": "tenant-a", "suppressions": [], "x": "' + bytes([0xFF]) + b'"}')
    _refused(_cli(run_args(config) + ["--suppressions", path]), "is not valid UTF-8")
