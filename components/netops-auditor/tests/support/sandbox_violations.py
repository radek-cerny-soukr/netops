import os
from pathlib import Path
import socket

DOCUMENTATION_ADDRESS = "192.0.2.1"
PROBE = Path.home() / ".netops-sandbox-guard-probe"

def test_demo_write_into_the_home_directory():
    with open(PROBE, "w", encoding="utf-8") as handle:
        handle.write("written by a test\n")

def test_demo_swallowed_refusal_still_fails():
    try:
        PROBE.write_text("written by a test\n", encoding="utf-8")
    except OSError:
        pass

def test_demo_write_into_the_null_device():
    with open(os.devnull, "w", encoding="utf-8") as handle:
        handle.write("written by a test\n")

def test_demo_replace_onto_the_null_device(tmp_path):
    staged = tmp_path / "staged"
    staged.write_text("x", encoding="utf-8")
    os.replace(staged, os.devnull)

def test_demo_connection_off_loopback():
    socket.create_connection((DOCUMENTATION_ADDRESS, 9), timeout=1).close()
