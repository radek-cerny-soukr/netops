"""Shared retention for formats without device identity keeps the pre-G58 stop-before-publish behaviour."""

import os

import pytest

from netops.files import write_private
from netops_admin import backup, backup_eos, backup_exos, backup_junos
from netops_admin.errors import Rejected

K1, K2 = b"1" * 32, b"2" * 32


@pytest.mark.parametrize("magic", (backup_exos.MAGIC, backup_junos.MAGIC, backup_eos.MAGIC),
                         ids=("exos", "junos", "eos"))
def test_unverifiable_newest_archive_stops_before_publication_and_deletion(tmp_path, magic):
    directory = tmp_path / "backups"
    directory.mkdir(mode=0o700)
    prefix = "device-" + "a" * 24
    # Device A: older archive under K1, newer under K2 (key rotation), written directly.
    old, newer = (f"{prefix}-20261101T000000Z-{'a' * 32}.netops-backup", f"{prefix}-20261102T000000Z-{'b' * 32}.netops-backup")
    for name, key, mtime in ((old, K1, 1), (newer, K2, 2)):
        write_private(directory / name, backup._seal(b"config A\n", key, magic))
        os.utime(directory / name, ns=(mtime, mtime))
    before = sorted(path.name for path in directory.iterdir())
    # Device replaced by B on the same host and port; operator is back on K1 with keep=1.
    with pytest.raises(Rejected) as refused:
        backup._save(directory, prefix, b"config B\n", 1, K1, magic=magic)
    assert refused.value.reason_codes == ["backup_invalid"]
    assert sorted(path.name for path in directory.iterdir()) == before
    assert {old, newer} <= set(before)


def test_identity_callback_keeps_unverifiable_archives_and_prunes_only_verified(tmp_path):
    directory = tmp_path / "backups"
    directory.mkdir(mode=0o700)
    prefix = "device-" + "b" * 24
    magic = backup_exos.MAGIC
    foreign, _, _, _ = backup._save(directory, prefix, b"foreign\n", 5, K1, magic=magic)
    os.utime(directory / foreign, ns=(1, 1))

    def read_previous(path):
        raise backup._reject("backup_invalid", "foreign device")

    backup._save(directory, prefix, b"mine\n", 1, K1, magic=magic, read_previous=read_previous)
    assert (directory / foreign).exists()
