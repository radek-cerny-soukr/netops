import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


def verify_tar_safety():
    for extraction_filter in ("data", "tar"):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.write_bytes(b"private sentinel")
            outside.chmod(0o600)
            os.utime(outside, (1700000000, 1700000000))
            original = outside.stat()
            destination = base / "output"
            destination.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as writer:
                decoy = tarfile.TarInfo("a/outside")
                decoy.size = 5
                writer.addfile(decoy, io.BytesIO(b"decoy"))
                link = tarfile.TarInfo("a/b/symlink")
                link.type = tarfile.SYMTYPE
                link.linkname = "../outside"
                writer.addfile(link)
                hardlink = tarfile.TarInfo("hardlink")
                hardlink.type = tarfile.LNKTYPE
                hardlink.linkname = "a/b/symlink"
                hardlink.mode = 0o777
                hardlink.mtime = 1800000000
                writer.addfile(hardlink)
            archive.seek(0)
            try:
                with tarfile.open(fileobj=archive) as reader:
                    reader.extractall(destination, filter=extraction_filter)
            except tarfile.FilterError:
                pass
            current = outside.stat()
            assert current.st_mode == original.st_mode
            assert current.st_mtime_ns == original.st_mtime_ns
            assert not (destination / "hardlink").is_symlink()
            assert (destination / "hardlink").read_bytes() == b"decoy"
            valid = io.BytesIO()
            with tarfile.open(fileobj=valid, mode="w") as writer:
                entry = tarfile.TarInfo("regular")
                entry.size = 5
                writer.addfile(entry, io.BytesIO(b"valid"))
                link = tarfile.TarInfo("regular-link")
                link.type = tarfile.LNKTYPE
                link.linkname = "regular"
                writer.addfile(link)
            valid.seek(0)
            with tarfile.open(fileobj=valid) as reader:
                reader.extractall(destination, filter=extraction_filter)
            assert (destination / "regular").read_bytes() == b"valid"
            assert (destination / "regular-link").read_bytes() == b"valid"


class RuntimeTarSafety(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (3, 14), "the shipped runtime uses Python 3.14")
    def test_extraction_filters_reject_outside_links_and_accept_regular_files(self):
        verify_tar_safety()


if __name__ == "__main__":
    verify_tar_safety()
    print("runtime_tar_safety=passed")
