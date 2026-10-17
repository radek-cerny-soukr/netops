"""Container health check that performs no network activity."""

from __future__ import annotations

import os
import shutil
import ssl
from pathlib import Path

from netops_core import ssh as ssh_module

SSH_BINARIES = ("ssh", "ssh-keyscan", "sftp")


def askpass_unsafe() -> bool:
    named_askpass = os.environ.get(ssh_module.ASKPASS_PROGRAM_ENV)
    if named_askpass is None:
        return False
    try:
        ssh_module._named_askpass(named_askpass)
    except ssh_module.SshError:
        return True
    return False


def main() -> int:
    import fastmcp  # noqa: F401
    import httpx  # noqa: F401
    import pysnmp  # noqa: F401

    if any(shutil.which(binary) is None for binary in SSH_BINARIES):
        return 1
    trust_paths = ssl.get_default_verify_paths()
    if not trust_paths.cafile or not Path(trust_paths.cafile).is_file():
        return 1
    if not ssl.create_default_context().get_ca_certs(binary_form=True):
        return 1
    if not Path("/var/lib/netops-helper").is_dir():
        return 1
    if askpass_unsafe():
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
