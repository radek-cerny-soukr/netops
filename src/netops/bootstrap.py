import ctypes
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from .files import RUNTIME, STATE, UIDS
from .launcher import stop_requested

LIBC = ctypes.CDLL(None, use_errno=True)

def demote(uid):
    for capability in range(41):
        if LIBC.prctl(24, capability, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            if error != 22:
                raise OSError(error, "Cannot discard bounding capabilities")
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    if LIBC.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError("Cannot set no-new-privileges")
    if LIBC.prctl(4, 0, 0, 0, 0) != 0:
        raise OSError("Cannot disable process dumps")

def role_environment(role):
    directory = STATE / role
    os.environ["HOME"] = str(directory)
    if role == "helper":
        os.environ["NETOPS_HELPER_AUDIT_PATH"] = str(directory / "operations.jsonl")
    return directory

def directory(path, uid, mode):
    try:
        path.mkdir(mode=mode)
        os.chown(path, uid, uid)
        os.chmod(path, mode)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError("Unsafe state directory ownership or permissions")

def prepare():
    if os.geteuid() != 0:
        raise ValueError("Initialization and the short start bootstrap require the declared container user and capabilities")
    state_info = STATE.lstat()
    if not stat.S_ISDIR(state_info.st_mode):
        raise ValueError("State must be a real directory")
    if any(item.name not in UIDS for item in STATE.iterdir()):
        raise ValueError("State contains data outside the NetOps 1.x layout; 0.x volumes are not migrated or modified")
    for top in (STATE, RUNTIME):
        info = top.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("State and runtime must be real directories")
        os.chown(top, 0, 0)
        os.chmod(top, 0o711)
    for role, uid in UIDS.items():
        directory(STATE / role, uid, 0o700)
        directory(RUNTIME / role, uid, 0o755)

def serve():
    from .files import read_private, write_private
    import json
    from .state import __version__, admin_devices, auditor_settings, read_state_settings
    if stop_requested():
        return
    read_state_settings(STATE, allow_previous=True)
    prepare()
    import fcntl
    from .files import check_regular
    descriptor = os.open(STATE / "gateway" / "instance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    if os.fstat(descriptor).st_uid == 0:
        os.fchown(descriptor, UIDS["gateway"], UIDS["gateway"])
    check_regular(descriptor, UIDS["gateway"])
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError("An existing instance is using this state; stop it before starting or upgrading") from None
    settings = read_state_settings(STATE, allow_previous=True)
    upgraded_from = None
    if settings["product_version"] != __version__:
        from .init import check_start
        from .certificates import renewal_inputs
        check_start(settings, STATE)
        renewal_inputs(settings["server_name"])
        auditor_settings(STATE / "auditor", read_private)
        if settings["admin_enabled"]:
            admin_devices(STATE / "admin", read_private)
        upgraded_from = settings["product_version"]
        settings = dict(settings, product_version=__version__)
        write_private(STATE / "gateway" / "config.json", json.dumps(settings).encode(), UIDS["gateway"], replace=True)
    roles = ["helper", "auditor"] + (["admin"] if settings["admin_enabled"] else [])
    children = []
    try:
        for role in roles:
            if stop_requested():
                return
            socket_path = RUNTIME / role / "worker.sock"
            if socket_path.exists():
                info = socket_path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != UIDS[role]:
                    raise ValueError("Unsafe stale worker socket")
                socket_path.unlink()
            child = subprocess.Popen([sys.executable, "-m", "netops", "worker", role], preexec_fn=lambda uid=UIDS[role]: demote(uid), stdin=subprocess.DEVNULL)
            children.append(child)
        if stop_requested():
            return
        demote(UIDS["gateway"])
        role_environment("gateway")
        from .gateway import serve as gateway_serve
        if not stop_requested():
            if upgraded_from is None:
                gateway_serve(settings, roles, children)
            else:
                gateway_serve(settings, roles, children, upgraded_from=upgraded_from)
    finally:
        for child in children:
            try:
                os.kill(child.pid, signal.SIGTERM)
            except (PermissionError, ProcessLookupError):
                pass
