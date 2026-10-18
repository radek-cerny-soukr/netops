import argparse
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from .files import UIDS
from .diagnostics import OPERATION_SUFFIX

SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
COMMANDS = ("import-snapshot", "import-policy")


class ImportRefused(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ImportRefused("Invalid Auditor import arguments")


def _arguments(arguments):
    kind = arguments[0]
    parser = _Parser(prog="netops auditor " + kind)
    parser.add_argument("--name", required=True)
    if kind == "import-policy":
        parser.add_argument("--platform", required=True, choices=("fortios", "exos"))
    return parser.parse_args(arguments[1:])


def help_text():
    return ("NetOps operator imports:\n"
            "  import-snapshot --name NAME < snapshot.cfg\n"
            "  import-policy --name NAME --platform fortios|exos < policy.json\n"
            "Imports are private and create-only; use a new name to change an input.\n")


def _private_directory(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != UIDS["auditor"] or stat.S_IMODE(info.st_mode) != 0o700:
        raise ImportRefused("Auditor input directories require the isolated owner and mode 0700")


def _inputs(directory):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(directory, flags)
    try:
        _private_directory(parent)
        try:
            os.mkdir("inputs", mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        descriptor = os.open("inputs", flags, dir_fd=parent)
        try:
            _private_directory(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(parent)


def _new_name(descriptor, name):
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ImportRefused("Auditor input already exists; use a new name")


def _publish(directory, arguments, stream):
    if os.geteuid() != UIDS["auditor"] or os.getegid() != UIDS["auditor"]:
        raise ImportRefused("Auditor imports require the isolated Auditor UID and GID")
    options = _arguments(arguments)
    if SAFE_NAME.fullmatch(options.name) is None:
        raise ImportRefused("Invalid Auditor input name")
    policy = arguments[0] == "import-policy"
    if policy:
        from netops_auditor.management import MAX_POLICY_BYTES
        limit = MAX_POLICY_BYTES
    else:
        from netops_auditor.collect import MAX_SNAPSHOT_BYTES
        limit = MAX_SNAPSHOT_BYTES
    name = options.name + (".policy.json" if policy else ".conf")
    descriptor = _inputs(directory)
    temporary = None
    opened = None
    published = False
    try:
        _new_name(descriptor, name)
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ImportRefused("Auditor input exceeds its supported byte limit")
        try:
            data.decode("utf-8")
        except UnicodeError:
            raise ImportRefused("Auditor input must be valid UTF-8") from None
        candidate = ".import-" + uuid.uuid4().hex
        opened = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=descriptor)
        temporary = candidate
        os.fchmod(opened, 0o600)
        remaining = memoryview(data)
        while remaining:
            count = os.write(opened, remaining)
            if count <= 0:
                raise OSError("No input write progress")
            remaining = remaining[count:]
        os.fsync(opened)
        if policy:
            from netops_auditor.management import load_policy
            try:
                load_policy("/proc/self/fd/" + str(opened), options.platform)
            except (ValueError, UnicodeError):
                raise ImportRefused("Invalid Auditor management policy") from None
        try:
            os.link(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
        except FileExistsError:
            raise ImportRefused("Auditor input already exists; use a new name") from None
        published = True
        os.unlink(temporary, dir_fd=descriptor)
        temporary = None
        os.fsync(descriptor)
        current = os.stat(Path(directory) / "inputs", follow_symlinks=False)
        pinned = os.fstat(descriptor)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise ImportRefused("Auditor input publication is uncertain; its private directory changed")
        return str(Path(directory) / "inputs" / name)
    except OSError:
        if published:
            raise ImportRefused("Auditor input publication is uncertain; inspect its private destination before retrying") from None
        raise ImportRefused("Auditor input could not be stored privately") from None
    finally:
        try:
            if opened is not None:
                os.close(opened)
        finally:
            try:
                if temporary is not None:
                    try:
                        os.unlink(temporary, dir_fd=descriptor)
                    except FileNotFoundError:
                        pass
            finally:
                os.close(descriptor)


def main(directory, arguments, stream=None):
    try:
        path = _publish(directory, arguments, sys.stdin.buffer if stream is None else stream)
    except ImportRefused as error:
        sys.stderr.write("netops: " + str(error) + OPERATION_SUFFIX)
        return 2
    except (OSError, ValueError):
        sys.stderr.write("netops: Auditor input import failed; inspect its private destination before retrying" + OPERATION_SUFFIX)
        return 2
    print(path)
    return 0
