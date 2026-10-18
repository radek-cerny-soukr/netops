"""Seal only the fixed private collector capture; never decrypt on a runner."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tarfile
import urllib.request

VERSION = "v1.3.2"
ARCHIVES = {
    "amd64": "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10",
    "arm64": "6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4",
}
BINARIES = {
    "amd64": ("eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c", 6977014),
    "arm64": ("41b072352f4561018949623c674d16ef704019b9108a9bbdbd21292efebfc94f", 6540637),
}
MACHINES = {"x86_64": "amd64", "aarch64": "arm64"}
RUNNERS = {"X64": "amd64", "ARM64": "arm64"}
RECIPIENT_FILE_SHA256 = "b730517b3ccd09f786bb9316599008cac77b0789afba0d74280f924e9d5469c6"
RECIPIENT_FINGERPRINTS = (
    "fb7d5fcf5627a696662d6228c12f517b9cb0c41876d8aa70f50af7705c88ae9a",
    "52c35077afa7a92e9c0b10b7585e74ae580a2f0976bd910da754835cb7091227",
    "ee1fdbcebaed7dc49bda9d96aded57d5bdc76e2f7e8809fe7e536e351646e459",
)
CAPTURES = ("collector.stdout", "collector.stderr", "result.json")
TOOL_FILES = ("age", "archive.tar.gz", "install.json", "version.stdout", "version.stderr", "version.json")


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def create(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    require(stat.S_IMODE(path.lstat().st_mode) == mode, "created-mode")


def snapshot(directory, names, executable=()):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    raw, facts = {}, {}
    try:
        before = os.fstat(fd)
        require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700, "directory")
        require(set(os.listdir(fd)) == set(names), "membership")
        for name in names:
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(file, "rb") as stream:
                first = os.fstat(stream.fileno())
                require(stat.S_ISREG(first.st_mode) and first.st_uid == os.getuid() and first.st_nlink == 1
                        and stat.S_IMODE(first.st_mode) == (0o700 if name in executable else 0o600), "file")
                raw[name] = stream.read()
                require(identity(os.fstat(stream.fileno())) == identity(first)
                        == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), "file-changed")
                facts[name] = identity(first)
        require(identity(os.fstat(fd)) == identity(before) == identity(directory.lstat())
                and set(os.listdir(fd)) == set(names), "directory-changed")
        return raw, (identity(before), facts)
    finally:
        os.close(fd)


def recipient_bytes():
    path = Path(__file__).with_name("process_profile_recipients.txt")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022, "recipients-file")
        data = stream.read()
        require(identity(os.fstat(stream.fileno())) == identity(before) == identity(path.lstat()), "recipients-changed")
    require(sha(data) == RECIPIENT_FILE_SHA256, "recipients-pin")
    lines = data.decode("ascii").splitlines()
    require(len(lines) == 3 and len(set(lines)) == 3
            and all(re.fullmatch(r"age1[0-9a-z]{58}", line) for line in lines)
            and tuple(sha(line.encode()) for line in lines) == RECIPIENT_FINGERPRINTS, "recipient-set")
    return data


def execute(command, private, label, *, data=None, output=None, pass_fds=()):
    try:
        done = subprocess.run(command, input=data, stdin=subprocess.DEVNULL if data is None else None,
                              stdout=subprocess.PIPE if output is None else output, stderr=subprocess.PIPE,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, pass_fds=pass_fds, timeout=150)
        stdout, stderr, rc, timed_out = done.stdout or b"", done.stderr, done.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, rc, timed_out = error.stdout or b"", error.stderr or b"", None, True
    except OSError:
        stdout, stderr, rc, timed_out = b"", b"", None, False
    if output is None:
        create(private / (label + ".stdout"), stdout)
    create(private / (label + ".stderr"), stderr)
    create(private / (label + ".json"), (json.dumps({"actual_rc": rc, "timed_out": timed_out}) + "\n").encode())
    require(not timed_out and type(rc) is int and rc == 0, "age-child")
    return stdout


def archive_binary(data, arch):
    require(sha(data) == ARCHIVES[arch], "archive-pin")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == 9 and len({m.name for m in members}) == 9, "archive-members")
        selected = [m for m in members if m.name == "age/age"]
        require(len(selected) == 1 and selected[0].isfile(), "archive-member")
        binary = archive.extractfile(selected[0]).read()
    require((sha(binary), len(binary)) == BINARIES[arch], "binary-pin")
    require(binary[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(binary[18:20], "little") == {"amd64": 62, "arm64": 183}[arch], "binary-architecture")
    return binary


def install(directory, arch, archive=None):
    require(arch in ARCHIVES and MACHINES.get(platform.machine()) == arch, "host-architecture")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require(os.environ.get("RUNNER_OS") == "Linux" and RUNNERS.get(os.environ.get("RUNNER_ARCH")) == arch, "runner-architecture")
    directory.mkdir(mode=0o700)
    if archive is None:
        url = "https://github.com/FiloSottile/age/releases/download/" + VERSION + "/age-" + VERSION + "-linux-" + arch + ".tar.gz"
        with urllib.request.urlopen(url, timeout=30) as source:
            archive = source.read(32 * 1024 * 1024 + 1)
        require(len(archive) <= 32 * 1024 * 1024, "archive-size")
    binary = archive_binary(archive, arch)
    create(directory / "archive.tar.gz", archive)
    create(directory / "age", binary, 0o700)
    
    stdout = execute([str(directory / "age"), "--version"], directory, "version")
    require(stdout == (VERSION + "\n").encode() and (directory / "version.stderr").read_bytes() == b"", "age-version")
    version_call = json.loads((directory / "version.json").read_bytes())
    require(type(version_call) is dict and set(version_call) == {"actual_rc", "timed_out"}
            and type(version_call["actual_rc"]) is int and version_call["actual_rc"] == 0
            and version_call["timed_out"] is False, "age-version")
    create(directory / "install.json", (json.dumps({"schema": "netops-age-install/1", "arch": arch,
           "archive_sha256": ARCHIVES[arch], "age_sha256": sha(binary), "age_bytes": len(binary),
           "version": VERSION}) + "\n").encode())
    snapshot(directory, TOOL_FILES, ("age",))


def validated_capture(raw):
    result = json.loads(raw["result.json"])
    require(type(result) is dict and set(result) == {"schema", "actual_rc", "timed_out", "timeout_seconds", "outcome",
            "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256", "mcp_token_scan"}, "capture-result")
    require(result["schema"] == "netops-process-profile-collector/1" and type(result["timed_out"]) is bool
            and type(result["timeout_seconds"]) is int and result["timeout_seconds"] == 150, "capture-result")
    completed = type(result["actual_rc"]) is int and not result["timed_out"] and result["outcome"] == "completed"
    incomplete = result["actual_rc"] is None and ((result["timed_out"] and result["outcome"] == "timeout")
                  or (not result["timed_out"] and result["outcome"] == "spawn-error"))
    require(completed or incomplete, "capture-result")
    require(result["mcp_token_scan"] in ("PASS", "FAIL", "UNKNOWN"), "capture-result")
    for name in ("stdout", "stderr"):
        content = raw["collector." + name]
        require(type(result[name + "_bytes"]) is int and result[name + "_bytes"] == len(content)
                and type(result[name + "_sha256"]) is str and result[name + "_sha256"] == sha(content), "capture-binding")


def seal(directory, age_directory):
    require(directory.name == "process-profile-collector" and "reports" not in directory.resolve().parts, "capture-path")
    raw, binding = snapshot(directory, CAPTURES)
    validated_capture(raw)
    recipients = recipient_bytes()
    tools, tool_binding = snapshot(age_directory, TOOL_FILES, ("age",))
    tool = json.loads(tools["install.json"])
    require(type(tool) is dict and set(tool) == {"schema", "arch", "archive_sha256", "age_sha256", "age_bytes", "version"}
            and tool["schema"] == "netops-age-install/1" and type(tool["arch"]) is str and tool["arch"] in ARCHIVES
            and tool["version"] == VERSION and MACHINES.get(platform.machine()) == tool["arch"], "tool-receipt")
    binary = archive_binary(tools["archive.tar.gz"], tool["arch"])
    require(tools["age"] == binary and tool["archive_sha256"] == ARCHIVES[tool["arch"]]
            and tool["age_sha256"] == sha(binary) and type(tool["age_bytes"]) is int and tool["age_bytes"] == len(binary)
            and tools["version.stdout"] == (VERSION + "\n").encode() and tools["version.stderr"] == b"", "tool-binding")
    version_call = json.loads(tools["version.json"])
    require(type(version_call) is dict and set(version_call) == {"actual_rc", "timed_out"}
            and type(version_call["actual_rc"]) is int and version_call["actual_rc"] == 0
            and version_call["timed_out"] is False, "tool-binding")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in CAPTURES:
            member = tarfile.TarInfo(name); member.size = len(raw[name]); member.mode = 0o600
            archive.addfile(member, io.BytesIO(raw[name]))
    private = directory.with_name("process-profile-seal-private")
    private.mkdir(mode=0o700)
    create(private / "recipients.txt", recipients)
    output = directory.with_name("process-profile-sealed")
    output.mkdir(mode=0o700)
    fd = os.open(age_directory / "age", os.O_RDONLY | os.O_NOFOLLOW)
    recipient_fd = os.open(private / "recipients.txt", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        recipient_identity = identity(os.fstat(recipient_fd))
        with os.fdopen(os.dup(recipient_fd), "rb") as stream:
            require(stream.read() == recipients, "recipients-changed")
        os.lseek(recipient_fd, 0, os.SEEK_SET)
        require(identity(os.fstat(fd)) == tool_binding[1]["age"], "tool-changed")
        cipher = output / "collector.tar.age"
        out = os.open(cipher, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, "w+b") as stream:
            execute(["/proc/self/fd/" + str(fd), "--encrypt", "--recipients-file", "/proc/self/fd/" + str(recipient_fd)],
                    private, "encrypt", data=buffer.getvalue(), output=stream, pass_fds=(fd, recipient_fd))
            cipher_identity = identity(os.fstat(stream.fileno()))
            stream.seek(0)
            ciphertext = stream.read()
            require(identity(os.fstat(stream.fileno())) == cipher_identity == identity(cipher.lstat()), "ciphertext-changed")
        require(identity(os.fstat(fd)) == tool_binding[1]["age"], "tool-changed")
        require(identity(os.fstat(recipient_fd)) == recipient_identity
                == identity((private / "recipients.txt").lstat()), "recipients-changed")
    finally:
        os.close(recipient_fd)
        os.close(fd)
    require(recipient_bytes() == recipients, "recipients-changed")
    require(snapshot(directory, CAPTURES) == (raw, binding)
            and snapshot(age_directory, TOOL_FILES, ("age",)) == (tools, tool_binding), "input-changed")
    require(ciphertext.startswith(b"age-encryption.org/v1\n") and len(ciphertext) > 100, "ciphertext")
    metadata = {"schema": "netops-process-profile-sealed/1", "age_version": VERSION,
                "sealer_sha256": sha(Path(__file__).read_bytes()), "recipient_file_sha256": RECIPIENT_FILE_SHA256,
                "ciphertext_bytes": len(ciphertext), "ciphertext_sha256": sha(ciphertext)}
    create(output / "sealed.json", (json.dumps(metadata, sort_keys=True) + "\n").encode())
    final, _ = snapshot(output, ("collector.tar.age", "sealed.json"))
    require(final["collector.tar.age"] == ciphertext and json.loads(final["sealed.json"]) == metadata, "sealed-output")
    return metadata


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--install-dir", type=Path)
    choice.add_argument("--directory", type=Path)
    parser.add_argument("--arch", choices=tuple(ARCHIVES))
    parser.add_argument("--age-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.install_dir is not None:
            require(args.arch is not None and args.age_dir is None, "arguments")
            install(args.install_dir.absolute(), args.arch)
            result = {"schema": "netops-age-install-status/1", "installed": True}
        else:
            require(args.age_dir is not None and args.arch is None, "arguments")
            result = seal(args.directory.absolute(), args.age_dir.absolute())
        print(json.dumps(result, sort_keys=True))
        return 0
    except Refused:
        print(json.dumps({"schema": "netops-process-profile-seal-status/1", "sealed": False, "reason": "seal-refused"}))
    except (OSError, ValueError, TypeError, KeyError, OverflowError, tarfile.TarError):
        print(json.dumps({"schema": "netops-process-profile-seal-status/1", "sealed": False, "reason": "seal-unavailable"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
