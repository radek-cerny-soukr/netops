import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_gate
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import check_release

CAPTURES = ("collector.stdout", "collector.stderr", "result.json")
PUBLIC_FILENAMES = {"redteam.py", "collect_health_bootstrap_trace.py", "health_bootstrap_profile.py"}


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check_captures(directory, token_file, environment=None):
    environment = os.environ if environment is None else environment
    summary = {"schema": "netops-process-profile-upload/1", "upload_allowed": False,
               "reason": "capture-unavailable", "findings": {}, "files": {}}
    parent = None
    handles = {}
    try:
        directory = Path(directory)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        before = os.fstat(parent)
        require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700, "capture-directory")
        require(sorted(os.listdir(parent)) == sorted(CAPTURES), "capture-membership")
        raw = {}
        infos = {}
        for name in CAPTURES:
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            handles[name] = file
            info = os.fstat(file)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "capture-file")
            infos[name] = identity(info)
            with os.fdopen(os.dup(file), "rb") as stream:
                raw[name] = stream.read()
            summary["files"][name] = {"bytes": len(raw[name]), "sha256": hashlib.sha256(raw[name]).hexdigest()}
        result = json.loads(raw["result.json"])
        require(type(result) is dict and set(result) == {"schema", "actual_rc", "timed_out", "timeout_seconds", "outcome", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256", "mcp_token_scan"}, "capture-result")
        require(result["schema"] == "netops-process-profile-collector/1" and
                type(result["timed_out"]) is bool and type(result["timeout_seconds"]) is int and result["timeout_seconds"] == 150, "capture-result")
        completed = type(result["actual_rc"]) is int and not result["timed_out"] and result["outcome"] == "completed"
        incomplete = result["actual_rc"] is None and ((result["timed_out"] and result["outcome"] == "timeout") or (not result["timed_out"] and result["outcome"] == "spawn-error"))
        require(completed or incomplete, "capture-result")
        require(result["mcp_token_scan"] == "PASS", "original-token-scan-refused")
        for key in ("stdout", "stderr"):
            content = raw["collector." + key]
            require(type(result[key + "_bytes"]) is int and result[key + "_bytes"] == len(content) and
                    type(result[key + "_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", result[key + "_sha256"]) and
                    result[key + "_sha256"] == hashlib.sha256(content).hexdigest(), "capture-content-binding")
        token = Path(token_file).read_bytes().removesuffix(b"\n")
        require(re.fullmatch(rb"[A-Za-z0-9_-]{64}", token) is not None, "current-token-unavailable")
        known = [token]
        for name in ("GITHUB_TOKEN", "GHCR_TOKEN", "REGISTRY_TOKEN"):
            value = environment.get(name)
            require(value is None or type(value) is str, "known-token-environment")
            if value:
                known.append(value.encode())
        if environment.get("GITHUB_ACTIONS") == "true":
            require(bool(environment.get("GITHUB_TOKEN")), "known-token-environment")
        require(not any(token in content for token in known for content in raw.values()), "known-token-found")
        markers = report_gate.privacy_rules()
        for name in CAPTURES:
            findings = report_gate.check_file(str(directory / name), markers, PUBLIC_FILENAMES)
            for text in report_gate.all_variants([raw[name].decode("utf-8")], collections.Counter()):
                if check_release._pem_material_errors(name, text):
                    findings["private key material"] = 1
            for kind, count in findings.items():
                summary["findings"][kind] = summary["findings"].get(kind, 0) + count
        for name, file in handles.items():
            require(identity(os.fstat(file)) == infos[name] and
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == infos[name], "capture-changed")
        require(identity(os.fstat(parent)) == identity(before) and
                identity(directory.lstat()) == identity(before) and sorted(os.listdir(parent)) == sorted(CAPTURES), "capture-directory-changed")
        require(not summary["findings"], "public-privacy-findings")
        summary.update(upload_allowed=True, reason="public-privacy-checked")
    except Refused as error:
        summary["reason"] = error.args[0]
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        summary["reason"] = "capture-unreadable-or-malformed"
    finally:
        for file in handles.values():
            os.close(file)
        if parent is not None:
            os.close(parent)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    summary = check_captures(args.directory, args.token_file)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["upload_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
