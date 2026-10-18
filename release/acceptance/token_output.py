import argparse
import json
from pathlib import Path
import re


def check_output_files(token_file, output_files, allow_empty=()):
    try:
        raw = Path(token_file).read_bytes()
    except OSError:
        return False, "Token file could not be read"
    token = raw.removesuffix(b"\n")
    if re.fullmatch(rb"[A-Za-z0-9_-]{64}", token) is None:
        return False, "Token file malformed"
    if not output_files:
        return False, "No captured outputs provided"
    try:
        outputs = [Path(name).resolve() for name in output_files]
        allowed = [Path(name).resolve() for name in allow_empty]
    except (OSError, RuntimeError):
        return False, "Captured output path could not be resolved"
    if len(allowed) > 1 or any(name not in outputs for name in allowed):
        return False, "Empty-output allowance must name one captured output"
    empty_allowed = 0
    for name in outputs:
        try:
            content = Path(name).read_bytes()
        except OSError:
            return False, "Captured output could not be read"
        if not content:
            if name not in allowed:
                return False, "Captured output empty"
            empty_allowed += 1
        if token in content:
            return False, "Exact token bytes found in captured output"
    return True, "Exact token bytes absent from all captured outputs; explicitly allowed empty captures: %d" % empty_allowed


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--files", nargs="+", required=True)
    parser.add_argument("--allow-empty-file", action="append", default=[])
    parser.add_argument("--commit")
    parser.add_argument("--image-digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    passed, detail = check_output_files(args.token_file, args.files, args.allow_empty_file)
    status = "PASS" if passed else "FAIL"
    report = {"schema": "netops-acceptance-token-output/1",
              "summary": {status: 1},
              "checks": [{"check": "token-output-bytes", "spec": "F14",
                          "status": status, "detail": detail}]}
    if args.commit:
        report["candidate_commit"] = args.commit
    if args.image_digest:
        report["candidate_image"] = args.image_digest
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
