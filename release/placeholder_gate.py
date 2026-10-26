#!/usr/bin/env python3
import argparse
import os
import re
import sys

PLACEHOLDER = re.compile(r"TODO\(([^)\s]{0,64})\)?")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SKIPPED = {".git", "node_modules"}
ARCHIVE = os.path.join("docs", "archive")


def markdown_files(root):
    for directory, names, files in os.walk(root):
        relative = os.path.relpath(directory, root)
        names[:] = sorted(name for name in names if name not in SKIPPED and os.path.join(relative, name) != ARCHIVE)
        for name in sorted(files):
            if name.endswith(".md"):
                yield os.path.normpath(os.path.join(relative, name))


def check(root, version, candidate=False):
    errors = []
    pending = []
    undated = "## %s - TODO(release-date)" % version
    notes = os.path.join("release", "notes-%s.md" % version)
    if not os.path.isfile(os.path.join(root, notes)):
        errors.append("%s is missing" % notes)
    try:
        with open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8") as stream:
            changelog = stream.read()
    except OSError:
        changelog = ""
    if not re.search(r"(?m)^## %s - [0-9]{4}-[0-9]{2}-[0-9]{2}$" % re.escape(version), changelog) and not (candidate and re.search(r"(?m)^%s$" % re.escape(undated), changelog)):
        errors.append("CHANGELOG.md has no dated section ## %s - YYYY-MM-DD" % version)
    for relative in markdown_files(root):
        with open(os.path.join(root, relative), encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                for match in PLACEHOLDER.finditer(line):
                    if candidate and (match.group(0) == "TODO(acceptance-%s)" % version or (relative == "CHANGELOG.md" and line.rstrip("\n") == undated)):
                        pending.append("%s:%d: %s" % (relative, number, match.group(0)))
                    else:
                        errors.append("%s:%d: open placeholder TODO(%s)" % (relative, number, match.group(1)))
    return errors, pending


def main():
    parser = argparse.ArgumentParser(description="Refuse a release whose public Markdown still carries TODO( placeholders or whose notes and dated changelog section are missing")
    parser.add_argument("--version", required=True)
    parser.add_argument("--candidate", action="store_true", help="allow TODO(acceptance-X.Y.Z) and the changelog heading ## X.Y.Z - TODO(release-date), which are filled after the acceptance of the candidate")
    parser.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    args = parser.parse_args()
    if not VERSION.fullmatch(args.version):
        parser.error("--version must be X.Y.Z")
    errors, pending = check(os.path.abspath(args.root), args.version, args.candidate)
    for item in pending:
        print("PENDING " + item)
    for error in errors:
        print("FAIL " + error)
    print("placeholder_gate=%s" % ("FAIL" if errors else "PASS"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
