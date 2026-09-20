#!/usr/bin/env python3
import os
import sys


def main() -> int:
    with open(os.environ["NETOPS_ASKPASS_FILE"], "rb") as handle:
        sys.stdout.buffer.write(handle.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
