#!/usr/bin/env python3
import os
import stat
import sys

SECRET_FILE_ENV = "NETOPS_ASKPASS_FILE"
MAX_SECRET_BYTES = 1024 * 1024


class Refused(Exception):
    pass


def _secret(path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except ValueError:
        raise Refused("%s holds a NUL character" % SECRET_FILE_ENV) from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise Refused("the secret file is not a regular file")
        chunks, size = [], 0
        while size <= MAX_SECRET_BYTES:
            chunk = os.read(descriptor, MAX_SECRET_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    if size > MAX_SECRET_BYTES:
        raise Refused("the secret file is larger than %d bytes" % MAX_SECRET_BYTES)
    return b"".join(chunks)


def main() -> int:
    try:
        path = os.environ.get(SECRET_FILE_ENV)
        if not path:
            raise Refused("%s does not name the secret file" % SECRET_FILE_ENV)
        try:
            data = _secret(path)
        except OSError as error:
            raise Refused("cannot read the secret file: %s" % (error.strerror or type(error).__name__)) from None
    except Refused as refusal:
        sys.stderr.write("netops-askpass: %s\n" % refusal)
        return 1
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
