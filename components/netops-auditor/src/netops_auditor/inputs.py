from __future__ import annotations

import os
import stat


class InputError(Exception):
    pass


def read_regular(path, limit: int, follow: bool = True) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (0 if follow else os.O_NOFOLLOW)
    try:
        descriptor = os.open(path, flags)
    except ValueError:
        raise InputError("path holds a NUL character") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InputError("not a regular file")
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(descriptor, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    if size > limit:
        raise InputError("larger than %d bytes" % limit)
    return b"".join(chunks)
