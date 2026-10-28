from array import array
import hashlib
import sys

CHUNK = 65536

class Content:
    def __init__(self, chunks, total, digest):
        self.chunks, self.total, self.sha256 = tuple(chunks), total, digest
        self.memory_bytes = sys.getsizeof(self) + sys.getsizeof(self.chunks) + sum(map(sys.getsizeof, self.chunks))
    def __repr__(self):
        return '<redacted content bytes=%d sha256=%s>' % (self.total, self.sha256)
    def page(self, offset, limit):
        if offset > self.total:
            raise ValueError('configuration page offset is beyond completed content')
        end = min(self.total, offset + limit)
        first, last = offset // CHUNK, (end - 1) // CHUNK if end > offset else offset // CHUNK
        data = b''.join(self.chunks[first:last+1]) if end > offset else b''
        return data[offset % CHUNK:offset % CHUNK + end - offset].decode('ascii'), end
    def lines(self):
        pending = b''
        for chunk in self.chunks:
            parts = (pending + chunk).split(b'\n')
            pending = parts.pop()
            for line in parts:
                yield line + b'\n'
        if pending:
            yield pending
    def __eq__(self, other):
        return isinstance(other, Content) and (self.total, self.sha256) == (other.total, other.sha256)

class ContentBuilder:
    def __init__(self, maximum, forbidden=()):
        self.maximum, self.total = maximum, 0
        self.buffer, self.chunks = bytearray(), []
        self.stored_bytes = 0
        self.digest = hashlib.sha256()
        self.forbidden = tuple(v.encode() for v in forbidden if v) + (b'-----BEGIN', b'ENC ', b'$6$', b'$9$')
        self.overlap = max(map(len, self.forbidden), default=1) - 1
        self.tail = b''
    @property
    def memory_bytes(self):
        return sys.getsizeof(self.buffer) + sys.getsizeof(self.chunks) + self.stored_bytes
    def add(self, data):
        if isinstance(data, str):
            data = data.encode('ascii')
        self.total += len(data)
        if self.total > self.maximum:
            raise ValueError('redacted configuration exceeds safety cap')
        combined = self.tail + data
        if any(marker in combined for marker in self.forbidden):
            raise ValueError('redaction could not be verified; output withheld')
        self.tail = combined[-self.overlap:] if self.overlap else b''
        self.digest.update(data)
        self.buffer.extend(data)
        while len(self.buffer) >= CHUNK:
            chunk = bytes(self.buffer[:CHUNK])
            self.chunks.append(chunk)
            self.stored_bytes += sys.getsizeof(chunk)
            del self.buffer[:CHUNK]
    def finish(self):
        if self.buffer:
            self.chunks.append(bytes(self.buffer))
        result = Content(self.chunks, self.total, self.digest.hexdigest())
        self.close()
        return result
    def close(self):
        self.buffer.clear()
        self.chunks.clear()
        self.stored_bytes = 0
        self.forbidden, self.tail = (), b''

class HiddenRecords:
    def __init__(self):
        self.data = bytearray()
        self.index = array('I', [0]) * 16
        self.order = hashlib.sha256()
    def __len__(self):
        return len(self.data) // 32
    @property
    def memory_bytes(self):
        return sys.getsizeof(self.data) + sys.getsizeof(self.index) + sys.getsizeof(self)
    def __repr__(self):
        return '<private keyed records count=%d>' % len(self)
    def _slot(self, key, index):
        slot = int.from_bytes(key[:8], 'little') & (len(index)-1)
        while index[slot]:
            offset = (index[slot]-1)*32
            if self.data[offset:offset+16] == key:
                return slot, offset
            slot = (slot+1) & (len(index)-1)
        return slot, None
    def add(self, key, value):
        if (len(self)+1)*10 >= len(self.index)*7:
            grown = array('I', [0]) * (2*len(self.index))
            for i in range(len(self)):
                start = i*32
                slot, unused = self._slot(self.data[start:start+16], grown)
                grown[slot] = i+1
            self.index = grown
        slot, found = self._slot(key, self.index)
        if found is not None:
            raise ValueError('ambiguous configuration record; output withheld')
        self.index[slot] = len(self)+1
        self.data.extend(key)
        self.data.extend(value)
        self.order.update(key)
    def get(self, key):
        unused, found = self._slot(key, self.index)
        return None if found is None else bytes(self.data[found+16:found+32])
    def records(self):
        for i in range(0, len(self.data), 32):
            yield bytes(self.data[i:i+16]), bytes(self.data[i+16:i+32])
    def __iter__(self):
        for key, value in self.records():
            yield 'record:' + key.hex(), value

class ChangedRecords:
    def __init__(self):
        self.data = bytearray()
    def __len__(self):
        return len(self.data)//16
    @property
    def memory_bytes(self):
        return sys.getsizeof(self.data)+sys.getsizeof(self)
    def add(self, key):
        self.data.extend(key)
    def page(self, offset):
        if type(offset) is not int or not 0 <= offset <= len(self):
            raise ValueError('invalid secret change page')
        end = min(len(self), offset+256)
        rows = ['record:'+self.data[i*16:(i+1)*16].hex() for i in range(offset,end)]
        return rows, end if end < len(self) else None

