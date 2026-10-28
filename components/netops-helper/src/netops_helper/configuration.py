from dataclasses import dataclass
from collections import OrderedDict
import codecs
import sys
from pathlib import Path
from contextlib import contextmanager
from itertools import zip_longest
from .config_buffers import Content, ContentBuilder, HiddenRecords, ChangedRecords
import hashlib
import hmac
import re
import secrets
import shlex
from netops_core import prompt
import threading
import time

_KEY = secrets.token_bytes(32)
_LOCK = threading.RLock()
_SNAPSHOTS = OrderedDict()
_MAX_BYTES = 48000
_BYTE_BUDGET = 512 * 1024 * 1024
_ACTIVE_BUDGET = _BYTE_BUDGET
_CAPTURE_LOCK = threading.Lock()
_DIFFS = OrderedDict()
_TTL = 86400
PROFILE = 'fortios-minimal-4'
SECTIONS = frozenset(('system interface', 'firewall policy', 'firewall address',
                      'router static', 'vpn ipsec phase1-interface'))
_HEADER = re.compile(r'^#(?:config-version|conf_file_ver|buildno|global_vdom)(?:[= :].*)?$')

def _prune():
    now = time.monotonic()
    for key in list(_SNAPSHOTS):
        if now - _SNAPSHOTS[key].created > _TTL:
            del _SNAPSHOTS[key]
    for pair in list(_DIFFS):
        if any(key not in _SNAPSHOTS for key in pair):
            del _DIFFS[pair]

def _budget(staged=0):
    with _LOCK:
        retained = sum(s.memory_bytes for s in _SNAPSHOTS.values())
        retained += sum(t.memory_bytes + c.memory_bytes for t,c,i in _DIFFS.values())
        if retained + staged > min(_BYTE_BUDGET, _ACTIVE_BUDGET):
            raise ValueError('configuration memory budget exhausted; output withheld')

def _available_memory():
    values = []
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                values.append(int(line.split()[1])*1024)
        base = Path('/sys/fs/cgroup')
        limit = (base/'memory.max').read_text().strip()
        if limit != 'max':
            values.append(max(0, int(limit)-int((base/'memory.current').read_text())))
    except (OSError, ValueError):
        pass
    return min(values) if values else 0

@contextmanager
def capture():
    global _ACTIVE_BUDGET
    if not _CAPTURE_LOCK.acquire(blocking=False):
        raise ValueError('another configuration capture or comparison is active')
    try:
        with _LOCK:
            _prune()
        available = _available_memory()
        if available < 64*1024*1024:
            raise ValueError('insufficient memory for configuration capture')
        with _LOCK:
            retained = sum(s.memory_bytes for s in _SNAPSHOTS.values())
            retained += sum(t.memory_bytes+c.memory_bytes for t,c,i in _DIFFS.values())
        _ACTIVE_BUDGET = min(_BYTE_BUDGET, retained + available - 64*1024*1024)
        _budget()
        yield
    finally:
        _ACTIVE_BUDGET = _BYTE_BUDGET
        _CAPTURE_LOCK.release()

def content_digest(text):
    return text.sha256 if isinstance(text, Content) else hashlib.sha256(text.encode()).hexdigest()

def read_command(section, include_all=False):
    if type(include_all) is not bool or not isinstance(section, str):
        raise ValueError('invalid configuration section')
    if section == 'all' and include_all:
        return 'show'
    if section in SECTIONS and not include_all:
        return 'show ' + section
    raise ValueError('invalid configuration section')

@dataclass(frozen=True)
class Snapshot:
    scope: tuple
    text: str
    hidden: tuple
    created: float
    redacted_count: int
    section: str
    firmware: tuple
    profile: str

    @property
    def memory_bytes(self):
        return self.text.memory_bytes + self.hidden.memory_bytes + sys.getsizeof(self) + 1024

def require(auth, platform, permission):
    if platform not in ('fortios', 'fortinet'):
        raise ValueError('config_platform_not_supported')
    if auth.ssh_platform != 'fortinet':
        raise ValueError('configuration platform is outside target policy')
    rights = auth.read_inventory.get('config_access', ())
    if permission not in rights:
        raise ValueError('config access is not enabled for this target')
    auth.require_tcp_port(auth.port)

def require_single_vdom(status):
    from netops_core import platforms
    if (not isinstance(status, str) or len(status.encode()) > 65536 or
            any(ord(c) < 32 and c not in "\n\r\t" for c in status) or
            "\ufffd" in status):
        raise ValueError("configuration identity could not be verified")
    try:
        identity = platforms.version_record(status)
    except platforms.VersionRecordError:
        raise ValueError("configuration identity could not be verified") from None
    version_lines = [line for line in status.splitlines()
                     if line.lstrip().casefold().startswith("version:")]
    if (len(version_lines) != 1 or
            not re.fullmatch(r"(?:FortiGate|FortiWiFi)-[A-Za-z0-9_.+-]+", identity[0])):
        raise ValueError("configuration identity could not be verified")
    markers = [line for line in status.splitlines()
               if " ".join(line.split()).casefold().startswith("virtual domain configuration")]
    if markers != ["Virtual domain configuration: disable"]:
        raise ValueError("config_platform_not_supported: verified single-VDOM mode required")
    return identity

def scope(auth):
    material = '\0'.join((auth.alias, auth.host, str(auth.port), auth.login,
                          auth.host_key_fingerprint, auth.credential_kind, auth.secret))
    return (hmac.digest(_KEY, material.encode(), 'sha256'), 'fortios', 'running')


class StreamRedactor:
    def __init__(self, forbidden, section):
        self.forbidden, self.section = tuple(forbidden), section
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.maximum = (256 if section == 'all' else 64)*1024*1024
        self.result = ContentBuilder(self.maximum, forbidden)
        self.hidden, self.stack, self.path = HiddenRecords(), [], []
        self.logical_bytes = self.physical_bytes = 0
        self.configured = False
        self.started = self.header = self.closed = False
        self.count = self.raw_bytes = 0
        self.physical, self.pending = [], []
        self.quote, self.escaped, self.after_cr = None, False, False
        self.frame_first, self.frame_ended, self.frame_prompt = True, False, None

    def close(self):
        self.closed = True
        self.physical.clear()
        self.pending.clear()
        self.result.close()
        self.hidden = None
        self.stack.clear()
        self.path.clear()
        self.forbidden = ()
        self.decoder = None
        self.frame_prompt = None

    def feed(self, data):
        try:
            if self.closed or not isinstance(data, bytes):
                raise ValueError()
            self.raw_bytes += len(data)
            if self.raw_bytes > self.maximum:
                raise ValueError()
            text = self.decoder.decode(data, final=False)
            if not text:
                return
            if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x85\u2028\u2029\ufffd]', text):
                raise ValueError()
            if self.after_cr and text.startswith('\n'):
                text = text[1:]
            self.after_cr = text.endswith('\r')
            text = text.replace('\r\n','\n').replace('\r','\n')
            parts = text.split('\n')
            for i,part in enumerate(parts):
                self.physical_bytes += len(part.encode())
                if self.physical_bytes > 65536:
                    raise ValueError()
                self.physical.append(part)
                if i < len(parts)-1:
                    self._line()
        except Exception:
            self.close()
            raise ValueError('redaction could not be verified; output withheld') from None

    def _line(self):
        line = ''.join(self.physical)
        self.physical.clear()
        self.physical_bytes = 0
        if self.frame_first:
            self.frame_first = False
            found = prompt.prefix('fortinet').match(line)
            if found:
                self.frame_prompt = found.group(1).rstrip()
                line = line[len(found.group(1)):]
        if self.quote is None and self.frame_prompt and line.rstrip() == self.frame_prompt:
            if self.stack or self.pending or not self.configured:
                raise ValueError('redaction could not be verified; output withheld')
            self.frame_ended = True
            return
        if self.frame_ended and line.strip():
            raise ValueError('redaction could not be verified; output withheld')
        if len(line.encode()) > 65536:
            raise ValueError()
        self.logical_bytes += len(line.encode()) + 1
        if self.logical_bytes > 1024*1024:
            raise ValueError()
        self.pending.append(line)
        skip = -1
        for match in re.finditer(r"[\\'\"]", line):
            index, char = match.start(), match.group()
            if index == skip:
                skip = -1
                continue
            if char == chr(92) and self.quote != "'":
                skip = index+1
            elif self.quote:
                if char == self.quote:
                    self.quote = None
            elif char in ('"', "'"):
                self.quote = char
        if skip == len(line):
            raise ValueError()
        if self.quote is None:
            logical = '\n'.join(self.pending)
            self.pending.clear()
            self.logical_bytes = 0
            if '--More--' in logical:
                raise ValueError()
            self._record(logical)

    def _record(self, line):
        result, hidden, stack, path = self.result, self.hidden, self.stack, self.path
        section = self.section
        if not line.strip():
            return
        if line.lstrip().startswith('#'):
            if self.started or '\n' in line or not _HEADER.fullmatch(line.strip()):
                raise ValueError('redaction could not be verified; output withheld')
            if not self.header:
                result.add('# configuration\n')
                self.header = True
            return
        self.started = True
        try:
            ordinary_set = re.fullmatch(r'[ \t]*set[ \t]+([a-z][a-z0-9-]*)[ \t]+(.+)', line, re.S)
            if ordinary_set and ordinary_set.group(1) != 'status' and ordinary_set.group(2).strip():
                words = ['set', ordinary_set.group(1), '<private-value>']
            else:
                words = shlex.split(line, comments=False, posix=True)
        except ValueError:
            raise ValueError('redaction could not be verified; output withheld') from None
        command = words[0]
        clean = None
        if command == 'config' and len(words) >= 2 and all(
                re.fullmatch('[a-z][a-z0-9-]*', w) for w in words[1:]):
            if words[1:] == ['vdom']:
                raise ValueError('config_platform_not_supported: VDOM configuration refused')
            if not stack and section != 'all' and ' '.join(words[1:]) != section:
                raise ValueError('configuration section scope mismatch; output withheld')
            self.configured = True
            stack.append('config')
            path.append(b'config\0' + ' '.join(words[1:]).encode())
            clean = ' '.join(words)
        elif command == 'edit' and len(words) == 2 and stack and stack[-1] == 'config':
            stack.append('edit')
            path.append(b'edit\0' + hmac.digest(_KEY, words[1].encode(), 'sha256'))
            clean = 'edit <REDACTED>'
        elif command == 'next' and len(words) == 1 and stack and stack[-1] == 'edit':
            stack.pop()
            path.pop()
            clean = 'next'
        elif command == 'end' and len(words) == 1 and stack and stack[-1] == 'config':
            stack.pop()
            path.pop()
            clean = 'end'
        elif command in ('set', 'unset') and len(words) >= 2 and stack and re.fullmatch(
                '[a-z][a-z0-9-]*', words[1]):
            if command == 'unset' and len(words) == 2:
                clean = 'unset ' + words[1]
            elif command == 'set' and len(words) >= 3:
                if words[1] == 'status' and len(words) == 3 and words[2] in ('up', 'down'):
                    clean = 'set status ' + words[2]
                else:
                    clean = 'set ' + words[1] + ' <REDACTED>'
        if clean is None:
            raise ValueError('redaction could not be verified; output withheld')
        if '<REDACTED>' in clean:
            self.count += 1
            components = path + [command.encode(), words[1].encode() if command == 'set' else b'']
            material = b''.join(len(part).to_bytes(4, 'big') + part for part in components)
            location = hmac.digest(_KEY, material, 'sha256')[:16]
            hidden.add(location, hmac.digest(_KEY, line.encode(), 'sha256')[:16])
        result.add(('    ' + clean if command in ('set', 'unset') else clean) + '\n')
        if self.count % 1024 == 0:
            _budget(result.memory_bytes + hidden.memory_bytes + 2*1024*1024)
            if _available_memory() < 32*1024*1024:
                raise ValueError('configuration memory exhausted')

    def finish(self):
        try:
            if self.closed or not self.raw_bytes:
                raise ValueError()
            self.decoder.decode(b'', final=True)
            if self.physical:
                self._line()
            if self.pending or self.quote is not None:
                raise ValueError()
            return self._finished()
        except Exception:
            raise ValueError('redaction could not be verified; output withheld') from None
        finally:
            self.close()

    def _finished(self):
        if self.stack or not self.configured:
            raise ValueError('redaction could not be verified; output withheld')
        _budget(self.result.memory_bytes + self.hidden.memory_bytes)
        return self.result.finish(), self.hidden, self.count

def redact(raw, forbidden, section):
    if not isinstance(raw, str):
        raise ValueError('redaction could not be verified; output withheld')
    capture = StreamRedactor(forbidden, section)
    try:
        capture.feed(raw.encode())
        return capture.finish()
    finally:
        capture.close()

def store(auth, text, hidden, count, section, firmware):
    now = time.monotonic()
    target = scope(auth)
    with _LOCK:
        for key in list(_SNAPSHOTS):
            if now - _SNAPSHOTS[key].created > _TTL:
                del _SNAPSHOTS[key]
        same = [key for key, value in _SNAPSHOTS.items() if value.scope == target]
        while len(same) >= 4:
            del _SNAPSHOTS[same.pop(0)]
        while len(_SNAPSHOTS) >= 16:
            _SNAPSHOTS.popitem(last=False)
        identity = 'cfg_' + secrets.token_hex(16)
        while identity in _SNAPSHOTS:
            identity = 'cfg_' + secrets.token_hex(16)
        _prune()
        _budget(text.memory_bytes + hidden.memory_bytes + 1024)
        _SNAPSHOTS[identity] = Snapshot(target, text, hidden, now, count, section, tuple(firmware), PROFILE)
    return identity

def compare(auth, base, other):
    if not all(isinstance(i, str) and re.fullmatch('cfg_[0-9a-f]{32}', i) for i in (base, other)):
        raise ValueError('configuration snapshot not found or expired')
    with _LOCK:
        _prune()
        pair = [_SNAPSHOTS.get(i) for i in (base, other)]
        if any(s is None for s in pair):
            raise ValueError('configuration snapshot not found or expired')
        if any(s.scope != scope(auth) for s in pair):
            raise ValueError('configuration snapshot scope mismatch')
    left, right = pair
    if (left.section, left.firmware, left.profile) != (right.section, right.firmware, right.profile):
        raise ValueError('configuration snapshot section, firmware or profile mismatch')
    if (base,other) in _DIFFS:
        return _DIFFS[base,other]
    changed = ChangedRecords()
    for key, value in left.hidden.records():
        if right.hidden.get(key) != value:
            changed.add(key)
    for key, value in right.hidden.records():
        if left.hidden.get(key) is None:
            changed.add(key)
    out = ContentBuilder(512*1024*1024)
    equal = left.text == right.text
    order_changed = left.hidden.order.digest() != right.hidden.order.digest()
    if not equal:
        wrote = False
        for before,after in zip_longest(left.text.lines(), right.text.lines()):
            if before == after:
                continue
            if not wrote:
                out.add(b'--- base\n+++ other\n')
                wrote = True
            if before is not None:
                out.add(b'-'+before)
            if after is not None:
                out.add(b'+'+after)
            _budget(out.memory_bytes + changed.memory_bytes)
    elif order_changed:
        out.add('record order changed\n')
    value = out.finish(), changed, equal and not len(changed) and not order_changed
    _budget(value[0].memory_bytes + changed.memory_bytes)
    with _LOCK:
        _DIFFS[base,other] = value
    return value

def page_arguments(offset, limit):
    if type(offset) is not int or not 0 <= offset <= 1073741824 or type(limit) is not int or not 1 <= limit <= 48000:
        raise ValueError('invalid configuration page')
    return offset, limit

def get_snapshot(auth, identity, section):
    if not isinstance(identity, str) or not re.fullmatch('cfg_[0-9a-f]{32}', identity):
        raise ValueError('configuration snapshot not found or expired')
    with _LOCK:
        value = _SNAPSHOTS.get(identity)
        if value is None or time.monotonic() - value.created > _TTL:
            raise ValueError('configuration snapshot not found or expired')
        if value.scope != scope(auth) or value.section != section or value.profile != PROFILE:
            raise ValueError('configuration snapshot scope mismatch')
        return value

def payload(text, offset=0, limit=48000):
    page_arguments(offset, limit)
    if isinstance(text, Content):
        page, end = text.page(offset, limit)
        total, sha = text.total, text.sha256
    else:
        data = text.encode()
        if offset > len(data):
            raise ValueError('configuration page offset is beyond completed content')
        end = min(len(data), offset + limit)
        page = data[offset:end].decode('utf-8')
        total, sha = len(data), hashlib.sha256(data).hexdigest()
    return {'untrusted_device_output': page, 'content_sha256': sha,
            'total_bytes': total, 'returned_bytes': end-offset,
            'offset': offset, 'next_offset': end if end < total else None}
