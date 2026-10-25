import base64
import binascii
from datetime import datetime, timedelta
import hashlib
import json
import re
from .files import MAX_MESSAGE

SCHEMA = "netops-syslog-part/1"
CHUNK_BYTES = 1024
MAX_PARTS = 8192
MAX_RECORD_BYTES = MAX_MESSAGE * 2
MAX_MESSAGE_BYTES = 2048
FIELDS = {"schema", "record_id", "part", "parts", "sha256", "data_b64"}
ID = re.compile(r"[0-9a-f]{32}")
SHA = re.compile(r"[0-9a-f]{64}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00")

class ReassemblyError(ValueError):
    def __init__(self, line_number, message, end=False):
        self.line_number = line_number
        self.end = end
        location = "archive end after line " if end else "line "
        super().__init__(location + str(line_number) + ": " + message)

class ReassemblyWarning:
    def __init__(self, code, line_number):
        self.code = code
        self.line_number = line_number

class _Object(list):
    pass

def _id(record_id):
    if type(record_id) is not str or ID.fullmatch(record_id) is None:
        raise ValueError("An explicit lowercase 32-hex record ID is required")

def _constant(value):
    raise ValueError("Nonfinite JSON constants are unsupported")

def _header(timestamp):
    if type(timestamp) is not str or STAMP.fullmatch(timestamp) is None:
        raise ValueError("A fixed UTC timestamp with six fractional digits is required")
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        raise ValueError("Invalid UTC timestamp") from None
    if moment.utcoffset() != timedelta(0):
        raise ValueError("Invalid UTC timestamp")
    header = b"<134>1 " + timestamp.encode("ascii") + b" - netops - - - "
    if len(header) != 55:
        raise ValueError("Unsupported syslog header length")
    return header

def encode_messages(raw_record, record_id, timestamp):
    _id(record_id)
    if type(raw_record) is not bytes or not 1 <= len(raw_record) <= MAX_RECORD_BYTES:
        raise ValueError("Audit record exceeds its supported byte limit")
    header = _header(timestamp)
    digest = hashlib.sha256(raw_record).hexdigest()
    parts = (len(raw_record) + CHUNK_BYTES - 1) // CHUNK_BYTES
    for part in range(parts):
        chunk = raw_record[part * CHUNK_BYTES:(part + 1) * CHUNK_BYTES]
        row = {"schema": SCHEMA, "record_id": record_id, "part": part, "parts": parts,
               "sha256": digest, "data_b64": base64.b64encode(chunk).decode("ascii")}
        message = header + json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(message) > MAX_MESSAGE_BYTES:
            raise ValueError("Encoded syslog message exceeds 2048 bytes")
        yield message

def frame_message(message):
    if type(message) is not bytes or not 1 <= len(message) <= MAX_MESSAGE_BYTES:
        raise ValueError("Syslog message must contain 1 to 2048 bytes")
    return str(len(message)).encode("ascii") + b" " + message

def _compact(raw):
    quoted = escaped = False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in b" \t\r\n":
            return False
    return True

def _selected(raw, record_id):
    if type(raw) is not bytes:
        raise ValueError("MSG archive members must be bytes")
    try:
        row = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_Object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid or unattributable MSG JSON") from None
    if not isinstance(row, _Object):
        raise ValueError("MSG must be a JSON object with one record_id")
    identifiers = [value for key, value in row if key == "record_id"]
    if len(identifiers) != 1 or type(identifiers[0]) is not str:
        raise ValueError("MSG has a missing, ambiguous or non-string record_id")
    if identifiers[0] != record_id:
        return None
    try:
        raw.decode("ascii", "strict")
    except UnicodeError:
        raise ValueError("Selected MSG must be ASCII") from None
    if len(raw) > MAX_MESSAGE_BYTES or not _compact(raw):
        raise ValueError("Selected MSG must use bounded compact ASCII JSON")
    if len(row) != len(FIELDS) or {key for key, value in row} != FIELDS:
        raise ValueError("Selected MSG has duplicate, missing or unknown fields")
    row = dict(row)
    if row["schema"] != SCHEMA or type(row["schema"]) is not str:
        raise ValueError("Unsupported selected MSG schema")
    if type(row["part"]) is not int or type(row["parts"]) is not int or not 1 <= row["parts"] <= MAX_PARTS or not 0 <= row["part"] < row["parts"]:
        raise ValueError("Invalid selected part number or total")
    if type(row["sha256"]) is not str or SHA.fullmatch(row["sha256"]) is None or type(row["data_b64"]) is not str:
        raise ValueError("Invalid selected SHA or base64 field")
    try:
        chunk = base64.b64decode(row["data_b64"], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid selected base64") from None
    if base64.b64encode(chunk).decode("ascii") != row["data_b64"]:
        raise ValueError("Noncanonical selected base64")
    final = row["part"] == row["parts"] - 1
    if (not final and len(chunk) != CHUNK_BYTES) or (final and not 1 <= len(chunk) <= CHUNK_BYTES):
        raise ValueError("Invalid selected raw part length")
    return row, chunk

def decode_messages(messages, record_id, *, on_warning=None):
    _id(record_id)
    selected = {}
    identity = None
    completed = None
    last_line = 0
    for line_number, raw in enumerate(messages, 1):
        last_line = line_number
        warning = None
        try:
            parsed = _selected(raw, record_id)
        except ValueError as error:
            if completed is None:
                raise ReassemblyError(line_number, str(error)) from None
            warning = "late_invalid"
        else:
            if parsed is None:
                continue
            row, chunk = parsed
            current = row["parts"], row["sha256"]
            previous = selected.get(row["part"])
            if completed is not None:
                if current != identity or previous != (row, chunk):
                    warning = "late_conflict"
            else:
                if identity is None:
                    identity = current
                elif current != identity:
                    raise ReassemblyError(line_number, "Conflicting selected record metadata")
                if previous is not None and previous != (row, chunk):
                    raise ReassemblyError(line_number, "Conflicting selected duplicate part")
                selected[row["part"]] = row, chunk
                if len(selected) == identity[0]:
                    original = b"".join(selected[part][1] for part in range(identity[0]))
                    if not 1 <= len(original) <= MAX_RECORD_BYTES or hashlib.sha256(original).hexdigest() != identity[1]:
                        raise ReassemblyError(line_number, "Selected record length or whole SHA does not match")
                    completed = original
        if warning is not None and on_warning is not None:
            on_warning(ReassemblyWarning(warning, line_number))
    if completed is None:
        raise ReassemblyError(last_line, "Selected record is missing or incomplete", end=True)
    return completed
