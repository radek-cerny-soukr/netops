import base64
from datetime import datetime, timedelta
import importlib
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from netops.audit import Audit
from netops.files import MAX_MESSAGE, read_private, write_private

RID = "0123456789abcdef0123456789abcdef"
STAMP = "2026-10-24T12:34:56.123456+00:00"
HEADER = b"<134>1 " + STAMP.encode() + b" - netops - - - "
MARKER = b" - netops - - - "
PREFIX_PATTERN = rb"<134>1 [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00$"


class Channel:
    def __init__(self, fail_on=None):
        self.writes = []
        self.fail_on = fail_on
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def settimeout(self, value):
        pass
    def wrap_socket(self, raw, server_hostname=None):
        return self
    def sendall(self, data):
        self.writes.append(bytes(data))
        if self.fail_on == len(self.writes):
            raise ConnectionResetError("synthetic reset after possibly delivered part")
    def unwrap(self):
        return None


def wire_messages(writes):
    pending = b"".join(writes)
    result = []
    while pending:
        prefix, separator, rest = pending.partition(b" ")
        if not separator or not re.fullmatch(rb"[1-9][0-9]*", prefix):
            raise RuntimeError("APPARATUS_COUNT_GRAMMAR")
        n = int(prefix)
        if len(rest) < n:
            raise RuntimeError("APPARATUS_TRUNCATED_FRAME")
        result.append(rest[:n])
        pending = rest[n:]
    return result


def envelope(message):
    prefix, marker, body = message.partition(MARKER)
    if not marker or not re.fullmatch(PREFIX_PATTERN, prefix):
        raise RuntimeError("APPARATUS_RFC_HEADER")
    return json.loads(body)


def message(row):
    return HEADER + json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class SyslogPartsT157(unittest.TestCase):

    def assert_actual_headers(self, messages):
        for item in messages:
            prefix, marker, body = item.partition(MARKER)
            self.assertEqual(len(prefix + marker), 55, "T157_ACTUAL_HEADER_LENGTH")
            self.assertEqual(marker, MARKER)
            self.assertRegex(prefix, PREFIX_PATTERN, "T157_ACTUAL_HEADER_GRAMMAR")
            try:
                moment = datetime.fromisoformat(prefix[7:].decode("ascii"))
            except (ValueError, UnicodeError):
                self.fail("T157_ACTUAL_TIMESTAMP_NOT_VALID_UTC")
            self.assertEqual(moment.utcoffset(), timedelta(0))

    def module(self):
        return importlib.import_module("netops.syslog_parts")

    def decode(self, messages, record_id, *, on_warning=None):
        bodies = []
        for item in messages:
            header, marker, body = item.partition(MARKER)
            if not marker or not re.fullmatch(PREFIX_PATTERN, header):
                raise RuntimeError("APPARATUS_REASSEMBLY_HEADER")
            bodies.append(body)
        return self.module().decode_messages(bodies, record_id, on_warning=on_warning)

    def fixture(self, raw=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        audit = Audit(root / "audit", {"mode": "syslog", "host": "receiver.invalid", "port": 6514})
        if raw is None:
            raw = json.dumps({"direction": "response", "correlation": "same-synthetic-record",
                              "payload": {"text": "x" * 8192}}, separators=(",", ":")).encode() + b"\n"
        queued = audit.directory / ("1792843200000000000-" + RID + ".queue")
        write_private(queued, raw)
        return audit, queued, raw

    def send(self, audit, queued, channel):
        with patch("netops.audit.socket.create_connection", return_value=channel), \
             patch("netops.audit.ssl.create_default_context", return_value=channel):
            audit._send(queued)

    def encoded(self, raw=None):
        if raw is None:
            raw = b'{"direction":"response","text":"' + b"x" * 7000 + b'"}\n'
        messages = list(self.module().encode_messages(raw, RID, STAMP))
        if len(messages) < 3:
            raise RuntimeError("APPARATUS_NEEDS_MULTIPART")
        return raw, messages

    def test_actual_sender_bounded_and_exact_reassembly(self):
        audit, queued, raw = self.fixture()
        channel = Channel()
        self.send(audit, queued, channel)
        messages = wire_messages(channel.writes)
        if not messages:
            raise RuntimeError("APPARATUS_EMPTY_CAPTURE")
        self.assertTrue(all(len(m) <= 2048 for m in messages),
                        "T157_ACTUAL_SENDER_OVERSIZE")
        self.assert_actual_headers(messages)
        self.assertEqual(self.decode(messages, RID), raw,
                         "T157_ACTUAL_SENDER_BYTE_REASSEMBLY")
        self.assertFalse(queued.exists(), "T157_COMPLETE_HANDOVER_REMOVES_QUEUE")

    def test_utf8_and_maximum_record_roundtrip(self):
        for raw in [
            ('{"text":"' + "ž🚦" * 3000 + '"}\n').encode("utf-8"),
            b'{"text":"' + b"x" * (MAX_MESSAGE * 2 - 12) + b'"}\n',
        ]:
            audit, queued, original = self.fixture(raw)
            channel = Channel()
            self.send(audit, queued, channel)
            messages = wire_messages(channel.writes)
            self.assertTrue(all(len(m) <= 2048 for m in messages))
            self.assertLessEqual(max(map(len, messages)), 1618, "T157_DECLARED_MESSAGE_BOUND")
            self.assert_actual_headers(messages)
            self.assertEqual(self.decode(messages, RID), original)


    def test_lengths_reject_even_when_full_record_sha_is_valid(self):
        for name, size, lengths in [
            ("short-nonfinal", 1025, [1000, 25]),
            ("empty-final", 1024, [1024, 0]),
            ("same-sha-boundary-shift", 2048, [1000, 1048]),
            ("long-nonfinal", 2049, [1025, 1024]),
        ]:
            with self.subTest(case=name):
                raw = b'{"text":"' + b"x" * (size - 12) + b'"}\n'
                chunks, offset = [], 0
                for length in lengths:
                    chunks.append(raw[offset:offset + length])
                    offset += length
                digest = hashlib.sha256(raw).hexdigest()
                if offset != len(raw) or b"".join(chunks) != raw:
                    raise RuntimeError("APPARATUS_EXACT_LENGTH_MUTATION")
                rows = [message({"schema": "netops-syslog-part/1", "record_id": RID,
                                 "part": i, "parts": len(chunks), "sha256": digest,
                                 "data_b64": base64.b64encode(chunk).decode("ascii")})
                        for i, chunk in enumerate(chunks)]
                if hashlib.sha256(b"".join(base64.b64decode(envelope(item)["data_b64"], validate=True)
                                           for item in rows)).hexdigest() != digest:
                    raise RuntimeError("APPARATUS_FULL_SHA_MUST_REMAIN_VALID")
                with self.assertRaises(ValueError):
                    self.decode(rows, RID)

    def test_unattributable_json_or_duplicate_record_id_fails_entire_selection(self):
        raw, rows = self.encoded()
        body = rows[0].split(MARKER, 1)[1]
        foreign = envelope(rows[0])
        foreign["record_id"] = "f" * 32
        foreign_body = message(foreign).split(MARKER, 1)[1]
        malformed = [
            b"{", b'{"record_id":', b"\xff",
            b'{"record_id":"' + b"f" * 32 + b'",' + body[1:],
            b'{"record_id":"' + RID.encode() + b'",' + foreign_body[1:],
            b'{"record_id":"' + RID.encode() + b'",' + body[1:],
        ]
        for bad in malformed:
            with self.subTest(body_sha=hashlib.sha256(bad).hexdigest()):
                with self.assertRaises(ValueError):
                    self.decode([HEADER + bad] + rows, RID)
                warnings = []
                self.assertEqual(self.decode(rows + [HEADER + bad], RID, on_warning=warnings.append), raw)
                self.assertEqual([(item.code, item.line_number) for item in warnings],
                                 [("late_invalid", len(rows) + 1)])

    def test_part_range_and_explicit_record_id_admission(self):
        raw, rows = self.encoded()
        first = envelope(rows[0])
        for key, value in [("part", first["parts"]), ("part", -1), ("parts", 8193)]:
            bad = dict(first)
            bad[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    self.decode([message(bad)] + rows, RID)
                warnings = []
                self.assertEqual(self.decode(rows + [message(bad)], RID, on_warning=warnings.append), raw)
                self.assertEqual([(item.code, item.line_number) for item in warnings],
                                 [("late_invalid", len(rows) + 1)])
        for bad_id in ["A" * 32, RID[:-1], RID + "0"]:
            with self.subTest(record_id=bad_id):
                with self.assertRaises(ValueError):
                    list(self.module().encode_messages(raw, bad_id, STAMP))
                with self.assertRaises(ValueError):
                    self.decode(rows, bad_id)

    def test_missing_corrupt_conflicting_duplicate_and_wrong_numbers_reject(self):
        raw, rows = self.encoded()
        with self.subTest(case="missing"):
            with self.assertRaises(ValueError):
                self.decode(rows[:-1], RID)
        bad = envelope(rows[0])
        decoded = base64.b64decode(bad["data_b64"], validate=True)
        bad["data_b64"] = base64.b64encode(bytes([decoded[0] ^ 1]) + decoded[1:]).decode()
        for name, mutated in [
            ("corrupt", [message(bad)] + rows[1:]),
            ("conflict-duplicate", [message(bad)] + rows),
            ("duplicate-hides-missing", [rows[0]] + rows[:-1]),
        ]:
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    self.decode(mutated, RID)
        first, second = envelope(rows[0]), envelope(rows[1])
        first["part"], second["part"] = second["part"], first["part"]
        with self.assertRaises(ValueError):
            self.decode([message(first), message(second)] + rows[2:], RID)

    def test_zero_based_indices_and_typed_conflicting_duplicate(self):
        raw, rows = self.encoded()
        parts = [envelope(item) for item in rows]
        self.assertEqual([part["part"] for part in parts], list(range(len(parts))))
        self.assertTrue(all(type(part["part"]) is int and part["parts"] == len(parts) for part in parts))
        conflict = dict(parts[0])
        conflict["part"] = False
        with self.assertRaises(ValueError):
            self.decode([message(conflict)] + rows, RID)
        warnings = []
        self.assertEqual(self.decode(rows + [message(conflict)], RID, on_warning=warnings.append), raw)
        self.assertEqual([(item.code, item.line_number) for item in warnings],
                         [("late_invalid", len(rows) + 1)])

    def test_bad_other_record_does_not_poison_selected_id(self):
        raw, rows = self.encoded()
        other = envelope(rows[0])
        other.update(record_id="f" * 32, part=False, parts="wrong-type", sha256="bad", data_b64="not base64")
        self.assertEqual(self.decode([message(other)] + rows, RID), raw)

    def test_selected_noncompact_or_nonascii_envelope_is_not_silently_deduplicated(self):
        raw, rows = self.encoded()
        body = rows[0].split(MARKER, 1)[1]
        for malformed in (b" " + body, body + b" ", body.replace(b"netops-syslog-part/1", b"netops-syslog-part/\xc3\xa9")):
            with self.subTest(body_sha=hashlib.sha256(malformed).hexdigest()):
                with self.assertRaises(ValueError):
                    self.decode([HEADER + malformed] + rows, RID)
                warnings = []
                self.assertEqual(self.decode(rows + [HEADER + malformed], RID, on_warning=warnings.append), raw)
                self.assertEqual([(item.code, item.line_number) for item in warnings],
                                 [("late_invalid", len(rows) + 1)])

    def test_retry_duplicates_permutation_and_interleaving_preserve_bytes(self):
        raw, rows = self.encoded()
        foreign = list(self.module().encode_messages(b'{"foreign":true}\n', "f" * 32, STAMP))
        self.assertEqual(self.decode(rows[:2] + list(reversed(rows)) + foreign, RID), raw)

    def test_schema_types_duplicate_keys_and_noncanonical_base64_reject(self):
        raw, rows = self.encoded()
        for key, value in [("schema", "unknown-schema"), ("part", False), ("part", True), ("parts", True), ("parts", 0), ("sha256", "A" * 64),
                           ("record_id", "not-a-record-id"), ("data_b64", "YQ==\n")]:
            mutated = envelope(rows[0])
            mutated[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.decode([message(mutated)] + rows[1:], RID)
        extra = envelope(rows[0])
        extra["unexpected"] = 1
        with self.assertRaises(ValueError):
            self.decode([message(extra)] + rows[1:], RID)
        body = rows[0].split(MARKER, 1)[1]
        duplicate = HEADER + b'{"part":0,' + body[1:]
        with self.assertRaises(ValueError):
            self.decode([duplicate] + rows[1:], RID)

    def test_frame_message_rejects_over_cap_and_counts_message_only(self):
        codec = self.module()
        with self.assertRaises(ValueError):
            codec.frame_message(b"x" * 2049)
        raw, rows = self.encoded()
        framed = [codec.frame_message(m) for m in rows]
        self.assertEqual(wire_messages(framed), rows)
        self.assertTrue(all(len(f) > len(m) and len(m) <= 2048 for f, m in zip(framed, rows)))

    def test_mid_parts_failure_retains_whole_record_and_retry_is_reconstructable(self):
        audit, queued, raw = self.fixture()
        failed = Channel(fail_on=2)
        with self.assertRaises(ConnectionResetError):
            self.send(audit, queued, failed)
        self.assertEqual(read_private(queued, MAX_MESSAGE * 2), raw)
        retry = Channel()
        self.send(audit, queued, retry)
        self.assertEqual(self.decode(wire_messages(failed.writes + retry.writes), RID), raw)
        self.assertFalse(queued.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
