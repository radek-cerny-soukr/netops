import hashlib

from conftest import _target
import netops_helper.engine as engine
from netops.redaction import redact as product_redact
from netops_helper.proxy_sanitize import sanitize_object


def _show_wlan_all(count=60):
    """Synthetic Ruckus Unleashed `show wlan all`: about 2 kB per WLAN with one `Passphrase =` line."""
    blocks = ["WLAN Service:\n"]
    for number in range(count):
        blocks.append(
            "ID:\n"
            "  %d:\n" % number
            + "".join("    Option%02d = synthetic-setting-%02d-%02d, reserved text of the fixture\n" % (line, number, line)
                      for line in range(14))
            + "    Name = synthetic-wlan-%02d\n" % number
            + "    Authentication = open\n"
            + "    Passphrase = SYNTHETIC-PASSPHRASE-%02d-only-for-this-fixture\n" % number
            + "".join("    Tail%02d = synthetic-tail-%02d-%02d, reserved text of the fixture\n" % (line, number, line)
                      for line in range(14))
        )
    return "".join(blocks)


SIZES = [*range(1000, 16401, 154), 16400]


def _canonical(monkeypatch, output=None):
    target = _target("ruckus_unleashed", "wlans")
    text = _show_wlan_all() if output is None else output
    monkeypatch.setattr(engine, "_verified_read", lambda auth, platform, command, prompt=False: (0, text))
    return target, engine._redact_output(text, target)


def _still_unchanged(page, secrets):
    return product_redact(sanitize_object(page, secrets), secrets)[0] == page


def test_the_fixture_has_the_measured_shape(wire, monkeypatch):
    _, cleaned = _canonical(monkeypatch)
    size = len(cleaned.encode("utf-8"))
    assert 100_000 < size < 140_000
    assert cleaned.count("Passphrase = [REDACTED]") == 60 and "SYNTHETIC-PASSPHRASE" not in cleaned
    assert all(1_500 < len(block) < 2_500 for block in cleaned.split("ID:\n")[1:])


def test_pages_of_show_wlan_all_end_on_a_line_and_are_not_changed_by_later_layers(wire, monkeypatch):
    target, cleaned = _canonical(monkeypatch)
    raw = cleaned.encode("utf-8")
    for max_bytes in SIZES:
        offset = 0
        while True:
            page = engine._page_text(cleaned, offset, max_bytes, whole_lines=True)
            text = page["untrusted_device_output"]
            assert 0 < page["returned_bytes"] <= max_bytes
            assert _still_unchanged(text, target.secrets), (max_bytes, offset)
            if not page["complete"]:
                assert text.endswith("\n") and raw[page["next_offset"] - 1:page["next_offset"]] == b"\n"
            else:
                assert page["next_offset"] is None
                break
            offset = page["next_offset"]


def test_ssh_read_pages_of_show_wlan_all_keep_hash_and_offsets(wire, monkeypatch):
    target, cleaned = _canonical(monkeypatch)
    expected = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    for max_bytes in (1000, 1400, 4096, 16000, 16400):
        engine._SSH_PAGE_CACHE.clear()
        pages, offset, digest = [], 0, None
        while True:
            page = engine.ssh_read(target, "ruckus_unleashed", "wlans", {}, offset, max_bytes, digest)
            assert page["ok"] is True, page
            assert page["offset"] == sum(item["returned_bytes"] for item in pages)
            assert page["returned_bytes"] == len(page["untrusted_device_output"].encode("utf-8"))
            assert _still_unchanged(page["untrusted_device_output"], target.secrets), (max_bytes, offset)
            pages.append(page)
            if page["complete"]:
                break
            offset, digest = page["next_offset"], page["content_sha256"]
        joined = "".join(item["untrusted_device_output"] for item in pages)
        assert joined == cleaned
        assert {item["content_sha256"] for item in pages} == {expected}
        assert pages[0]["total_bytes"] == len(joined.encode("utf-8"))
        assert pages[0]["pagination_source"] == "fresh"
        assert all(item["pagination_source"] == "cached" for item in pages[1:])


def test_a_page_without_any_newline_is_still_cut_on_the_byte_limit_and_kept_whole_for_utf8(wire, monkeypatch):
    # A single line longer than the page has no newline to cut at: the cut stays at the limit.
    text = "ž" * 1500 + "\n" + "q" * 2600 + "\n" + "y" * 100
    first = engine._page_text(text, 0, 1000, whole_lines=True)
    assert first["returned_bytes"] == 1000 and first["next_offset"] == 1000
    long = engine._page_text(text, first["next_offset"], 1000, whole_lines=True)
    assert long["returned_bytes"] == 1000
    # With a newline in the page the cut moves to just after it, and never splits a UTF-8 character.
    text = "a\n" + "ž" * 300 + "\n" + "ž" * 700 + "\n"
    page = engine._page_text(text, 0, 1000, whole_lines=True)
    assert page["untrusted_device_output"] == "a\n" + "ž" * 300 + "\n" and page["returned_bytes"] == 603
    assert page["next_offset"] == 603 and page["total_bytes"] == len(text.encode("utf-8"))
    rest = engine._page_text(text, page["next_offset"], 1500, whole_lines=True)
    assert rest["complete"] and page["untrusted_device_output"] + rest["untrusted_device_output"] == text
    # Only ssh_read cuts on lines; other callers keep the byte limit (here moved back to a UTF-8 boundary).
    plain = engine._page_text(text, 0, 1000)
    assert plain["returned_bytes"] == 999 and plain["next_offset"] == 999


def test_a_page_cutting_a_marker_in_a_line_without_newline_is_still_changed_by_a_later_layer(wire, monkeypatch):
    # The only case left to withhold: a page that holds no newline at all.
    body = '{"k":"' + "x" * 980 + '","password":"SYNTHETICVAL"}\n' + "y" * 3000 + "\n"
    target = _target("ruckus_unleashed", "wlans")
    cleaned = engine._redact_output(body, target)
    page = engine._page_text(cleaned, 0, 1000, whole_lines=True)
    assert "\n" not in page["untrusted_device_output"] and page["returned_bytes"] == 1000
    assert not _still_unchanged(page["untrusted_device_output"], target.secrets)
