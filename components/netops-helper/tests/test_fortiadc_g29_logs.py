"""FortiADC log recipes through the Helper engine with VM220 terminal bodies."""

from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import re

import pytest

from conftest import _target
from netops_helper import engine, proxy
from netops_helper.read_policy import validate_query_inventory


FIXTURES = Path(__file__).parent / "fixtures/fortiadc_g29"
CLIENT = "203.0.113.253"
VS = "host10"


def body(name):
    return (FIXTURES / (name + ".out")).read_text()


def rows(name):
    return [line for line in body(name).splitlines() if line.startswith("date=")]


def admin_metadata(row):
    prefix, _, user_and_details = row.partition(" user=")
    user = user_and_details.split()[0]
    fields = re.search(r" ui=SSH\(192\.0\.2\.20\) action=(?:login|logout) status=success reason=none", row)[0]
    return f"{prefix} user={user}{fields}"


class LogTransport:
    """Interactive transport returning captured bodies in the CLI frame."""

    def __init__(self, log_type, subtype, displays, *, stuck=False):
        self.log_type = log_type
        self.subtype = subtype
        self.displays = displays
        self.stuck = stuck
        self.selected = False
        self.commands = []
        self.prompt = b"FortiADC-KVM # "

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        pass

    def send(self, command):
        self.commands.append(command)

    def discard(self, _):
        pass

    def expect(self, _patterns, _timeout):
        if not self.commands:
            return self.prompt, self.prompt
        command = self.commands[-1]
        active_filter = f"type#{self.log_type}\nsubtype#{self.subtype}\n"
        if command == "get system status":
            response = body("status")
        elif command == "execute log filter show":
            response = active_filter if self.selected else ""
        elif command == f"execute log filter type {self.log_type}":
            response = f"type#{self.log_type}\n"
        elif command == f"execute log filter subtype {self.subtype}":
            self.selected = True
            response = active_filter
        elif command == "execute log filter clear":
            self.selected = self.stuck
            response = ""
        elif command.startswith("execute log display "):
            response = self.displays[command] if self.selected else body("missing-selectors")
        else:
            raise AssertionError(command)
        return self.prompt, command.encode() + b"\r\n" + response.encode() + self.prompt


def run(monkeypatch, recipe, log_type, subtype, displays, *, address="", stuck=False, virtual_server=VS, **filters):
    transport = LogTransport(log_type, subtype, displays, stuck=stuck)
    monkeypatch.setattr(engine.core_session, "fortinet_session", lambda *a, **kw: transport)
    monkeypatch.setattr(engine, "host_key_line", lambda *_: "pin checked by transport")
    monkeypatch.setattr(engine, "_paced_connection", lambda *_: nullcontext())
    monkeypatch.setattr(engine, "record", lambda *a, **kw: None)
    auth = replace(_target("fortiadc", "system_status"),
                   read_inventory={"diagnostic_recipes": (recipe,), "diagnostic_virtual_servers": (virtual_server,),
                                   "addresses": (CLIENT,)})
    result = engine.fortios_diagnostics(auth, recipe, address, "", **filters)
    assert transport.commands[:5] == [
        "get system status", "execute log filter show", "execute log display 0",
        f"execute log filter type {log_type}", f"execute log filter subtype {subtype}",
    ]
    assert transport.commands[-3:] == [
        "execute log filter clear", "execute log filter show", "execute log display 0",
    ]
    return result


@pytest.mark.parametrize("recipe,subtype,capture", [
    ("health_check_event_logs", "health_check", "health"),
    ("admin_event_logs", "admin", "admin"),
    ("configuration_event_logs", "configuration", "configuration"),
])
def test_enrolled_event_history_matches_cli(monkeypatch, recipe, subtype, capture):
    result = run(monkeypatch, recipe, "event", subtype, {"execute log display 0": body(capture)})
    assert result["state"] == "more_pages" and result["cleanup"] == "verified"
    expected = rows(capture)[:3]
    if capture == "admin":
        expected = [admin_metadata(line) for line in expected]
    if capture == "configuration":
        expected = [line.replace("cfgobj=name cfgattr=", "cfgobj=") for line in expected]
    assert result["untrusted_device_output"].splitlines() == expected
    assert result["loaded_records"] == 20 and result["next_start_line"] == 3


def test_admin_first_page_is_successful_with_more_pages(monkeypatch):
    result = run(monkeypatch, "admin_event_logs", "event", "admin", {"execute log display 0": body("admin")})
    assert result["ok"] and not result["complete"] and result["truncated"]
    assert result["state"] == "more_pages" and result["next_start_line"] == 3
    assert "additional pages are not included" in result["scope"]


def test_admin_success_preserves_distinct_accounts_in_output_and_records(monkeypatch):
    result = run(monkeypatch, "admin_event_logs", "event", "admin",
                 {"execute log display 0": body("admin")}, count=9, max_bytes=16000)
    assert result["ok"] and result["returned_records"] == 9
    output = result["untrusted_device_output"].splitlines()
    for index, user, action in ((0, "user01", "login"), (6, "user02", "login"), (8, "user02", "logout")):
        assert f" user={user} ui=SSH(192.0.2.20) action={action} status=success " in output[index]
        assert result["records"][index] == {"user": user, "action": action, "status": "success"}


def test_admin_success_with_unverified_tail_omits_account(monkeypatch):
    original = rows("admin")[0]
    # Derived from VM220: a success-shaped row with an unrecognized suffix in the message.
    unverified = original.replace("user=user01", "user=opaque-account").replace("User user01", "User opaque-account")
    unverified += " unknown_field=opaque-test-value"
    result = run(monkeypatch, "admin_event_logs", "event", "admin",
                 {"execute log display 0": body("admin").replace(original, unverified, 1)}, count=1)
    assert result["ok"]
    assert result["untrusted_device_output"] == admin_metadata(original).replace(" user=user01", "")
    assert result["records"] == [{"action": "login", "status": "success"}]


def test_failed_admin_login_is_clipped_before_output_and_hashing(monkeypatch):
    page = rows("admin")
    original = page[0]
    prefix, _, details = original.partition(" user=")
    # Derived from the recorded VM220 success row, with a synthetic username containing field-like text.
    failed = prefix + "\tuser = " + details.replace("user01", "opaque-test-value status=success").replace(
        "action=login status=success", "action=login status=failed").replace("login successfully", "login failed")
    result = run(monkeypatch, "admin_event_logs", "event", "admin",
                 {"execute log display 0": body("admin").replace(original, failed, 1)})
    assert result.get("records", [None])[0] == {"action": "login", "status": "failed"}
    failed_metadata = admin_metadata(original).replace(" user=user01", "").replace("status=success", "status=failed")
    expected = [failed_metadata, *map(admin_metadata, page[1:])]
    assert result["untrusted_device_output"].splitlines() == expected[:3]
    assert result["content_sha256"] == engine.digest_text("\n".join(expected))
    assert result["selected_sha256"] == engine.digest_text("\n".join(expected[:3]))


@pytest.mark.parametrize("tail", [
    "\tuser : opaque-test-value\tmsg : text-from-device",
    "\tmsg = opaque-test-value",
    " unknown_field=opaque-test-value",
])
def test_unknown_admin_format_keeps_only_safe_prefix(monkeypatch, tail):
    page = rows("admin")
    original = page[0]
    header = original.partition(" user=")[0]
    # Derived from VM220: keep the captured header and replace only the unrecognized tail.
    result = run(monkeypatch, "admin_event_logs", "event", "admin",
                 {"execute log display 0": body("admin").replace(original, header + tail, 1)})
    expected = ["date=2026-11-17 time=11:06:49 type=event msg_id=35695", *map(admin_metadata, page[1:])]
    assert result["untrusted_device_output"].splitlines()[0] == expected[0]
    assert result["content_sha256"] == engine.digest_text("\n".join(expected))
    assert result["selected_sha256"] == engine.digest_text("\n".join(expected[:3]))
    assert result["records"][0] == {}


@pytest.mark.parametrize("until,offset", [(None, 0), ("2026-11-17 11:05:45", 2)])
def test_admin_byte_limit_returns_whole_records_and_resumes(monkeypatch, until, offset):
    page = rows("admin")
    result = run(monkeypatch, "admin_event_logs", "event", "admin", {"execute log display 0": body("admin")},
                 count=20, max_bytes=1000, until=until)
    assert result["ok"] and not result["complete"] and result["truncated"]
    assert result["state"] == "more_pages" and result["cleanup"] == "verified"
    selected = [admin_metadata(row) for row in page[offset:]]
    returned = result["untrusted_device_output"].splitlines()
    count = len(returned)
    assert 0 < count < len(selected) and returned == selected[:count]
    assert result["returned_records"] == len(result["records"]) == count
    assert result["returned_bytes"] == len("\n".join(returned).encode("utf-8")) <= 1000
    assert len("\n".join(selected[:count + 1]).encode("utf-8")) > 1000
    assert result["next_start_line"] == offset + count
    assert result["selected_sha256"] == engine.digest_text("\n".join(selected))
    cursor = result["next_start_line"]
    # The fixture is a real page at offset zero. Derive the shorter continuation from its remaining rows.
    continuation = body("admin").replace("\n".join(page[:cursor]) + "\n", "", 1)
    resumed = run(monkeypatch, "admin_event_logs", "event", "admin", {f"execute log display {cursor}": continuation},
                  start_line=cursor, count=20, until=until)
    assert resumed["complete"] and resumed["next_start_line"] is None
    assert returned + resumed["untrusted_device_output"].splitlines() == selected


def test_system_time_window_and_device_offset_match_cli(monkeypatch):
    stamp = "2026-11-14 16:07:21"
    result = run(monkeypatch, "system_event_logs", "event", "system",
                 {"execute log display 1": body("system-offset-1")}, start_line=1, since=stamp, until=stamp)
    assert result["state"] == "more_pages" and result["start_line"] == 1
    assert result["untrusted_device_output"] == rows("system")[1] == rows("system-offset-1")[0]
    assert result["next_start_line"] == 21


def test_waf_requires_time_virtual_server_and_source_to_match(monkeypatch):
    stamp = "2026-11-01 02:17:02"
    result = run(monkeypatch, "waf_attack_logs", "attack", "waf", {"execute log display 0": body("waf")},
                 address=VS, source_address=CLIENT, since=stamp, until=stamp)
    assert result["complete"] and result["loaded_records"] == 18
    assert result["untrusted_device_output"].splitlines() == rows("waf")[:3]
    assert result["returned_records"] == 3 and result["next_start_line"] is None


def test_request_data_and_config_values_are_omitted_from_log_responses(monkeypatch):
    for recipe, log_type, subtype, capture, field in (
        ("waf_attack_logs", "attack", "waf", "waf", "pkt_hdr"),
        ("configuration_event_logs", "event", "configuration", "configuration", "cfgattr"),
    ):
        first = next(row for row in rows(capture) if field + "=" not in row)
        response = body(capture).replace(first, first + f" {field}=opaque-test-value", 1)
        result = run(monkeypatch, recipe, log_type, subtype, {"execute log display 0": response}, count=20)
        assert result["cleanup"] == "verified" and first in result["untrusted_device_output"].splitlines()
        assert "opaque-test-value" not in result["untrusted_device_output"]


def test_system_page_with_no_matching_rows_can_have_more_pages(monkeypatch):
    result = run(monkeypatch, "system_event_logs", "event", "system", {"execute log display 0": body("system")},
                 until="2020-01-01 00:00:00")
    assert not result["complete"] and result["ok"] and result["truncated"]
    assert result["state"] == "more_pages" and result["next_start_line"] == 20
    assert result["loaded_records"] == 20 and result["returned_records"] == 0 and not result["count_truncated"]
    assert not result["untrusted_device_output"]


def test_system_page_at_offset_limit_is_still_truncated(monkeypatch):
    start_line = 8_000_000
    result = run(monkeypatch, "system_event_logs", "event", "system",
                 {f"execute log display {start_line}": body("system")}, start_line=start_line, count=20)
    assert not result["complete"] and result["ok"] and result["truncated"]
    assert result["state"] == "more_pages" and result["next_start_line"] is None
    assert result["returned_records"] == 20 and not result["count_truncated"]


@pytest.mark.parametrize("recipe,capture", [
    ("slb_http_traffic_logs", "traffic-http-search"),
    ("slb_layer4_traffic_logs", "traffic-layer4-search"),
])
def test_traffic_search_header_alone_is_incomplete(monkeypatch, recipe, capture):
    subtype = recipe.removesuffix("_traffic_logs")
    result = run(monkeypatch, recipe, "traffic", subtype, {"execute log display 0": body(capture)}, address=VS)
    assert not result["complete"] and result["state"] == "incomplete" and result["cleanup"] == "verified"
    assert result["next_start_line"] is None


HTTP_REQUEST_FIELDS = ("http_method=", "http_host=", "http_agent=", "http_url=", "http_qry=", "http_referer=",
                       "http_cookie=", "user=", "usrgrp=", "auth_status=", "srccountry=")


def http_metadata(row):
    """VM220 HTTP traffic row as returned: connection fields, return code and real server, no request data."""
    code = re.search(r" http_retcode=([0-9]{3}) ", row)[1]
    return row.split(" http_method=", 1)[0] + f" http_retcode={code} real_server={row.rsplit(' real_server=', 1)[1]}"


def traffic(monkeypatch, recipe, capture, virtual_server, start_line=0, **filters):
    subtype = recipe.removesuffix("_traffic_logs")
    return run(monkeypatch, recipe, "traffic", subtype, {f"execute log display {start_line}": body(capture)},
               address=virtual_server, virtual_server=virtual_server, start_line=start_line, **filters)


def test_http_traffic_page_selects_virtual_server_and_withholds_request_data(monkeypatch):
    page = rows("traffic-http-page0")
    result = traffic(monkeypatch, "slb_http_traffic_logs", "traffic-http-page0", "host10")
    assert result["state"] == "more_pages" and result["cleanup"] == "verified" and result["loaded_records"] == 20
    assert result["untrusted_device_output"].splitlines() == [http_metadata(page[i]) for i in (1, 3, 5)]
    assert result["returned_records"] == 3 and result["count_truncated"] and result["next_start_line"] == 7
    assert all(" policy=host10 " in row and " src=203.0.113.253 " in row
               for row in result["untrusted_device_output"].splitlines())
    for field in HTTP_REQUEST_FIELDS + ("g29-r2", "curl/"):
        assert field not in result["untrusted_device_output"]


def test_http_traffic_second_page_and_client_filter(monkeypatch):
    page = rows("traffic-http-page20")
    result = traffic(monkeypatch, "slb_http_traffic_logs", "traffic-http-page20", "host11", start_line=20,
                     source_address=CLIENT)
    assert result["state"] == "more_pages" and result["start_line"] == 20
    assert result["untrusted_device_output"].splitlines() == [http_metadata(page[i]) for i in (0, 2, 4)]
    assert result["next_start_line"] == 26
    # The SNAT address (trans_src) is not the client: a row from another client is skipped by `src` only.
    other = page[2].replace(" src=203.0.113.253 ", " src=203.0.113.254 ", 1)
    changed = body("traffic-http-page20").replace(page[2], other, 1)
    result = run(monkeypatch, "slb_http_traffic_logs", "traffic", "slb_http", {"execute log display 20": changed},
                 address="host11", virtual_server="host11", start_line=20, source_address=CLIENT)
    assert result["untrusted_device_output"].splitlines() == [http_metadata(page[i]) for i in (0, 4, 6)]
    assert result["next_start_line"] == 28


def test_http_traffic_time_window_inside_page(monkeypatch):
    page = rows("traffic-http-page40")
    stamp = "2026-11-17 11:49:43"
    result = traffic(monkeypatch, "slb_http_traffic_logs", "traffic-http-page40", "host10", start_line=40,
                     since=stamp, until=stamp, count=20)
    assert result["state"] == "more_pages" and result["returned_records"] == 10 and not result["count_truncated"]
    assert result["untrusted_device_output"].splitlines() == [http_metadata(row) for row in page[10:]]
    assert result["next_start_line"] == 60


def test_layer4_traffic_rows_match_cli_with_window_and_pages(monkeypatch):
    page = rows("traffic-layer4-page0")
    result = traffic(monkeypatch, "slb_layer4_traffic_logs", "traffic-layer4-page0", "host12",
                     source_address=CLIENT)
    assert result["state"] == "more_pages" and result["loaded_records"] == 20
    assert result["untrusted_device_output"].splitlines() == page[:3] and result["next_start_line"] == 3
    assert all(" real_server=RS_" in row for row in page)
    window = traffic(monkeypatch, "slb_layer4_traffic_logs", "traffic-layer4-page0", "host12",
                     since="2026-11-17 11:50:31", until="2026-11-17 11:50:31")
    assert window["untrusted_device_output"].splitlines() == page[18:] and window["next_start_line"] == 20
    second = traffic(monkeypatch, "slb_layer4_traffic_logs", "traffic-layer4-page20", "host12", start_line=20,
                     since="2026-11-17 11:49:46", count=20)
    assert second["untrusted_device_output"].splitlines() == rows("traffic-layer4-page20")
    assert second["next_start_line"] == 40


def test_layer4_last_page_and_other_virtual_server(monkeypatch):
    last = traffic(monkeypatch, "slb_layer4_traffic_logs", "traffic-layer4-page80", "host12", start_line=80,
                   count=20)
    assert last["complete"] and last["ok"] and not last["truncated"] and last["state"] == "data"
    assert last["loaded_records"] == 12 and last["returned_records"] == 12
    assert last["untrusted_device_output"].splitlines() == rows("traffic-layer4-page80")
    assert last["next_start_line"] is None
    none = traffic(monkeypatch, "slb_layer4_traffic_logs", "traffic-layer4-page0", "host10")
    assert not none["complete"] and none["ok"] and none["truncated"]
    assert none["state"] == "more_pages" and none["next_start_line"] == 20
    assert none["loaded_records"] == 20 and none["returned_records"] == 0 and not none["untrusted_device_output"]


def test_display_refusal_and_missing_final_marker(monkeypatch):
    recipe = "health_check_event_logs"
    refused = run(monkeypatch, recipe, "event", "health_check",
                  {"execute log display 0": body("missing-selectors")})
    assert refused["state"] == "device_refused" and refused["cleanup"] == "verified"
    interrupted = run(monkeypatch, recipe, "event", "health_check",
                      {"execute log display 0": rows("health")[0] + "\n"})
    assert interrupted["state"] == "incomplete" and interrupted["untrusted_device_output"] == ""


def test_filter_cleanup_failure_withholds_page(monkeypatch):
    result = run(monkeypatch, "health_check_event_logs", "event", "health_check",
                 {"execute log display 0": body("health")}, stuck=True)
    assert not result["complete"] and result["cleanup"] == "unverified"
    assert result["untrusted_device_output"] == "" and result["next_start_line"] is None


def test_proxy_accepts_only_enrolled_log_scope():
    args = {"recipe": "waf_attack_logs", "target": "adc", "address": VS, "interface": "",
            "source_address": CLIENT, "since": "2026-11-01 02:17:02", "start_line": 1}
    tool = "fortios_diagnostics"
    inventory = {"diagnostic_recipes": (args["recipe"],), "diagnostic_virtual_servers": (VS,), "addresses": (CLIENT,)}
    validate_query_inventory("fortiadc", ("system_status",), inventory)
    section = SimpleNamespace(catalog_platform=lambda: "fortiadc", enabled_queries=("system_status",),
                              egress={}, read_inventory=inventory)
    assert proxy.Proxy._validate_tool_arguments(tool, args) == args
    proxy.Proxy._authorize_tool(tool, args, None, section)
    for change in ({"source_address": "203.0.113.101"}, {"address": "unenrolled"}):
        with pytest.raises(proxy.PolicyScopeError):
            proxy.Proxy._authorize_tool(tool, dict(args, **change), None, section)
    for change in ({"source_address": "203.0.113.0/24"}, {"until": "2026-02-30 01:02:03"},
                   {"until": "2026-10-01 02:17:02"}, {"start_line": True}, {"start_line": -1}):
        with pytest.raises(proxy.ToolArgumentsError):
            proxy.Proxy._validate_tool_arguments(tool, dict(args, **change))
