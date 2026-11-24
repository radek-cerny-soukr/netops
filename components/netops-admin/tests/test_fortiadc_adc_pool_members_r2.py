"""ADC-POOL-MEMBERS r2 (review): the service outage of a virtual server, protected objects reached through a real server,
a pool member or a virtual server, dynamic virtual servers unrelated to the change and the undo of an address
change. Real fortiadc-kvm FortiADC-KVM 7.6.7 build0676 answers at the transport boundary (fixtures/fortiadc_adc_pool_members and
fixtures/fortiadc_adc_pool_members/r2/PROVENANCE.md); derived answers are marked where they are built."""

import re
from pathlib import Path

import pytest

from fake_fortiadc_admin import measured
from netops_admin import execute, fortiadc
from test_fortiadc_admin_runtime import make_runtime, request
from test_fortiadc_adc_pool_members import (DNS, MEMBER, POOL, POOL_KEY, RS, SMTP, TARGET, VS, Wire, capture, confirm_and_return,
                               server_steps)

R2 = Path(__file__).with_name("fixtures") / "fortiadc_adc_pool_members" / "r2"
SCHEDULE_CAPTURES = (Path(__file__).resolve().parents[2] / "netops-helper" / "tests" / "fixtures" /
                     "real" / "fortiadc" / "fortiadc-kvm_7.6.7_schedule_20261114")
HTTPS = "LAB_VS_HTTPS"
CR = "show full-configuration load-balance content-routing "
SP = "show full-configuration load-balance schedule-pool "


def r2(name):
    return (R2 / name).read_bytes().decode()


def down(text, numbers=("1", "2", "13")):
    # derived: the measured vs_stat answer with the listed members reported DOWN
    return re.sub(r"(id:(?:%s), hc_state: )UP" % "|".join(numbers), r"\1DOWN", text)


def block(text, name):
    start = text.index('  edit "%s"' % name)
    return start, text.index("  next", start) + len("  next")


def with_https(replacement):
    # derived: the measured virtual-server listing with the LAB_VS_HTTPS block replaced
    listing = measured("show_load-balance_virtual-server.txt")
    start, end = block(listing, HTTPS)
    return listing[:start] + replacement + listing[end:]


def content_routing_block():
    text = r2("vs-cr-show.out")
    start, end = block(text, HTTPS)
    return text[start:end]


SCHEDULE_BLOCK = ('  edit "LAB_VS_HTTPS"\n    set type l7-load-balance\n    set schedule-list enable\n'
                  '    set schedule-pool-list netops-173-sp-a \n    set load-balance-method LB_METHOD_ROUND_ROBIN\n'
                  '  next')


def maintenance(changes=("set status maintain",), inverse=("set status enable",), after="real-maintain",
                before=None, diagnoses=None, after_diagnoses=None):
    runtime_before = {name: capture("runtime-link-discovery-before-" + name) for name in (DNS, SMTP)}
    return Wire([server_steps(RS, TARGET, *changes), server_steps(RS, TARGET, *inverse)],
                before={"show " + RS: capture("real-ip"), "show load-balance pool": capture("pools-with-members")}
                | (before or {}),
                after={"show " + RS: capture(after)},
                diagnoses=runtime_before | (diagnoses or {}),
                after_diagnoses=after_diagnoses if after_diagnoses is not None
                else {name: capture("runtime-link-discovery-maintain-" + name) for name in (DNS, SMTP)})


# Finding 1: maintain/disable of a virtual server is a service outage


@pytest.mark.parametrize("status", ["maintain", "disable"])
def test_r2_virtual_server_outage_is_a_plan_field_and_a_precheck_text(tmp_path, status):
    wire = Wire([server_steps(VS, SMTP, "set status " + status), server_steps(VS, SMTP, "set status enable")],
                before={"show " + VS: capture("vs-smtp-baseline")},
                after={"show " + VS: capture("vs-" + status)})
    preview = confirm_and_return(tmp_path, wire, request(table=VS, key=SMTP, changes={"status": status}),
                                 "show " + VS)
    assert preview["service_outage"] == [SMTP]
    assert [line for line in preview["prechecks"] if line.startswith("SERVICE OUTAGE")] == [
        "SERVICE OUTAGE: virtual server %s stops serving its clients while its status is %s; the service is"
        " unavailable until the status is enable again (undo)" % (SMTP, status)]


def test_r2_enabling_a_virtual_server_is_not_an_outage(tmp_path):
    wire = Wire(before={"show " + VS: capture("vs-maintain")})
    preview = execute.preview(make_runtime(tmp_path, wire), "adc",
                              request(table=VS, key=SMTP, changes={"status": "enable"}))
    assert preview["result"] == "ready", preview
    assert preview["service_outage"] == []
    assert not any("OUTAGE" in line for line in preview["prechecks"])


def test_r2_real_server_that_is_the_only_healthy_member_is_refused_as_an_outage(tmp_path):
    # members 1 and 2 DOWN, the target (member 13) is the only healthy member of both virtual servers
    wire = maintenance(diagnoses={name: down(capture("runtime-link-discovery-before-" + name), ("1", "2")) for name in (DNS, SMTP)})
    result = execute.preview(make_runtime(tmp_path, wire), "adc",
                             request(table=RS, key=TARGET, changes={"status": "disable"}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["no_healthy_member"]
    assert "service outage" in result["reasons"][0]
    assert result["reason_details"] == [{"code": "no_healthy_member", "virtual_server": DNS, "service_outage": True}]
    assert not wire.writes


# Finding 2: protected objects behind a real server, a pool member or a virtual server


@pytest.mark.parametrize(("protected", "named"), [
    ({VS: [SMTP]}, SMTP),
    ({VS: [DNS.lower()]}, DNS),
    ({"load-balance pool": [POOL]}, POOL),
    ({MEMBER: ["LAB_POOL_DNS:13"]}, "LAB_POOL_DNS:13"),
])
@pytest.mark.parametrize("changes", [{"status": "maintain"}, {"ip": "192.0.2.12"}])
def test_r2_real_server_change_refuses_a_protected_virtual_server_pool_or_member(tmp_path, protected, named, changes):
    wire = maintenance()
    result = execute.preview(make_runtime(tmp_path, wire, protected=protected), "adc",
                             request(table=RS, key=TARGET, changes=changes))
    assert result["result"] == "rejected", result
    assert result["reasons"] == ["the change of real server %s affects protected object %s" % (TARGET, named)]
    assert not wire.writes and not wire.health_reads


def test_r2_real_server_change_ignores_an_unrelated_protected_virtual_server(tmp_path):
    wire = maintenance()
    result = execute.preview(make_runtime(tmp_path, wire, protected={VS: ["VS_APP_HTTP"], MEMBER: ["POOL_APP:1"]}),
                             "adc", request(table=RS, key=TARGET, changes={"status": "maintain"}))
    assert result["result"] == "ready", result


@pytest.mark.parametrize(("protected", "named"), [({VS: [SMTP]}, SMTP), ({"load-balance pool": [POOL]}, POOL)])
def test_r2_pool_member_change_refuses_a_protected_virtual_server_or_pool(tmp_path, protected, named):
    command = "show load-balance pool " + POOL
    pools = capture("pools-with-members")
    wire = Wire(before={command: pools, "show load-balance pool": pools, "show " + RS: capture("real-ip")})
    result = execute.preview(make_runtime(tmp_path, wire, protected=protected), "adc",
                             request(table=MEMBER, key=POOL_KEY, changes={"pool-member-weight": 7}))
    assert result["result"] == "rejected", result
    assert result["reasons"] == ["the change of pool member %s affects protected object %s" % (POOL_KEY, named)]
    assert not wire.writes and not wire.health_reads


@pytest.mark.parametrize(("protected", "named"), [({MEMBER: [POOL + ":1"]}, POOL + ":1"),
                                                  ({"load-balance pool": [POOL.lower()]}, POOL)])
def test_r2_virtual_server_change_refuses_a_protected_pool_or_member(tmp_path, protected, named):
    wire = Wire(before={"show " + VS: capture("vs-smtp-baseline")})
    result = execute.preview(make_runtime(tmp_path, wire, protected=protected), "adc",
                             request(table=VS, key=SMTP, changes={"status": "maintain"}))
    assert result["result"] == "rejected", result
    assert result["reasons"] == ["the change of virtual server %s affects protected object %s" % (SMTP, named)]
    assert not wire.writes and not wire.health_reads


# Non-blocking item: a dynamic virtual server refuses the real server change only when it may use its pools


def dynamic(block_text, answers, https_stat):
    return maintenance(before={"show " + VS: with_https(block_text)} | answers, diagnoses={HTTPS: https_stat})


CR_ANSWERS = {CR + "NETOPS_TEST_CR1": r2("cr1-full.out"), CR + "NETOPS_TEST_CR2": r2("cr2-full.out")}


def test_r2_unrelated_content_routing_virtual_server_does_not_refuse_the_real_server(tmp_path):
    wire = dynamic(content_routing_block(), CR_ANSWERS, r2("vs-stat-cr.out"))
    preview = confirm_and_return(tmp_path, wire, request(table=RS, key=TARGET, changes={"status": "maintain"}),
                                 "show " + RS)
    assert ("virtual server %s selects pools POOL_APP (content routing or schedule, vs_stat); real server %s is not"
            " in them" % (HTTPS, TARGET)) in preview["prechecks"]
    assert fortiadc.vs_stat_command(HTTPS) in wire.health_reads


def test_r2_unrelated_schedule_virtual_server_does_not_refuse_the_real_server(tmp_path):
    # derived: the virtual server of the schedule capture renamed to LAB_VS_HTTPS ("no rs for this vs")
    stat = r2("vs_stat_schedule_exec.txt").replace("netops-173-vs", HTTPS)
    wire = dynamic(SCHEDULE_BLOCK, {SP + "netops-173-sp-a": r2("schedule_pool_sp_a_full.txt")}, stat)
    result = execute.preview(make_runtime(tmp_path, wire), "adc",
                             request(table=RS, key=TARGET, changes={"status": "maintain"}))
    assert result["result"] == "ready", result
    assert any(HTTPS in line and "netops-173-pool-a" in line for line in result["prechecks"])


@pytest.mark.parametrize("case", ["related-entry", "related-stored-pool", "missing-entry", "unreadable-stat"])
def test_r2_related_or_unreadable_dynamic_virtual_server_still_refuses(tmp_path, case):
    answers, stat = dict(CR_ANSWERS), r2("vs-stat-cr.out")
    if case == "related-entry":  # derived: the second entry names the pool of the target
        answers[CR + "NETOPS_TEST_CR2"] = answers[CR + "NETOPS_TEST_CR2"].replace("POOL_APP", "LAB_POOL_DNS")
    elif case == "related-stored-pool":  # derived: vs_stat names the stored pool LAB_POOL_SMTP
        stat = stat.replace("real-server-pool: POOL_APP", "real-server-pool: " + POOL)
    elif case == "missing-entry":
        answers[CR + "NETOPS_TEST_CR2"] = r2("cr-missing.out")
    else:
        stat = measured("diagnose_vs_stat_LAB_VS_SMTP.stderr.txt")
    wire = dynamic(content_routing_block(), answers, stat)
    result = execute.preview(make_runtime(tmp_path, wire), "adc",
                             request(table=RS, key=TARGET, changes={"status": "maintain"}))
    assert result["result"] == "rejected", result
    assert result["reasons"][0].startswith("the virtual server %s selects pools by content routing or schedule"
                                           % HTTPS)
    assert not wire.writes


# Non-blocking item: the undo of an address change of an active backend is not a member loss


def test_r2_undo_of_an_address_change_is_not_refused_as_a_member_loss(tmp_path):
    # after the change every member reports DOWN (derived); the undo restores the previous address anyway
    wire = maintenance(changes=("set ip 192.0.2.12",), inverse=("set ip 192.0.2.11",), after="real-ip-update",
                       after_diagnoses={name: down(capture("runtime-link-discovery-before-" + name)) for name in (DNS, SMTP)})
    confirm_and_return(tmp_path, wire, request(table=RS, key=TARGET, changes={"ip": "192.0.2.12"}), "show " + RS)


def test_r2_forward_address_change_without_a_healthy_alternative_is_still_refused(tmp_path):
    wire = maintenance(diagnoses={name: down(capture("runtime-link-discovery-before-" + name), ("1", "2")) for name in (DNS, SMTP)})
    result = execute.preview(make_runtime(tmp_path, wire), "adc",
                             request(table=RS, key=TARGET, changes={"ip": "192.0.2.12"}))
    assert result["result"] == "rejected" and result["reason_codes"] == ["no_healthy_member"]
    assert not wire.writes


def test_r2_pool_member_change_refuses_a_protected_content_routing_virtual_server_of_the_pool(tmp_path):
    command = "show load-balance pool POOL_APP"
    pools = capture("pools-with-members")
    wire = Wire(before={command: pools, "show load-balance pool": pools, "show " + RS: capture("real-ip"),
                        "show " + VS: with_https(content_routing_block())} | CR_ANSWERS,
                diagnoses={HTTPS: r2("vs-stat-cr.out")})
    req = request(table=MEMBER, key="POOL_APP:1", changes={"pool-member-weight": 7})
    assert execute.preview(make_runtime(tmp_path / "free", wire), "adc", req)["result"] == "ready"
    result = execute.preview(make_runtime(tmp_path / "guarded", wire, protected={VS: [HTTPS]}), "adc", req)
    assert result["result"] == "rejected", result
    assert result["reasons"] == ["the change of pool member POOL_APP:1 affects protected object %s" % HTTPS]
    assert not wire.writes


def scheduled_content_routing(schedule_answer):
    # Derived from the measured content-routing entry and schedule-pool listing. FortiADC selects the
    # schedule-pool list in place of the direct load-balance-pool when scheduling is enabled.
    entry = CR_ANSWERS[CR + "NETOPS_TEST_CR1"].replace(
        "set schedule-list disable\n    set load-balance-pool POOL_APP",
        "set schedule-list enable\n    set schedule-pool-list netops-173-sp-a netops-173-sp-b")
    answers = CR_ANSWERS | {CR + "NETOPS_TEST_CR1": entry,
                            SP + "netops-173-sp-a": r2("schedule_pool_sp_a_full.txt"),
                            SP + "netops-173-sp-b": schedule_answer}
    return dynamic(content_routing_block(), answers, r2("vs-stat-cr.out"))


def schedule_pool_b():
    # Derived targeted listing retaining the measured second entry and removing the first one.
    listing = (SCHEDULE_CAPTURES / "schedule_pool_full.txt").read_bytes().decode()
    start, end = block(listing, "netops-173-sp-a")
    return listing[:start] + listing[end:]


@pytest.mark.parametrize(("table", "key", "changes"), [
    (RS, TARGET, {"status": "maintain"}),
    (MEMBER, POOL_KEY, {"pool-member-weight": 7}),
    (MEMBER, POOL_KEY, {"status": "maintain"}),
    (MEMBER, POOL_KEY, {"pool-member-service-port": 2526}),
])
def test_r3_unrelated_scheduled_content_routing_does_not_block_changes(tmp_path, table, key, changes):
    wire = scheduled_content_routing(schedule_pool_b())
    wire.answers["show load-balance pool " + POOL] = capture("pools-with-members")
    result = execute.preview(make_runtime(tmp_path, wire, protected={VS: [HTTPS]}), "adc",
                             request(table=table, key=key, changes=changes))
    assert result["result"] == "ready", result
    assert fortiadc.vs_stat_command(HTTPS) in wire.health_reads
    if changes.keys() & {"status", "pool-member-service-port"} and table == MEMBER:
        assert fortiadc.vs_stat_command(SMTP) in wire.health_reads
    assert not wire.writes


@pytest.mark.parametrize("protected", [False, True])
def test_member_health_change_refuses_a_dynamic_user_of_its_pool(tmp_path, protected):
    wire = scheduled_content_routing(schedule_pool_b().replace("netops-173-pool-b", POOL))
    wire.answers["show load-balance pool " + POOL] = capture("pools-with-members")
    runtime = make_runtime(tmp_path, wire, protected={VS: [HTTPS]} if protected else {})
    result = execute.preview(runtime, "adc", request(table=MEMBER, key=POOL_KEY, changes={"status": "maintain"}))
    assert result["result"] == "rejected", result
    expected = ("affects protected object " + HTTPS) if protected else "the pool use cannot be evaluated"
    assert result["reasons"][0].endswith(expected)
    assert fortiadc.vs_stat_command(HTTPS) in wire.health_reads
    assert not wire.writes


@pytest.mark.parametrize("schedule_pool", [POOL, None])
def test_r3_related_or_unreadable_content_routing_schedule_is_refused(tmp_path, schedule_pool):
    # The second referenced entry reaches the backend pool or is unreadable (derived truncation).
    answer = schedule_pool_b()
    if schedule_pool is None:
        answer = answer.split("    set load-balance-pool", 1)[0]
        expected = "the pool of load-balance content-routing NETOPS_TEST_CR1 cannot be read"
    else:
        answer = answer.replace("netops-173-pool-b", schedule_pool)
        expected = "the real server use cannot be evaluated"
    wire = scheduled_content_routing(answer)
    result = execute.preview(make_runtime(tmp_path, wire), "adc",
                             request(table=RS, key=TARGET, changes={"status": "maintain"}))
    assert result["result"] == "rejected", result
    assert result["reasons"][0].endswith(expected)
    assert not wire.writes


@pytest.mark.parametrize("output", ["stored", "truncated", "partial-name", "no-rs"])
def test_r3_schedule_vs_stat_requires_a_pool_or_explicit_empty_result(tmp_path, output):
    # Derived answers name the lab VS and its hidden SMTP pool. Truncate before the row or inside the pool name.
    fixture = "vs_stat_schedule_exec.txt" if output == "no-rs" else "vs_stat_stored_pool_exec.txt"
    stat = (SCHEDULE_CAPTURES / fixture).read_bytes().decode().replace("netops-173-vs", HTTPS)
    stat = stat.replace("netops-173-pool-b", POOL)
    if output == "truncated":
        stat = stat.split("\t\treal-server-pool:", 1)[0]
    elif output == "partial-name":
        stat = stat[:stat.index(POOL) + len(POOL) - 1]
    wire = dynamic(SCHEDULE_BLOCK, {SP + "netops-173-sp-a": r2("schedule_pool_sp_a_full.txt")}, stat)
    result = execute.preview(make_runtime(tmp_path, wire, protected={VS: [HTTPS]}), "adc",
                             request(table=RS, key=TARGET, changes={"status": "maintain"}))
    if output == "no-rs":
        assert result["result"] == "ready", result
    else:
        assert result["result"] == "rejected", result
        expected = ("its stored pool cannot be read from vs_stat" if output in ("truncated", "partial-name")
                    else "the real server use cannot be evaluated")
        assert result["reasons"][0].endswith(expected)
    assert fortiadc.vs_stat_command(HTTPS) in wire.health_reads
    assert not wire.writes


def test_r3_undo_of_address_and_maintenance_restores_service_without_a_healthy_alternative(tmp_path):
    # Derived real-server readback combines measured maintain and address changes. During maintenance the other
    # backends go DOWN, so the undo is the only available way to restore the original active backend.
    wire = maintenance(changes=("set ip 192.0.2.12", "set status maintain"),
                       inverse=("set ip 192.0.2.11", "set status enable"), after="real-maintain",
                       after_diagnoses={name: down(capture("runtime-link-discovery-maintain-" + name)) for name in (DNS, SMTP)})
    listing = wire.after["show " + RS]
    start, end = block(listing, TARGET)
    wire.after["show " + RS] = listing[:start] + listing[start:end].replace("192.0.2.11", "192.0.2.12") + listing[end:]
    confirm_and_return(tmp_path, wire,
                       request(table=RS, key=TARGET, changes={"ip": "192.0.2.12", "status": "maintain"}), "show " + RS)
