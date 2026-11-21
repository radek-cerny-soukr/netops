"""FortiADC G30 Admin through the common execution engine and VM220 captures."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_admin import cli, execute, exec_fortiadc, fortiadc, fortiadc_certificate_import, readiness
from netops_admin.errors import Rejected
from netops_core.fortiadc_https import RequestError
from test_fortiadc_admin_runtime import make_runtime, request
from test_fortiadc_g34 import POOL, POOL_KEY, RS, Wire, capture, member_steps

FIXTURES = (Path(__file__).resolve().parents[2] / "netops-helper" / "tests" / "fixtures" / "fortiadc_g30")
KEY = "host02:1"
GROUP = exec_fortiadc.CERT_GROUP_QUERY
PIN = "a" * 64


def setup_runtime(tmp_path, **fields):
    before = (FIXTURES / "groups.out").read_text()
    after = before.replace("set local-cert host01", "set local-cert Fortiadc_ssl")
    commands = ["config " + fortiadc.CERT_GROUP, 'edit "host02"', "config group_member", "edit 1",
                'set local-cert "Fortiadc_ssl"', "next", "end", "next", "end"]
    inverse = commands.copy()
    inverse[4] = 'set local-cert "host01"'
    wire = Wire([commands, inverse], before={GROUP: before,
                exec_fortiadc.CERT_NAMES_QUERY: (FIXTURES / "acme.out").read_text()}, after={GROUP: after})
    wire.device = SimpleNamespace(fortiadc_https_sha256=PIN)
    runtime = make_runtime(tmp_path, wire, fortiadc_https_sha256=PIN, **fields)
    wire.device = runtime.config.devices["adc"]
    return wire, runtime


def change(name="Fortiadc_ssl", key=KEY):
    return request(table=fortiadc.CERT_MEMBER, key=key, changes={"local-cert": name})


def test_rotation_with_confirmed_apply_and_real_inverse(tmp_path):
    wire, runtime = setup_runtime(tmp_path)
    preview = execute.preview(runtime, "adc", change())
    assert preview["result"] == "ready", preview
    assert wire.writes == []
    assert preview["predicted"] == {"before": {"local-cert": "host01"},
                                    "after": {"local-cert": "Fortiadc_ssl"}}
    with pytest.raises(Rejected) as missing:
        execute.apply(runtime, "adc", change())
    assert missing.value.reason_codes == ["fortiadc_certificate_preview_required"]
    apply = execute.apply(runtime, "adc", change(), expected_plan_sha256=preview["plan_sha256"])
    assert apply["result"] == "confirmed", apply
    assert execute.preview_undo(runtime, apply["change_id"], "test restore")["result"] == "ready"
    undo = execute.undo(runtime, apply["change_id"], "test restore")
    assert undo["result"] == "confirmed", undo
    assert wire.original == wire.answers and len(wire.writes) == 2
    assert wire.checks.count(GROUP) >= 4


@pytest.mark.parametrize("scenario", ["missing", "truncated", "protected", "timeout"])
def test_certificate_preflight_keeps_device_read_only(tmp_path, scenario):
    protected = {"system certificate local_cert_group": ["host02"]} if scenario == "protected" else {}
    wire, runtime = setup_runtime(tmp_path, protected=protected)
    if scenario == "truncated":
        wire.answers[GROUP] = wire.answers[GROUP].split("set local-cert host01")[0]
    elif scenario == "timeout":
        def timeout(_command):
            raise TimeoutError()
        wire.check_query = timeout
    result = execute.preview(runtime, "adc", change("missing-cert" if scenario == "missing" else "Fortiadc_ssl"))
    assert result["result"] == "rejected", result
    expected = {"missing": "fortiadc_certificate_missing", "truncated": "fortiadc_certificate_unreadable",
                "protected": "fortiadc_certificate_protected", "timeout": "fortiadc_certificate_read_timeout"}
    assert expected[scenario] in result["reason_codes"]
    assert not wire.writes


@pytest.mark.parametrize("scenario", ["confirmed", "not_enrolled", "export_blocked", "lost_readback",
                                      "interrupted_import"])
def test_certificate_import_requires_approval_and_checks_uploaded_leaf(tmp_path, monkeypatch, capsys, scenario):
    from contextlib import contextmanager
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone
    from email import policy
    from email.parser import BytesParser
    import hashlib
    import json

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    wire, runtime = setup_runtime(tmp_path, certified=scenario != "not_enrolled")
    if scenario == "export_blocked":
        runtime.config = replace(runtime.config, export_status_file=str(tmp_path / "missing-export.json"))
        from enrollment_helpers import certify
        certify(runtime, wire, "adc")
    device = runtime.config.devices["adc"]
    private = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "netops-g30-test.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
            .sign(private, hashes.SHA256()))
    cert_path = tmp_path / "certificate.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    key_path.chmod(0o600)
    data = json.loads((FIXTURES / "rest.json").read_text())
    uploads = []
    assigned = []
    readback_unavailable = scenario in ("lost_readback", "interrupted_import")
    interrupt_readback = scenario == "interrupted_import"

    class Interrupted(BaseException):
        pass

    class HTTPSWire:
        def read(self, endpoint, **parameters):
            nonlocal interrupt_readback
            assert parameters == {"vdom": "global"}
            if endpoint == "system_certificate_local" and assigned and readback_unavailable:
                if interrupt_readback:
                    interrupt_readback = False
                    raise Interrupted()
                raise RequestError("timeout")
            return data[endpoint]["payload"] + assigned if endpoint == "system_certificate_local" else data[endpoint]["payload"]

        def upload_certificate(self, media_type, body):
            message = BytesParser(policy=policy.default).parsebytes(
                b'MIME-Version: 1.0\r\nContent-Type: ' + media_type.encode() + b'\r\n\r\n' + body)
            fields = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
                      for part in message.iter_parts()}
            assert fields["mkey"] == b"import-test" and fields["vdom"] == b"global"
            # Compare digests: a failing assert must not print the generated private key (550-rv/5, 702).
            key_matches = (hashlib.sha256(fields["key"]).digest() == hashlib.sha256(key_path.read_bytes()).digest())
            assert fields["cert"] == cert_path.read_bytes()
            assert key_matches, "uploaded private key differs from the key file"
            uploads.append(1)
            assigned.append({"mkey": "import-test", "status": "OK", "fingerprint": cert.fingerprint(hashes.SHA1()).hex()})
            return 0

    @contextmanager
    def login(_device, credential):
        assert credential in (wire.credential, wire.check_credential)
        yield HTTPSWire()

    monkeypatch.setattr(fortiadc_certificate_import, "certificate_https", login)
    preview = fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path)
    assert preview["result"] == "ready" and not uploads
    if scenario in ("not_enrolled", "export_blocked"):
        with pytest.raises(Rejected) as denied:
            fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path,
                                                           preview["plan_sha256"])
        if scenario == "not_enrolled":
            assert denied.value.reason_codes == ["enrollment_required"]
        else:
            assert "audit export is blocked" in denied.value.reasons[0]
        assert not uploads and not runtime.store.records()
        return
    with pytest.raises(Rejected) as changed:
        fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path, "0" * 64)
    assert changed.value.reason_codes == ["plan_changed"] and not uploads
    if scenario == "interrupted_import":
        with pytest.raises(Interrupted):
            fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path,
                                                           preview["plan_sha256"])
        running, = runtime.store.running("adc")
        pending, = execute.recover(runtime, "adc")
        assert pending["change_id"] == running["change_id"] and pending["result"] == "unknown"
        assert [step["step"] for step in pending["steps"]].count("recovery_start") == 1
        readback_unavailable = False
        settled, = execute.recover(runtime, "adc")
        assert settled["result"] == "confirmed" and runtime.store.blocked("adc") is None and uploads == [1]
        return
    confirmed = fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path, preview["plan_sha256"])
    if scenario == "lost_readback":
        assert confirmed["result"] == "unknown" and uploads == [1]
        change_id = confirmed["change_id"]
        from netops_admin import config
        monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
        assert cli.main(["status", "--config", "unused", "--change-id", change_id]) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["result"] == "unknown" and status["change_id"] == change_id
        assert runtime.store.blocked("adc")["change_id"] == change_id
        with pytest.raises(Rejected) as unfinished:
            fortiadc_certificate_import.import_certificate(runtime, device, "import-test", cert_path, key_path)
        assert unfinished.value.reason_codes == ["operation_unfinished"]
        assert execute.recover(runtime, "adc")[0]["result"] == "unknown"
        readback_unavailable = False
        observed = assigned[0]["fingerprint"]
        assigned[0]["fingerprint"] = "\ufffd"
        assert execute.recover(runtime, "adc")[0]["result"] == "unknown"
        assert runtime.store.operation(change_id)["steps"][-1]["detail"] == "readback_mismatch"
        assigned[0]["fingerprint"] = observed
        settled, = execute.recover(runtime, "adc")
        assert settled["change_id"] == change_id and settled["result"] == "confirmed"
        assert runtime.store.blocked("adc") is None and uploads == [1]
        return
    assert confirmed["result"] == "confirmed" and uploads == [1]
    with pytest.raises(Rejected) as already:
        fortiadc_certificate_import.import_certificate(runtime, device, "IMPORT-TEST", cert_path, key_path)
    assert already.value.reason_codes == ["fortiadc_certificate_exists"] and uploads == [1]
    assert "PRIVATE KEY" not in json.dumps(confirmed)
    events = [item for line in runtime.audit.path.read_text().splitlines()
              if (item := json.loads(line))["event"] == "certificate-import"]
    assert [(item["event"], item["status"]) for item in events] == [
        ("certificate-import", "started"), ("certificate-import", "confirmed")]
    assert all(set(item) == {"event", "at", "device", "key", "plan_sha256", "status", "change_id"} for item in events)
    assert all(item["change_id"] == confirmed["change_id"] for item in events)


def test_pinned_pool_preview_does_not_read_certificates(tmp_path):
    certificate_reads = []

    class CertificateTimeout(Wire):
        def query(self, command):
            if command in (GROUP, exec_fortiadc.CERT_NAMES_QUERY):
                certificate_reads.append(command)
            if command == exec_fortiadc.CERT_NAMES_QUERY:
                raise TimeoutError()
            return super().query(command)

    command = fortiadc.show_command(POOL)
    original, changed = capture("pool-member-before"), capture("pool-member-update")
    wire = CertificateTimeout(
        [member_steps("set pool_member_service_port 2526", 'set pool_member_cookie "g34cookie"', "set pool_member_weight 7"),
         member_steps("set pool_member_service_port 2525", "set pool_member_weight 1", 'set pool_member_cookie "rs13"')],
        before={GROUP: (FIXTURES / "groups.out").read_text(), command: original,
                "show load-balance pool": original, "show " + RS: capture("real-ip")},
        after={command: changed, "show load-balance pool": changed})
    runtime = make_runtime(tmp_path, wire, fortiadc_https_sha256=PIN)
    req = request(key=POOL_KEY, changes={"pool-member-weight": 7, "pool-member-service-port": 2526,
                                       "pool-member-cookie": "g34cookie"})
    baseline = execute.preview(runtime, "adc", req)
    assert baseline["result"] == "ready", baseline
    wire.device = runtime.config.devices["adc"]
    pinned = execute.preview(runtime, "adc", req)
    assert pinned == baseline, pinned
    assert not wire.writes
    assert readiness.doctor(runtime, "adc")["firmware"] == "7.6.7 build0676"
    applied = execute.apply(runtime, "adc", req, expected_plan_sha256=pinned["plan_sha256"])
    assert applied["result"] == "confirmed"
    assert execute.undo(runtime, applied["change_id"], "test restore")["result"] == "confirmed"
    assert wire.answers == wire.original and not certificate_reads
