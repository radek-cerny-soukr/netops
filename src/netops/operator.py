import fcntl
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
from .bootstrap import demote, role_environment
from .files import MAX_MESSAGE, STATE, UIDS, check_regular, read_private, write_private
from .gateway import strict_pairs
from .state import read_state_settings, OperatorAccessError



from .diagnostics import configuration_error as _configuration_error
from .diagnostics import configuration_message as _configuration_message
from .diagnostics import syslog_configuration_error as _syslog_configuration_error
from .diagnostics import configuration_json_error as _configuration_json_error
from .diagnostics import RoleConfigurationError, SyslogConfigurationError, operation_error


def _configuration_document(raw, *, syslog=False):
    message = _syslog_configuration_error if syslog else _configuration_message
    def pairs(items):
        try:
            return strict_pairs(items)
        except ValueError:
            raise message("json-duplicate") from None
    def constant(value):
        raise message("json-nonfinite")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (RoleConfigurationError, SyslogConfigurationError):
        raise
    except json.JSONDecodeError as error:
        raise _configuration_json_error(error.lineno, error.colno, syslog=syslog) from None
    except UnicodeError:
        raise message("json-encoding") from None
    except (ValueError, RecursionError):
        raise message("json-limits") from None

def _validate_helper_inventory(path, store):
    from netops_helper import inventory
    try:
        entries = inventory.load(path)
        kinds = {name: store.credential(name).kind for name in store.names()}
        for entry in inventory.devices(entries):
            inventory.section(entry, kinds)
    except inventory.InventoryError as error:
        if getattr(error, "diagnostic", None):
            raise _configuration_error(error, field="inventory") from None
        raise _configuration_message("helper-inventory") from None

def acquire_state():
    read_state_settings(STATE, allow_previous=True)
    descriptor = os.open(STATE / "gateway" / "instance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    if os.fstat(descriptor).st_uid == 0:
        os.fchown(descriptor, UIDS["gateway"], UIDS["gateway"])
    check_regular(descriptor, UIDS["gateway"])
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise OperatorAccessError("Stop the running instance before modifying role configuration or running an operator workflow") from None
    try:
        read_state_settings(STATE)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def configure_syslog():
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    demote(UIDS["gateway"])
    role_environment("gateway")
    try:
        raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise _syslog_configuration_error("size")
        document = _configuration_document(raw, syslog=True)
        if not isinstance(document, dict) or set(document) - {"host", "port", "ca_pem"} or not document.get("host"):
            raise _syslog_configuration_error("envelope")
        from .certificates import names
        try:
            names(document["host"])
        except (ValueError, TypeError, AttributeError):
            raise _syslog_configuration_error("host") from None
        try:
            port = int(document.get("port", 6514))
        except (ValueError, TypeError, OverflowError):
            raise _syslog_configuration_error("port-decimal") from None
        if not 1 <= port <= 65535:
            raise _syslog_configuration_error("port-range")
        from .files import read_private
        config_path = STATE / "gateway" / "config.json"
        settings = json.loads(read_private(config_path, owner=UIDS["gateway"]))
        audit = {**settings["audit"], "mode": "syslog", "host": document["host"], "port": port}
        certificate = document.get("ca_pem")
        if certificate is not None:
            from cryptography import x509
            try:
                parsed = x509.load_pem_x509_certificate(certificate.encode())
                constraints = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
            except (ValueError, TypeError, AttributeError, x509.ExtensionNotFound, x509.InvalidVersion, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
                raise _syslog_configuration_error("certificate") from None
            if not constraints.ca:
                raise _syslog_configuration_error("certificate-ca")
            ca_path = STATE / "gateway" / "syslog-ca.pem"
            write_private(ca_path, certificate.encode(), replace=True)
            audit["ca_file"] = str(ca_path)
        else:
            audit.pop("ca_file", None)
        settings["audit"] = audit
        write_private(config_path, json.dumps(settings).encode(), replace=True)
        print("TLS syslog receiver and trust configured; normal certificate and hostname verification remain enabled.")
    finally:
        os.close(descriptor)
    return 0

def configure_auditor():
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    try:
        _operator_audit_preflight("auditor", "configure")
    except BaseException:
        os.close(descriptor)
        raise
    demote(UIDS["auditor"])
    role_environment("auditor")
    try:
        raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise _configuration_message("size")
        settings = _configuration_document(raw)
        if not isinstance(settings, dict) or not {"tenant", "catalog"} <= set(settings) or set(settings) - {"tenant", "catalog", "inventory", "vault"} or ("inventory" in settings) != ("vault" in settings):
            raise _configuration_message("auditor-envelope")
        from netops_auditor.findings import checked_component
        from netops_auditor.mcp_server import available_platforms, _rules
        from netops_auditor.findings import FingerprintError
        if not isinstance(settings["tenant"], str):
            raise _configuration_error(field="auditor.tenant", code="fingerprint-component")
        try:
            checked_component("tenant", settings["tenant"])
        except FingerprintError:
            raise _configuration_error(field="auditor.tenant", code="fingerprint-component") from None
        if settings["catalog"] not in available_platforms():
            raise _configuration_error(field="auditor.catalog", code="auditor-platform")
        _rules(settings["catalog"])
        directory = STATE / "auditor"
        if "inventory" in settings:
            staging = Path(tempfile.mkdtemp(prefix=".configure-", dir=directory))
            try:
                write_private(staging / "inventory.json", json.dumps(settings["inventory"]).encode())
                write_private(staging / "vault.json", json.dumps(settings["vault"]).encode())
                from netops_core import inventory, vault
                from netops_auditor.cli import _inventory_record, _credential, _catalog_platform, Failure
                try:
                    entries = inventory.load(staging / "inventory.json")
                except inventory.InventoryError as error:
                    raise _configuration_error(error, field="inventory") from None
                try:
                    vault.load(staging / "vault.json")
                except vault.VaultError as error:
                    raise _configuration_error(error, settings) from None
                for index, entry in enumerate(entries):
                    try:
                        record, section = _inventory_record(staging / "inventory.json", entry.name)
                    except Failure as error:
                        raise _configuration_error(error, field="inventory.devices[].auditor", index=index) from None
                    try:
                        _catalog_platform(record)
                    except Failure as error:
                        raise _configuration_error(error, field="inventory.devices[].platform", code="auditor-platform", index=index) from None
                    try:
                        _credential(record, section, staging / "vault.json" if record.credential is not None else None)
                    except (vault.VaultError, Failure) as error:
                        raise _configuration_error(error, field="inventory.devices[].credential", code="channel-credential", reference_field="inventory.devices[].credential", index=index) from None
                for name in ("inventory", "vault"):
                    write_private(directory / (name + ".json"), json.dumps(settings[name]).encode(), replace=True)
            finally:
                shutil.rmtree(staging)
        write_private(directory / "config.json", json.dumps({name: settings[name] for name in ("tenant", "catalog")}).encode(), replace=True)
        print("Auditor configuration validated; existing store data preserved.")
    finally:
        os.close(descriptor)
    return 0


def _admin_notification(config, document, directory):
    from netops_admin.notify import TOPIC
    notify = config.get("notify")
    topic = document.get("notification_topic")
    if notify is None:
        if "notification_topic" in document:
            raise _configuration_message("notification-server")
        return None
    if not isinstance(notify, dict):
        raise _configuration_message("notification-object")
    path = directory / "notification.env"
    if "notification_topic" in document:
        if not isinstance(topic, str) or TOPIC.fullmatch(topic) is None:
            raise _configuration_message("notification-topic")
        data = ("NTFY_TOPIC=" + topic + "\n").encode()
    else:
        try:
            data = read_private(path)
            lines = data.decode().splitlines()
            if len(lines) != 1 or not lines[0].startswith("NTFY_TOPIC="):
                raise ValueError
            stored = lines[0].removeprefix("NTFY_TOPIC=")
            if TOPIC.fullmatch(stored) is None:
                raise ValueError
        except FileNotFoundError:
            raise operation_error("topic-missing") from None
        except (OSError, ValueError, UnicodeError):
            raise operation_error("topic-unreadable") from None
    config["notify"] = {**notify, "topic_file": str(path)}
    return data

def configure(role):
    if role == "syslog":
        return configure_syslog()
    if role == "auditor":
        return configure_auditor()
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    try:
        _operator_audit_preflight(role, "configure")
    except BaseException:
        os.close(descriptor)
        raise
    demote(UIDS[role])
    role_environment(role)
    raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
    if len(raw) > MAX_MESSAGE:
        raise _configuration_message("size")
    document = _configuration_document(raw)
    required = {"inventory", "vault"} if role == "helper" else {"config", "vault"}
    allowed = required if role == "helper" else required | {"notification_topic"}
    if not isinstance(document, dict) or not required <= set(document) or set(document) - allowed:
        raise _configuration_message("role-envelope")
    directory = STATE / role
    staging = Path(tempfile.mkdtemp(prefix=".configure-", dir=directory))
    try:
        write_private(staging / "vault.json", json.dumps(document["vault"]).encode())
        from netops_core import vault
        try:
            store = vault.load(staging / "vault.json")
        except vault.VaultError as error:
            raise _configuration_error(error, document) from None
        if role == "helper":
            write_private(staging / "inventory.json", json.dumps(document["inventory"]).encode())
            _validate_helper_inventory(staging / "inventory.json", store)
            values = {"inventory.json": document["inventory"], "vault.json": document["vault"]}
        else:
            if not isinstance(document["config"], dict):
                raise _configuration_error(field="config", code="object")
            config = dict(document["config"])
            devices = config.get("devices")
            if not isinstance(devices, dict) or not devices:
                raise _configuration_error(field="config.devices", code="nonempty-object")
            if any(not isinstance(device, dict) for device in devices.values()):
                raise _configuration_error(field="config.devices[]", code="object")
            config["state_dir"] = str(directory / "changes")
            config["audit_file"] = str(directory / "operations.jsonl")
            notification = _admin_notification(config, document, directory)
            for device in config.get("devices", {}).values():
                device["vault"] = str(directory / "vault.json")
            from netops_admin.config import load_config, CONFIG_MAX_BYTES
            serialized = json.dumps(config).encode()
            if len(serialized) > CONFIG_MAX_BYTES:
                raise _configuration_error(field="config", code="size")
            write_private(staging / "config.json", serialized)
            from netops_admin.errors import Rejected
            try:
                validated = load_config(staging / "config.json")
            except (Rejected, vault.VaultError) as error:
                raise _configuration_error(error, document) from None
            for device in validated.devices.values():
                for reference in ("credential", "check_credential"):
                    try:
                        store.credential(getattr(device, reference))
                    except vault.VaultError as error:
                        raise _configuration_error(error, document, reference_field="config.devices[]." + reference) from None
            values = {"config.json": config, "vault.json": document["vault"]}
            if notification is not None:
                write_private(directory / "notification.env", notification, replace=True)
        for name, value in values.items():
            write_private(directory / name, json.dumps(value).encode(), replace=True)
        print("Role configuration validated and saved; start NetOps to use it.")
    finally:
        shutil.rmtree(staging)
        os.close(descriptor)
    return 0


def _operator_audit_preflight(role, workflow):
    if role not in UIDS or workflow not in {"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo", "other", "configure", "import-snapshot", "import-policy"}:
        raise operation_error("audit-metadata")
    child = os.fork()
    if child == 0:
        try:
            demote(UIDS["gateway"])
            settings = json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"]))
            audit_settings = settings["audit"]
            if not isinstance(audit_settings, dict) or audit_settings.get("mode") not in ("local", "syslog"):
                raise ValueError("Invalid mandatory audit configuration")
            import asyncio
            import uuid
            from .audit import Audit
            audit = Audit(STATE / "gateway" / "audit", audit_settings)
            asyncio.run(audit.record("operator", {"role": role, "action": "operator-preflight", "workflow": workflow}, uuid.uuid4().hex))
        except BaseException as error:
            try:
                os.write(2, ("netops: Operator audit preflight failed (" + type(error).__name__ + ")\n").encode())
            finally:
                os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise operation_error("audit-unavailable")


def _admin_audit_preflight(arguments=()):
    workflows = {"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo"}
    workflow = arguments[0] if arguments and arguments[0] in workflows else "other"
    return _operator_audit_preflight("admin", workflow)


def role_cli(role, arguments):
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    try:
        if role == "admin":
            _admin_audit_preflight(arguments)
        elif role == "auditor" and arguments and arguments[0] in {"import-snapshot", "import-policy"}:
            _operator_audit_preflight(role, arguments[0])
        demote(UIDS[role])
        role_environment(role)
        if role == "admin":
            from netops_admin.cli import main
            state_commands = {"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo"}
            if arguments and arguments[0] in state_commands:
                arguments = [arguments[0], "--config", str(STATE / role / "config.json"), *arguments[1:]]
            return main(arguments, require_export=False)
        from netops_auditor.cli import main
        directory = STATE / "auditor"
        from . import auditor_inputs
        if arguments and arguments[0] in auditor_inputs.COMMANDS:
            return auditor_inputs.main(directory, arguments)
        if arguments in (["--help"], ["-h"]):
            print(auditor_inputs.help_text())
        if arguments and arguments[0] in {"run", "collect", "status"}:
            settings = json.loads(read_private(directory / "config.json", owner=UIDS[role]))
            defaults = {"--tenant": settings["tenant"], "--store": str(directory / "store.sqlite")}
            if arguments[0] == "collect":
                defaults.update({"--inventory": str(directory / "inventory.json")})
            for option, value in defaults.items():
                if not any(item == option or item.startswith(option + "=") for item in arguments[1:]):
                    arguments = [*arguments, option, value]
        if arguments and arguments[0] == "collect":
            from netops_auditor.cli import Failure, _parser, _inventory_record
            parsed = _parser().parse_args(arguments)
            try:
                record, section = _inventory_record(parsed.inventory, parsed.device)
            except Failure:
                raise operation_error("auditor-inventory") from None
            if record.credential is not None and not any(item == "--vault" or item.startswith("--vault=") for item in arguments[1:]):
                arguments = [*arguments, "--vault", str(directory / "vault.json")]
        snapshot = None
        try:
            if arguments and arguments[0] == "run":
                from netops_auditor.cli import _parser
                parsed = _parser().parse_args(arguments)
                if parsed.config == "-":
                    from netops_auditor.collect import MAX_SNAPSHOT_BYTES
                    data = sys.stdin.buffer.read(MAX_SNAPSHOT_BYTES + 1)
                    if len(data) > MAX_SNAPSHOT_BYTES:
                        raise ValueError("Snapshot exceeds the supported size")
                    handle, name = tempfile.mkstemp(prefix=".snapshot-", dir=directory)
                    os.close(handle)
                    snapshot = Path(name)
                    write_private(snapshot, data, replace=True)
                    arguments = [item if item != "--config=-" else "--config=" + str(snapshot) for item in arguments]
                    for index, item in enumerate(arguments[:-1]):
                        if item == "--config" and arguments[index + 1] == "-":
                            arguments[index + 1] = str(snapshot)
            return main(arguments)
        finally:
            if snapshot is not None:
                snapshot.unlink()
    finally:
        os.close(descriptor)


def _gateway_operator(action):
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    demote(UIDS["gateway"])
    role_environment("gateway")
    settings = json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"]))
    return descriptor, settings


def rotate_instance_ca():
    import asyncio
    import uuid
    from . import certificates
    from .audit import RECOVER_HINT, Audit, AuditUnavailable
    descriptor, settings = _gateway_operator("CA rotation")
    try:
        audit = Audit(STATE / "gateway" / "audit", settings["audit"])
        correlation = uuid.uuid4().hex
        try:
            previous = certificates.ca_fingerprint()
        except Exception:
            previous = None
        name = settings["server_name"]
        certificates.server_name(name)
        try:
            asyncio.run(audit.record("operator", {"action": "ca-rotate", "phase": "start", "previous_ca_sha256": previous, "server_name": name}, correlation))
        except AuditUnavailable:
            hint = RECOVER_HINT if settings["audit"]["mode"] == "local" else "check the syslog receiver and the queue with `audit stats`"
            raise ValueError("Mandatory audit unavailable; CA rotation refused before any change; " + hint) from None
        try:
            current, expires, retired = certificates.rotate_ca(name)
        except Exception as error:
            raise ValueError("CA rotation was interrupted (" + type(error).__name__ + "); the instance cannot start until `docker compose run --rm netops ca rotate` completes") from None
        try:
            asyncio.run(audit.record("operator", {"action": "ca-rotate", "phase": "complete", "previous_ca_sha256": previous, "ca_sha256": current, "server_name": name}, correlation))
            recorded = True
        except AuditUnavailable:
            recorded = False
        print("Instance CA rotated. New CA SHA-256: " + current + "; valid until " + expires.strftime("%Y-%m-%d") + ".")
        print("The previous CA and server key were kept privately in " + retired + "; the token and role data are unchanged.")
        print("Export the new CA with `docker compose run --rm netops ca > netops-ca.pem` and replace the CA at every MCP client before starting the instance; clients that trust only the previous CA refuse the connection.")
        print("If rotation was interrupted, run it again; it always issues a complete new pair.")
        if not recorded:
            sys.stderr.write("netops: the CA was rotated, but its completion record could not be written; only the start record is in the audit; check the audit before starting\n")
            return 3
        return 0
    finally:
        os.close(descriptor)


def recover_audit():
    import asyncio
    import uuid
    from .audit import Audit, AuditUnavailable, recover
    descriptor, settings = _gateway_operator("Audit recovery")
    try:
        audit = Audit(STATE / "gateway" / "audit", settings["audit"])
        results = recover(STATE / "gateway" / "audit")
        if not results:
            print("No incomplete audit record found; this run changed nothing.")
            earlier = len(list((STATE / "gateway" / "audit").glob("incomplete-*.partial")))
            if earlier:
                print("Earlier quarantined fragments remain in the audit directory: " + str(earlier) + " incomplete-*.partial file(s); review them before removing.")
            return 0
        try:
            asyncio.run(audit.record("operator", {"action": "audit-recover", "quarantined": results}, uuid.uuid4().hex))
            recorded = True
        except AuditUnavailable:
            recorded = False
        for item in results:
            print("Moved " + str(item["bytes"]) + " bytes of an incomplete final record from " + item["segment"] + " to " + item["quarantine"] + " (SHA-256 " + item["sha256"] + ").")
        print("Quarantined bytes were kept privately in the audit directory, not deleted. An operation whose response was not recorded may still have completed: check `audit pending` and the actual device state before any repeat.")
        if not recorded:
            sys.stderr.write("netops: the incomplete bytes were quarantined, but the recovery could not be recorded in the audit; check the audit storage before starting\n")
            return 3
        print("The recovery is recorded in the audit.")
        return 0
    finally:
        os.close(descriptor)

