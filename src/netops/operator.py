import fcntl
import json
import os
import re
from pathlib import Path
import shutil
import signal
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
from .diagnostics import helper_inventory_error as _helper_inventory_error
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
        warnings = []
        for entry in inventory.devices(entries):
            try:
                section = inventory.section(entry, kinds)
            except inventory.InventoryError as error:
                error.diagnostic_index = list(entries).index(entry)
                raise
            if section.fortios_rest_credential:
                from netops_helper.wifi_rest import checked_token
                try:
                    checked_token(store.credential(section.fortios_rest_credential).use())
                except ValueError:
                    raise _configuration_message("helper-rest-token") from None
            warnings.extend(inventory.section_warnings(entry.name, section))
        return warnings
    except inventory.InventoryError as error:
        if getattr(error, "diagnostic", None):
            raise _configuration_error(error, field="inventory") from None
        located = _helper_inventory_error(error)
        if located is not None:
            raise located from None
        raise _configuration_message("helper-inventory") from None

RUNNING_MESSAGE = "Stop the running instance before modifying role configuration or running an operator workflow"
STORE_BUSY_MESSAGE = ("Another Auditor write is running (auditor collect, run or status, or an Auditor operator workflow"
                      " holds auditor/store.lock); wait for it to finish and retry")
RUNNING_ELSEWHERE_MESSAGE = ("Another NetOps instance or operator workflow holds the state; next to a running instance, auditor collect,"
                             " run and status run only inside its container with `docker compose exec netops netops auditor ...`;"
                             " otherwise stop the instance or wait for the workflow")
# Auditor commands that may run inside the running instance (`docker compose exec`).
RUNNING_AUDITOR_COMMANDS = frozenset({"collect", "run", "status"})
# Auditor commands with an operator preflight and an operator result record.
RESULT_AUDITOR_COMMANDS = frozenset({"collect", "run"})
RESULT_LIMIT = 4096
EXCEPTION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")

# Store locks taken together with the instance lock, keyed by the returned descriptor.
_STORE_LOCKS = {}


class InstanceRunningError(OperatorAccessError):
    pass


def _open_instance_lock():
    descriptor = os.open(STATE / "gateway" / "instance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        check_regular(descriptor)
        if os.fstat(descriptor).st_uid == 0:
            os.fchown(descriptor, UIDS["gateway"], UIDS["gateway"])
        check_regular(descriptor, UIDS["gateway"])
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _acquire_store_lock():
    """Exclusive non-blocking flock of auditor/store.lock; None when no Auditor state directory exists."""
    try:
        descriptor = os.open(STATE / "auditor" / "store.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileNotFoundError:
        # No Auditor directory, so no Auditor store or input exists that a concurrent write could touch.
        return None
    try:
        check_regular(descriptor)
        if os.fstat(descriptor).st_uid == 0:
            os.fchown(descriptor, UIDS["auditor"], UIDS["auditor"])
        check_regular(descriptor, UIDS["auditor"])
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OperatorAccessError(STORE_BUSY_MESSAGE) from None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def acquire_state():
    read_state_settings(STATE, allow_previous=True)
    descriptor = _open_instance_lock()
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise InstanceRunningError(RUNNING_MESSAGE) from None
    try:
        read_state_settings(STATE)
        store = _acquire_store_lock()
    except BaseException:
        os.close(descriptor)
        raise
    if store is not None:
        _STORE_LOCKS[descriptor] = store
    return descriptor


def release_state(descriptor):
    store = _STORE_LOCKS.pop(descriptor, None)
    try:
        os.close(descriptor)
    finally:
        if store is not None:
            os.close(store)


def _instance_lock_mount_device(descriptor):
    """Superblock device of the lock's most specific mount, in /proc/locks terms.

    btrfs stat() reports an anonymous subvolume device, while both mountinfo
    and /proc/locks report the superblock device. Resolve the open descriptor
    so the mount lookup refers to the same file as fstat(), including bind mounts.
    """
    try:
        path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        with open("/proc/self/mountinfo", "rb") as handle:
            lines = handle.read(1048576).splitlines()
    except OSError:
        return None
    if not path.is_absolute():
        return None
    device, depth = None, -1
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or b"-" not in fields[6:]:
            continue
        # proc escapes whitespace and backslashes in mount paths as octal bytes.
        mount = Path(os.fsdecode(re.sub(rb"\\(040|011|012|134)",
                                       lambda match: bytes([int(match[1], 8)]), fields[4])))
        if not mount.is_absolute() or not path.is_relative_to(mount) or len(mount.parts) <= depth:
            continue
        numbers = fields[2].split(b":")
        try:
            if len(numbers) != 2:
                continue
            candidate = (int(numbers[0]), int(numbers[1]))
        except ValueError:
            continue
        device, depth = candidate, len(mount.parts)
    return device


def _instance_holder_pid(descriptor):
    """PID of the exclusive flock holder of instance.lock as visible in this PID namespace.

    /proc/locks shows the holder PID translated into the PID namespace of the reader
    and 0 when the holder runs in another container (`docker compose run`).
    """
    info = os.fstat(descriptor)
    file_device = (os.major(info.st_dev), os.minor(info.st_dev))
    mount_device, mountinfo_read = None, False
    try:
        with open("/proc/locks", "rb") as handle:
            lines = handle.read(1048576).splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or fields[1] == b"->" or fields[1] != b"FLOCK" or fields[3] != b"WRITE":
            continue
        identity = fields[5].split(b":")
        try:
            if len(identity) != 3 or int(identity[2]) != info.st_ino:
                continue
            device = (int(identity[0], 16), int(identity[1], 16))
            if device != file_device:
                if not mountinfo_read:
                    mount_device = _instance_lock_mount_device(descriptor)
                    mountinfo_read = True
                if device != mount_device:
                    continue
            return int(fields[4])
        except ValueError:
            continue
    return None


def _running_instance_here(descriptor):
    """True when the instance.lock holder is the gateway `serve` process of this container."""
    pid = _instance_holder_pid(descriptor)
    # compose.yaml has a private PID namespace and no init wrapper. netops-start
    # execs `python /usr/local/bin/netops serve`, so the gateway remains PID 1.
    # A gateway-UID child can copy argv, but cannot become that namespace's PID 1.
    if pid != 1 or pid == os.getpid():
        return False
    try:
        with open("/proc/" + str(pid) + "/status", "rb") as handle:
            status = handle.read(65536)
        with open("/proc/" + str(pid) + "/cmdline", "rb") as handle:
            command = handle.read(65536).split(b"\0")
    except OSError:
        return False
    uids = [line.split()[1:] for line in status.splitlines() if line.startswith(b"Uid:")]
    try:
        effective = int(uids[0][1])
    except (IndexError, ValueError):
        return False
    # The gateway keeps the lock of `netops serve` after it demoted itself to the gateway UID.
    return effective == UIDS["gateway"] and b"serve" in command


def acquire_auditor_state():
    """Locks for `auditor collect|run|status`.

    Stopped instance: the 1.0.8 behavior (instance.lock) plus auditor/store.lock.
    Running instance in this container (`docker compose exec`): auditor/store.lock only,
    the instance keeps instance.lock. A running instance in another container
    (`docker compose run` next to it) stays refused.
    """
    try:
        return acquire_state()
    except InstanceRunningError:
        pass
    # The running instance and this command come from one image: the state must hold this version.
    read_state_settings(STATE)
    descriptor = _open_instance_lock()
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            running = True
        else:
            # The instance stopped meanwhile; keep the stopped-instance behavior.
            running = False
        if running and not _running_instance_here(descriptor):
            raise OperatorAccessError(RUNNING_ELSEWHERE_MESSAGE)
        store = _acquire_store_lock()
        if running and store is None:
            # A started instance always prepared the Auditor directory.
            raise OperatorAccessError(RUNNING_MESSAGE)
    except BaseException:
        os.close(descriptor)
        raise
    if not running:
        if store is not None:
            _STORE_LOCKS[descriptor] = store
        return descriptor
    os.close(descriptor)
    return store


def configure_syslog():
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    try:
        recorded = _syslog_audit_preflight()
    except BaseException:
        release_state(descriptor)
        raise
    demote(UIDS["gateway"])
    role_environment("gateway")
    try:
        raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise _syslog_configuration_error("size")
        document = _configuration_document(raw, syslog=True)
        if not isinstance(document, dict) or set(document) - {"host", "port", "ca_pem"} or not document.get("host"):
            raise _syslog_configuration_error("envelope")
        if not isinstance(document["host"], str):
            raise _syslog_configuration_error("host-type")
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
        if not recorded:
            sys.stderr.write("netops: the new syslog target was saved, but the full or unavailable audit queue could not take a record, so this change is not recorded in the audit; start the instance and check delivery with `audit stats`\n")
            return 3
    finally:
        release_state(descriptor)
    return 0


def _syslog_audit_preflight():
    try:
        _operator_audit_preflight("gateway", "configure")
    except ValueError as error:
        if getattr(error, "operation_diagnostic", None) != "audit-unavailable":
            raise
        settings = json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"]))
        if settings["audit"].get("mode") != "syslog":
            raise
        return False
    return True

def configure_auditor():
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    descriptor = acquire_state()
    try:
        _operator_audit_preflight("auditor", "configure")
    except BaseException:
        release_state(descriptor)
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
        release_state(descriptor)
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
        release_state(descriptor)
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
            for warning in _validate_helper_inventory(staging / "inventory.json", store):
                print("Warning: " + warning, file=sys.stderr)
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
        release_state(descriptor)
    return 0


PREFLIGHT_WORKFLOWS = frozenset({"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo", "other",
                                 "configure", "import-snapshot", "import-policy", "collect", "run"})


def _operator_audit_record(payload, correlation):
    """Write one operator record as the gateway UID (only inside a forked child)."""
    demote(UIDS["gateway"])
    settings = json.loads(read_private(STATE / "gateway" / "config.json", owner=UIDS["gateway"]))
    audit_settings = settings["audit"]
    if not isinstance(audit_settings, dict) or audit_settings.get("mode") not in ("local", "syslog"):
        raise ValueError("Invalid mandatory audit configuration")
    import asyncio
    from .audit import Audit
    audit = Audit(STATE / "gateway" / "audit", audit_settings)
    asyncio.run(audit.record("operator", payload, correlation))


def _operator_audit_preflight(role, workflow, correlation=None):
    if role not in UIDS or workflow not in PREFLIGHT_WORKFLOWS:
        raise operation_error("audit-metadata")
    if correlation is None:
        import uuid
        correlation = uuid.uuid4().hex
    child = os.fork()
    if child == 0:
        try:
            _operator_audit_record({"role": role, "action": "operator-preflight", "workflow": workflow}, correlation)
        except BaseException as error:
            try:
                os.write(2, ("netops: Operator audit preflight failed (" + type(error).__name__ + ")\n").encode())
            finally:
                os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise operation_error("audit-unavailable")


def _checked_result(raw):
    """Validated operator result received from the demoted workflow process; empty input = interrupted."""
    if not raw:
        return {"completed": False, "exit": None, "run_id": None}
    result = json.loads(raw, object_pairs_hook=strict_pairs)
    if not isinstance(result, dict) or set(result) - {"exit", "run_id", "exception"}:
        raise ValueError("Invalid operator result")
    for name in ("exit", "run_id"):
        value = result.get(name)
        if value is not None and (type(value) is not int or not -2147483648 <= value <= 9223372036854775807):
            raise ValueError("Invalid operator result")
    exception = result.get("exception")
    if exception is not None and (not isinstance(exception, str) or EXCEPTION_NAME.fullmatch(exception) is None):
        raise ValueError("Invalid operator result")
    checked = {"completed": exception is None, "exit": result.get("exit"), "run_id": result.get("run_id")}
    if exception is not None:
        checked["exception"] = exception
    return checked


def _operator_audit_result(role, workflow, correlation, previous):
    """Start the gateway-UID writer of the operator result record before the caller demotes.

    The caller demotes to the role UID and cannot write the gateway audit itself; it sends
    the outcome over a pipe. A caller that ends without sending (killed) closes the pipe,
    and the record then says the workflow did not complete.

    Call only with SIGINT blocked (see `_recorded_role_main`); `previous` is the signal mask
    to restore. Ctrl+C reaches the whole terminal process group, this writer included: a
    SIGINT that reaches the writer before it ignores the signal stays pending (blocked) and
    is discarded by SIG_IGN, so the writer always records the interrupted workflow.
    """
    if role != "auditor" or workflow not in RESULT_AUDITOR_COMMANDS:
        raise operation_error("audit-metadata")
    read_end, write_end = os.pipe()
    try:
        child = os.fork()
    except BaseException:
        os.close(read_end)
        os.close(write_end)
        raise
    if child == 0:
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            os.close(write_end)
            chunks, size = [], 0
            while True:
                part = os.read(read_end, RESULT_LIMIT + 1)
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                if size > RESULT_LIMIT:
                    raise ValueError("Operator result exceeds its limit")
            os.close(read_end)
            result = _checked_result(b"".join(chunks))
            _operator_audit_record({"role": role, "action": "operator-result", "workflow": workflow, **result}, correlation)
        except BaseException as error:
            try:
                os.write(2, ("netops: Operator audit result failed (" + type(error).__name__ + ")\n").encode())
            finally:
                os._exit(1)
        os._exit(0)
    os.close(read_end)
    return child, write_end


def _finish_operator_result(writer, outcome):
    child, write_end = writer
    try:
        try:
            os.write(write_end, json.dumps(outcome, separators=(",", ":")).encode()[:RESULT_LIMIT])
        finally:
            os.close(write_end)
    except OSError:
        pass
    try:
        _, status = os.waitpid(child, 0)
    except OSError:
        return False
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def _latest_run_id(path):
    """Highest run id in the Auditor store, read-only; None when unknown."""
    import sqlite3
    try:
        location = Path(path)
        if not location.is_file():
            return None
        from netops_auditor.store import BUSY_TIMEOUT_SECONDS
        connection = sqlite3.connect(location.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None,
                                     timeout=BUSY_TIMEOUT_SECONDS)
        try:
            row = connection.execute("SELECT max(id) FROM runs").fetchone()
        finally:
            connection.close()
    except (OSError, ValueError, sqlite3.Error):
        return None
    value = row[0] if row else None
    return value if type(value) is int else None


def _admin_audit_preflight(arguments=()):
    workflows = {"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo"}
    workflow = arguments[0] if arguments and arguments[0] in workflows else "other"
    return _operator_audit_preflight("admin", workflow)


def role_cli(role, arguments):
    if os.geteuid() != 0:
        raise OperatorAccessError("Use the image default container user for this operator command; remove any --user override")
    store_command = role == "auditor" and bool(arguments) and arguments[0] in RUNNING_AUDITOR_COMMANDS
    descriptor = acquire_auditor_state() if store_command else acquire_state()
    try:
        if role == "admin":
            _admin_audit_preflight(arguments)
        elif role == "auditor" and arguments and arguments[0] in {"import-snapshot", "import-policy"}:
            _operator_audit_preflight(role, arguments[0])
        elif store_command and arguments[0] in RESULT_AUDITOR_COMMANDS:
            import uuid
            correlation = uuid.uuid4().hex
            _operator_audit_preflight(role, arguments[0], correlation)
            return _recorded_role_main(role, arguments, correlation)
        return _role_main(role, arguments)
    finally:
        release_state(descriptor)


def _recorded_role_main(role, arguments, correlation):
    """Run the workflow with its result writer; the writer is owned and reaped on every exit path.

    SIGINT stays blocked from before the writer exists until the try below owns it, and again
    from the finally until the writer is reaped. A Ctrl+C in between is therefore only taken
    where the finally sends the incomplete result and waits; the writer inherits the descriptors
    of the state locks, so the caller never returns while the writer still holds them.
    """
    outcome = {"exit": None, "run_id": None}
    writer, returned = None, False
    # Only reads the current mask; a Ctrl+C up to the block below ends before any writer exists.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        writer = _operator_audit_result(role, arguments[0], correlation, previous)
        # A SIGINT that arrived since the block (also during the fork) is raised here as KeyboardInterrupt.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        code = _role_main(role, arguments, outcome)
        outcome["exit"] = code if type(code) is int else None
        returned = True
        return code
    finally:
        try:
            # A further Ctrl+C (also one already pending) waits until the writer is reaped.
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        finally:
            try:
                if writer is not None:
                    if not returned:
                        # described here, with SIGINT blocked, so a second Ctrl+C cannot leave it out
                        _exception_outcome(outcome, sys.exc_info()[1])
                    if not _finish_operator_result(writer, outcome):
                        sys.stderr.write("netops: the Auditor " + arguments[0] + " ended, but its result could not be"
                                         " recorded in the audit; only the operator preflight record is there; check the"
                                         " audit storage with `audit stats`\n")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _exception_outcome(outcome, error):
    """The operator result of a workflow that ended with `error` instead of returning."""
    if isinstance(error, SystemExit):
        outcome["exit"] = 0 if error.code is None else error.code if type(error.code) is int else 1
    else:
        outcome["exception"] = type(error).__name__


def _role_main(role, arguments, outcome=None):
    demote(UIDS[role])
    role_environment(role)
    if role == "admin":
        from netops_admin.cli import main
        state_commands = {"apply", "preview", "doctor", "enroll", "status", "recover", "notify-retry", "unblock", "undo",
                          "pool-member", "pool-member-add", "pool-member-remove"}
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
        if outcome is None:
            return main(arguments)
        # The store lock excludes every other Auditor writer and the MCP server never
        # writes, so a new highest run id after the command is the run of this command.
        store = getattr(parsed, "store", None)
        before = _latest_run_id(store) if store else None
        try:
            return main(arguments)
        finally:
            after = _latest_run_id(store) if store else None
            if after is not None and after != before:
                outcome["run_id"] = after
    finally:
        if snapshot is not None:
            snapshot.unlink()


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
        release_state(descriptor)


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
        release_state(descriptor)

