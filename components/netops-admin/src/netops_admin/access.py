from __future__ import annotations

from contextlib import ExitStack, contextmanager, nullcontext
import re
from socket import SOCK_STREAM, getaddrinfo

from netops_auditor import collect
from netops_core import hostkey, platforms, prompt, session, ssh, vault, schema
from netops_core import fortios as core_fortios
from netops_admin import fortinet_cli, fortios, schema_runtime
from netops_admin.errors import Rejected

QUERY_TIMEOUT_SECONDS = 60.0
# vJunos under load answered ssh exec reads in more than 60 s (verification; the measurement of verification saw 121 s until
# the SSH banner), the same limit as a collected snapshot
JUNOS_QUERY_TIMEOUT_SECONDS = 180.0
SNAPSHOT_TIMEOUT_SECONDS = 180.0
LINE_TIMEOUT_SECONDS = 30.0
LOGIN_TIMEOUT_SECONDS = 30.0
PASSWORD_PROMPT = b"password:"
EOS_SNAPSHOT = "show running-config"
NXOS_SNAPSHOT = "show running-config"
IOS_SNAPSHOT = "show running-config"
JUNOS_SNAPSHOT = "show configuration | display set"
FORTINET = ("fortios", "fortiadc")
FORTIOS_GUARD_ENTRY = re.compile(
    r'show (?:full-configuration )?system (?:automation-(?:action|trigger|stitch)|api-user|accprofile) "?'
    + re.escape(fortios.SAFEGUARD_PREFIX) + r'[0-9a-f]{12}-[a-z]+"?'
)
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AccessError(Exception):
    def __init__(self, message, accepted_lines=0):
        super().__init__(message)
        self.accepted_lines = accepted_lines


def operation(access):
    return access.operation() if isinstance(access, DeviceAccess) else nullcontext(access)


def fortios_version_record(status):
    try:
        model, version, build = platforms.version_record(status)
    except platforms.VersionRecordError:
        return None
    if not model.startswith(platforms.PRODUCT_HARDWARE["fortios"]):
        return None
    return model, version, build


class DeviceAccess:
    _fortinet_shells = None
    read_seconds = None
    last_stderr = ""
    # set only for an adapter that watches its on-device timer (TIMER_WATCH: IOS, IOS XE, NX-OS and Junos; Junos
    # through its line_guard_for, see execute.py): a callable that answers whether the next configuration line may
    # still be sent; None (every other platform) sends every line as before
    line_guard = None
    # the answers of the lines of the last apply (decoded, in order); an adapter that needs the output of its own
    # session as evidence (IOS: the archive named by "configure terminal revert timer") reads them
    last_answers = ()
    # set only by an adapter that notes what its own session created (NX-OS safeguard installation): called with the
    # number and the decoded answer of every line the device accepted, right after it; None (every other platform
    # and every other session) calls nothing
    line_answered = None
    # For interactive SSH batches, called with the line number after send and before waiting for its answer.
    # FortiOS calls it without an argument after sending the first line of an apply.
    line_sent = None

    def __init__(self, device):
        self.device = device
        try:
            store = vault.load(device.vault, names=[device.credential, device.check_credential])
            self.credential = store.credential(device.credential)
            self.check_credential = store.credential(device.check_credential)
        except Exception as exc:
            raise AccessError("the credentials cannot be loaded (%s)" % type(exc).__name__) from None
        if self.check_credential.login == self.credential.login and device.platform != "ruckus":
            # Unleashed has one administrator account in the lab: its check reads run in an independent session
            raise AccessError("the check credential logs in with the write account")
        self._host_key_lines = {}
        self.last_stderr = ""

    @property
    def _is_fortinet(self):
        device = getattr(self, "device", None)
        return getattr(device, "platform", None) in FORTINET

    @contextmanager
    def operation(self):
        if not self._is_fortinet or self._fortinet_shells is not None:
            yield self
            return
        with ExitStack() as stack:
            self._fortinet_stack = stack
            self._fortinet_shells = {}
            try:
                yield self
            finally:
                self._fortinet_shells = None

    @contextmanager
    def _fortinet(self, credential, address=None):
        with self.operation():
            # Keep failed attempts and closed sessions in the map until operation exit.
            if credential.login not in self._fortinet_shells:
                self._fortinet_shells[credential.login] = None
                try:
                    shell = self._fortinet_stack.enter_context(session.fortinet_session(
                        self.device, credential, address=address, connect_timeout_seconds=LOGIN_TIMEOUT_SECONDS,
                    ))
                except hostkey.HostKeyError as exc:
                    raise AccessError("host key check failed: %s" % exc) from None
                self._fortinet_shells[credential.login] = shell
            shell = self._fortinet_shells[credential.login]
            if shell is None:
                raise AccessError("Fortinet SSH login already failed in this operation")
            yield shell

    def write_session_lost(self) -> bool:
        if self._fortinet_shells is None:
            return False
        shell = self._fortinet_shells.get(self.credential.login)
        return shell is not None and shell._closed

    def _host_key(self, address=None) -> str:
        address = address or self.device.address
        if self._is_fortinet:
            try:
                return hostkey.pinned_line(address, self.device.port, self.device.host_key_fingerprint,
                                           getattr(self.device, "host_key", None))
            except hostkey.HostKeyError as exc:
                raise AccessError("host key check failed: %s" % exc) from None
        if address not in self._host_key_lines:
            try:
                self._host_key_lines[address] = hostkey.scan(
                    address, self.device.port, self.device.host_key_fingerprint, QUERY_TIMEOUT_SECONDS,
                    legacy=self.device.legacy_ssh,
                )
            except hostkey.HostKeyError as exc:
                raise AccessError("host key check failed: %s" % exc) from None
        return self._host_key_lines[address]

    def snapshot(self) -> str:
        if self.device.platform == "eos":
            # one ssh exec command with privilege 15 at login (measured on cEOSLab 4.36.1F); the plan adapter
            # refuses an answer without its first line "! Command: show running-config" or its last line "end"
            return self._query(self.credential, EOS_SNAPSHOT)
        if self.device.platform == "nxos":
            # one ssh exec command of the write account (network-admin); NX-OS prints no "end", so the plan
            # adapter refuses an answer without its header or without interface mgmt0, line vty and boot nxos
            return self._query(self.credential, NXOS_SNAPSHOT)
        if self.device.platform in ("ios", "iosxe"):
            # one ssh exec command of the write account (privilege 15 at login, measured on IOSv, IOSvL2, IOL XE and
            # IOL-L2 XE); the plan adapter refuses an answer without "Building configuration..." and the configuration
            # size or without its last line "end", and an exec answer "Line has invalid autocommand" (exit status 0)
            text = self._query(self.credential, IOS_SNAPSHOT)
            if self.device.platform in ("ios", "iosxe") and (" switchport" in text or "vlan internal allocation" in text):
                from netops_admin import ios
                text = ios.with_vlan_database(text, self._query(self.credential, "show vlan brief"))
            if re.search(r"^(?:ip|ipv6) access-list ", text, re.MULTILINE):
                # 1.0.12 ios access control: the running configuration of IOS 15.9 omits the sequence numbers of ACL rules, so the
                # ACL listings (the answers of the check account too) are part of the snapshot
                from netops_admin import ios_acl
                text = ios_acl.with_listing(text, self._query(self.credential, ios_acl.LISTING_COMMANDS["ipv4"]),
                                            self._query(self.credential, ios_acl.LISTING_COMMANDS["ipv6"]))
            return text
        if self.device.platform == "junos":
            # one ssh exec command of the write account (measured on vJunos-switch 26.2R1.7: the answer has no pager,
            # starts with "set version" and its status is 0 even for an error); the plan adapter refuses anything else
            return self._query(self.credential, JUNOS_SNAPSHOT)
        if self.device.platform == "ruckus":
            # the pty CLI has no exec channel and no configuration export: Admin composes the snapshot from the
            # identity and the WLAN listing (exec_ruckus.snapshot)
            from netops_admin import exec_ruckus
            try:
                return exec_ruckus.snapshot(self)
            except Rejected:
                raise
            except Exception as exc:
                raise AccessError("snapshot collection failed: %s" % exc) from None
        if self.device.platform == "fortios":
            return self._fortios_snapshot()
        if self.device.platform == "fortiadc":
            # the Auditor collector has no FortiADC steps: Admin composes the four sections it plans against
            from netops_admin import exec_fortiadc
            try:
                with self.operation():
                    return exec_fortiadc.snapshot(self)
            except Rejected:
                raise
            except Exception as exc:
                raise AccessError("snapshot collection failed: %s" % exc) from None
        try:
            taken, _events = collect.collect_ssh(
                self.device.name, self.device.platform, self.device.address, self.device.port,
                self.credential, self.device.host_key_fingerprint, legacy_ssh=self.device.legacy_ssh,
                timeout=SNAPSHOT_TIMEOUT_SECONDS,
            )
        except collect.CollectError as exc:
            raise AccessError("snapshot collection failed: %s" % exc) from None
        return taken.text

    def _fortios_snapshot(self):
        # The Auditor integration runs separately. Preserve its console check
        # and decoding here, using the write-account PTY for both commands.
        try:
            with self._fortinet(self.credential) as shell:
                console = self._fortinet_read(shell, "get system console", SNAPSHOT_TIMEOUT_SECONDS)
                answer = prompt.cleaned(console.stdout.decode("utf-8", "replace"), "fortios")
                field = collect._field(answer, "output")
                if console.rc or field is None:
                    raise AccessError("cannot read output from 'get system console'")
                if field != "standard":
                    raise AccessError("set console output to standard first")
                result = self._fortinet_read(shell, "show", SNAPSHOT_TIMEOUT_SECONDS)
                if result.rc or not result.stdout.strip():
                    raise AccessError("show did not return a complete snapshot")
                return prompt.cleaned(result.stdout.decode("utf-8"), "fortios")
        except (AccessError, UnicodeDecodeError) as exc:
            raise AccessError("snapshot collection failed: %s" % exc) from None
        except session.SessionError as exc:
            raise AccessError("snapshot collection failed: %s" % exc) from None

    def query(self, command: str) -> str:
        return self._query(self.credential, command)

    def diagnose_query(self, command: str) -> str:
        return self._query(self.credential, command, with_stderr=True)

    def query_status(self, command: str) -> tuple:
        """Exit status and stdout answer of a write-account query; the caller judges the status.

        The stderr of the exec call is not part of the answer: the SSH client of the runtime image writes its own
        warnings there (for example that the key exchange is not post-quantum, ref admin-exos-184 N01), and EXOS
        answers on stdout. The cleaned stderr is kept in ``last_stderr`` for diagnosis only.
        """
        return self._query(self.credential, command, any_status=True, with_status=True)

    def resolve_addresses(self, address: str) -> set[str]:
        return {entry[4][0] for entry in getaddrinfo(address, None, type=SOCK_STREAM)}

    def check_query(self, command: str) -> str:
        return self._query(self.check_credential, command, any_status=True,
                           address=self.device.check_address or self.device.address)

    def check_query_status(self, command: str) -> tuple:
        return self._query(self.check_credential, command, any_status=True, with_status=True,
                           address=self.device.check_address or self.device.address)

    def own_query(self, command: str, check: bool = False) -> str:
        if check:
            return self._query(self.check_credential, command, any_status=True, with_stderr=True,
                               address=self.device.check_address or self.device.address)
        return self._query(self.credential, command, any_status=True, with_stderr=True)

    def _fortinet_read(self, shell, command, seconds, *, keep_refusal=False, capture_max_bytes=None):
        original = shell.context
        typed = fortios.typed if self.device.platform == "fortios" and "?" in command else None
        if keep_refusal or typed:
            result = fortinet_cli.dialog(shell, command, seconds, typed=typed, capture_max_bytes=capture_max_bytes)
        else:
            result = shell.run(command, timeout_seconds=seconds, idle_timeout_seconds=seconds,
                               capture_max_bytes=capture_max_bytes)
        if result.continuation or result.context != original:
            shell.close()
            raise AccessError("Fortinet query did not return to its original CLI context")
        return result

    def _query(self, credential, command: str, any_status: bool = False, address=None,
               with_stderr: bool = False, with_status: bool = False):
        address = address or self.device.address
        if self.device.platform == "ruckus":
            return self._ruckus_query(credential, address, command, with_status)
        limit = JUNOS_QUERY_TIMEOUT_SECONDS if self.device.platform == "junos" else QUERY_TIMEOUT_SECONDS
        limit = limit if self.read_seconds is None else min(limit, self.read_seconds)
        guarded = self._is_fortinet and self.device.platform == "fortios" and FORTIOS_GUARD_ENTRY.fullmatch(command)
        try:
            if self._is_fortinet:
                with self._fortinet(credential, address) as shell:
                    result = self._fortinet_read(shell, command, limit, keep_refusal=any_status or guarded)
            else:
                result = ssh.run_command(
                    address, self.device.port, None, credential, self._host_key(address), command,
                    legacy_ssh=self.device.legacy_ssh, timeout_seconds=limit,
                )
        except (ssh.SshError, session.SessionError) as exc:
            raise AccessError("query failed: %s" % exc) from None
        absent_guard = guarded and _fortios_missing(result.stdout.decode("utf-8", "replace"))
        if result.rc != 0 and not (any_status or absent_guard):
            raise AccessError("query ended with exit status %s" % result.rc)
        text = prompt.cleaned(result.stdout.decode("utf-8", "replace"), self.device.platform)
        raw_stderr = getattr(result, "stderr", b"") or b""
        error_text = prompt.cleaned(raw_stderr.decode("utf-8", "replace"), self.device.platform)
        self.last_stderr = error_text
        if not with_stderr:
            return (result.rc, text) if with_status else text
        # FortiADC (measured 7.6.7 build0676) writes the whole exec answer to stderr, so the readers that ask
        # for it (diagnose_query, own_query) keep the joined answer
        if len(raw_stderr) >= ssh.STDERR_MAX_BYTES:
            raise AccessError("query answer on stderr reached the capture limit")
        joined = "\n".join(part for part in (text, error_text) if part.strip())
        return (result.rc, joined) if with_status else joined

    def _ruckus_query(self, credential, address, command, with_status=False):
        """One read in a fresh interactive session (Unleashed has no exec channel): login, enable, the command."""
        from netops_admin import exec_ruckus
        seconds = QUERY_TIMEOUT_SECONDS if self.read_seconds is None else min(QUERY_TIMEOUT_SECONDS, self.read_seconds)
        try:
            with session.Session(address, self.device.port, None, credential, self._host_key(address),
                                 legacy_ssh=self.device.legacy_ssh, timeout_seconds=LOGIN_TIMEOUT_SECONDS) as shell:
                exec_ruckus.login(shell, credential, LOGIN_TIMEOUT_SECONDS)
                shell.send(command)
                _index, data = shell.expect([exec_ruckus.ENABLE_PROMPT], seconds)
        except session.SessionError as exc:
            raise AccessError("query failed: %s" % exc) from None
        text = data.decode("utf-8", "replace")
        return (0, text) if with_status else text

    def _session(self):
        if self._is_fortinet:
            raise AccessError("Fortinet interactive SSH needs the operation session")
        return session.Session(
            self.device.address, self.device.port, None, self.credential, self._host_key(),
            legacy_ssh=self.device.legacy_ssh, timeout_seconds=LOGIN_TIMEOUT_SECONDS,
        )

    def _login(self, shell, spec) -> bytes:
        if getattr(spec, "login", None) is not None:
            return spec.login(shell, self.credential, LOGIN_TIMEOUT_SECONDS)
        _index, data = shell.expect([_login_anchor(spec)] + [anchor.lstrip(b"\n") for anchor in _alternatives(spec)],
                                    LOGIN_TIMEOUT_SECONDS)
        shell.discard(data)
        _index, prompt = shell.expect(list(spec.ends), LOGIN_TIMEOUT_SECONDS)
        return data + prompt

    def login_prefix(self, spec) -> bytes:
        try:
            with self._session() as shell:
                data = self._login(shell, spec)
        except session.SessionError as exc:
            raise AccessError("interactive login failed: %s" % exc) from None
        before, anchor, _after = re.split(rb"[\r\n]", data)[-1].partition(_login_anchor(spec))
        if not anchor:
            raise AccessError("the login prompt does not carry the device name")
        return before.strip()

    def query_interactive(self, command, spec) -> str:
        """Read session-local CLI data that SSH exec does not expose."""
        return self.with_interactive_reader(spec, lambda read: read(command))

    def with_interactive_reader(self, spec, inspect):
        """Keep related read commands in the same interactive SSH session."""
        if self._is_fortinet:
            try:
                with self._fortinet(self.credential) as shell:
                    self._verify_fortinet_hostname(shell, spec)

                    def read(command):
                        seconds = _line_seconds(spec, command)
                        if self.read_seconds is not None:
                            seconds = min(seconds, self.read_seconds)
                        result = self._fortinet_read(shell, command, seconds)
                        text = result.stdout.decode("utf-8", "replace")
                        if result.rc or spec.error("\n" + text) is not None:
                            raise AccessError("interactive query was refused")
                        return text

                    return inspect(read)
            except session.SessionError as exc:
                raise AccessError("interactive query failed: %s" % exc) from None
        try:
            with self._session() as shell:
                self._login(shell, spec)
                def read(command):
                    seconds = _line_seconds(spec, command)
                    if self.read_seconds is not None:
                        seconds = min(seconds, self.read_seconds)
                    shell.send(command)
                    _index, data = shell.expect([spec.anchor], seconds)
                    shell.expect(list(spec.ends), seconds)
                    text = data.decode("utf-8", "replace")
                    if spec.error(text) is not None:
                        raise AccessError("interactive query was refused")
                    return text

                return inspect(read)
        except session.SessionError as exc:
            raise AccessError("interactive query failed: %s" % exc) from None

    def secret_value(self, name: str) -> str:
        """The value of one vault entry that is not a login credential (a Ruckus WLAN passphrase reference). Only
        an api-token entry qualifies, so a reference cannot name the password or key of a device account."""
        try:
            entry = vault.load(self.device.vault, names=[name]).credential(name, where="the passphrase reference")
        except Exception as exc:
            raise Rejected(["the vault entry %s cannot be loaded (%s)" % (name, type(exc).__name__)]) from None
        if entry.kind != "api-token":
            raise Rejected(["the vault entry %s is not a secret entry (kind api-token)" % name])
        return entry.use()

    def apply(self, steps: list, spec) -> int:
        if not all(_usable_anchor(anchor) for anchor in [spec.anchor] + _alternatives(spec)):
            raise AccessError("the device hostname is not usable as a prompt anchor")
        if self._is_fortinet:
            return self._fortinet_apply(steps, spec)
        anchors = [spec.anchor] + _alternatives(spec)
        prompts = anchors + ([spec.continuation] if spec.continuation else [])
        if any(_step(step)[0] == "password" for step in steps) and getattr(self.credential, "kind", None) != "password":
            raise AccessError("the administrator password prompt needs a password write credential")
        accepted, frames, answers = 0, [], []
        self.last_answers = answers
        guard, sent, answered = self.line_guard, self.line_sent, self.line_answered
        secret_values = set()
        answer_secrets = getattr(spec, "answer_secrets", None)
        try:
            with self._session() as shell:
                self._login(shell, spec)
                for number, step in enumerate(steps, 1):
                    kind, text, pattern = _step(step)
                    if guard is not None and not guard():
                        raise AccessError("line %d was not sent: the safeguard of the device has too little time left"
                                          % number, accepted)
                    _enter(frames, text)
                    typed = spec.typed(text) if spec.typed else text
                    resolve = getattr(spec, "resolve", None)
                    if resolve is not None:
                        # 1.0.12 wireless dhcp: a vault reference in the line becomes its secret only here, in the transport
                        typed = resolve(typed, self)
                    if answer_secrets is not None:
                        secret_values.update(answer_secrets(typed))
                    shell.send(typed)
                    if sent is not None:
                        sent(number)
                    if kind == "raw":
                        accepted += 1
                        continue
                    seconds = _line_seconds(spec, text)
                    if kind == "ask":
                        _index, data = shell.expect([pattern], seconds)
                    else:
                        index, data = shell.expect(([PASSWORD_PROMPT] if kind == "password" else []) + prompts,
                                                   seconds)
                        if kind == "password" and index == 0:
                            shell.send(self.credential.use())
                            index, answer = shell.expect(prompts, seconds)
                            data += answer
                        elif kind == "password":
                            index -= 1
                        if index < len(anchors):
                            _tail_index, tail = shell.expect(list(spec.ends), seconds)
                            data += tail
                    answer = data.decode("utf-8", "replace")
                    answers.append(_hide_values(answer, secret_values))
                    # A Ruckus passphrase can contain the same word as a CLI acceptance marker.
                    marker = spec.error(answer)
                    if marker is not None:
                        detail = _hide_values(_answer(spec, answer, marker), secret_values)
                        raise AccessError("line %d%s was refused by the device: %s"
                                          % (number, _where(frames), detail), accepted)
                    _leave(frames, text)
                    accepted += 1
                    if answered is not None:
                        answered(number, answers[-1])
        except session.SessionError as exc:
            reason = _hide_values(str(exc), secret_values)
            raise AccessError("interactive session failed after %d lines: %s" % (accepted, reason), accepted) from None
        return accepted

    def _verify_fortinet_hostname(self, shell, spec):
        if not fortinet_cli.has_hostname(shell, _login_anchor(spec)):
            shell.close()
            raise AccessError("the Fortinet prompt does not match the device hostname")

    def _fortinet_password(self, shell, command, seconds, *, typed=None, required=False):
        reply = fortinet_cli.dialog(shell, command, seconds, typed=typed, password=True)
        if reply.password and not reply.rc:
            try:
                answer = fortinet_cli.dialog(shell, self.credential.use(), seconds, password=True)
                if answer.password:
                    raise AccessError("the device did not accept the administrator password")
                return answer
            except BaseException:
                shell.close()
                raise
        if reply.password:
            shell.close()
        if required:
            raise AccessError("the device did not ask for the administrator password")
        return reply

    def _fortinet_apply(self, steps, spec):
        prepared = [_step(step) for step in steps]
        if any(kind not in ("line", "password") for kind, _, _ in prepared):
            raise AccessError("unsupported Fortinet session step")
        if any(kind == "password" for kind, _, _ in prepared) and self.credential.kind != "password":
            raise AccessError("the administrator password prompt needs a password write credential")
        accepted, frames, answers = 0, [], []
        self.last_answers = answers
        continuing, quotes = False, (False, False)
        try:
            with self._fortinet(self.credential) as shell:
                self._verify_fortinet_hostname(shell, spec)
                original = shell.context
                try:
                    for number, (kind, text, _) in enumerate(prepared, 1):
                        if self.line_guard is not None and not self.line_guard():
                            raise AccessError("line %d was not sent: the safeguard of the device has too little time left"
                                              % number, accepted)
                        if not continuing:
                            _enter(frames, text)
                        seconds = _line_seconds(spec, text)
                        if kind == "password":
                            try:
                                reply = self._fortinet_password(shell, text, seconds, typed=spec.typed)
                            except AccessError as exc:
                                raise AccessError(str(exc), accepted) from None
                        else:
                            reply = fortinet_cli.dialog(shell, text, seconds, typed=spec.typed,
                                                        sent=self.line_sent if number == 1 else None)
                        data = b"\n" + reply.stdout
                        answers.append(data.decode("utf-8", "replace"))
                        marker = spec.error(answers[-1])
                        if marker is not None or reply.rc == 1 or reply.password:
                            if reply.continuation or reply.password:
                                shell.close()
                            raise AccessError("line %d%s was refused by the device: %s"
                                              % (number, _where(frames), _answer(spec, answers[-1], marker or "CLI error")),
                                              accepted)
                        if self.device.platform == "fortios":
                            if continuing or text.startswith('set script "'):
                                quotes = core_fortios._quote_state(("\n" if continuing else "") + text, *quotes)
                            if reply.continuation != quotes[0] or not _scope_transition(
                                    frames, text, original, reply.context, continuing):
                                shell.close()
                                raise AccessError("line %d did not return the expected FortiOS CLI context" % number,
                                                  accepted)
                        if not continuing:
                            _leave(frames, text)
                        continuing = reply.continuation
                        accepted += 1
                        if self.line_answered is not None:
                            self.line_answered(number, answers[-1])
                    if continuing or frames or shell.context != original:
                        raise AccessError("Fortinet write did not return to its original CLI context", accepted)
                except BaseException as exc:
                    if (not continuing and shell.context != original and self.device.platform == "fortios"
                            and isinstance(exc, AccessError) and "was refused by the device" in str(exc)
                            and self._abort_block(shell, original, spec)):
                        frames.clear()
                    if continuing or shell.context != original or (original is not None and frames):
                        shell.close()
                    raise
        except session.SessionError as exc:
            raise AccessError("interactive session failed after %d lines: %s" % (accepted, exc), accepted) from None
        return accepted

    def _abort_block(self, shell, original, spec) -> bool:
        """1.0.12 firewall commit: a line the device refused inside a config or edit block leaves FortiOS in that block. `abort`
        discards the unfinished edit and returns the held session to its context, so the return of a profile batch
        runs on the same session (one held session per operation and account)."""
        try:
            reply = fortinet_cli.dialog(shell, "abort", _line_seconds(spec, "abort"))
        except Exception:
            return False
        return reply.rc == 0 and not reply.continuation and not reply.password and shell.context == original

    def generate_api_key(self, command: str, spec) -> str:
        if getattr(self.credential, "kind", None) != "password":
            raise AccessError("the API key needs a password write credential")
        if not HOSTNAME.fullmatch(spec.anchor.decode("ascii", "replace").strip().rstrip(".")):
            raise AccessError("the device hostname is not usable as a prompt anchor")
        if self._is_fortinet:
            try:
                with self._fortinet(self.credential) as shell:
                    self._verify_fortinet_hostname(shell, spec)
                    original = shell.context
                    reply = self._fortinet_password(shell, command, LINE_TIMEOUT_SECONDS, required=True)
                    if reply.continuation or reply.context != original:
                        shell.close()
                        raise AccessError("API key generation did not return to its original CLI context")
                    if reply.rc or spec.error("\n" + reply.stdout.decode("utf-8", "replace")) is not None:
                        raise AccessError("the device refused API key generation")
                    return reply.stdout.decode("utf-8", "replace")
            except session.SessionError as exc:
                raise AccessError("interactive session failed while generating the API key: %s" % exc) from None
        try:
            with self._session() as shell:
                self._login(shell, spec)
                shell.send(command)
                index, asked = shell.expect([PASSWORD_PROMPT, spec.anchor], LINE_TIMEOUT_SECONDS)
                if index != 0:
                    raise AccessError("the device did not ask for the administrator password")
                shell.send(self.credential.use())
                _index, answer = shell.expect([spec.anchor], LINE_TIMEOUT_SECONDS)
                shell.expect(list(spec.ends), LINE_TIMEOUT_SECONDS)
        except session.SessionError as exc:
            raise AccessError("interactive session failed while generating the API key: %s" % exc) from None
        return (asked + answer).decode("utf-8", "replace")


def _scope_transition(frames, command, home, context, continuing):
    if continuing or len(frames) != 1:
        return True
    scope, _ = frames[0]
    if scope not in ("config global", "config vdom"):
        return True
    if command == scope:
        return context == scope.split()[1]
    if command == "end":
        return context == home
    if scope == "config vdom" and command.startswith("edit "):
        tokens = core_fortios.tokenize(command)
        return len(tokens) == 2 and context == tokens[1]
    return True


def _fortios_missing(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines in ([fortios.NOT_FOUND], [fortios.NOT_FOUND, "Command fail. Return code -3"])


def _line_seconds(spec, text) -> float:
    limit = getattr(spec, "seconds", None)
    return LINE_TIMEOUT_SECONDS if limit is None else float(limit(text))


def _enter(frames, text):
    words = text.strip().split(None, 1)
    if words[:1] == ["config"]:
        frames.append([text.strip(), None])
    elif words[:1] == ["edit"] and frames:
        frames[-1][1] = text.strip()


def _leave(frames, text):
    word = text.strip()
    if word == "next" and frames:
        frames[-1][1] = None
    elif word == "end" and frames:
        frames.pop()


def _where(frames) -> str:
    parts = [part for frame in frames for part in frame if part]
    return " (%s)" % ", ".join(parts) if parts else ""


def _hide_values(text: str, values: set[str]) -> str:
    if not values:
        return text
    from netops_admin.ruckus import strip_terminal_controls

    text = strip_terminal_controls(text)
    pattern = "|".join(re.escape(value) for value in sorted(values, key=len, reverse=True))
    return re.sub(pattern, "<redacted>", text)


def _answer(spec, data: str, marker: str) -> str:
    rows = data.replace("\r", "").split("\n")[1:]
    found = [row.strip() for row in rows if row.strip() and spec.error("\n" + row) is not None]
    return " | ".join(found) or marker


def _login_anchor(spec) -> bytes:
    return spec.anchor.lstrip(b"\n")


def _alternatives(spec) -> list:
    """The alternative prompt anchors of the spec (1.0.12 junos port ownership: the old and the new Junos host name)."""
    return list(getattr(spec, "anchors", ()) or ())


def _usable_anchor(anchor: bytes) -> bool:
    """A prompt anchor is a host name, optionally after the "@" of a Junos prompt (1.0.12 junos port ownership)."""
    text = anchor.decode("ascii", "replace").strip().rstrip(".")
    return bool(HOSTNAME.fullmatch(text[1:] if text.startswith("@") else text))


def _step(step):
    if isinstance(step, str):
        return "line", step, None
    if step[0] == "raw" and len(step) == 2:
        return "raw", step[1], None
    if step[0] == "password" and len(step) == 2:
        return "password", step[1], None
    if step[0] == "ask" and len(step) == 3:
        return "ask", step[1], step[2]
    raise AccessError("unknown session step")


class SchemaAccess:
    def __init__(self,base,device):
        self.base=base;self.device=device;self.credential=base.credential;self.check_credential=base.check_credential
        self.lib,_=schema_runtime.policy(device)
        status=base.query("get system status")
        try:identity=platforms.version_record(status)
        except platforms.VersionRecordError:identity=None
        names=re.findall(r"(?m)^Hostname:\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\s*$",status)
        if identity is None or len(names)!=1:raise Rejected(["schema live identity cannot be established"])
        try:self.lib.require_identity(*identity)
        except ValueError:raise Rejected(["schema live identity differs from the measured library"]) from None
        self.hostname=names[0]
        self.spec=schema_runtime.exec_fortios.prompt_spec(self.hostname)

    def _require_vdom(self,domain):
        if domain not in self.device.schema["vdoms"]:
            raise Rejected(["schema live VDOM is outside the declared binding"])
        try:
            answer=self._context(None,"show full-configuration system vdom-property")
            table=core_fortios.parse(self._body(answer)).section("system vdom-property")
        except Exception:
            raise Rejected(["schema live VDOM inventory cannot be established"]) from None
        if table is None or domain not in table.entries:
            raise Rejected(["schema live VDOM does not exist"])

    def _context(self, domain, command, check=False, allow_not_found=False):
        if domain is not None:
            self._require_vdom(domain)
        credential = self.check_credential if check else self.credential
        address = self.device.check_address or self.device.address if check else self.device.address
        try:
            with self.base._fortinet(credential, address) as shell:
                self.base._verify_fortinet_hostname(shell, self.spec)
                home = shell.context
                current = []
                if check and domain is not None:
                    status = self.base.check_query("get system status")
                    current = re.findall(r"(?m)^Current virtual domain:[ \t]+(\S+)[ \t]*$", status)
                direct = domain is not None and current == [domain] and home in (None, domain)
                if direct:
                    return self._read_scope(shell, command, allow_not_found)
                context = "global" if domain is None else "vdom"
                if home == context:
                    shell.close()
                    raise Rejected(["schema live session is already in the requested CLI context"])
                self._navigate(shell, "config " + context, context)
                try:
                    if domain is not None:
                        self._navigate(shell, "edit " + schema.quoted(domain), domain)
                    return self._read_scope(shell, command, allow_not_found)
                finally:
                    if not shell._closed:
                        self._navigate(shell, "end", home)
        except session.SessionError as exc:
            raise Rejected(["schema live read failed: %s" % exc]) from None

    def _navigate(self, shell, command, expected):
        result = shell.run(command, timeout_seconds=60, idle_timeout_seconds=60)
        if (result.rc or result.continuation or result.context != expected
                or fortios.cli_error("\n" + result.stdout.decode("utf-8", "replace")) is not None):
            shell.close()
            raise Rejected(["schema live CLI context could not be verified"])

    def _read_scope(self, shell, command, allow_not_found):
        result = self.base._fortinet_read(shell, command, 180 if command == "show" else 60,
                                         keep_refusal=allow_not_found, capture_max_bytes=schema_runtime.MAX_BYTES)
        text = result.stdout.decode("utf-8", "replace")
        if (result.rc or fortios.cli_error("\n" + text)) and not (allow_not_found and _fortios_missing(text)):
            raise Rejected(["schema live read context was refused"])
        return text

    def snapshot(self, check=False):
        with self.base.operation():
            return self._snapshot(check)

    def _snapshot(self, check):
        outputs={}
        for domain in [None]+self.device.schema["vdoms"]:
            answer=self._context(domain,"show",check)
            lines=answer.splitlines()
            start=next((i for i,x in enumerate(lines) if x.lstrip().startswith("config ")),None)
            end=max((i for i,x in enumerate(lines) if x.strip()=="end"),default=-1)
            if start is None or end<start:raise Rejected(["schema live snapshot boundaries are missing"])
            outputs[domain]="\n".join(lines[start:end+1])+"\n"
        text="config global\n"+outputs[None]+"end\nconfig vdom\n"
        for domain in self.device.schema["vdoms"]:
            text+="edit "+schema.quoted(domain)+"\n"+outputs[domain]+"next\n"
        text+="end\n"
        tree=schema_runtime._parse(text)
        schema_runtime.scoped_fortios.views(self.lib,tree)
        return text

    def observe(self, plan):
        with self.base.operation():
            return self._observe(plan)

    def _observe(self, plan):
        domains=list(dict.fromkeys(step["operation"]["scope"] for step in plan["schema_plan"]["operations"]))
        text="config global\n"
        if None in domains:
            text+=self._body(self._context(None,"show",True))
        text+="end\nconfig vdom\n"
        for domain in domains:
            if domain is not None:
                text+="edit "+schema.quoted(domain)+"\n"+self._body(self._context(domain,"show",True))+"next\n"
        text+="end\n"
        tree=schema_runtime._parse(text)
        schema_runtime._generated(tree,plan,"after")
        objects=[]
        for step in schema_runtime.targets(plan["schema_plan"]):
            _,_,node=schema_runtime.schema_plan._locate(tree,self.lib,step["operation"])
            objects.append(schema_runtime.schema_plan._digest(schema_runtime.schema_plan._state(node) if node is not None else None))
        return {"objects":objects}

    @staticmethod
    def _body(answer):
        lines=answer.splitlines()
        start=next((i for i,x in enumerate(lines) if x.lstrip().startswith("config ")),None)
        end=max((i for i,x in enumerate(lines) if x.strip()=="end"),default=-1)
        if start is None or end<start:
            raise Rejected(["schema live snapshot boundaries are missing"])
        return "\n".join(lines[start:end+1])+"\n"

    def query(self,command):
        allow_missing=re.fullmatch(r"show system automation-(?:action|trigger|stitch) "+re.escape(schema_runtime.fortios.SAFEGUARD_PREFIX)+r"[0-9a-f]{12}-[ats]",command) is not None
        answer=self._context(None,command,allow_not_found=allow_missing)
        lines=answer.splitlines()
        start=next((i for i,x in enumerate(lines) if x.lstrip().startswith("config ")),None)
        end=max((i for i,x in enumerate(lines) if x.strip()=="end"),default=-1)
        return "\n".join(lines[start:end+1])+"\n" if start is not None and end>=start else answer

    def apply(self,lines,spec):
        return self.base.apply(lines,spec)
