from __future__ import annotations

import re

from netops_auditor import collect
from netops_core import hostkey, prompt, session, ssh, vault

QUERY_TIMEOUT_SECONDS = 60.0
SNAPSHOT_TIMEOUT_SECONDS = 180.0
LINE_TIMEOUT_SECONDS = 30.0
LOGIN_TIMEOUT_SECONDS = 30.0
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AccessError(Exception):
    def __init__(self, message, accepted_lines=0):
        super().__init__(message)
        self.accepted_lines = accepted_lines


class DeviceAccess:
    def __init__(self, device):
        self.device = device
        try:
            store = vault.load(device.vault, names=[device.credential, device.check_credential])
            self.credential = store.credential(device.credential)
            self.check_credential = store.credential(device.check_credential)
        except Exception as exc:
            raise AccessError("the credentials cannot be loaded (%s)" % type(exc).__name__) from None
        if self.check_credential.login == self.credential.login:
            raise AccessError("the check credential logs in with the write account")
        self._host_key_lines = {}

    def _host_key(self, address=None) -> str:
        address = address or self.device.address
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
        try:
            taken, _events = collect.collect_ssh(
                self.device.name, self.device.platform, self.device.address, self.device.port,
                self.credential, self.device.host_key_fingerprint, legacy_ssh=self.device.legacy_ssh,
                timeout=SNAPSHOT_TIMEOUT_SECONDS,
            )
        except collect.CollectError as exc:
            raise AccessError("snapshot collection failed: %s" % exc) from None
        return taken.text

    def query(self, command: str) -> str:
        return self._query(self.credential, command)

    def check_query(self, command: str) -> str:
        return self._query(self.check_credential, command, any_status=True,
                           address=self.device.check_address or self.device.address)

    def _query(self, credential, command: str, any_status: bool = False, address=None) -> str:
        address = address or self.device.address
        try:
            result = ssh.run_command(
                address, self.device.port, None, credential, self._host_key(address), command,
                legacy_ssh=self.device.legacy_ssh, timeout_seconds=QUERY_TIMEOUT_SECONDS,
            )
        except ssh.SshError as exc:
            raise AccessError("query failed: %s" % exc) from None
        if result.rc != 0 and not any_status:
            raise AccessError("query ended with exit status %s" % result.rc)
        return prompt.cleaned(result.stdout.decode("utf-8", "replace"), self.device.platform)

    def _session(self):
        return session.Session(
            self.device.address, self.device.port, None, self.credential, self._host_key(),
            legacy_ssh=self.device.legacy_ssh, timeout_seconds=LOGIN_TIMEOUT_SECONDS,
        )

    def _login(self, shell, spec) -> bytes:
        _index, data = shell.expect([_login_anchor(spec)], LOGIN_TIMEOUT_SECONDS)
        shell.discard(data)
        shell.expect(list(spec.ends), LOGIN_TIMEOUT_SECONDS)
        return data

    def login_prefix(self, spec) -> bytes:
        try:
            with self._session() as shell:
                data = self._login(shell, spec)
        except session.SessionError as exc:
            raise AccessError("interactive login failed: %s" % exc) from None
        return data[:-len(_login_anchor(spec))].rsplit(b"\n", 1)[-1].strip()

    def apply(self, steps: list, spec) -> int:
        if not HOSTNAME.fullmatch(spec.anchor.decode("ascii", "replace").strip().rstrip(".")):
            raise AccessError("the device hostname is not usable as a prompt anchor")
        prompts = [spec.anchor] + ([spec.continuation] if spec.continuation else [])
        accepted = 0
        try:
            with self._session() as shell:
                self._login(shell, spec)
                for number, step in enumerate(steps, 1):
                    kind, text, pattern = _step(step)
                    shell.send(text)
                    if kind == "raw":
                        accepted += 1
                        continue
                    if kind == "ask":
                        _index, data = shell.expect([pattern], LINE_TIMEOUT_SECONDS)
                    else:
                        index, data = shell.expect(prompts, LINE_TIMEOUT_SECONDS)
                        if index == 0:
                            _tail_index, tail = shell.expect(list(spec.ends), LINE_TIMEOUT_SECONDS)
                            data += tail
                    marker = spec.error(data.decode("utf-8", "replace"))
                    if marker is not None:
                        raise AccessError("line %d was refused by the device (%s)" % (number, marker), accepted)
                    accepted += 1
        except session.SessionError as exc:
            raise AccessError("interactive session failed after %d lines: %s" % (accepted, exc), accepted) from None
        return accepted


def _login_anchor(spec) -> bytes:
    return spec.anchor.lstrip(b"\n")


def _step(step):
    if isinstance(step, str):
        return "line", step, None
    if step[0] == "raw" and len(step) == 2:
        return "raw", step[1], None
    if step[0] == "ask" and len(step) == 3:
        return "ask", step[1], step[2]
    raise AccessError("unknown session step")
