from __future__ import annotations

import re

from netops_auditor import collect
from netops_core import hostkey, prompt, session, ssh, vault, schema
from netops_core import fortios as core_fortios
from netops_admin import schema_runtime
from netops_admin.errors import Rejected

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


class SchemaAccess:
    def __init__(self,base,device):
        self.base=base;self.device=device;self.credential=base.credential;self.check_credential=base.check_credential
        self.lib,_=schema_runtime.policy(device)
        status=base.query("get system status")
        identities=re.findall(r"(?m)^Version:\s+([A-Za-z0-9_.+-]+)\s+v(\d+\.\d+\.\d+),\s*build(\d{4,6})(?:,|\s|$)",status)
        names=re.findall(r"(?m)^Hostname:\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\s*$",status)
        if len(identities)!=1 or len(names)!=1:raise Rejected(["schema live identity cannot be established"])
        try:self.lib.require_identity(*identities[0])
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

    def _context(self,domain,command,check=False,allow_not_found=False):
        if domain is not None:self._require_vdom(domain)
        credential=self.check_credential if check else self.credential
        address=(self.device.check_address or self.device.address) if check else self.device.address
        commands=["config global"] if domain is None else ["config vdom","edit "+schema.quoted(domain)]
        if check:
            status=self.base.check_query("get system status")
            current=re.findall(r"(?m)^Current virtual domain:\s+(\S+)\s*$",status)
            if domain is not None and current==[domain]:
                commands=[]
        commands.append(command)
        with session.Session(address,self.device.port,None,credential,self.base._host_key(address),
                             legacy_ssh=self.device.legacy_ssh,timeout_seconds=30) as shell:
            self.base._login(shell,self.spec)
            answer=b""
            for line in commands:
                shell.send(line)
                answer=b""
                while True:
                    index,part=shell.expect([self.spec.anchor,b"--More--"],180 if line=="show" else 60)
                    answer+=part
                    if len(answer)>schema_runtime.MAX_BYTES:raise Rejected(["schema live read output exceeds its limit"])
                    if index==0:
                        _,tail=shell.expect(list(self.spec.ends),60);answer+=tail
                        break
                    shell.send(" ")
                answer=answer.replace(b"--More--",b"")
                decoded=answer.decode("utf-8","replace")
                if schema_runtime.fortios.cli_error(decoded) and not (allow_not_found and line==command and any(x.strip()==schema_runtime.fortios.NOT_FOUND for x in decoded.splitlines())):
                    raise Rejected(["schema live read context was refused"])
            text=answer.decode("utf-8","replace").replace("\r","")
            text=re.sub(r"\x1b\[[0-9;?]*[A-Za-z]","",text)
            if "--More--" in text:raise Rejected(["schema live snapshot pagination is not supported"])
            return text

    def snapshot(self,check=False):
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

    def observe(self,plan):
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
