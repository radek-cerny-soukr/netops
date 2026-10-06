from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass

from netops_admin.errors import Rejected
from netops_admin.jsontext import loads
from netops_admin.request import DEVICE, REQUEST_ID, MAX_REASON, MAX_USER_REQUEST, _text

@dataclass(frozen=True)
class Transaction:
    device: str | None
    operations: list
    reason: str
    user_request: str
    request_id: str
    table: str = "schema"
    op: str = "update"
    key: str = "transaction"

    def fingerprint(self):
        body = {"device":self.device,"operations":self.operations,"reason":self.reason,"user_request":self.user_request}
        return hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()

def parse(raw):
    if not isinstance(raw,bytes) or len(raw)>131072:
        raise Rejected(["schema transaction request exceeds its limit"])
    data=loads(raw,"schema transaction")
    fields={"device","operations","reason","user_request","request_id"}
    if not isinstance(data,dict) or set(data)-fields or fields-{"device"}-set(data):
        raise Rejected(["schema transaction request fields are invalid"])
    device=data.get("device")
    if device is not None and (not isinstance(device,str) or not DEVICE.fullmatch(device)):
        raise Rejected(["schema transaction device must be an inventory alias"])
    operations=data["operations"]
    if not isinstance(operations,list) or not 1<=len(operations)<=32:
        raise Rejected(["schema transaction requires 1 to 32 operations"])
    for operation in operations:
        if not isinstance(operation,dict) or set(operation)!={"path","scope","owners","op","changes"}:
            raise Rejected(["schema transaction operation fields are invalid"])
        if not isinstance(operation["path"],str) or not operation["path"] or len(operation["path"])>512:
            raise Rejected(["schema transaction path is invalid"])
        scope=operation["scope"]
        if scope is not None and (not isinstance(scope,str) or not scope or len(scope)>128 or not scope.isprintable()):
            raise Rejected(["schema transaction scope is invalid"])
        owners=operation["owners"]
        if not isinstance(owners,list) or len(owners)>16 or any(not isinstance(x,str) or not x or len(x)>128 or not x.isprintable() for x in owners):
            raise Rejected(["schema transaction owners are invalid"])
        if operation["op"] not in ("create","update","delete") or not isinstance(operation["changes"],dict) or len(operation["changes"])>64:
            raise Rejected(["schema transaction changes are invalid"])
        for name,value in operation["changes"].items():
            if not isinstance(name,str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}",name):
                raise Rejected(["schema transaction attribute name is invalid"])
            if value is not None and type(value) not in (str,int,list):
                raise Rejected(["schema transaction attribute value is invalid"])
            if isinstance(value,list) and (len(value)>128 or any(type(x) not in (str,int) for x in value)):
                raise Rejected(["schema transaction list value is invalid"])
    request_id=data["request_id"]
    if not isinstance(request_id,str) or not REQUEST_ID.fullmatch(request_id):
        raise Rejected(["schema transaction request_id is invalid"])
    return Transaction(device,copy.deepcopy(operations),_text(data["reason"],"reason",MAX_REASON),
                       _text(data["user_request"],"user_request",MAX_USER_REQUEST),request_id)
