"""Operator CLI for one inventory-driven check through the public Helper endpoint."""
from __future__ import annotations

import itertools
import json
import os
import ssl
from urllib.parse import urlsplit

import httpx

from netops_admin.notify import discord_intent
from netops_core.inputs import InputError, read_regular
from netops_helper import engine, inventory

PROTOCOL = "2025-06-18"
EXIT_STATUS = {"pass": 0, "fail": 1, "incomplete": 2}


class _HelperClient:
    def __init__(self, client, endpoint):
        self.client = client
        self.endpoint = endpoint
        self.ids = itertools.count(1)
        self.session_headers = {"MCP-Protocol-Version": PROTOCOL}

    def _request(self, method, params=None, *, notification=False):
        request = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            request["params"] = params
        if not notification:
            request["id"] = next(self.ids)
        response = self.client.post(self.endpoint, json=request, headers=self.session_headers)
        response.raise_for_status()
        if notification:
            return None, response
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("id") != request["id"] or not isinstance(payload.get("result"), dict):
            raise ValueError("invalid MCP response")
        return payload["result"], response

    def initialize(self):
        initialized, response = self._request("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "netops check-intent", "version": "1"},
        })
        if initialized.get("protocolVersion") != PROTOCOL:
            raise ValueError("unsupported MCP protocol")
        if "Mcp-Session-Id" in response.headers:
            self.session_headers["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
        self._request("notifications/initialized", notification=True)

    def switch_read(self, arguments):
        try:
            result, _ = self._request("tools/call", {"name": "switch_read", "arguments": arguments})
        except (httpx.HTTPError, ValueError):
            return {"status": "gateway_read_failed"}
        structured = result.get("structuredContent")
        return structured if isinstance(structured, dict) else {"status": "gateway_read_failed"}


def _plans(path, name):
    if not inventory.INTENT_NAME.fullmatch(name):
        raise ValueError("invalid_plan_name")
    plans = []
    for device in inventory.devices(inventory.load(path)):
        if name in inventory._checked_intent(device.helper.get("intent", {})):
            section = inventory.section(device)
            plans.append((device.name, section.catalog_platform(), section.intent[name]))
    if not plans:
        raise ValueError("plan_not_found")
    return plans


def main(args):
    result = {"plan": None, "status": "incomplete", "checks": [], "notification": "not_needed"}
    try:
        plans = _plans(args.inventory, args.plan)
    except (inventory.InventoryError, InputError, OSError):
        result["reason"] = "invalid_inventory"
    except ValueError as error:
        result["reason"] = str(error)
    else:
        try:
            parts = urlsplit(args.endpoint)
            if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                    or parts.path != "/mcp" or parts.query or parts.fragment):
                raise ValueError("invalid NetOps endpoint")
            token = read_regular(args.token_file, 256).decode("ascii").strip()
            if len(token) < 32 or not token.isascii() or any(char.isspace() for char in token):
                raise ValueError("invalid NetOps token")
            ca = ssl.create_default_context(cafile=args.ca)
            with httpx.Client(verify=ca, trust_env=False, timeout=75, headers={
                "Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
            }) as client:
                helper = _HelperClient(client, args.endpoint)
                helper.initialize()
                result = engine.check_intent(args.plan, plans, helper.switch_read)
        except (httpx.HTTPError, InputError, OSError, ValueError):
            result.update(plan=args.plan, reason="gateway_unavailable")
        result["notification"] = (
            discord_intent(os.environ.get("NETOPS_DISCORD_WEBHOOK"), result) if args.notify else "disabled"
        )
    print(json.dumps(result, allow_nan=False))
    return EXIT_STATUS[result["status"]]
