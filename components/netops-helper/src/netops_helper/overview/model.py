"""Public limits and the contract between the overview coordinator and platform adapters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Literal, Mapping

MAX_TARGETS = 64
MAX_DETAILS = 64
MAX_OUTPUT = 256 * 1024
MAX_MESSAGE = 4 * 1024 * 1024
TARGET_SECONDS = 30
READ_SECONDS = 10
DEFAULT_TIMEOUT = 45
MAX_PARALLEL = 4
# Without an explicit limit one page runs at most one parallel round, so every target
# starts when the page starts and the page fits the default request budget.
DEFAULT_LIMIT = MAX_PARALLEL
ALIAS_PATTERN = r"^[^\x00-\x20\x7f]+$"

ARGUMENTS = frozenset({"targets", "groups", "limit", "after", "timeout_seconds"})

REASONS = frozenset({
    "not_applicable", "not_enrolled", "unknown_target", "group_unverified", "unsupported_platform",
    "policy_scope", "auth_failed", "host_key_failed", "identity_unverified", "timeout", "unreachable",
    "rate_limited", "read_limit", "source_limit", "permission_denied", "rest_unavailable", "unparsed",
    "truncated", "output_limit", "internal_error",
})
IDENTITY_QUERIES = {
    "linux": "kernel", "fortinet": "system_status", "fortiadc": "system_status",
    "ruckus_unleashed": "system_info",
    **dict.fromkeys(("extreme_exos", "cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos",
                     "juniper_junos", "juniper_junos_els"), "version"),
}
REST_TOOLS = {
    "switch_status": "fortiswitch_overview", "switch_health": "fortiswitch_overview",
    "managed_ap": "wifi_aps_live", "ap_status": "wifi_aps_live",
}

FACT_FIELDS = (
    "version", "model", "uptime_seconds", "firmware_support", "cpu", "memory", "temperatures",
    "fans", "power", "poe", "interfaces", "redundancy", "licenses", "fortiguard", "managed",
)


@dataclass(frozen=True)
class Scope:
    platform: str
    enabled_queries: tuple[str, ...]
    read_inventory: Mapping[str, tuple[str, ...]]
    device_types: tuple[str, ...] = ()
    https_enrolled: bool = False


@dataclass(frozen=True)
class ReadSpec:
    """Fixed read declaration. Dependencies name earlier steps in the same plan.

    The frame determines the minimum command cost from the catalog and scope.
    A declared cost can reserve more for a step with additional scope work.
    """

    id: str
    query: str
    fields: tuple[str, ...]
    parameters: Mapping[str, str] = field(default_factory=dict)
    requires: tuple[str, ...] = ()
    cost: int = 1
    transport: Literal["ssh", "https"] = "ssh"

    def wire(self) -> dict[str, Any]:
        return {"id": self.id, "query": self.query, "fields": self.fields, "parameters": dict(self.parameters),
                "requires": self.requires, "cost": self.cost, "transport": self.transport}

    def source(self, platform: str) -> dict[str, str]:
        if self.transport == "https":
            return {"transport": "https", "monitor": self.query}
        return {"transport": "ssh", "platform": platform, "query": self.query}


@dataclass(frozen=True)
class ReadResult:
    """Redacted parser input. Document is the original structure of a verified HTTPS GET."""

    spec: ReadSpec
    status: str
    duration_ms: int | None = None
    observed_at: str | None = None
    reason: str | None = None
    text: str | None = None
    document: dict[str, Any] | None = None
    retry_after_seconds: int | None = None
    reachability: str = "unknown"
    scope: Mapping[str, Any] = field(default_factory=dict)
    # Exit status of the SSH read when the transport reported one; adapters may require the measured
    # status before they recognize a device answer. It is not part of the public read record.
    rc: int | None = None

    def public(self, platform: str) -> dict[str, Any]:
        return {"id": self.spec.id, "source": self.spec.source(platform), "status": self.status,
                "duration_ms": self.duration_ms, "observed_at": self.observed_at, "fields": list(self.spec.fields)}


@dataclass
class DeviceFacts:
    """Normalized fields and evidence. Read and missing records from the frame are added separately.

    Adapters may downgrade a read to incomplete when their parser detects missing coverage.
    `answered_reads` maps a read whose device answer the frame could not classify (reason
    `unparsed`) to `empty` (a valid answer without data, e.g. no managed access point) or
    `not_applicable` (the device explicitly states that the capability is absent or not
    configured). The adapter recognizes only exact, measured device answers; refusals,
    timeouts and authorization reasons are never changed.
    """

    fields: dict[str, Any] = field(default_factory=dict)
    missing: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    incomplete_reads: tuple[str, ...] = ()
    answered_reads: Mapping[str, str] = field(default_factory=dict)


def refused_lines(read: ReadResult | None) -> list[str] | None:
    """Stripped non-blank lines of a captured answer the frame left unparsed, else None.

    Adapters compare them with exact, measured device answers before naming the read in
    `DeviceFacts.answered_reads`.
    """
    if read is None or read.reason != "unparsed" or read.text is None:
        return None
    return [line.strip() for line in read.text.splitlines() if line.strip()]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def encoded_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode())


def blank_device(target: str, platform: str | None) -> dict[str, Any]:
    fields = dict.fromkeys(key for key in FACT_FIELDS if key != "firmware_support")
    fields["interfaces"] = {"scope": "device", "admin_up_down": None, "with_errors": None}
    return {"target": target, "platform": platform, "status": "partial", "reachability": "unknown",
            "duration_ms": None, **fields, "reads": [], "missing": [], "findings": []}


def missing(field: str, reason: str, **details: Any) -> dict[str, Any]:
    return {"field": field, "reason": reason, **details}


def with_identity(scope: Scope, specs: tuple[ReadSpec, ...]) -> tuple[ReadSpec, ...]:
    if not isinstance(specs, tuple):
        raise ValueError("overview plan must be a tuple")
    query = IDENTITY_QUERIES[scope.platform]
    if specs and not isinstance(specs[0], ReadSpec):
        raise ValueError("invalid overview identity declaration")
    if (specs and specs[0].transport == "ssh" and specs[0].query == query
            and not specs[0].parameters and not specs[0].requires):
        plan = specs
    else:
        plan = (ReadSpec("identity", query, ("identity",)), *specs)
    seen = set()
    for spec in plan:
        if (not isinstance(spec, ReadSpec) or not re.fullmatch(r"[a-zA-Z0-9_:.\-]{1,128}", spec.id)
                or spec.id in seen
                or not spec.fields or not set(spec.requires) <= seen
                or spec.transport not in ("ssh", "https")
                or type(spec.cost) is not int or not 1 <= spec.cost <= 30):
            raise ValueError("invalid overview read declaration")
        seen.add(spec.id)
    return plan


def expiry_state(expires_on: str, *, today: date | None = None) -> str:
    """Classify a confirmed calendar expiry against the current UTC date."""
    remaining = (date.fromisoformat(expires_on) - (today or datetime.now(timezone.utc).date())).days
    return "expired" if remaining < 0 else "expiring" if remaining <= 30 else "valid"
