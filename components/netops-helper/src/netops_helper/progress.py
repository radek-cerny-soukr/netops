"""Progress reports of the triage tools: one report per planned device read.

A triage tool runs a fixed plan of device reads in a worker thread. Each read reports
`done of at most total` so that a client with a request timeout can see the call is alive
(`notifications/progress`, sent only when the client supplied a `progressToken`).
The messages name the internal query or step only, never device output.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Awaitable, Callable

# Device reads a triage may take; also the cost charged to the target's triage budget.
TRIAGE_READS = {"triage_health": 10, "triage_routing": 5, "triage_vpn": 4, "triage_slb": 21}

Report = Callable[[int, int, str], None]
Sink = Callable[[int, int, str], Awaitable[Any]]

_REPORT: ContextVar[Report | None] = ContextVar("netops_triage_report", default=None)
_TRANSPORT: ContextVar[Sink | None] = ContextVar("netops_triage_transport", default=None)


def bind(report: Report) -> Any:
    return _REPORT.set(report)


def unbind(token: Any) -> None:
    _REPORT.reset(token)


def bind_transport(sink: Sink) -> Any:
    """The embedding worker supplies its own way to deliver progress (it has no MCP request context)."""
    return _TRANSPORT.set(sink)


def unbind_transport(token: Any) -> None:
    _TRANSPORT.reset(token)


def transport() -> Sink | None:
    return _TRANSPORT.get()


class Steps:
    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.total = TRIAGE_READS[tool]
        self.done = 0
        self._report = _REPORT.get()
        self._send("started")

    def read(self, label: str) -> None:
        self.done = min(self.done + 1, self.total)
        self._send(label)

    def _send(self, label: str) -> None:
        if self._report is None:
            return
        try:
            self._report(self.done, self.total, "%s: %d of at most %d reads (%s)" % (
                self.tool, self.done, self.total, label))
        except Exception:
            pass  # a broken progress channel never stops the triage
