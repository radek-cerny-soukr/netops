"""The one deterministic Linux overview adapter used by the overview contract tests.

The in-process tests and the stdio server subprocess both import this module, so no test
runs a second, silently diverging copy of the adapter.
"""

from netops_helper import normalization
from netops_helper.overview import model


def plan(scope):
    return (
        model.ReadSpec("kernel", "kernel", ("version",)),
        model.ReadSpec("links", "links", ("interfaces.admin_up_down",)),
    )


def assemble(scope, reads):
    fields = {}
    kernel, links = reads["kernel"], reads["links"]
    if kernel.status == "ok" and kernel.text:
        fields["version"] = normalization.parse_identity("linux", kernel.text)["os_version"]
    if links.status == "ok" and links.text:
        entries = []
        for line in links.text.splitlines():
            if not line.strip():
                continue
            interface, state, _, flags = line.split(maxsplit=3)
            if state == "DOWN" and "UP" in flags.strip().strip("<>").split(","):
                entries.append({"name": interface, "read_ids": ["links"]})
        fields["interfaces"] = {"scope": "device", "admin_up_down": entries, "with_errors": None}
    return model.DeviceFacts(fields, [model.missing(field, "not_applicable") for field in model.FACT_FIELDS
                                      if field not in ("version", "interfaces", "firmware_support")])
