"""Read-only FortiOS audit steps and scope-bound visibility evidence."""
from __future__ import annotations

from copy import deepcopy

from . import collect, l1_fortios
from .platforms import INCOMPLETE, UNPROVEN, VISIBLE, SectionVisibility, SnapshotMetadata, SSHStep

ADMIN = "system admin"
INTERFACE = "system interface"
GLOBAL = "system global"
SNMP_INFO = "system snmp sysinfo"
SNMP_USERS = "system snmp user"
NTP = "system ntp"
GROUP = "user group"
AAA_SERVERS = ("user radius", "user tacacs+")
SYSLOG = tuple(
    (f"log syslogd{suffix} setting", f"log syslogd{suffix} filter")
    for suffix in ("", "2", "3", "4")
)
SAFEGUARDS = (
    "system accprofile", "system api-user", "system automation-action",
    "system automation-trigger", "system automation-stitch",
)
READBACKS = {ADMIN: "@admin-readback", SYSLOG[0][0]: "@syslog-readback"}
SECTIONS = (
    ADMIN, GLOBAL, INTERFACE, SNMP_INFO, SNMP_USERS, NTP, GROUP, *AAA_SERVERS, *SAFEGUARDS,
    *(section for pair in SYSLOG for section in pair),
)
# FortiOS show and HTTPS backups can omit these tables and default-only sections.
DEFAULT_OMITTED = frozenset({
    *SAFEGUARDS, SNMP_INFO, SNMP_USERS, NTP, *AAA_SERVERS,
    *(section for pair in SYSLOG for section in pair),
})

SSH_STEPS = (
    SSHStep("get system status", section="system status"),
    SSHStep("get system console", section="system console"),
    SSHStep("show", snapshot=True, prompt=True),
    SSHStep("show system admin", section="@admin-readback"),
    SSHStep("show log syslogd setting", section="@syslog-readback"),
    *(SSHStep(f"show full-configuration {name}", section=name) for name in SECTIONS),
)

VERIFIED = SectionVisibility(VISIBLE, "verified-profile")
UNVERIFIED = SectionVisibility(UNPROVEN, "visibility-unproven")
ADMIN_UNVERIFIED = SectionVisibility(UNPROVEN, "admin-visibility-unproven")
TRUNCATED = SectionVisibility(INCOMPLETE, "truncated")


def _same_objects_and_fields(original, effective):
    """The full rendering may add default fields and default-only sub-blocks."""
    return (
        original.entries.keys() == effective.entries.keys()
        and original.attrs.keys() <= effective.attrs.keys()
        and original.sub.keys() <= effective.sub.keys()
        and all(_same_objects_and_fields(node, effective.entries[name])
                for name, node in original.entries.items())
        and all(_same_objects_and_fields(node, effective.sub[name])
                for name, node in original.sub.items())
    )


def _merge(original, effective):
    """Keep original line numbers and fields. Add demonstrated effective fields."""
    original.attrs = {**effective.attrs, **original.attrs}
    for family in ("entries", "sub"):
        children = getattr(original, family)
        for name, node in getattr(effective, family).items():
            if name in children:
                _merge(children[name], node)
            else:
                children[name] = node


def _targeted(text, name):
    try:
        parsed = l1_fortios.parse(text)
    except l1_fortios.ParseError:
        return None
    if set(parsed.sub) == {name} and not (parsed.attrs or parsed.entries):
        return parsed.section(name)
    return None


def _integrity(text):
    if collect.PAGER.search(collect.ANSI.sub("", text)) or "\x08" in text:
        return "pager", None
    try:
        tree = l1_fortios.parse(text)
    except l1_fortios.TruncatedError:
        return "truncated", None
    except l1_fortios.ParseError:
        return "", None  # Preserve the parser's existing diagnostic for malformed input.
    if not tree.sub or tree.attrs or tree.entries:
        return "truncated", None
    return "", tree


def snapshot_metadata(snapshot, answers, visibility):
    integrity, original = _integrity(snapshot.text)
    if original is None:
        return SnapshotMetadata("fortios", integrity_reason=integrity)

    # A root table proves visibility only for its own scope. Wrapped exports
    # retain their scopes for the existing FortiOS gate and scoped audit.
    if original.section("global") is not None or original.section("vdom") is not None:
        return SnapshotMetadata("fortios", complete=True, tree=original)

    admin = original.section(ADMIN)
    verified = admin is not None and any(
        account.value("accprofile") == "super_admin" for account in admin.entries.values()
    )
    tree = deepcopy(original)
    sections = dict(visibility)
    for name in SECTIONS:
        base = original.section(name)
        state = visibility.get(name)
        response = answers.get(name)
        full = _targeted(response, name) if response is not None else None
        readback = READBACKS.get(name)
        check = _targeted(answers[readback], name) if readback in answers else None
        populated = base is not None and bool(base.attrs or base.entries or base.sub)
        mismatch = base is not None and (
            (full is not None and not _same_objects_and_fields(base, full))
            or (check is not None and not _same_objects_and_fields(base, check))
            or populated and (response == "" or answers.get(readback) == "")
        )
        if mismatch or (response and full is None) or (
                readback in answers and answers[readback] and check is None):
            sections[name] = TRUNCATED
            if name in SAFEGUARDS and base is not None and full is not None:
                _merge(tree.section(name), full)
            continue
        if state is not None and state.state != VISIBLE:
            sections[name] = state
            continue
        if readback in visibility and visibility[readback].state != VISIBLE:
            sections[name] = visibility[readback]
            continue
        if base is None and full is None and name not in DEFAULT_OMITTED:
            if state is not None:
                sections[name] = TRUNCATED
            continue
        if full is not None:
            if base is None:
                tree.sub[name] = full
            else:
                _merge(tree.section(name), full)
        if verified:
            sections[name] = VERIFIED
        else:
            sections[name] = ADMIN_UNVERIFIED if name == ADMIN else UNVERIFIED
    return SnapshotMetadata("fortios", sections, {"effective-tree": tree}, complete=True, tree=original)


def effective_tree(tree, context):
    if context.snapshot is None:
        return tree
    return context.snapshot.auxiliary.get("effective-tree", tree)


def live_admin_gap(tree, context):
    return (context.live and context.snapshot is not None and tree.section(ADMIN) is not None
            and context.visibility(ADMIN).state != VISIBLE)
