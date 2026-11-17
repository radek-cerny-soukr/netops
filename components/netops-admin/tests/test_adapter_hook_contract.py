"""Module attribute contract documented beside execute._watched; no device I/O."""

import pytest

from netops_admin import execute


BOOL_HOOKS = {
    "TIMER_WATCH", "COMPENSATING", "AUDIT_RULES", "REVERT_NOW_KEEPS_SAFEGUARD",
    "REVERT_AFTER_EXPIRY", "INSTALL_JOURNAL",
}
SECONDS_HOOKS = {"FIRING_SLACK_SECONDS", "REVERT_NOW_SECONDS"}
CALLABLE_HOOKS = {
    "revert_now", "adopt_change_head", "revoke_token", "discard_installation",
    "safeguard_rearmed", "safeguard_preflight", "line_guard_for", "timer_seconds", "before_write", "line_allowed",
}
STRING_HOOKS = {"REFUSED_REASON_CODE", "FIRE_AT_TEXT"}
HOOKS = BOOL_HOOKS | SECONDS_HOOKS | CALLABLE_HOOKS | STRING_HOOKS
HOOK_PREFIXES = (
    "TIMER_", "FIRING_", "FIRE_AT_", "REVERT_", "COMPENSAT", "AUDIT_RULE", "INSTALL_", "REFUSED_REASON",
    "revert_", "adopt_change_", "revoke_token", "discard_install", "safeguard_rearm", "safeguard_preflight",
    "line_", "timer_seconds", "before_write",
)
# Existing command/data constants share prefixes but are not optional engine hooks.
NON_HOOK_NAMES = {"TIMER_TOLERANCE_SECONDS", "FIRING_OBSERVED", "REVERT_NOW", "INSTALL_EFFECTS"}


@pytest.mark.parametrize("platform,adapter", [*execute.ADAPTERS.items(),
                                            ("fortios-schema", execute.exec_schema_fortios)],
                         ids=[*execute.ADAPTERS, "fortios-schema"])
def test_adapter_hook_contract(platform, adapter):
    attributes = vars(adapter)
    unknown = {name for name in attributes if name.startswith(HOOK_PREFIXES)} - HOOKS - NON_HOOK_NAMES
    assert not unknown, (platform, "unknown hook names", sorted(unknown))
    for name in HOOKS & attributes.keys():
        value = attributes[name]
        if name in BOOL_HOOKS:
            valid = type(value) is bool
        elif name in SECONDS_HOOKS:
            valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif name in STRING_HOOKS:
            valid = isinstance(value, str)
        else:
            valid = callable(value)
        assert valid, (platform, name, type(value).__name__)
    if getattr(adapter, "TIMER_WATCH", False) is True:
        for name in ("timer_seconds", "before_write", "line_allowed"):
            assert callable(getattr(adapter, name, None)), (platform, "required timer hook", name)
        assert isinstance(getattr(adapter, "FIRE_AT_TEXT", None), str), (platform, "required timer hook", "FIRE_AT_TEXT")
