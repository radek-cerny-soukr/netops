"""Test helper: every profile apply carries the plan_sha256 of the preview of the same request.

`execute.apply` rejects a profile request without the approved preview's plan_sha256 before it reads the device.
Tests that exercise what happens after that gate call `approved_apply` instead of `execute.apply`:

* a ready preview gives its plan_sha256, exactly as an operator approves it;
* a rejected preview gives the plan_sha256 the preview computed before its later check refused (the plan approved
  before the condition the test sets up changed, e.g. the audit policy or the check account view);
* a repeated request_id (a `known-request` preview) reuses the hash its first apply carried;
* a request refused before any plan exists has no plan to approve; the apply then carries a well-formed hash that no
  preview issued, and must be refused by the same earlier check before the hash is compared.

An explicit `expected_plan_sha256` is passed through unchanged. A schema Transaction is approved the same way: its
preview's plan_sha256 (schema_runtime.build of the same request and snapshot) is the one apply computes.
When the hash did not come from a ready preview and the apply is still refused with plan_changed, the helper fails the
test: the refusal would then come from the hash and not from the condition the test sets up.
"""
from __future__ import annotations

from netops_admin import engine, execute, schema_runtime
from netops_admin.errors import Rejected

UNISSUED_PLAN = "f" * 64
_APPROVED: dict[str, str] = {}


def plan_hash(runtime, device_name, request, preview=None, *, preview_call=execute.preview):
    """The plan_sha256 a preview of `request` approves and whether a ready preview issued it (see the docstring)."""
    digests = []
    original = engine.plan_digest
    original_schema = schema_runtime.build

    def recorded(plan):
        digest = original(plan)
        digests.append(digest)
        return digest

    def recorded_schema(*args, **kwargs):
        plan = original_schema(*args, **kwargs)
        digests.append(plan["plan_sha256"])
        return plan

    if preview is None:
        engine.plan_digest = recorded
        schema_runtime.build = recorded_schema
        try:
            preview = preview_call(runtime, device_name, request)
        except Exception:  # noqa: BLE001 - only the hash is wanted here; the apply itself meets the same failure
            preview = {"result": "rejected"}
        finally:
            engine.plan_digest = original
            schema_runtime.build = original_schema
    if preview.get("plan_sha256"):
        return preview["plan_sha256"], preview.get("result") == "ready"
    if preview.get("result") == "known-request":
        return _APPROVED.get(request.request_id, UNISSUED_PLAN), False
    return (digests[-1] if digests else UNISSUED_PLAN), False


def approved_apply(runtime, device_name, request, *args, **kwargs):
    return _approved(execute.apply, execute.preview, runtime, device_name, request, *args, **kwargs)


def approved_cycle(module, runtime, device_name, request, **kwargs):
    """`module.apply` of a port action (cycle) with the plan_sha256 of `module.preview` of the same action."""
    action = {"action": kwargs["action"]} if "action" in kwargs else {}
    return _approved(module.apply, lambda rt, name, item: module.preview(rt, name, item, **action),
                     runtime, device_name, request, **kwargs)


def _approved(apply, preview, runtime, device_name, request, *args, **kwargs):
    issued = True
    if kwargs.get("expected_plan_sha256") is None:
        kwargs["expected_plan_sha256"], issued = plan_hash(runtime, device_name, request, preview_call=preview)
    _APPROVED[request.request_id] = kwargs["expected_plan_sha256"]
    try:
        return apply(runtime, device_name, request, *args, **kwargs)
    except Rejected as exc:
        if not issued and exc.reason_codes == ["plan_changed"]:
            raise AssertionError("approved_apply: the apply was refused by a plan hash no ready preview issued, "
                                 "not by the condition under test: %s" % exc.reasons) from exc
        raise


def preview_hash(runtime, device_name, request):
    """plan_sha256 of a ready preview, taken before the test arms a fault that the preview's reads would trigger."""
    preview = execute.preview(runtime, device_name, request)
    assert preview["result"] == "ready", preview
    return preview["plan_sha256"]
