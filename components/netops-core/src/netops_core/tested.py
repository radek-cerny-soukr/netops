"""Tested versions: one rule for "tested" and "untested" firmware (G00, decision of 2026-11-17).

NetOps does not refuse an OS version, build or model only because a function was not tested on it. Each function
keeps the list of the versions it was tested on where it is today (Admin profiles, Helper and Auditor modules);
this module compares the device against that list in one way and returns the same structure everywhere:

    {"status": "tested" | "untested" | "unknown", "platform": ..., "device_version": ..., "model": ...,
     "tested_versions": [...], "message": ...}

- tested: the version of the device is exactly one of the listed versions (plain string comparison, no ranges and
  no families), and when the list names a model, the model of the device is the listed one;
- untested: the version (or the model) of the device is not listed; the function runs and reports this warning;
- unknown: the version of the device could not be read; the caller keeps its technical refusal, since without a
  version it can neither plan reliably nor warn.

The message is plain English for a person and an agent alike.
"""
from __future__ import annotations

TESTED = "tested"
UNTESTED = "untested"
UNKNOWN = "unknown"
STATUSES = (TESTED, UNTESTED, UNKNOWN)
WARNING_CODE = "firmware_untested"
MESSAGE = ("%s %s%s is not among the versions %s was tested on (%s). It may or may not work as designed and"
           " tested; check the result.")
UNKNOWN_MESSAGE = "the %s version of the device could not be read; tested versions: %s."


def _entry(item):
    """A tested entry is a version string or a (model, version) pair."""
    if isinstance(item, str) and item:
        return None, item
    if (isinstance(item, (tuple, list)) and len(item) == 2
            and all(isinstance(part, str) and part for part in item)):
        return item[0], item[1]
    raise ValueError("a tested version is a non-empty string or a (model, version) pair")


def _shown(model, version) -> str:
    return version if model is None else "%s %s" % (model, version)


def support(platform: str, device_version, tested, *, model=None, function: str = "this function") -> dict:
    """Compare the device with the tested versions of one function.

    platform names the OS for the message (for example "FortiOS" or "fortios"), device_version is the version or
    build as the function reads it, tested lists version strings or (model, version) pairs, model is the device
    model when the list names models. A model is compared only for the entries that name one.
    """
    entries = [_entry(item) for item in tested]
    if not entries:
        raise ValueError("a function needs at least one tested version")
    shown = [_shown(*item) for item in entries]
    if not isinstance(device_version, str) or not device_version:
        return {"status": UNKNOWN, "platform": platform, "device_version": None, "model": model,
                "tested_versions": shown, "message": UNKNOWN_MESSAGE % (platform, ", ".join(shown))}
    matched = any(version == device_version and (listed is None or listed == model)
                  for listed, version in entries)
    result = {"status": TESTED if matched else UNTESTED, "platform": platform, "device_version": device_version,
              "model": model, "tested_versions": shown, "message": None}
    if not matched:
        result["message"] = MESSAGE % (platform, device_version, "" if model is None else " on %s" % model,
                                       function, ", ".join(shown))
    return result


def is_tested(result) -> bool:
    return isinstance(result, dict) and result.get("status") == TESTED


def warning(result):
    """The warnings[] item of an untested (or unknown) result, None for a tested one."""
    if is_tested(result):
        return None
    return {"code": WARNING_CODE, "message": result["message"]}


def valid(result) -> bool:
    """A firmware_support structure as this module writes it (used to read stored plans back)."""
    if not isinstance(result, dict):
        return False
    if set(result) != {"status", "platform", "device_version", "model", "tested_versions", "message"}:
        return False
    texts = (result["platform"],)
    optional = (result["device_version"], result["model"], result["message"])
    return (result["status"] in STATUSES and all(isinstance(item, str) for item in texts)
            and all(item is None or isinstance(item, str) for item in optional)
            and isinstance(result["tested_versions"], list)
            and all(isinstance(item, str) for item in result["tested_versions"])
            and (result["message"] is None) == (result["status"] == TESTED))
