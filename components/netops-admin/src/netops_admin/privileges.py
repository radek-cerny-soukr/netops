from __future__ import annotations

import re

from netops_admin import fortios
from netops_admin.errors import Rejected

OK = "ok"
WARNING = "warning"
UNVERIFIED = "cannot verify"
ADMINISTRATOR_PROFILES = ("super_admin", "prof_admin")
SETTING = re.compile(r"^\s*set\s+([A-Za-z0-9_-]+)\s+(.*?)\s*$")
FORTIOS_FIELD = re.compile(r"accprofile|cli-[a-z-]+|[a-z]+grp|wifi")
FORTIADC_FIELD = re.compile(r"access-profile|is-system-admin")
AREA_VALUE = re.compile(r"none|read|read-write")
NOTHING = re.compile(r"(?!)")
REFUSAL = re.compile(r"not found|command fail|parse error|parsing error|unknown action|permission denied|"
                     r"not authori[sz]ed|return code", re.IGNORECASE)
SECRET = re.compile(r"ENC|password|passwd|BEGIN|PRIVATE|secret|token|key", re.IGNORECASE)
TABLE = "Accounts and least privilege (components/netops-helper/docs/read-only-accounts.md)"
NOT_FOUND = re.compile(r"not found", re.IGNORECASE)
NO_SHOW = re.compile(r"unknown action", re.IGNORECASE)
REMOTE = " (a wildcard, RADIUS or TACACS+ login has no local entry to verify)"
CLI_SHOW = " (the account does not have cli-show in its access profile)"
FORTIOS_WRITE_ROW = "Admin write, firewall policy (FortiOS 7.6.8, cli-script safeguard)"


def _row(platform, row):
    return 'see the %s row "%s" in %s' % (platform, row, TABLE)


def _shown(line):
    if SECRET.search(line):
        return "%s (the rest of the line is withheld)" % REFUSAL.search(line).group(0)
    return line.strip()


def _refusal(command, text, entry):
    found = [_shown(line) for line in text.replace("\r", "").split("\n") if REFUSAL.search(line)]
    if found:
        joined = " | ".join(found)
        hint = (REMOTE if entry and NOT_FOUND.search(joined) else "") + (CLI_SHOW if NO_SHOW.search(joined) else "")
        raise Rejected(["the device refused %s: %s%s" % (command, joined, hint)])


def _fields(text, allowed, areas=False):
    fields = {}
    for line in text.replace("\r", "").split("\n"):
        setting = SETTING.match(line)
        if setting is None:
            continue
        name, value = setting.group(1), setting.group(2).strip('"')
        if allowed.fullmatch(name) or (areas and AREA_VALUE.fullmatch(value)):
            fields[name] = value
    return fields


def _read(access, command, check, allowed, areas=False, entry=False):
    text = access.own_query(command, check=check)
    _refusal(command, text, entry)
    return _fields(text, allowed, areas)


def _admin_command(login):
    return "show system admin %s" % fortios._quoted(login)


def _profile_command(profile):
    return "show system accprofile %s" % fortios._quoted(profile)


def _fortios_profile(access, login, check):
    profile = _read(access, _admin_command(login), check, FORTIOS_FIELD, entry=True).get("accprofile")
    if profile is None:
        raise Rejected(["the administrator entry of %s shows no local access profile (a wildcard, RADIUS, TACACS+"
                        " or VDOM administrator cannot be verified)" % login])
    return profile


def fortios_write(access, firmware):
    login = access.credential.login
    profile = _fortios_profile(access, login, False)
    if profile not in ADMINISTRATOR_PROFILES:
        return OK, "access profile %s" % profile
    if not firmware:
        return UNVERIFIED, ("access profile %s; the firmware is unknown, so it cannot be told whether the webhook"
                            " safeguard of FortiOS 8.0.1 and later needs it" % profile)
    if fortios.webhook_firmware(firmware):
        return OK, "access profile %s; the webhook safeguard of FortiOS 8.0.1 and later needs super_admin" % profile
    return WARNING, ("the write account %s has access profile %s, more than Admin needs on FortiOS %s; %s"
                     % (login, profile, firmware.split()[0], _row("FortiOS", FORTIOS_WRITE_ROW)))


def fortios_check(access):
    login = access.check_credential.login
    profile = _fortios_profile(access, login, True)
    if profile in ADMINISTRATOR_PROFILES:
        return WARNING, ("the check account %s has access profile %s; it only reads, %s"
                         % (login, profile, _row("FortiOS", "Admin check")))
    rights = _read(access, _profile_command(profile), True, FORTIOS_FIELD)
    rights.pop("accprofile", None)
    if not rights:
        raise Rejected(["the check account %s does not see its own access profile %s" % (login, profile)])
    extra = ["%s %s" % item for item in sorted(rights.items())
             if item[1] == "read-write" or item == ("cli-config", "enable")]
    if extra:
        return WARNING, ("the check account %s has access profile %s with %s; it only reads, %s"
                         % (login, profile, ", ".join(extra), _row("FortiOS", "Admin check")))
    custom = ["%s custom" % name for name, value in sorted(rights.items()) if value == "custom"]
    if custom:
        return UNVERIFIED, ("access profile %s has %s; the permissions inside a custom group are not read"
                            % (profile, ", ".join(custom)))
    return OK, "access profile %s: read only" % profile


def fortiadc_write(access):
    fields = _read(access, _admin_command(access.credential.login), False, FORTIADC_FIELD, entry=True)
    if fields.get("is-system-admin") == "yes":
        return OK, "system administrator, which pool-member needs"
    if "access-profile" not in fields:
        raise Rejected(["the administrator entry of %s shows no local access profile" % access.credential.login])
    return OK, "access profile %s" % fields["access-profile"]


def fortiadc_check(access):
    login = access.check_credential.login
    fields = _read(access, _admin_command(login), True, FORTIADC_FIELD, entry=True)
    if fields.get("is-system-admin") == "yes":
        return WARNING, ("the check account %s is a system administrator (is-system-admin yes); it only reads, %s"
                         % (login, _row("FortiADC", "Admin check")))
    profile = fields.get("access-profile")
    if profile is None:
        raise Rejected(["the administrator entry of %s shows no local access profile" % login])
    areas = _read(access, _profile_command(profile), True, NOTHING, areas=True)
    if not areas:
        raise Rejected(["the check account %s does not see its own access profile %s" % (login, profile)])
    extra = ["%s read-write" % name for name, value in sorted(areas.items()) if value == "read-write"]
    if extra:
        return WARNING, ("the check account %s has access profile %s with %s; it only reads, %s"
                         % (login, profile, ", ".join(extra), _row("FortiADC", "Admin check")))
    return OK, "access profile %s: read only" % profile
