REASONS = {
    "invalid": "invalid configuration; check the documented schema",
    "size": "exceeds its supported byte limit",
    "null": "must be null for the selected credential kind or collection channel",
    "required": "is required for the selected platform, credential kind or channel",
    "text": "must be a non-empty string",
    "login": "must be a plain user name without a leading hyphen, @, colon, slash or whitespace",
    "credential-kind": "kind must be password, ssh-key, api-token or snmp-community",
    "private-key": "must contain the private key text with a private-key header, rather than a path or public key",
    "reference": "must name an existing record",
    "owner": "file must belong to the process user",
    "single-link": "file must have exactly one hard link",
    "private-mode": "file mode must be 0600 or 0400",
    "read": "file cannot be read within the supported size",
    "regular": "must be a regular file without a symbolic link",
    "utf8": "must contain valid UTF-8 without unpaired surrogate escapes",
    "json": "must contain valid JSON within the supported number and nesting limits",
    "duplicate": "contains a duplicate key or name",
    "depth": "exceeds the supported nesting depth",
    "object": "must be a JSON object",
    "missing-fields": "missing required fields; check the documented schema",
    "unknown-fields": "contains unknown fields; only documented fields are accepted",
    "version2": "version must be 2",
    "version1": "version must be 1",
    "selection": "must be a collection of non-empty credential names",
    "secret-fields": "secret fields are forbidden in inventory; use credential-store references",
    "choice": "must be one of the documented choices",
    "inventory-role": "must be one of the documented inventory roles",
    "platform": "must be a supported platform identifier",
    "address": "must be null, a canonical IPv4 literal or a lowercase DNS name",
    "ipv4": "IPv6 targets are unsupported; use a canonical IPv4 literal or lowercase DNS name",
    "optional-port": "must be null or an integer in 1..65535",
    "address-port": "address and port must either both be null or both be set",
    "optional-reference": "must be null or a non-empty credential-store reference",
    "ssh-pin": "must be an OpenSSH SHA256 host-key pin",
    "address-required": "must be null when the device has no address",
    "legacy-profile": "must name a supported legacy SSH profile or be null",
    "pin-required": "requires an explicit host-key fingerprint; first-contact trust is refused",
    "optional-object": "must be null or an object",
    "consumer-required": "at least one helper or auditor section must be an object",
    "list": "must be a list",
    "channel": "must be file, fortios-rest or ssh",
    "https": "must use https",
    "nonempty-list": "must be a non-empty list",
    "tls-pin": "must contain a SHA256 certificate fingerprint as 64 hexadecimal characters",
    "component": "must use the documented safe name format",
    "fingerprint-component": "must be a string without U+001F, the finding fingerprint separator",
    "absolute": "must be an absolute path without NUL",
    "integer": "must be an integer in the documented range",
    "admin-platform": "must be fortios or exos",
    "protected": "must map table names to lists of names",
    "distinct-names": "must be a list of distinct non-empty account names",
    "different-address": "must be a different address from the write address",
    "different-credential": "must name a different account from the write credential",
    "schema": "schema binding requires fortios and exactly the documented binding fields",
    "digest": "must be a lowercase hexadecimal SHA256 digest",
    "vdoms": "must contain 1..64 distinct printable VDOM names of at most 128 bytes, without %%",
    "nonempty-object": "must be a non-empty JSON object",
    "notify-fields": "requires server and topic_file and only the documented notification fields",
    "boolean": "must be true or false",
    "notify-timeout": "must be a number in 1..60",
    "policy": "audit policy cannot be loaded or is invalid for the platform",
    "channel-credential": "credential kind must match the collection channel: ssh uses password or ssh-key, fortios-rest uses api-token, file uses no credential",
    "auditor-platform": "the Auditor has no rule catalog for this platform",
}
FIELDS = {
    "configuration", "vault", "vault.version", "vault.credentials", "vault.credentials[]",
    "vault.credentials[].name", "vault.credentials[].kind", "vault.credentials[].login", "vault.credentials[].value",
    "inventory", "inventory.version", "inventory.devices", "inventory.devices[]",
    "config", "config.version", "config.devices", "config.devices[]", "config.notify",
    "config.notify.server", "config.notify.topic_file", "config.notify.timeout_seconds",
    "config.notify.x509_strict", "config.limits", "config.export_status_require_audit_file",
    "config.devices[].schema", "config.devices[].schema.vdoms",
    "config.devices[].schema.library", "config.devices[].schema.calibration",
    "auditor.tenant", "auditor.catalog",
}
FIELDS.update("inventory.devices[]." + field for field in (
    "name", "platform", "address", "port", "role", "credential", "host_key_fingerprint",
    "legacy_ssh", "helper", "auditor", "auditor.channel", "auditor.source",
    "auditor.required_sections", "auditor.required_sections[]", "auditor.tls_fingerprint"))
FIELDS.update("config.devices[]." + field for field in (
    "name", "platform", "address", "port", "host_key_fingerprint", "vault", "credential", "firmware",
    "safeguard_seconds", "confirm_margin_seconds", "protected", "legacy_ssh", "accounts",
    "check_credential", "check_address", "audit_policy"))
FIELDS.update("config." + field for field in (
    "state_dir", "audit_file", "vault", "audit_policy", "schema.library", "schema.calibration",
    "export_status_file", "safeguard_seconds", "confirm_margin_seconds", "port",
    "export_max_pending", "export_max_age_seconds", "export_status_max_age_seconds",
    "changes_per_device_per_hour", "changes_per_day", "rejections_per_hour", "plan_commands", "journal_records"))

FIELDS.update("config.limits." + field for field in (
    "export_max_pending", "export_max_age_seconds", "export_status_max_age_seconds",
    "changes_per_device_per_hour", "changes_per_day", "rejections_per_hour", "plan_commands", "journal_records"))

def _reason(code):
    if code == "platform":
        from netops_core.platforms import PLATFORMS, ALIASES
        return "must be one of " + ", ".join(PLATFORMS) + "; aliases: " + ", ".join(
            alias + " -> " + ALIASES[alias] for alias in sorted(ALIASES))
    if code == "inventory-role":
        from netops_core.inventory import ROLES
        return "must be one of " + ", ".join(ROLES)
    if code == "legacy-profile":
        from netops_core.legacy_ssh import PROFILES
        return "must be null or one of " + ", ".join(PROFILES)
    if code == "auditor-platform":
        from netops_auditor.mcp_server import available_platforms
        return "must be one of " + ", ".join(available_platforms())
    return REASONS[code]

OPERATION_SUFFIX = "; operation failed without automatic retry\n"
OPERATION_FAILURE = "Configuration operation failed; inspect private state and audit before retrying"
GENERAL_OPERATION_FAILURE = "Operation failed; inspect private state and audit before retrying"
GENERAL_OPERATION_PERMISSION = "NetOps could not access required files; check ownership and permissions"
OPERATION_PERMISSION = "Configuration could not access required files; check ownership and permissions"
OPERATION_MESSAGES = {
    "file-regular": "A single-link regular file is required",
    "file-owner": "Unexpected file owner",
    "file-mode": "Private file permissions are required",
    "file-size": "File exceeds its documented size limit",
    "file-changed": "File changed during read",
    "file-length": "File length changed during read",
    "audit-unavailable": "Mandatory MCP audit unavailable; operator workflow refused",
    "auditor-inventory": "Auditor inventory could not be loaded or the device selected; configure Auditor inventory/vault, or check --inventory and --device",
    "audit-metadata": "Unsupported operator audit metadata",
    "topic-missing": "No saved notification topic is available; supply notification_topic for setup or restore the private notification file",
    "topic-unreadable": "Saved Admin notification topic could not be read safely; inspect private state before supplying a replacement",
}

def operation_error(code):
    error = ValueError(OPERATION_MESSAGES.get(code, OPERATION_FAILURE))
    error.operation_diagnostic = code
    return error

def operation_message(error):
    seen = set()
    while isinstance(error, BaseException) and id(error) not in seen:
        seen.add(id(error))
        code = getattr(error, "operation_diagnostic", None)
        if isinstance(code, str) and code in OPERATION_MESSAGES:
            return OPERATION_MESSAGES[code]
        error = error.__cause__
    return None

class RoleConfigurationError(ValueError):
    pass

class SyslogConfigurationError(ValueError):
    pass

CONFIGURATION_MESSAGES = {
    "size": "Configuration exceeds supported size",
    "helper-inventory": "Invalid Helper inventory. Each helper section requires account_role, ssh_platform, enabled_queries and egress; check field types, target scope and credential references in docs/helper-configuration.md",
    "auditor-envelope": "Auditor configuration requires tenant/catalog and an optional inventory/vault pair",
    "role-envelope": "Use inventory/vault for Helper or config/vault with optional notification_topic for Admin",
    "notification-server": "notification_topic requires a notify server in Admin config",
    "notification-object": "Admin notify must be an object",
    "notification-topic": "Admin notification_topic must contain 8 to 64 letters, digits, underscores or hyphens",
}
SYSLOG_MESSAGES = {
    "invalid": "Invalid syslog configuration; check the documented schema",
    "size": "Configuration exceeds supported size",
    "envelope": "Syslog configuration requires host, optional port and optional public ca_pem",
    "port-decimal": "Syslog port must be a decimal port number",
    "port-range": "Syslog port must be between 1 and 65535",
    "certificate-ca": "The supplied public certificate must be a CA",
    "certificate": "ca_pem must contain a PEM-encoded CA certificate with BasicConstraints",
    "host": "Invalid certificate DNS name",
}

JSON_INPUT_MESSAGES = {
    "json-duplicate": "Duplicate JSON object keys are unsupported",
    "json-nonfinite": "Nonfinite JSON constants are unsupported",
    "json-encoding": "Input JSON encoding is invalid",
    "json-limits": "Input JSON exceeds supported number or nesting limits",
}
CONFIGURATION_MESSAGES.update(JSON_INPUT_MESSAGES)
SYSLOG_MESSAGES.update(JSON_INPUT_MESSAGES)

def configuration_message(code):
    return RoleConfigurationError(CONFIGURATION_MESSAGES.get(code, "Invalid role configuration: configuration: " + REASONS["invalid"]))

def syslog_configuration_error(code="invalid"):
    return SyslogConfigurationError(SYSLOG_MESSAGES.get(code, SYSLOG_MESSAGES["invalid"]))

def configuration_json_error(line, column, *, syslog=False):
    if type(line) is not int or type(column) is not int or line < 1 or column < 1:
        return syslog_configuration_error() if syslog else configuration_error()
    kind = SyslogConfigurationError if syslog else RoleConfigurationError
    return kind("Input is not valid JSON (line " + str(line) + ", column " + str(column) + ")")

def configuration_error(error=None, document=None, *, field="configuration", code="invalid", reference_field=None, index=None):
    seen = set()
    current = error
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        diagnostic = getattr(current, "diagnostic", None)
        if (isinstance(diagnostic, tuple) and len(diagnostic) == 2
                and all(isinstance(part, str) for part in diagnostic)
                and diagnostic[0] in FIELDS and diagnostic[1] in REASONS):
            field, code = diagnostic
            derived_index = getattr(current, "diagnostic_index", None)
            if type(derived_index) is int and derived_index >= 0:
                index = derived_index
            break
        current = current.__cause__
    if field not in FIELDS or code not in REASONS:
        field, code = "configuration", "invalid"
    if code == "reference" and isinstance(reference_field, str) and reference_field in FIELDS:
        field = reference_field
    if type(index) is int and index >= 0 and field.startswith("inventory.devices[]"):
        field = field.replace("inventory.devices[]", "inventory.devices[" + str(index) + "]", 1)
    prefix = ("Role configuration could not be loaded: " if code in
              {"read", "regular", "owner", "private-mode", "single-link", "policy"} else
              "Invalid role configuration: ")
    return RoleConfigurationError(prefix + field + ": " + _reason(code))
