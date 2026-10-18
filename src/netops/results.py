def tool_failed(role, name, result):
    if result.get("isError") is True:
        return True
    payload = result.get("structuredContent")
    if not isinstance(payload, dict):
        return False
    if role == "helper":
        return payload.get("ok") is False
    if role == "admin":
        outcome = payload.get("result")
        if outcome == "unknown-operation":
            return True
        if name == "admin_status":
            return False
        if name == "admin_doctor":
            return payload.get("ready") is False or outcome == "rejected"
        return outcome in {"rejected", "unknown", "reverted", "revert-failed"}
    return False
