"""Validated per-target Wi-Fi heuristics; these are operator defaults, not vendor limits."""
DEFAULTS = {"weak_signal_dbm": -70, "very_weak_signal_dbm": -75, "low_snr_db": 20,
            "busy_percent": 70, "retry_percent": 20, "interfering_aps": 5, "strong_neighbor_dbm": -60}


def thresholds(value=None):
    value = {} if value is None else value
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError("wifi_thresholds must contain only documented threshold names")
    result = {**DEFAULTS, **value}
    for key, number in result.items():
        low, high = (-150, 0) if key.endswith("dbm") else (0, 100) if key != "interfering_aps" else (1, 1000)
        if type(number) is not int or not low <= number <= high:
            raise ValueError("wifi_thresholds values must be integers within documented bounds")
    if result["very_weak_signal_dbm"] >= result["weak_signal_dbm"]:
        raise ValueError("very_weak_signal_dbm must be below weak_signal_dbm")
    return result
