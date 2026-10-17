import json
from . import __version__
from .files import STATE, UIDS, read_private

INITIALIZE_HINT = "NetOps is not initialized; run docker compose run --rm netops init first"

class StateCompatibilityError(ValueError):
    pass

class OperatorAccessError(ValueError):
    pass

def require_initialized(directory=None):
    directory = STATE if directory is None else directory
    try:
        (directory / "gateway" / "config.json").lstat()
    except FileNotFoundError:
        raise StateCompatibilityError(INITIALIZE_HINT) from None

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate state setting")
        result[key] = value
    return result

def _constant(value):
    raise ValueError("Nonfinite state setting")

def check_state_version(settings):
    if not isinstance(settings, dict) or type(settings.get("version")) is not int or settings["version"] != 1:
        raise StateCompatibilityError("Unsupported state schema; use the matching NetOps release and its verified recovery procedure")
    if settings.get("product_version") != __version__:
        raise StateCompatibilityError("State belongs to another product version; automatic upgrade or downgrade is refused. Use the verified release procedure")
    return settings

def read_state_settings(directory=None):
    directory = STATE if directory is None else directory
    try:
        raw = read_private(directory / "gateway" / "config.json", owner=UIDS["gateway"])
        settings = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except FileNotFoundError:
        raise StateCompatibilityError(INITIALIZE_HINT) from None
    except (OSError, ValueError, RecursionError):
        raise StateCompatibilityError("Initialized private state cannot be read safely; initialize a new instance or use the matching release to inspect existing state") from None
    return check_state_version(settings)
