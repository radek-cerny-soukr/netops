"""Local, explicit RF relevance and BSSID grouping of untrusted observations."""
from .wifi_rest import radio_band, width_mhz


def span(channel, width, band):
    if type(channel) is not int or channel <= 0 or band not in ("24ghz", "5ghz", "6ghz"):
        return None
    frequency = (2407 if band == "24ghz" else 5000 if band == "5ghz" else 5950) + 5 * channel
    if width is None:
        return frequency, frequency  # primary only, never invent a channel width
    if band == "24ghz":
        # Without a secondary-channel direction only possible overlap can be decided.
        return frequency - width + 10, frequency + width - 10
    base = 1 if band == "6ghz" else 149 if channel >= 149 else 36 if channel < 100 else 100
    start = base + ((channel - base) // (4 * (width // 20))) * (4 * (width // 20))
    low = (5950 if band == "6ghz" else 5000) + 5 * start - 10
    return low, low + width


def relevant_contexts(row, contexts, *, require_observer=False):
    """Keep the observer/operating-radio pairs with established spectral overlap."""
    band = row.get("band") or radio_band(row)
    width = width_mhz(row.get("channel_width", row.get("bw", row.get("channel_bonding"))))
    observed = span(row.get("channel"), width, band)
    if observed is None:
        return []
    observers = row.get("detected_by_wtp", row.get("wtps", []))
    if require_observer and not observers:
        return []
    result = []
    for context in contexts:
        own = span(context.get("channel"), context.get("channel_width_mhz"), context.get("band"))
        if band != context.get("band") or own is None or (observers and not any(
                observer_matches(w, context) for w in observers if isinstance(w, dict))):
            continue
        # Unknown width does not invalidate an exact primary-channel match.
        # Only that match is established; spectral overlap remains unknown.
        if row.get("channel") == context.get("channel"):
            result.append(context)
            continue
        if context.get("channel_width_mhz") is None:
            continue
        if max(own[0], observed[0]) < min(own[1], observed[1]):
            result.append(context)
        elif observed[0] == observed[1] and own[0] < observed[0] < own[1]:
            result.append(context)
    return result


def relevant(row, contexts, *, require_observer=False):
    return bool(relevant_contexts(row, contexts, require_observer=require_observer))


def observer_matches(observer, context):
    ids = set(context.get("ap_ids", [context.get("ap_id")])) - {None}
    radio = observer.get("wtp_radio", observer.get("radio"))
    return bool(ids.intersection((observer.get("serial"), observer.get("wtp_id"), observer.get("name")))) and (
        radio is None or context.get("radio") is None or radio == context["radio"])


def context_status(contexts):
    if not contexts:
        return "missing_context"
    return "width_unknown" if any(c.get("channel_width_mhz") is None for c in contexts) else "available"


def group_bssid(rows, full):
    groups = {}
    for index, row in enumerate(rows):
        key = row.get("mac")
        key = key.lower() if isinstance(key, str) else ("unidentified", index)
        groups.setdefault(key, []).append(row)
    result = []
    for mac, observations in groups.items():
        row = dict(max(observations, key=lambda o: o.get("signal_strength")
                       if type(o.get("signal_strength")) in (int, float) else -151)) if not full else dict(observations[0])
        row["deduplicated_bssid"] = len(observations) > 1
        row["observation_count"] = len(observations)
        if full:
            row["observations"] = observations
        else:
            row = {k: v for k, v in row.items() if k in {"mac", "ssid", "channel", "band", "signal_strength", "signal_observers", "signal_scope", "noise", "last_seen", "deduplicated_bssid", "observation_count"}}
            row["heard_by"] = sorted({w.get("name") or w.get("serial") or w.get("wtp_id") for o in observations
                                      for w in o.get("detected_by_wtp", o.get("wtps", [])) if isinstance(w, dict)
                                      and (w.get("name") or w.get("serial") or w.get("wtp_id"))})
        result.append(row)
    return result


def observation_signal(row, kind, contexts, full=False):
    """Strongest valid signal from selected observers (or all for a full read)."""
    observers = row.get("detected_by_wtp", row.get("wtps", []))
    if not full and (kind == "rogue" or row.get("channel") is not None):
        contexts = relevant_contexts(row, contexts)
    scoped = [w for w in observers if isinstance(w, dict) and
              (full or any(observer_matches(w, c) for c in contexts))]
    if observers and not full:
        values = [w.get("signal_strength", w.get("signal")) for w in scoped]
    else:
        values = ([row.get("signal_strength")] if kind == "rogue" else
                  [w.get("signal") for w in observers if isinstance(w, dict)])
    values = [v for v in values if type(v) in (int, float) and -150 <= v <= 0]
    return max(values) if values else -151


def scoped_observation(row, kind, contexts):
    """Use the same relevant observers for filtering, ordering and the public summary."""
    if kind == "rogue" or row.get("channel") is not None:
        contexts = relevant_contexts(row, contexts)
    result = dict(row)
    key = "detected_by_wtp" if "detected_by_wtp" in row else "wtps"
    observers = [w for w in row.get(key, []) if isinstance(w, dict)
                 and any(observer_matches(w, c) for c in contexts)]
    result[key] = observers
    signal = observation_signal(result, kind, contexts)
    result["signal_strength"] = signal if signal > -151 else None
    result["signal_scope"] = "relevant_observers" if row.get(key) else "controller_wide"
    result["signal_observers"] = sorted({w.get("name") or w.get("serial") or w.get("wtp_id") for w in observers
        if w.get("signal_strength", w.get("signal")) == signal
        and (w.get("name") or w.get("serial") or w.get("wtp_id"))})
    return result
