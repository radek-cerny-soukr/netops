"""Shared Wi-Fi value interpretation, independent of transports and event parsing."""

_BAND_EXACT = {"11B": "24ghz", "11G": "24ghz", "11A": "5ghz"}
_BAND_PREFIX = (("11NG", "24ghz"), ("11AXG", "24ghz"), ("11NA", "5ghz"), ("11AC", "5ghz"),
                ("11AXA", "5ghz"), ("11AX6G", "6ghz"))


def phy_band(mode):
    """Band only for measured-shape PHY modes; anything else (e.g. 11BE*) stays unknown."""
    if mode in _BAND_EXACT:
        return _BAND_EXACT[mode]
    return next((band for prefix, band in _BAND_PREFIX if mode.startswith(prefix)), None)
