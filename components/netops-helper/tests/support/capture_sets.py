"""Select complete capture sets under fixtures/real/<platform>/ for the generic real-output tests."""
from pathlib import Path


def is_partial_capture(directory: Path) -> bool:
    """A partial capture documents itself in PROVENANCE.md and has no index.json (complete sets always have one)."""
    return (directory / 'PROVENANCE.md').is_file() and not (directory / 'index.json').is_file()


def complete_sets(parent: Path) -> list:
    """Every directory except explicitly partial ones; a complete set that lacks a file is still returned and fails."""
    return sorted(p for p in parent.iterdir() if p.is_dir() and not is_partial_capture(p))
