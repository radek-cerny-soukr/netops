import sys
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]

for source in (COMPONENT / "src", COMPONENT.parent / "netops-core" / "src"):
    sys.path.insert(0, str(source))
