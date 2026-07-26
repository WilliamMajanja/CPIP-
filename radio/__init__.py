from __future__ import annotations

import sys
from pathlib import Path

_radio_dir = Path(__file__).parent
if str(_radio_dir) not in sys.path:
    sys.path.insert(0, str(_radio_dir))

from radio_protocol import RadioError, RadioInterface

__all__ = ["RadioError", "RadioInterface"]
