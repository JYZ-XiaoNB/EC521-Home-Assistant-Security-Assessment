"""Hardened demo script interface without dynamic exec."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

_LOGGER = logging.getLogger(__name__)


def run_script(source: str, data: Optional[Mapping[str, Any]] = None) -> None:
    """Receive a script but do not execute it.

    In this hardened version we deliberately disable dynamic code execution.
    The function only logs metadata about the script for audit purposes.
    """
    if not isinstance(source, str):
        source = str(source)

    length = len(source)
    has_data = bool(data)
    _LOGGER.info(
        "Script execution is disabled for security. "
        "Received script length=%d, with_data=%s",
        length,
        has_data,
    )
