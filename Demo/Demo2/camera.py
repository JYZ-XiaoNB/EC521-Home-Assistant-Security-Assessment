from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional

_LOGGER = logging.getLogger(__name__)


class CameraError(RuntimeError):
    pass


def capture_still_image(output_path: Path) -> None:
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        placeholder = b"\xff\xd8\xff\xe0DEMO_CAMERA_IMAGE"
        with open(output_path, "wb") as fh:
            fh.write(placeholder)
        _LOGGER.info("Demo2 camera wrote placeholder image to %s", output_path)
    except OSError as err:
        raise CameraError(f"Failed to write image file {output_path}: {err}") from err


def demo_capture() -> Optional[Path]:
    out = Path("demo2_still.jpg")
    try:
        capture_still_image(out)
    except CameraError as exc:
        _LOGGER.error("Demo2 camera error: %s", exc)
        return None
    return out
