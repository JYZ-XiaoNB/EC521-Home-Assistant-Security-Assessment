from __future__ import annotations
import logging
from typing import Optional, Tuple

_LOGGER = logging.getLogger(__name__)

SUPPORTED_LANGUAGES = {"en-US","en-GB","de-DE","es-ES","fr-FR","it-IT"}


def _normalize_language(language: str) -> str:
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language: {language}")
    return language


def synthesize_to_wav(message: str, language: str) -> Tuple[Optional[str], Optional[bytes]]:
    if not isinstance(message, str):
        message = str(message)
    if len(message) > 5000:
        message = message[:5000]
    lang = _normalize_language(language)
    payload = f"DEMO2_TTS[{lang}]:{message}".encode("utf-8")
    _LOGGER.info("Demo2 TTS synthesized %d bytes of placeholder audio", len(payload))
    return "wav", payload
