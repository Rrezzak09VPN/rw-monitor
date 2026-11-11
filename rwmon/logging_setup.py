"""Logging to stdout (journald) with secret masking applied to every record."""

from __future__ import annotations

import logging
import sys

from .security import MASKER


class MaskingFormatter(logging.Formatter):
    """Masks the fully rendered record, including arguments and tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return MASKER.mask(super().format(record))


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        MaskingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Library loggers are noisy at INFO and may echo request URLs.
    logging.getLogger("aiogram.event").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
