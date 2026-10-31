"""Structured logging utility."""
from __future__ import annotations

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Return a logger with a consistent format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def configure_logging(verbose: bool = False, silent: bool = False) -> None:
    """Set global log level."""
    level = logging.DEBUG if verbose else (logging.CRITICAL if silent else logging.INFO)
    logging.getLogger("submap").setLevel(level)
    # Silence noisy third-party loggers
    for lib in ("httpx", "httpcore", "asyncio", "dnspython", "urllib3"):
        logging.getLogger(lib).setLevel(logging.CRITICAL)
