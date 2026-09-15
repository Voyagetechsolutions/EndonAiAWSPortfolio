"""Logging setup. In Lambda, the function uses the JSON log format, so fields
passed through ``extra`` arrive in CloudWatch as structured, queryable keys."""

from __future__ import annotations

import logging
import os


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(os.environ.get("ENDON_LOG_LEVEL", "INFO").upper())
    return logger
