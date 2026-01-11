"""Logging configuration for WPT scanner."""

import logging
import sys
from typing import Optional


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        name: Logger name (typically module name)
        verbose: If True, set log level to DEBUG, otherwise INFO

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
