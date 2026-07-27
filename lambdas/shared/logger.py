"""
Structured JSON logging for all cloudguard-pro Lambdas.

Every log line is a single JSON object so CloudWatch Logs Insights can
query on fields like `finding_id`, `severity`, or `lambda_name` without
regex parsing.
"""

import json
import logging
import sys
import time
from typing import Any


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def __init__(self, lambda_name: str):
        super().__init__()
        self.lambda_name = lambda_name

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)
            ),
            "level": record.levelname,
            "lambda_name": self.lambda_name,
            "message": record.getMessage(),
        }

        # Allow callers to attach structured context via `extra={"context": {...}}`
        context = getattr(record, "context", None)
        if context:
            payload["context"] = context

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def get_logger(lambda_name: str) -> logging.Logger:
    """
    Returns a configured logger that emits structured JSON to stdout,
    which Lambda automatically forwards to CloudWatch Logs.
    """
    logger = logging.getLogger(lambda_name)

    # Avoid duplicate handlers if Lambda container is reused (warm start)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter(lambda_name))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger


def log_with_context(
    logger: logging.Logger, level: int, message: str, **context: Any
) -> None:
    """Convenience wrapper to log a message with structured context fields."""
    logger.log(level, message, extra={"context": context})
