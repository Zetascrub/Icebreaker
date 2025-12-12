from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

console = Console()

class StructuredLogger:
    """Structured logger that supports both console output and JSON logging."""

    def __init__(self, name: str, log_file: Optional[Path] = None, json_format: bool = False):
        self.name = name
        self.log_file = log_file
        self.json_format = json_format
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        self.logger.handlers.clear()

        # Add file handler if log_file is specified
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(log_file)
            handler.setLevel(logging.DEBUG)
            if json_format:
                handler.setFormatter(JSONFormatter())
            else:
                handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
            self.logger.addHandler(handler)

    def _log(self, level: str, message: str, **kwargs: Any) -> None:
        """Internal logging method."""
        extra = kwargs.copy()
        extra['timestamp'] = datetime.now(timezone.utc).isoformat()

        # Log to file
        log_func = getattr(self.logger, level.lower())
        log_func(message, extra={'structured_data': extra})

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self._log('DEBUG', message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self._log('INFO', message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self._log('WARNING', message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self._log('ERROR', message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self._log('CRITICAL', message, **kwargs)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add structured data if present
        if hasattr(record, 'structured_data'):
            log_data.update(record.structured_data)

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def get_logger(name: str, ctx: Optional[Any] = None) -> StructuredLogger:
    """Get or create a structured logger."""
    log_file = None
    json_format = False

    if ctx and hasattr(ctx, 'out_dir'):
        log_file = Path(ctx.out_dir) / "icebreaker.log"
        json_format = ctx.settings.get('json_logs', False)

    return StructuredLogger(name, log_file=log_file, json_format=json_format)
