import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger("catalog")


class OperationalFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Library exception messages can contain user inputs. Retain severity/source, not payloads.
        data = {
            "time": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "source": record.name,
            "event": getattr(record, "event", "library_event"),
        }
        for field in ("tool", "outcome", "count", "status", "duration_ms"):
            if hasattr(record, field):
                data[field] = getattr(record, field)
        return json.dumps(data)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(OperationalFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)
    logger.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastmcp"):
        library = logging.getLogger(name)
        library.handlers = []
        library.propagate = True
