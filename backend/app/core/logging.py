import structlog
import logging
from pythonjsonlogger import jsonlogger

# Configure root logger to output JSON for structured logging
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    "%({levelname})s %(asctime)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[handler])

# Configure structlog to use the standard library logger
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("contextshield")
