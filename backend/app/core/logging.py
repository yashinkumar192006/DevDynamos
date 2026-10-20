"""Structured application logging (JSON) with sensitive-key redaction.

Log records are emitted as single-line JSON via the standard library
logging stack (python-json-logger), with structlog providing the event
API. Before any structlog event is rendered, a sanitizer processor
replaces the *values* of keys that look sensitive (passwords, tokens,
secrets, keys, credentials, cookies, SSNs, salaries, emails, phones) with
``"[REDACTED]"``.

This is defense in depth, not a licence to log payloads: application code
must still avoid passing sensitive values to loggers at all. The
sanitizer exists so that a future careless log call cannot casually emit
a credential or PII value into the log stream.
"""

import logging
from typing import Any, MutableMapping

import structlog
from pythonjsonlogger import jsonlogger

#: Case-insensitive substrings that mark an event-dict key whose value
#: must never be rendered. Chosen to over-match: a false positive only
#: makes a log line less useful, never less safe.
_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "cookie",
    "ssn",
    "social_security",
    "salary",
    "email",
    "phone",
    "iban",
    "card_number",
    "cvv",
)

_REDACTED = "[REDACTED]"


def sanitize_event_dict(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Structlog processor: redact values of sensitive-looking keys."""
    for key in list(event_dict.keys()):
        lowered = str(key).lower()
        if any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS):
            event_dict[key] = _REDACTED
    return event_dict


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
        sanitize_event_dict,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("contextshield")
