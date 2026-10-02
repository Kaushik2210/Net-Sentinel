import logging
import sys

# Separate loggers per concern so ingestion, detection and audit output can be routed and
# filtered independently (e.g. shipped to different sinks).
LOGGERS = ("netsentinel.app", "netsentinel.ingest", "netsentinel.detect", "netsentinel.audit", "netsentinel.seed")


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    for name in LOGGERS:
        lg = logging.getLogger(name)
        lg.setLevel(level)
        lg.handlers = [handler]
        lg.propagate = False
