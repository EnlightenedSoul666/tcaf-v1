import logging
from pathlib import Path

from config.settings import settings


def setup_logger():
    """
    Initialize the global TCAF logger.
    """

    log_file = settings.LOG_DIR / "tcaf.log"

    logger = logging.getLogger("tcaf")
    logger.setLevel(settings.LOG_LEVEL)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )

    # Create logs directory if it doesn't exist
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


logger = setup_logger()