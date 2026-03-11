import logging
from pathlib import Path
from datetime import datetime
from config.settings import settings


def setup_logger():
    """
    Initialize the global TCAF logger.
    """
    date_str = datetime.now().strftime("%Y_%m_%d")
    log_file = settings.LOG_DIR / f"{date_str}_tcaf.log"


    logger = logging.getLogger("tcaf")
    logger.setLevel(settings.LOG_LEVEL)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )

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

