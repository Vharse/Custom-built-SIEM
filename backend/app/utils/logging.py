import logging
import os
import sys

LOG_FILE_PATH = "/app/data/vault_errors.log"
logger = logging.getLogger("vault_security")
logger.setLevel(logging.ERROR)

try:
    handler = logging.FileHandler(LOG_FILE_PATH)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(handler)
except OSError:
    logger.addHandler(logging.StreamHandler(sys.stdout))


def setup_uvicorn_logging():
    """Injects gear icon branding and pipe syntax into Uvicorn terminal logs."""
    log_format = "[%(asctime)s] ⚙️ BACKEND | %(levelname)s | %(message)s"
    date_format = "%Y-%m-%dT%H:%M:%S%z"

    formatter = logging.Formatter(fmt=log_format, datefmt=date_format)

    uv_root = logging.getLogger("uvicorn")
    uv_root.propagate = False
    
    if uv_root.handlers:
        for h in uv_root.handlers:
            h.setFormatter(formatter)
    else:
        root_console = logging.StreamHandler(sys.stdout)
        root_console.setFormatter(formatter)
        uv_root.addHandler(root_console)

    uv_err = logging.getLogger("uvicorn.error")
    uv_err.propagate = True
    uv_err.handlers = []

    uv_acc = logging.getLogger("uvicorn.access")
    uv_acc.propagate = False
    
    if uv_acc.handlers:
        for h in uv_acc.handlers:
            h.setFormatter(formatter)
    else:
        access_console = logging.StreamHandler(sys.stdout)
        access_console.setFormatter(formatter)
        uv_acc.addHandler(access_console)


setup_uvicorn_logging()