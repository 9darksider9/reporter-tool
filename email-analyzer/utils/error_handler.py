import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def log_error(error_message):
    """Logs an error message."""
    logger.error(error_message)

def handle_exception(exception):
    """Handles exceptions and logs errors."""
    error_message = f"Exception: {str(exception)}"
    log_error(error_message)
    return {"error": "An internal error occurred. Please check logs."}