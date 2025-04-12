import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

def configure_logging(log_level=logging.INFO, log_dir='/tmp/hackfusion_logs'):
    """
    Configure comprehensive logging for HackFusion
    
    :param log_level: Logging level (default: INFO)
    :param log_dir: Directory to store log files
    """
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    # Logging format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            # Console handler with Rich formatting
            RichHandler(rich_tracebacks=True),
            
            # File handler with rotation
            RotatingFileHandler(
                os.path.join(log_dir, 'hackfusion.log'),
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5
            )
        ]
    )
    
    # Add error logging to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    
    # Configure specific loggers
    tool_loggers = [
        'information_gathering',
        'network_attacks',
        'vulnerability_analysis',
        'web_application',
        'password_attacks'
    ]
    
    for logger_name in tool_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)
    
    # Capture unhandled exceptions
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception

# Configure logging when module is imported
configure_logging()
