#!/usr/bin/env python3
"""
Main entry point for HackFusion
"""

import sys
import os

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

# Import logging configuration first
from src.utils.logging_config import configure_logging
configure_logging()

import logging
logger = logging.getLogger(__name__)

try:
    from src.menu import Menu
    from src.feedback import FeedbackManager

    def main():
        """
        Main entry point for HackFusion
        Provides comprehensive error handling and logging
        """
        try:
            logger.info("🚀 Initializing HackFusion")
            # Initialize feedback manager for colored output
            feedback = FeedbackManager()
            feedback.print_banner()
            
            # Create and run menu
            menu = Menu()
            menu.run()
        except Exception as e:
            logger.error(f"Critical error in HackFusion: {e}", exc_info=True)
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)
    
    if __name__ == "__main__":
        main()
except Exception as startup_error:
    logger.critical(f"Failed to start HackFusion: {startup_error}", exc_info=True)
    print(f"Startup error: {startup_error}")
    sys.exit(1)
