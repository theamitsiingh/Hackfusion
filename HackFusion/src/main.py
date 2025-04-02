#!/usr/bin/env python3
"""
Main entry point for HackFusion
"""

import os
import sys
import traceback

# Add src directory to Python path
src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if src_dir not in sys.path:
    sys.path.append(src_dir)

from src.menu import Menu
from src.feedback import FeedbackManager

def main():
    """Main entry point"""
    try:
        # Initialize feedback manager for colored output
        feedback = FeedbackManager()
        feedback.print_banner()
        
        # Create and run menu
        menu = Menu()
        menu.run()
        
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("\nTraceback:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
