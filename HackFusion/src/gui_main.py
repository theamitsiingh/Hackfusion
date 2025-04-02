"""
GUI entry point for HackFusion
"""

import sys
import os

# Add src directory to Python path
src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if src_dir not in sys.path:
    sys.path.append(src_dir)

from src.gui.main_window import main

if __name__ == "__main__":
    main()
