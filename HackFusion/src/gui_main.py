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
from src.error_management.error_logger import ErrorLogger

class HackFusionGUI:
    def __init__(self):
        # Existing initialization code...
        pass
    
    def show_error_management_menu(self):
        """
        Display error management and debugging menu
        """
        while True:
            print("\n--- Error Management & Debugging ---")
            print("1. View Recent Errors")
            print("2. Analyze Error Trends")
            print("3. Clear Old Error Logs")
            print("4. Export Error Logs")
            print("0. Return to Main Menu")
            
            choice = input("Enter your choice: ")
            
            if choice == '1':
                self._view_recent_errors()
            elif choice == '2':
                self._analyze_error_trends()
            elif choice == '3':
                self._clear_old_logs()
            elif choice == '4':
                self._export_error_logs()
            elif choice == '0':
                break
            else:
                print("Invalid choice. Please try again.")
    
    def _view_recent_errors(self):
        """View and display recent error logs"""
        recent_errors = ErrorLogger.get_recent_errors(limit=20)
        
        if not recent_errors:
            print("No recent errors found.")
            return
        
        print("\n--- Recent Error Logs ---")
        for idx, error in enumerate(recent_errors, 1):
            print(f"\nError {idx}:")
            print(f"Timestamp: {error.get('timestamp', 'N/A')}")
            print(f"Category: {error.get('category', 'Unknown')}")
            print(f"Tool: {error.get('tool', 'Unknown')}")
            print(f"Action: {error.get('action', 'Unknown')}")
            print(f"Severity: {error.get('severity', 'Unknown')}")
            print(f"Error Message: {error.get('error_message', 'No details')}")
    
    def _analyze_error_trends(self):
        """Analyze and display error trends"""
        trends = ErrorLogger.analyze_error_trends()
        
        print("\n--- Error Trend Analysis ---")
        
        print("\nSeverity Distribution:")
        for severity, count in trends['severity_distribution'].items():
            print(f"{severity}: {count}")
        
        print("\nTop Error Categories:")
        for category, count in sorted(trends['top_categories'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{category}: {count}")
        
        print("\nTop Problematic Tools:")
        for tool, count in sorted(trends['top_tools'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{tool}: {count}")
    
    def _clear_old_logs(self):
        """Clear old error logs"""
        days = input("Enter number of days to keep logs (default 30): ") or 30
        try:
            days = int(days)
            ErrorLogger.clear_old_logs(days)
            print(f"Cleared error logs older than {days} days.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    def _export_error_logs(self):
        """Export error logs to a specified location"""
        import shutil
        
        export_path = input("Enter export directory path: ")
        try:
            os.makedirs(export_path, exist_ok=True)
            shutil.copytree(
                ErrorLogger.ERROR_LOG_DIR, 
                os.path.join(export_path, 'hackfusion_error_logs'), 
                dirs_exist_ok=True
            )
            print("Error logs exported successfully.")
        except Exception as e:
            print(f"Error exporting logs: {e}")
    
    def main_menu(self):
        """Main menu with added error management option"""
        while True:
            print("\n--- HackFusion Main Menu ---")
            # ... existing menu options ...
            print("9. Error Management")
            print("0. Exit")
            
            choice = input("Enter your choice: ")
            
            # ... existing menu logic ...
            
            elif choice == '9':
                self.show_error_management_menu()
            
            # ... rest of the menu logic ...

if __name__ == "__main__":
    gui = HackFusionGUI()
    gui.main_menu()
