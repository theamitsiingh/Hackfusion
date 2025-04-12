import os
import json
from datetime import datetime
from typing import Dict, Any, List

class ErrorLogger:
    """
    Comprehensive error logging and management system for HackFusion
    """
    ERROR_LOG_DIR = '/home/kali/Desktop/main/HackFusionkali/HackFusion/reports/error_logs/'
    
    @classmethod
    def initialize(cls):
        """Ensure error log directory exists"""
        os.makedirs(cls.ERROR_LOG_DIR, exist_ok=True)
    
    @classmethod
    def log_error(cls, error_data: Dict[str, Any]) -> str:
        """
        Log an error with comprehensive details
        
        :param error_data: Dictionary containing error information
        :return: Path to the created error log file
        """
        # Ensure directory exists
        cls.initialize()
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"error_log_{timestamp}.json"
        filepath = os.path.join(cls.ERROR_LOG_DIR, filename)
        
        # Standardize error data
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'category': error_data.get('category', 'Unknown'),
            'tool': error_data.get('tool', 'Unknown'),
            'action': error_data.get('action', 'Unknown'),
            'error_message': error_data.get('error', 'No specific error message'),
            'context': error_data.get('context', {}),
            'severity': cls._determine_severity(error_data)
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(error_entry, f, indent=4)
        
        return filepath
    
    @classmethod
    def _determine_severity(cls, error_data: Dict[str, Any]) -> str:
        """
        Determine error severity based on error characteristics
        
        :param error_data: Dictionary containing error information
        :return: Severity level (Critical, High, Medium, Low)
        """
        error_msg = str(error_data.get('error', '')).lower()
        
        # Severity mapping
        severity_map = {
            'critical': ['authentication', 'permission', 'critical', 'fatal'],
            'high': ['network', 'connection', 'timeout', 'security'],
            'medium': ['configuration', 'tool', 'dependency'],
            'low': ['warning', 'info']
        }
        
        # Check severity based on error message
        for severity, keywords in severity_map.items():
            if any(keyword in error_msg for keyword in keywords):
                return severity.capitalize()
        
        return 'Low'
    
    @classmethod
    def get_recent_errors(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve most recent error logs
        
        :param limit: Number of recent error logs to retrieve
        :return: List of recent error logs
        """
        # Ensure directory exists
        cls.initialize()
        
        # Get all error log files, sorted by modification time
        error_files = sorted(
            [os.path.join(cls.ERROR_LOG_DIR, f) for f in os.listdir(cls.ERROR_LOG_DIR) 
             if f.startswith('error_log_') and f.endswith('.json')],
            key=os.path.getmtime,
            reverse=True
        )
        
        # Read and return recent error logs
        recent_errors = []
        for filepath in error_files[:limit]:
            try:
                with open(filepath, 'r') as f:
                    recent_errors.append(json.load(f))
            except Exception as e:
                print(f"Error reading {filepath}: {e}")
        
        return recent_errors
    
    @classmethod
    def analyze_error_trends(cls) -> Dict[str, Any]:
        """
        Analyze error trends across logged errors
        
        :return: Dictionary of error trend analysis
        """
        recent_errors = cls.get_recent_errors(limit=50)
        
        # Trend analysis
        trends = {
            'severity_distribution': {},
            'top_categories': {},
            'top_tools': {}
        }
        
        # Analyze severity
        for error in recent_errors:
            severity = error.get('severity', 'Unknown')
            trends['severity_distribution'][severity] = \
                trends['severity_distribution'].get(severity, 0) + 1
            
            # Analyze categories
            category = error.get('category', 'Unknown')
            trends['top_categories'][category] = \
                trends['top_categories'].get(category, 0) + 1
            
            # Analyze tools
            tool = error.get('tool', 'Unknown')
            trends['top_tools'][tool] = \
                trends['top_tools'].get(tool, 0) + 1
        
        return trends
    
    @classmethod
    def clear_old_logs(cls, days: int = 30):
        """
        Remove error logs older than specified days
        
        :param days: Number of days to keep logs
        """
        import time
        
        current_time = time.time()
        for filename in os.listdir(cls.ERROR_LOG_DIR):
            filepath = os.path.join(cls.ERROR_LOG_DIR, filename)
            file_modified = os.path.getmtime(filepath)
            
            # Remove if older than specified days
            if (current_time - file_modified) // (24 * 3600) >= days:
                os.remove(filepath)

# Initialize error logging directory
ErrorLogger.initialize()
