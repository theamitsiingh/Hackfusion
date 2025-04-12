"""
AI Assistant for HackFusion
"""

import os
import logging
import traceback
from typing import Dict, Any, List
from datetime import datetime
from openai import OpenAI
from src.error_management.error_logger import ErrorLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/tmp/hackfusion_ai_debug.log'
)
logger = logging.getLogger('AIAssistant')

class AIAssistant:
    def __init__(self):
        """Initialize AI Assistant with enhanced logging"""
        try:
            self.api_key = os.getenv('OPENAI_API_KEY')
            if not self.api_key:
                error_data = {
                    'category': 'AI Assistant',
                    'tool': 'OpenAI',
                    'action': 'Initialization',
                    'error': 'OPENAI_API_KEY environment variable not set',
                    'severity': 'Critical'
                }
                error_log_path = ErrorLogger.log_error(error_data)
                logger.error(f"Error logged to {error_log_path}")
                raise ValueError("OPENAI_API_KEY environment variable not set")
            
            self.client = OpenAI(api_key=self.api_key)
            logger.info("OpenAI client initialized successfully")
        except Exception as e:
            error_data = {
                'category': 'AI Assistant',
                'tool': 'OpenAI',
                'action': 'Initialization',
                'error': str(e),
                'context': {
                    'traceback': traceback.format_exc()
                }
            }
            ErrorLogger.log_error(error_data)
            logger.error(f"AI Assistant initialization failed: {e}")
            logger.error(traceback.format_exc())
            raise

    def analyze_request(self, user_input: str) -> Dict[str, Any]:
        """Analyze user request with comprehensive error handling"""
        logger.info(f"Analyzing request: {user_input[:100]}...")
        
        system_prompt = """You are HackFusion's AI assistant for cybersecurity tasks. Given the user's request:
1. Analyze what they want to do
2. Recommend the most appropriate tools and techniques
3. Create a detailed step-by-step action plan

The available tools and techniques include:
- Network scanning (nmap)
- Service enumeration
- Vulnerability assessment
- Port scanning
- Network sniffing
- WHOIS lookups
- DNS enumeration
- Password attacks
- Wireless network analysis
- Web application testing
- Man-in-the-middle attacks
- ARP spoofing
- Traffic analysis

Output format must be valid JSON with:
{
    "category": "main category (e.g., network_scanning, info_gathering)",
    "description": "Brief description of what we're going to do",
    "tools": ["list of required tools"],
    "steps": [
        {
            "tool": "tool name",
            "action": "specific action",
            "description": "detailed description of this step",
            "params": {"param1": "value1"}
        }
    ],
    "report_sections": ["sections to include in report"]
}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input}
                ]
            )
            
            result = self._validate_openai_response(response)
            logger.info("Request analysis completed successfully")
            return result
            
        except Exception as e:
            # Log detailed error information
            error_data = {
                'category': 'AI Request Analysis',
                'tool': 'OpenAI GPT-4',
                'action': 'Request Processing',
                'error': str(e),
                'context': {
                    'user_input': user_input,
                    'input_length': len(user_input),
                    'traceback': traceback.format_exc()
                }
            }
            
            # Log error and get log file path
            error_log_path = ErrorLogger.log_error(error_data)
            
            # Log additional diagnostic information
            logger.error(f"Error analyzing request. Log file: {error_log_path}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            raise Exception(f"Error analyzing request: {str(e)}")

    def get_next_step_params(self, step: Dict[str, Any], previous_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get optimal parameters for next step with error logging"""
        logger.info("Determining next step parameters...")
        
        system_prompt = """You are HackFusion's AI assistant. Based on the current step requirements and previous results,
determine the optimal parameters for the next step. Consider:
1. Previous step results
2. Target type (network, host, domain, etc.)
3. Required tool parameters
4. Safety and efficiency

Output must be valid JSON."""

        try:
            context = {
                "current_step": step,
                "previous_results": previous_results
            }
            
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": str(context)}
                ]
            )
            
            result = self._validate_openai_response(response)
            logger.info("Next step parameters determined successfully")
            return result
            
        except Exception as e:
            # Log detailed error information
            error_data = {
                'category': 'AI Step Parameter Generation',
                'tool': 'OpenAI GPT-4',
                'action': 'Next Step Determination',
                'error': str(e),
                'context': {
                    'current_step': step,
                    'previous_results_count': len(previous_results),
                    'traceback': traceback.format_exc()
                }
            }
            
            # Log error and get log file path
            error_log_path = ErrorLogger.log_error(error_data)
            
            logger.error(f"Error getting step parameters. Log file: {error_log_path}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            raise Exception(f"Error getting step parameters: {str(e)}")

    def _validate_openai_response(self, response):
        """Validate OpenAI API response with detailed error logging"""
        if not response or not response.choices:
            error_data = {
                'category': 'AI Response Validation',
                'tool': 'OpenAI',
                'action': 'Response Validation',
                'error': 'Received empty or invalid response from OpenAI',
                'severity': 'High'
            }
            ErrorLogger.log_error(error_data)
            logger.warning("Received empty or invalid response from OpenAI")
            raise ValueError("Invalid OpenAI API response")
        
        content = response.choices[0].message.content
        if not content:
            error_data = {
                'category': 'AI Response Validation',
                'tool': 'OpenAI',
                'action': 'Content Validation',
                'error': 'OpenAI response content is empty',
                'severity': 'Medium'
            }
            ErrorLogger.log_error(error_data)
            logger.warning("OpenAI response content is empty")
            raise ValueError("Empty response content")
        
        return content

    def generate_report(self, data: Dict[str, Any]) -> str:
        """Generate detailed report including logs and error tracking"""
        report = []
        
        # Add header
        report.append("# HackFusion Security Assessment Report")
        report.append(f"\n## Overview")
        report.append(f"- **Category:** {data['category']}")
        report.append(f"- **Description:** {data['description']}")
        report.append(f"- **Tools Used:** {', '.join(data['tools'])}")
        report.append(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Add results section
        report.append("\n## Results")
        for result in data['results']:
            step = result['step']
            report.append(f"\n### {step['action']}")
            report.append(f"- **Tool:** {step['tool']}")
            report.append(f"- **Description:** {step['description']}")
            
            # Format result data
            if isinstance(result['result'], dict):
                for key, value in result['result'].items():
                    report.append(f"- **{key}:** {value}")
            else:
                report.append(f"- **Output:** {result['result']}")
        
        # Add comprehensive error log section
        report.append("\n## Error Log")
        report.append("### Detailed Error Tracking")
        report.append("| Timestamp | Tool | Action | Error Type | Error Message | Severity | Recommended Action |")
        report.append("|-----------|------|--------|------------|---------------|----------|---------------------|")
        
        # Collect and categorize errors
        error_types = {
            'network': [],
            'authentication': [],
            'tool_execution': [],
            'configuration': [],
            'other': []
        }
        
        # Process logs and extract errors
        for log in data.get('logs', []):
            if log.get('status') == 'error':
                # Determine error type and severity
                error_type = 'other'
                severity = 'Low'
                recommended_action = 'Investigate'
                
                error_msg = log.get('error', 'Unknown error')
                
                # Categorize errors
                if 'network' in error_msg.lower():
                    error_type = 'network'
                    severity = 'High'
                    recommended_action = 'Check network connectivity'
                elif 'authentication' in error_msg.lower():
                    error_type = 'authentication'
                    severity = 'Critical'
                    recommended_action = 'Verify credentials and access permissions'
                elif 'tool' in error_msg.lower():
                    error_type = 'tool_execution'
                    severity = 'Medium'
                    recommended_action = 'Verify tool installation and configuration'
                elif 'config' in error_msg.lower():
                    error_type = 'configuration'
                    severity = 'High'
                    recommended_action = 'Review and update system configuration'
                
                # Add to categorized errors
                error_entry = {
                    'timestamp': log.get('timestamp', 'N/A'),
                    'tool': log.get('tool', 'Unknown'),
                    'action': log.get('action', 'N/A'),
                    'error_type': error_type,
                    'error_message': error_msg,
                    'severity': severity,
                    'recommended_action': recommended_action
                }
                error_types[error_type].append(error_entry)
                
                # Add to report
                report.append(
                    f"| {error_entry['timestamp']} | {error_entry['tool']} | {error_entry['action']} | "
                    f"{error_entry['error_type']} | {error_entry['error_message']} | "
                    f"{error_entry['severity']} | {error_entry['recommended_action']} |"
                )
        
        # Error Summary
        report.append("\n### Error Summary")
        for error_type, errors in error_types.items():
            if errors:
                report.append(f"- **{error_type.capitalize()} Errors:** {len(errors)}")
        
        # Recommendations based on errors
        report.append("\n## Error Mitigation Recommendations")
        for error_type, errors in error_types.items():
            if errors:
                report.append(f"\n### {error_type.capitalize()} Error Recommendations")
                unique_recommendations = set(error['recommended_action'] for error in errors)
                for recommendation in unique_recommendations:
                    report.append(f"- {recommendation}")
        
        return "\n".join(report)
