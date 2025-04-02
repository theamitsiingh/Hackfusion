"""
AI Assistant for HackFusion
"""

import os
from typing import Dict, Any, List
from datetime import datetime
from openai import OpenAI

class AIAssistant:
    def __init__(self):
        """Initialize AI Assistant"""
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        self.client = OpenAI(api_key=self.api_key)

    def analyze_request(self, user_input: str) -> Dict[str, Any]:
        """Analyze user request and generate action plan"""
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
            
            return response.choices[0].message.content
            
        except Exception as e:
            raise Exception(f"Error analyzing request: {str(e)}")

    def get_next_step_params(self, step: Dict[str, Any], previous_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get optimal parameters for next step based on previous results"""
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
            
            return response.choices[0].message.content
            
        except Exception as e:
            raise Exception(f"Error getting step parameters: {str(e)}")

    def generate_report(self, data: Dict[str, Any]) -> str:
        """Generate detailed report including logs"""
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
        
        # Add execution log section
        report.append("\n## Execution Log")
        report.append("| Time | Step | Action | Tool | Status | Details |")
        report.append("|------|------|--------|------|--------|---------|")
        
        for log in data['logs']:
            details = []
            if 'target' in log:
                details.append(f"Target: {log['target']}")
            if 'error' in log:
                details.append(f"Error: {log['error']}")
                
            status_icon = "✅" if log['status'] == 'success' else "❌" if log['status'] == 'error' else "⏳"
            
            report.append(
                f"| {log['timestamp']} | {log['step']} | {log['action']} | "
                f"{log['tool']} | {status_icon} | {' / '.join(details) if details else '-'} |"
            )
        
        # Add recommendations section
        report.append("\n## Recommendations")
        report.append("Based on the assessment results, we recommend:")
        
        # Analyze results and logs to generate recommendations
        if data['results']:
            for result in data['results']:
                if isinstance(result['result'], dict) and result['result'].get('vulnerabilities'):
                    report.append(f"\n- Address the identified vulnerabilities in {result['step']['tool']} scan")
                    
        # Add any failed steps from logs
        failed_steps = [log for log in data['logs'] if log['status'] == 'error']
        if failed_steps:
            report.append("\n### Failed Steps")
            report.append("The following steps encountered errors and should be investigated:")
            for step in failed_steps:
                report.append(f"- {step['action']}: {step.get('error', 'Unknown error')}")
        
        return "\n".join(report)
