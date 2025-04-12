"""
Web Application Analysis module for HackFusion
Handles web application security testing tools
"""

import subprocess
import requests
from typing import Dict, Optional
import logging

logger = logging.getLogger('HackFusion')

class WebApplicationAnalysis:
    def __init__(self, config: Dict):
        self.config = config
        self.tools = config.get('web_application', {})

    def start_burp_proxy(self, port: int = 8090) -> Dict:
        """
        Start Burp Suite in proxy mode
        
        Args:
            port: Port for the proxy to listen on
        
        Returns:
            Dict containing operation status
        """
        if not self.tools.get('burpsuite', {}).get('enabled'):
            return {'error': 'Burp Suite is not enabled'}

        try:
            cmd = [
                'burpsuite',
                '--project-file=temp',
                f'--config-file={self.tools["burpsuite"].get("config_file", "")}',
                '--unpause-spider-and-scanner'
            ]

            logger.info(f"Starting Burp Suite: {' '.join(cmd)}")
            process = subprocess.Popen(cmd)
            
            return {
                'success': True,
                'pid': process.pid,
                'proxy': f'http://localhost:{port}'
            }
        except Exception as e:
            logger.error(f"Error starting Burp Suite: {str(e)}")
            return {'error': str(e)}

    def run_zap_scan(self, target: str, api_key: Optional[str] = None) -> Dict:
        """
        Run OWASP ZAP security scan
        
        Args:
            target: Target URL
            api_key: ZAP API key
        
        Returns:
            Dict containing scan results
        """
        if not self.tools.get('zap', {}).get('enabled'):
            return {'error': 'OWASP ZAP is not enabled'}

        try:
            # Using ZAP API
            zap_api = self.tools['zap'].get('api_url', 'http://localhost:8080')
            headers = {'X-ZAP-API-Key': api_key} if api_key else {}

            # Start spider
            response = requests.get(
                f'{zap_api}/JSON/spider/action/scan/',
                params={'url': target},
                headers=headers
            )

            if response.status_code != 200:
                return {'error': 'Failed to start ZAP spider'}

            scan_id = response.json().get('scan')
            
            return {
                'success': True,
                'scan_id': scan_id,
                'status_url': f'{zap_api}/JSON/spider/view/status/?scanId={scan_id}'
            }
        except Exception as e:
            logger.error(f"Error running ZAP scan: {str(e)}")
            return {'error': str(e)}

    def check_scan_status(self, scan_id: str, api_key: Optional[str] = None) -> Dict:
        """Check the status of a running ZAP scan"""
        try:
            zap_api = self.tools['zap'].get('api_url', 'http://localhost:8080')
            headers = {'X-ZAP-API-Key': api_key} if api_key else {}

            response = requests.get(
                f'{zap_api}/JSON/spider/view/status/',
                params={'scanId': scan_id},
                headers=headers
            )

            if response.status_code != 200:
                return {'error': 'Failed to get scan status'}

            return {
                'success': True,
                'status': response.json().get('status'),
                'progress': response.json().get('progress')
            }
        except Exception as e:
            logger.error(f"Error checking scan status: {str(e)}")
            return {'error': str(e)}
