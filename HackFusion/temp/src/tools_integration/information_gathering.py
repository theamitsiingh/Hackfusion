import logging
import os

def configure_tool_logging(log_level=logging.INFO, log_dir='/tmp/hackfusion_logs'):
    """
    Configure logging for information gathering tools
    
    :param log_level: Logging level (default: INFO)
    :param log_dir: Directory to store log files
    """
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            # Console handler
            logging.StreamHandler(),
            # File handler
            logging.FileHandler(os.path.join(log_dir, 'information_gathering.log'), mode='a')
        ]
    )

# Configure logging when the module is imported
configure_tool_logging()

import subprocess
import re
import json
import os
import socket
import ipaddress
from typing import Dict, Any, Optional, List
from datetime import datetime

from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.text import Text

from src.utils.kali_tools import KaliToolsManager
from src.utils.tool_decorators import tool_loading_animation

class InformationGathering:
    """Information gathering tools with enhanced output and error handling"""
    
    def __init__(self, kali_tools_manager: Optional[KaliToolsManager] = None):
        """
        Initialize Information Gathering module with comprehensive diagnostics
        
        :param kali_tools_manager: KaliTools instance for tool management
        """
        import logging
        import subprocess
        
        logger = logging.getLogger(__name__)
        
        # Initialize Kali Tools
        self.kali_tools = kali_tools_manager or KaliToolsManager()
        
        # Critical tools for information gathering
        critical_tools = [
            'whois', 'nmap', 'dig', 'host', 
            'traceroute', 'netstat', 'ip'
        ]
        
        # Tool availability check
        missing_tools = []
        for tool in critical_tools:
            if not self.kali_tools.check_tool(tool):
                missing_tools.append(tool)
                logger.warning(f"Critical tool not found: {tool}")
        
        # Comprehensive tool installation check
        if missing_tools:
            logger.error(f"Missing critical tools: {', '.join(missing_tools)}")
            try:
                # Attempt to install missing tools
                install_cmd = ['sudo', 'apt-get', 'install', '-y'] + missing_tools
                result = subprocess.run(
                    install_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=300  # 5-minute timeout
                )
                
                if result.returncode == 0:
                    logger.info(f"Successfully installed: {', '.join(missing_tools)}")
                else:
                    logger.error(f"Tool installation failed. Output: {result.stderr}")
            except Exception as install_error:
                logger.error(f"Tool installation attempt failed: {install_error}")
        
        # Perform network diagnostics
        try:
            self.log_network_diagnostics()
        except Exception as diag_error:
            logger.error(f"Network diagnostics failed: {diag_error}")
        
        # Initialize console for rich output
        self.console = Console()
    
    def _validate_target(self, target: str) -> bool:
        """
        Validate target input for various information gathering tools
        
        :param target: Target IP, domain, or URL to validate
        :return: True if valid, False otherwise
        """
        try:
            # Check if it's a valid IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Check if it's a valid domain
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                # Check if it's a valid URL
                url_pattern = re.compile(
                    r'^https?://'  # http:// or https://
                    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                    r'localhost|'  # localhost...
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                    r'(?::\d+)?'  # optional port
                    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
                return bool(url_pattern.match(target))
        
        return False
    
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """
        Run a command with enhanced error handling, logging, and output capture
        
        :param cmd: Command to run as a list of strings
        :param timeout: Timeout in seconds
        :return: Dictionary with command execution results
        """
        import logging
        import subprocess
        import shlex
        import os
        
        logger = logging.getLogger(__name__)
        
        # Detailed logging of command execution
        logger.info(f"Executing command: {' '.join(cmd)}")
        
        try:
            # Enhanced subprocess configuration
            process_env = os.environ.copy()
            process_env['LC_ALL'] = 'C.UTF-8'  # Ensure consistent encoding
            process_env['LANG'] = 'C.UTF-8'
            
            # Comprehensive subprocess run with enhanced error handling
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True, 
                timeout=timeout, 
                universal_newlines=True,
                env=process_env,
                errors='replace'  # Handle potential encoding issues
            )
            
            # Log raw outputs for debugging
            logger.debug(f"Command STDOUT: {result.stdout}")
            logger.debug(f"Command STDERR: {result.stderr}")
            
            # Determine overall status
            status = 'success' if result.returncode == 0 else 'error'
            
            # Prepare detailed result dictionary
            command_result = {
                'status': status,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode,
                'command': ' '.join(cmd)
            }
            
            # Add extra diagnostics for error cases
            if status == 'error':
                logger.error(f"Command failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                
                # Additional error context
                command_result['error_details'] = {
                    'possible_reasons': self._analyze_command_error(result.stderr)
                }
            
            return command_result
        
        except subprocess.TimeoutExpired:
            error_msg = f"Command {' '.join(cmd)} timed out after {timeout} seconds"
            logger.error(error_msg)
            return {
                'status': 'timeout',
                'error': error_msg,
                'command': ' '.join(cmd)
            }
        
        except Exception as e:
            error_msg = f"Unexpected error running {' '.join(cmd)}: {str(e)}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'command': ' '.join(cmd)
            }
    
    def _analyze_command_error(self, error_output: str) -> List[str]:
        """
        Analyze command error output and provide potential reasons
        
        :param error_output: Error output from command execution
        :return: List of possible error reasons
        """
        possible_reasons = []
        
        # Check for common error patterns
        error_patterns = [
            ('permission', 'Insufficient permissions to run the command'),
            ('connection', 'Network connectivity or firewall issues'),
            ('resolve', 'Unable to resolve domain or hostname'),
            ('timeout', 'Network timeout occurred'),
            ('not found', 'Command or tool not installed'),
            ('denied', 'Access denied by system or network')
        ]
        
        for pattern, reason in error_patterns:
            if pattern.lower() in error_output.lower():
                possible_reasons.append(reason)
        
        # If no specific patterns match, provide generic suggestions
        if not possible_reasons:
            possible_reasons = [
                'Check network connectivity',
                'Verify tool installation',
                'Check system permissions',
                'Ensure correct command syntax'
            ]
        
        return possible_reasons
    
    def run_nmap_scan(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run Nmap scan with comprehensive error handling and output parsing
        
        :param target: Target IP or domain to scan
        :param params: Additional Nmap parameters
        :return: Scan results dictionary
        """
        # Import logging for detailed diagnostics
        import logging
        logger = logging.getLogger(__name__)
        
        # Validate and prepare target
        try:
            # Attempt to resolve target to IP if it's a domain
            import socket
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                target_ip = target
        except Exception as resolve_error:
            logger.error(f"Target resolution error: {resolve_error}")
            target_ip = target
        
        # Normalize and validate target
        target_ip = self._normalize_domain(target_ip)
        
        # Validate target
        if not self._validate_target(target_ip):
            logger.error(f"Invalid target: {target_ip}")
            return {'error': f'Invalid target: {target_ip}'}
        
        # Check tool availability
        if not self.kali_tools.check_tool('nmap'):
            logger.error('Nmap is not installed')
            return {'error': 'Nmap is not installed. Please install it first.'}
        
        # Prepare multiple Nmap scanning strategies with increased verbosity
        scan_strategies = [
            # Basic service and version detection with increased verbosity
            ['nmap', '-sV', '-sC', '-v', '-oX', '-', target_ip],
            
            # More aggressive scanning with OS detection and full verbosity
            ['nmap', '-A', '-p-', '-vv', '-oX', '-', target_ip],
            
            # Quick scan with top ports and network diagnostics
            ['nmap', '-sS', '-sV', '-Pn', '--traceroute', '--top-ports', '100', '-vv', '-oX', '-', target_ip]
        ]
        
        # Additional network diagnostics before scanning
        try:
            import subprocess
            # Ping test
            ping_result = subprocess.run(['ping', '-c', '4', target_ip], 
                                         capture_output=True, text=True, timeout=10)
            logger.info(f"Ping result: {ping_result.stdout}")
        except Exception as ping_error:
            logger.warning(f"Ping diagnostics failed: {ping_error}")
        
        # Try multiple scanning strategies
        for idx, cmd in enumerate(scan_strategies, 1):
            logger.info(f"Attempting Nmap scan strategy {idx}: {' '.join(cmd)}")
            
            try:
                result = self._run_command(cmd)
                
                # Log raw command output for debugging
                logger.debug(f"Nmap Scan Strategy {idx} Raw Output: {result}")
                
                # Parse and enhance Nmap output
                if result['status'] == 'success' and result['stdout']:
                    try:
                        # Try parsing XML output
                        parsed_output = self._parse_nmap_xml_output(result['stdout'])
                        
                        # Only return if we have meaningful parsed results
                        if parsed_output and parsed_output.get('open_ports'):
                            result['parsed_output'] = parsed_output
                            logger.info(f"Successful scan with strategy {idx}")
                            return result
                    except Exception as parse_error:
                        logger.error(f"XML Parsing error (Strategy {idx}): {parse_error}")
                        
                        # Fallback to text parsing
                        parsed_output = self._parse_nmap_output(result['stdout'])
                        if parsed_output and parsed_output.get('open_ports'):
                            result['parsed_output'] = parsed_output
                            logger.info(f"Successful text parsing with strategy {idx}")
                            return result
            except Exception as scan_error:
                logger.error(f"Scan strategy {idx} failed: {scan_error}")
        
        # If no results found, provide a detailed error with comprehensive diagnostics
        return {
            'status': 'not_found',
            'error': f'No scan results found for target: {target_ip}',
            'diagnostics': {
                'target_original': target,
                'target_resolved': target_ip,
                'suggestions': [
                    'Verify network connectivity',
                    'Check firewall settings',
                    'Ensure target is reachable',
                    'Verify target IP/domain is correct',
                    'Check network permissions'
                ]
            }
        }
    
    def _parse_nmap_xml_output(self, xml_output: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output for more detailed scanning results
        
        :param xml_output: Raw XML output from Nmap
        :return: Parsed scanning results
        """
        import xml.etree.ElementTree as ET
        
        parsed_results = {
            'open_ports': [],
            'services': [],
            'os_detection': None,
            'host_status': 'down'
        }
        
        try:
            # Parse XML output
            root = ET.fromstring(xml_output)
            
            # Check host status
            host = root.find('.//host')
            if host is not None:
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    parsed_results['host_status'] = 'up'
                
                # Extract port information
                for port in host.findall('.//port'):
                    port_info = {
                        'number': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                        'service': port.find('service').get('name', 'unknown') if port.find('service') is not None else 'unknown'
                    }
                    parsed_results['open_ports'].append(port_info)
                
                # OS Detection
                os_match = host.find('.//osmatch')
                if os_match is not None:
                    parsed_results['os_detection'] = {
                        'name': os_match.get('name', 'Unknown'),
                        'accuracy': os_match.get('accuracy', 'N/A')
                    }
            
            return parsed_results
        
        except Exception as e:
            # Fallback to text parsing if XML parsing fails
            return self._parse_nmap_output(xml_output)
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Nmap output into a more structured format
        
        :param output: Raw Nmap scan output
        :return: Parsed Nmap results
        """
        parsed_results = {
            'open_ports': [],
            'services': [],
            'os_detection': None
        }
        
        # Basic parsing - you can make this more sophisticated
        port_pattern = re.compile(r'(\d+)/(\w+)\s+(\w+)\s+(.+)')
        for line in output.split('\n'):
            port_match = port_pattern.search(line)
            if port_match:
                parsed_results['open_ports'].append({
                    'port': port_match.group(1),
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4)
                })
        
        return parsed_results
    
    @tool_loading_animation
    def run_whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Run comprehensive WHOIS lookup with multiple strategies
        
        :param domain: Domain to perform WHOIS lookup on
        :return: Lookup results dictionary
        """
        import logging
        logger = logging.getLogger(__name__)
        
        # Normalize and validate domain
        try:
            domain = self._normalize_domain(domain)
        except Exception as norm_error:
            logger.error(f"Domain normalization error: {norm_error}")
            return {'error': f'Invalid domain format: {domain}'}
        
        # Validate domain
        if not self._validate_target(domain):
            logger.error(f"Invalid domain: {domain}")
            return {'error': f'Invalid domain: {domain}'}
        
        # Check tool availability
        if not self.kali_tools.check_tool('whois'):
            logger.error('Whois tool is not installed')
            return {'error': 'Whois is not installed. Please install it first.'}
        
        # Prepare multiple WHOIS lookup strategies
        whois_strategies = [
            # Standard WHOIS lookup
            ['whois', domain],
            
            # Lookup with specific servers
            ['whois', '-h', 'whois.iana.org', domain],
            ['whois', '-h', 'whois.internic.net', domain],
            
            # Additional lookup methods
            ['whois', '-H', domain],  # Suppress legal disclaimers
            ['whois', '-h', 'whois.networksolutions.com', domain]
        ]
        
        # Fallback DNS lookup strategies
        dns_strategies = [
            ['dig', '+short', 'NS', domain],
            ['host', '-t', 'NS', domain],
            ['nslookup', '-type=NS', domain]
        ]
        
        # Try WHOIS lookup strategies
        for cmd in whois_strategies:
            try:
                logger.info(f"Attempting WHOIS lookup: {' '.join(cmd)}")
                result = self._run_command(cmd)
                
                # Parse and validate WHOIS output
                if result['status'] == 'success' and result['stdout']:
                    parsed_output = self._parse_whois_output(result['stdout'])
                    
                    # Return if meaningful results found
                    if parsed_output and any(parsed_output.values()):
                        result['parsed_output'] = parsed_output
                        logger.info(f"Successful WHOIS lookup with: {' '.join(cmd)}")
                        return result
            except Exception as lookup_error:
                logger.warning(f"WHOIS strategy failed: {lookup_error}")
        
        # If WHOIS fails, attempt DNS lookup strategies
        for cmd in dns_strategies:
            try:
                logger.info(f"Attempting DNS lookup: {' '.join(cmd)}")
                result = self._run_command(cmd)
                
                if result['status'] == 'success' and result['stdout']:
                    logger.info(f"Successful DNS lookup with: {' '.join(cmd)}")
                    return {
                        'status': 'partial',
                        'method': 'dns',
                        'output': result['stdout'].strip()
                    }
            except Exception as dns_error:
                logger.warning(f"DNS lookup strategy failed: {dns_error}")
        
        # Comprehensive error reporting if all strategies fail
        logger.error(f"All WHOIS and DNS lookup strategies failed for domain: {domain}")
        return {
            'status': 'not_found',
            'error': f'No WHOIS or DNS information found for domain: {domain}',
            'diagnostics': {
                'domain': domain,
                'suggestions': [
                    'Verify domain spelling',
                    'Check domain registration status',
                    'Ensure network connectivity',
                    'Try manual WHOIS lookup',
                    'Verify DNS server accessibility'
                ]
            }
        }
    
    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """
        Enhanced WHOIS output parsing with multiple extraction strategies
        
        :param output: Raw WHOIS output
        :return: Parsed domain information
        """
        import re
        
        parsed_results = {
            'domain_name': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'registrant': {}
        }
        
        # Regex patterns for extraction
        patterns = {
            'domain_name': r'Domain Name:\s*(.+)',
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Expiration Date:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'registrant_name': r'Registrant Name:\s*(.+)',
            'registrant_org': r'Registrant Organization:\s*(.+)'
        }
        
        # Extract information using regex
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                if key == 'name_servers':
                    parsed_results['name_servers'].extend(match.group(1).split())
                elif key == 'registrant_name':
                    parsed_results['registrant']['name'] = match.group(1)
                elif key == 'registrant_org':
                    parsed_results['registrant']['organization'] = match.group(1)
                else:
                    parsed_results[key] = match.group(1)
        
        return parsed_results
    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain input by removing protocols and www
        
        :param domain: Raw domain input
        :return: Normalized domain
        """
        # Remove protocols
        domain = domain.lower().replace('https://', '').replace('http://', '')
        
        # Remove www
        domain = domain.replace('www.', '')
        
        # Remove any trailing slashes or paths
        domain = domain.split('/')[0]
        
        return domain.strip()
    
    def _parse_dns_enum_output(self, output: str) -> Dict[str, Any]:
        """
        Parse DNS enumeration output into a more structured format
        
        :param output: Raw DNS enumeration output
        :return: Parsed DNS enumeration results
        """
        parsed_results = {
            'subdomains': []
        }
        
        # Basic parsing - you can make this more sophisticated
        subdomain_pattern = re.compile(r'([a-zA-Z0-9.-]+)\.' + re.escape(self.domain) + r'\s+([0-9.]+)')
        
        for line in output.split('\n'):
            subdomain_match = subdomain_pattern.search(line)
            if subdomain_match:
                parsed_results['subdomains'].append({
                    'subdomain': subdomain_match.group(1),
                    'ip': subdomain_match.group(2)
                })
        
        return parsed_results
    
    @tool_loading_animation
    def run_nikto_scan(self, target: str) -> Dict[str, Any]:
        """
        Run Nikto web server scanner with comprehensive error handling and output parsing
        
        :param target: Target URL or IP to scan
        :return: Scan results dictionary
        """
        # Validate target
        if not self._validate_target(target):
            return {'error': f'Invalid target: {target}'}
        
        # Check tool availability
        if not self.kali_tools.check_tool('nikto'):
            return {'error': 'Nikto is not installed. Please install it first.'}
        
        # Prepare Nikto command
        cmd = ['nikto', '-h', target, '-Format', 'json']
        
        # Execute Nikto scan
        result = self._run_command(cmd)
        
        # Parse and enhance Nikto output
        if result['status'] == 'success':
            # You could add more sophisticated parsing here
            result['parsed_output'] = self._parse_nikto_output(result['stdout'])
        
        return result
    
    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Nikto output into a more structured format
        
        :param output: Raw Nikto scan output
        :return: Parsed Nikto results
        """
        parsed_results = {
            'vulnerabilities': []
        }
        
        # Basic parsing - you can make this more sophisticated
        vulnerability_pattern = re.compile(r'OSVDB-\d+: (.+)')
        
        for line in output.split('\n'):
            vulnerability_match = vulnerability_pattern.search(line)
            if vulnerability_match:
                parsed_results['vulnerabilities'].append(vulnerability_match.group(1))
        
        return parsed_results
    
    @tool_loading_animation
    def run_dirb_scan(self, target: str) -> Dict[str, Any]:
        """
        Run Dirb web content scanner with comprehensive error handling and output parsing
        
        :param target: Target URL or IP to scan
        :return: Scan results dictionary
        """
        # Validate target
        if not self._validate_target(target):
            return {'error': f'Invalid target: {target}'}
        
        # Check tool availability
        if not self.kali_tools.check_tool('dirb'):
            return {'error': 'Dirb is not installed. Please install it first.'}
        
        # Prepare Dirb command
        cmd = ['dirb', target]
        
        # Execute Dirb scan
        result = self._run_command(cmd)
        
        # Parse and enhance Dirb output
        if result['status'] == 'success':
            # You could add more sophisticated parsing here
            result['parsed_output'] = self._parse_dirb_output(result['stdout'])
        
        return result
    
    def _parse_dirb_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Dirb output into a more structured format
        
        :param output: Raw Dirb scan output
        :return: Parsed Dirb results
        """
        parsed_results = {
            'directories': []
        }
        
        # Basic parsing - you can make this more sophisticated
        directory_pattern = re.compile(r'==> DIRECTORY: (.+)')
        
        for line in output.split('\n'):
            directory_match = directory_pattern.search(line)
            if directory_match:
                parsed_results['directories'].append(directory_match.group(1))
        
        return parsed_results
    
    @tool_loading_animation
    def run_web_analysis(self, tool: str, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run web application analysis tools with comprehensive error handling and output parsing
        
        :param tool: Name of the web analysis tool to use
        :param target: Target URL or IP to analyze
        :param params: Additional parameters for the tool
        :return: Analysis results dictionary
        """
        # Validate target
        if not self._validate_target(target):
            return {'error': f'Invalid target: {target}'}
        
        # Check tool availability
        if not self.kali_tools.check_tool(tool):
            return {'error': f'{tool} is not installed. Please install it first.'}
        
        # Prepare web analysis command
        cmd = [tool, target]
        if params:
            for k, v in params.items():
                cmd.extend([f'--{k}', str(v)])
        
        # Execute web analysis
        result = self._run_command(cmd)
        
        # Parse and enhance web analysis output
        if result['status'] == 'success':
            # You could add more sophisticated parsing here
            result['parsed_output'] = self._parse_web_analysis_output(result['stdout'], tool)
        
        return result
    
    def _parse_web_analysis_output(self, output: str, tool: str) -> Dict[str, Any]:
        """
        Parse web analysis output into a more structured format
        
        :param output: Raw web analysis output
        :param tool: Name of the web analysis tool used
        :return: Parsed web analysis results
        """
        parsed_results = {}
        
        # Basic parsing - you can make this more sophisticated
        if tool == 'burpsuite':
            # Burp Suite parsing
            parsed_results['issues'] = []
            issue_pattern = re.compile(r'([a-zA-Z]+): (.+)')
            for line in output.split('\n'):
                issue_match = issue_pattern.search(line)
                if issue_match:
                    parsed_results['issues'].append({
                        'severity': issue_match.group(1),
                        'description': issue_match.group(2)
                    })
        elif tool == 'wpscan':
            # WPScan parsing
            parsed_results['vulnerabilities'] = []
            vulnerability_pattern = re.compile(r'([a-zA-Z]+): (.+)')
            for line in output.split('\n'):
                vulnerability_match = vulnerability_pattern.search(line)
                if vulnerability_match:
                    parsed_results['vulnerabilities'].append({
                        'severity': vulnerability_match.group(1),
                        'description': vulnerability_match.group(2)
                    })
        # Add more tool-specific parsing here
        
        return parsed_results
    
    def system_diagnostics(self) -> Dict[str, Any]:
        """
        Perform comprehensive system diagnostics for information gathering tools
        
        :return: Detailed system diagnostic report
        """
        import subprocess
        import platform
        import shutil
        
        diagnostics = {
            'system_info': {
                'os': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'network_interfaces': [],
            'tool_availability': {},
            'permissions': {},
            'potential_issues': []
        }
        
        # Check network interfaces
        try:
            interfaces_output = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=10)
            diagnostics['network_interfaces'] = interfaces_output.stdout.strip().split('\n')
        except Exception as e:
            diagnostics['potential_issues'].append(f"Network interface detection failed: {e}")
        
        # Check critical tools availability
        critical_tools = [
            'nmap', 'whois', 'dig', 'host', 'traceroute', 
            'ping', 'netstat', 'ss', 'ip'
        ]
        
        for tool in critical_tools:
            tool_path = shutil.which(tool)
            diagnostics['tool_availability'][tool] = {
                'installed': bool(tool_path),
                'path': tool_path
            }
        
        # Check permissions
        try:
            current_user = subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()
            diagnostics['permissions']['current_user'] = current_user
            
            # Check sudo capabilities
            sudo_check = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
            diagnostics['permissions']['sudo_access'] = sudo_check.returncode == 0
        except Exception as e:
            diagnostics['potential_issues'].append(f"Permission check failed: {e}")
        
        # Network connectivity checks
        try:
            # Check internet connectivity
            internet_check = subprocess.run(['ping', '-c', '4', '8.8.8.8'], capture_output=True)
            diagnostics['network_connectivity'] = {
                'internet_access': internet_check.returncode == 0
            }
        except Exception as e:
            diagnostics['potential_issues'].append(f"Internet connectivity check failed: {e}")
        
        # Firewall status
        try:
            ufw_status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
            diagnostics['firewall'] = {
                'ufw_status': ufw_status.stdout.strip()
            }
        except Exception as e:
            diagnostics['potential_issues'].append(f"Firewall status check failed: {e}")
        
        return diagnostics

    def log_system_diagnostics(self):
        """
        Log system diagnostics for troubleshooting
        """
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            diag_report = self.system_diagnostics()
            
            # Log key diagnostic information
            logger.info("System Diagnostics Report:")
            logger.info(f"System: {diag_report['system_info']}")
            
            # Log tool availability
            logger.info("Tool Availability:")
            for tool, status in diag_report['tool_availability'].items():
                logger.info(f"{tool}: {'Installed' if status['installed'] else 'Not Found'}")
            
            # Log potential issues
            if diag_report.get('potential_issues'):
                logger.warning("Potential Issues Detected:")
                for issue in diag_report['potential_issues']:
                    logger.warning(issue)
            
            return diag_report
        except Exception as e:
            logger.error(f"Failed to generate system diagnostics: {e}")
            return {}

    def network_diagnostics(self, target: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive network diagnostics
        
        :param target: Optional target for specific network checks
        :return: Detailed network diagnostic report
        """
        import logging
        import subprocess
        import socket
        import json
        
        logger = logging.getLogger(__name__)
        diagnostics = {
            'network_interfaces': [],
            'dns_resolution': {},
            'connectivity': {},
            'routing': {},
            'firewall': {}
        }
        
        # Network Interfaces
        try:
            interfaces = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=10)
            diagnostics['network_interfaces'] = interfaces.stdout.strip().split('\n')
        except Exception as e:
            logger.error(f"Network interface detection failed: {e}")
        
        # DNS Resolution
        try:
            # Try resolving a few well-known domains
            test_domains = ['google.com', 'github.com', 'microsoft.com']
            for domain in test_domains:
                try:
                    ip = socket.gethostbyname(domain)
                    diagnostics['dns_resolution'][domain] = {
                        'resolved_ip': ip,
                        'status': 'success'
                    }
                except socket.gaierror as dns_err:
                    diagnostics['dns_resolution'][domain] = {
                        'status': 'failed',
                        'error': str(dns_err)
                    }
        except Exception as e:
            logger.error(f"DNS resolution check failed: {e}")
        
        # Connectivity Checks
        connectivity_targets = [
            ('8.8.8.8', 'Google DNS'),
            ('1.1.1.1', 'Cloudflare DNS')
        ]
        
        for ip, name in connectivity_targets:
            try:
                ping = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True, timeout=10)
                diagnostics['connectivity'][name] = {
                    'ip': ip,
                    'status': 'reachable' if ping.returncode == 0 else 'unreachable',
                    'output': ping.stdout.strip()
                }
            except Exception as e:
                diagnostics['connectivity'][name] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        # Routing Information
        try:
            route = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
            diagnostics['routing']['default_routes'] = route.stdout.strip().split('\n')
        except Exception as e:
            logger.error(f"Routing information detection failed: {e}")
        
        # Firewall Status
        try:
            ufw_status = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
            diagnostics['firewall']['ufw'] = ufw_status.stdout.strip()
        except Exception as e:
            logger.error(f"Firewall status check failed: {e}")
        
        # Specific Target Diagnostics (if provided)
        if target:
            try:
                # Traceroute to target
                traceroute = subprocess.run(['traceroute', target], capture_output=True, text=True, timeout=30)
                diagnostics['target_diagnostics'] = {
                    'traceroute': traceroute.stdout.strip().split('\n')
                }
            except Exception as e:
                logger.error(f"Target-specific diagnostics failed: {e}")
        
        # Log and return diagnostics
        logger.info("Network Diagnostics Completed")
        return diagnostics
    
    def log_network_diagnostics(self, target: str = None) -> None:
        """
        Log network diagnostics with detailed formatting
        
        :param target: Optional target for specific network checks
        """
        import logging
        import json
        
        logger = logging.getLogger(__name__)
        
        try:
            diag_report = self.network_diagnostics(target)
            
            # Log key diagnostic sections
            logger.info("🌐 Network Diagnostics Report 🌐")
            
            # Log Network Interfaces
            logger.info("Network Interfaces:")
            for interface in diag_report.get('network_interfaces', []):
                logger.info(f"  {interface}")
            
            # Log DNS Resolution
            logger.info("DNS Resolution:")
            for domain, result in diag_report.get('dns_resolution', {}).items():
                logger.info(f"  {domain}: {json.dumps(result, indent=2)}")
            
            # Log Connectivity
            logger.info("Connectivity:")
            for target, status in diag_report.get('connectivity', {}).items():
                logger.info(f"  {target}: {json.dumps(status, indent=2)}")
            
            # Log Routing
            logger.info("Routing:")
            for route in diag_report.get('routing', {}).get('default_routes', []):
                logger.info(f"  {route}")
            
            # Log Firewall
            logger.info("Firewall Status:")
            logger.info(f"  {diag_report.get('firewall', {}).get('ufw', 'Unknown')}")
            
            # Optional target-specific diagnostics
            if target and 'target_diagnostics' in diag_report:
                logger.info(f"Traceroute to {target}:")
                for hop in diag_report['target_diagnostics'].get('traceroute', []):
                    logger.info(f"  {hop}")
        
        except Exception as e:
            logger.error(f"Failed to log network diagnostics: {e}")

    @tool_loading_animation
    def comprehensive_scan(self, target: str, scan_options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Perform a comprehensive multi-tool scan on a given target
        
        :param target: Target IP, domain, or URL to scan
        :param scan_options: Dictionary to control which scans to run
        :return: Comprehensive scan results dictionary
        """
        # Validate target
        if not self._validate_target(target):
            return {
                'error': 'Invalid target',
                'message': 'Please provide a valid IP, domain, or URL'
            }
        
        # Default scan options if not provided
        if scan_options is None:
            scan_options = {
                'nmap': True,
                'whois': True,
                'nikto': True,
                'dirb': True,
                'dns_enum': True
            }
        
        # Comprehensive scan results
        scan_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': {}
        }
        
        # Run Nmap scan
        if scan_options.get('nmap', False):
            try:
                nmap_result = self.run_nmap_scan(target)
                scan_results['scans']['nmap'] = nmap_result
            except Exception as e:
                scan_results['scans']['nmap'] = {
                    'error': str(e),
                    'message': 'Nmap scan failed'
                }
        
        # Run WHOIS lookup
        if scan_options.get('whois', False):
            try:
                whois_result = self.run_whois_lookup(target)
                scan_results['scans']['whois'] = whois_result
            except Exception as e:
                scan_results['scans']['whois'] = {
                    'error': str(e),
                    'message': 'WHOIS lookup failed'
                }
        
        # Run Nikto web server scan
        if scan_options.get('nikto', False):
            try:
                nikto_result = self.run_nikto_scan(target)
                scan_results['scans']['nikto'] = nikto_result
            except Exception as e:
                scan_results['scans']['nikto'] = {
                    'error': str(e),
                    'message': 'Nikto scan failed'
                }
        
        # Run Dirb directory scan
        if scan_options.get('dirb', False):
            try:
                dirb_result = self.run_dirb_scan(target)
                scan_results['scans']['dirb'] = dirb_result
            except Exception as e:
                scan_results['scans']['dirb'] = {
                    'error': str(e),
                    'message': 'Dirb scan failed'
                }
        
        # Run DNS enumeration
        if scan_options.get('dns_enum', False):
            try:
                # Assuming you have a DNS enumeration method
                dns_result = self._run_dns_enumeration(target)
                scan_results['scans']['dns_enum'] = dns_result
            except Exception as e:
                scan_results['scans']['dns_enum'] = {
                    'error': str(e),
                    'message': 'DNS enumeration failed'
                }
        
        # Summarize findings
        scan_results['summary'] = self._summarize_scan_results(scan_results)
        
        return scan_results
    
    def _run_dns_enumeration(self, target: str) -> Dict[str, Any]:
        """
        Perform DNS enumeration using multiple tools
        
        :param target: Domain to enumerate
        :return: DNS enumeration results
        """
        dns_results = {}
        
        # DNS tools to use
        dns_tools = [
            ('dig', ['dig', '+short', target]),
            ('host', ['host', '-a', target]),
            ('nslookup', ['nslookup', target])
        ]
        
        for tool_name, cmd in dns_tools:
            try:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                if result.returncode == 0:
                    dns_results[tool_name] = {
                        'output': result.stdout.strip(),
                        'command': ' '.join(cmd)
                    }
                else:
                    dns_results[tool_name] = {
                        'error': result.stderr.strip(),
                        'command': ' '.join(cmd)
                    }
            except Exception as e:
                dns_results[tool_name] = {
                    'error': str(e),
                    'command': ' '.join(cmd)
                }
        
        return dns_results
    
    def _summarize_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize comprehensive scan results
        
        :param scan_results: Full scan results dictionary
        :return: Summary of key findings
        """
        summary = {
            'open_ports': [],
            'vulnerabilities': [],
            'dns_info': {},
            'whois_details': {}
        }
        
        # Extract open ports from Nmap
        if 'nmap' in scan_results['scans'] and 'ports' in scan_results['scans']['nmap']:
            summary['open_ports'] = [
                port for port in scan_results['scans']['nmap']['ports'] 
                if port.get('state') == 'open'
            ]
        
        # Extract vulnerabilities from Nikto
        if 'nikto' in scan_results['scans']:
            summary['vulnerabilities'] = scan_results['scans']['nikto'].get('vulnerabilities', [])
        
        # Extract DNS information
        if 'dns_enum' in scan_results['scans']:
            summary['dns_info'] = {
                tool: result.get('output', '') 
                for tool, result in scan_results['scans']['dns_enum'].items()
            }
        
        # Extract WHOIS details
        if 'whois' in scan_results['scans']:
            summary['whois_details'] = scan_results['scans']['whois']
        
        return summary
