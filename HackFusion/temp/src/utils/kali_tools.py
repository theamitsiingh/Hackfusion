"""
Kali Linux Tools Manager
"""

import os
import subprocess
import time
import json
import logging
from typing import List, Dict, Optional, Any
import shutil
from rich.console import Console

class KaliToolsManager:
    """Advanced Kali Linux Tools Manager with Optimization"""
    
    REQUIRED_TOOLS = {
        # 1. Information Gathering
        # Active Information Gathering
        'nmap': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'nmap',
            'description': 'Network exploration tool',
            'check_command': 'nmap -V'
        },
        'netdiscover': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'netdiscover',
            'description': 'Network discovery tool',
            'check_command': 'netdiscover -h'
        },
        'dnsrecon': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'dnsrecon',
            'description': 'DNS enumeration tool',
            'check_command': 'dnsrecon -h'
        },
        'dnswalk': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'dnswalk',
            'description': 'DNS integrity checker',
            'check_command': 'dnswalk -h'
        },
        'dmitry': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'dmitry',
            'description': 'Deepmagic Information Gathering Tool',
            'check_command': 'dmitry -h'
        },
        'fierce': {
            'category': 'Information Gathering',
            'subcategory': 'Active',
            'package': 'fierce',
            'description': 'DNS reconnaissance tool',
            'check_command': 'fierce -h'
        },
        
        # Passive Information Gathering
        'whois': {
            'category': 'Information Gathering',
            'subcategory': 'Passive',
            'package': 'whois',
            'description': 'Whois query tool',
            'check_command': 'whois -h'
        },
        'theharvester': {
            'category': 'Information Gathering',
            'subcategory': 'Passive',
            'package': 'theharvester',
            'description': 'Email, subdomain, and open-source intelligence gathering tool',
            'check_command': 'theharvester -h'
        },
        'maltego': {
            'category': 'Information Gathering',
            'subcategory': 'Passive',
            'package': 'maltego',
            'description': 'Data mining tool for link analysis',
            'check_command': 'maltego --version'
        },
        'recon-ng': {
            'category': 'Information Gathering',
            'subcategory': 'Passive',
            'package': 'recon-ng',
            'description': 'Web reconnaissance framework',
            'check_command': 'recon-ng -h'
        },
        
        # 2. Vulnerability Analysis
        # Vulnerability Scanners
        'nikto': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Scanners',
            'package': 'nikto',
            'description': 'Web server scanner',
            'check_command': 'nikto -Version'
        },
        'w3af': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Scanners',
            'package': 'w3af',
            'description': 'Web application attack and audit framework',
            'check_command': 'w3af -h'
        },
        'openvas': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Scanners',
            'package': 'openvas',
            'description': 'Vulnerability scanner',
            'check_command': 'openvas-start'
        },
        'lynis': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Scanners',
            'package': 'lynis',
            'description': 'Security and system auditing tool',
            'check_command': 'lynis --version'
        },
        
        # Exploit Frameworks
        'metasploit': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Exploit Frameworks',
            'package': 'metasploit-framework',
            'description': 'Exploit development framework',
            'check_command': 'msfconsole -v'
        },
        'beef': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Exploit Frameworks',
            'package': 'beef-xss',
            'description': 'Browser exploitation framework',
            'check_command': 'beef -h'
        },
        'msfvenom': {
            'category': 'Vulnerability Analysis',
            'subcategory': 'Exploit Frameworks',
            'package': 'metasploit-framework',
            'description': 'Payload generation tool',
            'check_command': 'msfvenom -h'
        },
        
        # 3. Wireless Attacks
        # WiFi Cracking
        'aircrack-ng': {
            'category': 'Wireless Attacks',
            'subcategory': 'WiFi Cracking',
            'package': 'aircrack-ng',
            'description': 'WiFi network cracking tool',
            'check_command': 'aircrack-ng -h'
        },
        'reaver': {
            'category': 'Wireless Attacks',
            'subcategory': 'WiFi Cracking',
            'package': 'reaver',
            'description': 'WPS brute-force attack tool',
            'check_command': 'reaver -h'
        },
        'wifite': {
            'category': 'Wireless Attacks',
            'subcategory': 'WiFi Cracking',
            'package': 'wifite',
            'description': 'Automated wireless attack tool',
            'check_command': 'wifite -h'
        },
        
        # Packet Injection
        'mdk3': {
            'category': 'Wireless Attacks',
            'subcategory': 'Packet Injection',
            'package': 'mdk3',
            'description': 'Wireless network testing tool',
            'check_command': 'mdk3 -h'
        },
        'aireplay-ng': {
            'category': 'Wireless Attacks',
            'subcategory': 'Packet Injection',
            'package': 'aircrack-ng',
            'description': 'Packet injection tool',
            'check_command': 'aireplay-ng --help'
        },
        
        # 4. Web Application Attacks
        'sqlmap': {
            'category': 'Web Application Attacks',
            'subcategory': 'SQL Injection',
            'package': 'sqlmap',
            'description': 'SQL injection tool',
            'check_command': 'sqlmap -h'
        },
        'wpscan': {
            'category': 'Web Application Attacks',
            'subcategory': 'WordPress',
            'package': 'wpscan',
            'description': 'WordPress vulnerability scanner',
            'check_command': 'wpscan -h'
        },
        'joomscan': {
            'category': 'Web Application Attacks',
            'subcategory': 'Joomla',
            'package': 'joomscan',
            'description': 'Joomla vulnerability scanner',
            'check_command': 'joomscan -h'
        },
        
        # 5. Sniffing & Spoofing
        'ettercap': {
            'category': 'Sniffing & Spoofing',
            'subcategory': 'Network Sniffing',
            'package': 'ettercap-graphical',
            'description': 'Comprehensive network intercepting tool',
            'check_command': 'ettercap -v'
        },
        'wireshark': {
            'category': 'Sniffing & Spoofing',
            'subcategory': 'Network Sniffing',
            'package': 'wireshark',
            'description': 'Network protocol analyzer',
            'check_command': 'wireshark -v'
        },
        'tcpdump': {
            'category': 'Sniffing & Spoofing',
            'subcategory': 'Network Sniffing',
            'package': 'tcpdump',
            'description': 'Command-line packet analyzer',
            'check_command': 'tcpdump -V'
        },
        
        # 6. Maintaining Access
        'backdoor-factory': {
            'category': 'Maintaining Access',
            'subcategory': 'Payload Generation',
            'package': 'backdoor-factory',
            'description': 'Backdoor creation tool',
            'check_command': 'backdoor-factory -h'
        },
        
        # 7. Reverse Engineering
        'radare2': {
            'category': 'Reverse Engineering',
            'subcategory': 'Binary Analysis',
            'package': 'radare2',
            'description': 'Reverse engineering framework',
            'check_command': 'r2 -h'
        },
        'ghidra': {
            'category': 'Reverse Engineering',
            'subcategory': 'Binary Analysis',
            'package': 'ghidra',
            'description': 'Software reverse engineering tool',
            'check_command': 'ghidra -version'
        },
        
        # 8. Social Engineering
        'set': {
            'category': 'Social Engineering',
            'subcategory': 'Toolkit',
            'package': 'set',
            'description': 'Social Engineering Toolkit',
            'check_command': 'setoolkit -h'
        },
        
        # 9. System Services
        'netcat': {
            'category': 'System Services',
            'subcategory': 'Networking',
            'package': 'netcat',
            'description': 'TCP/IP swiss army knife',
            'check_command': 'nc -h'
        },
        'ncat': {
            'category': 'System Services',
            'subcategory': 'Networking',
            'package': 'nmap',
            'description': 'Improved netcat with SSL support',
            'check_command': 'ncat -h'
        }
    }

    def __init__(self):
        """Initialize Kali Tools Manager with advanced tracking"""
        self.console = Console()
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.tool_performance = {}
        self.optimization_config_path = os.path.expanduser('~/.hackfusion/tool_optimization.json')
        
        # Load existing optimization data
        self.load_tool_optimization()
        
        # Check Kali Linux
        self.is_kali = self._check_kali_linux()
        if not self.is_kali:
            self.console.print("[yellow]Warning: Not running on Kali Linux. Some features may be limited.[/yellow]")
    
    def load_tool_optimization(self):
        """Load tool optimization data from persistent storage"""
        try:
            os.makedirs(os.path.dirname(self.optimization_config_path), exist_ok=True)
            if os.path.exists(self.optimization_config_path):
                with open(self.optimization_config_path, 'r') as f:
                    self.tool_performance = json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load tool optimization data: {e}")
    
    def save_tool_optimization(self):
        """Save tool optimization data to persistent storage"""
        try:
            with open(self.optimization_config_path, 'w') as f:
                json.dump(self.tool_performance, f, indent=4)
        except Exception as e:
            self.logger.error(f"Could not save tool optimization data: {e}")
    
    def optimize_tool_performance(self, tool_name: str, execution_time: float):
        """
        Track and optimize tool performance
        
        :param tool_name: Name of the tool
        :param execution_time: Time taken to execute the tool
        """
        if tool_name not in self.tool_performance:
            self.tool_performance[tool_name] = {
                'total_executions': 0,
                'total_time': 0,
                'average_time': 0,
                'last_optimized': time.time()
            }
        
        data = self.tool_performance[tool_name]
        data['total_executions'] += 1
        data['total_time'] += execution_time
        data['average_time'] = data['total_time'] / data['total_executions']
        
        # Periodic optimization suggestion
        if data['total_executions'] % 10 == 0:
            self.suggest_tool_optimization(tool_name)
        
        self.save_tool_optimization()
    
    def suggest_tool_optimization(self, tool_name: str):
        """
        Provide optimization suggestions for a tool
        
        :param tool_name: Name of the tool
        """
        data = self.tool_performance.get(tool_name, {})
        avg_time = data.get('average_time', 0)
        
        if avg_time > 5:  # If average execution time is more than 5 seconds
            self.console.print(f"[yellow]Performance Optimization Suggestion for {tool_name}:[/yellow]")
            self.console.print(f"- Average Execution Time: {avg_time:.2f} seconds")
            self.console.print("- Consider updating tool configuration or using alternative flags")
    
    def check_tool_dependencies(self, tool_name: str) -> List[str]:
        """
        Check and suggest missing dependencies for a tool
        
        :param tool_name: Name of the tool
        :return: List of missing dependencies
        """
        tool_dependencies = {
            'nmap': ['libpcap0.8', 'libssl1.1'],
            'metasploit': ['ruby', 'postgresql'],
            'sqlmap': ['python3', 'python3-pip'],
            'hydra': ['libssl-dev', 'libssh-dev'],
            'aircrack-ng': ['wireless-tools', 'iw'],
            'john': ['libssl-dev'],
            'hashcat': ['opencl-headers']
        }
        
        missing_deps = []
        for dep in tool_dependencies.get(tool_name, []):
            if not shutil.which(dep):
                missing_deps.append(dep)
        
        return missing_deps
    
    def install_tool_with_dependencies(self, tool_name: str) -> bool:
        """
        Install a tool along with its dependencies
        
        :param tool_name: Name of the tool
        :return: Whether installation was successful
        """
        # Check and install dependencies first
        missing_deps = self.check_tool_dependencies(tool_name)
        if missing_deps:
            self.console.print(f"[yellow]Installing dependencies for {tool_name}:[/yellow]")
            for dep in missing_deps:
                try:
                    subprocess.run(['sudo', 'apt-get', 'install', '-y', dep], check=True)
                except subprocess.CalledProcessError:
                    self.console.print(f"[red]Failed to install dependency: {dep}[/red]")
        
        # Then install the tool
        return self.install_tool(tool_name)
    
    def _check_kali_linux(self) -> bool:
        """Check if running on Kali Linux"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
        except:
            return False

    def _run_command(self, command: str, check_output: bool = True) -> Optional[str]:
        """Run a shell command"""
        try:
            if check_output:
                return subprocess.check_output(command.split(), stderr=subprocess.STDOUT).decode()
            else:
                subprocess.run(command.split(), check=True)
                return None
        except:
            return None

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        # First check if command exists in PATH
        if shutil.which(tool_name):
            return True
        
        # If not in REQUIRED_TOOLS, use shutil.which as fallback
        if tool_name not in self.REQUIRED_TOOLS:
            self.console.print(f"[yellow]Warning: Tool {tool_name} not in predefined list. Using basic check.[/yellow]")
            return shutil.which(tool_name) is not None
        
        # Try running the check command
        try:
            check_command = self.REQUIRED_TOOLS[tool_name].get('check_command')
            if check_command:
                result = self._run_command(check_command)
                return result is not None
            return False
        except Exception:
            return False

    def install_tool(self, tool_name: str) -> bool:
        """Install a Kali Linux tool"""
        if not self.is_kali:
            self.console.print("[red]Error: Tool installation is only supported on Kali Linux[/red]")
            return False

        if tool_name not in self.REQUIRED_TOOLS:
            raise ValueError(f"Unknown tool: {tool_name}")

        package = self.REQUIRED_TOOLS[tool_name]['package']
        try:
            # Update package list
            self.console.print(f"[cyan]Updating package list...[/cyan]")
            self._run_command("apt-get update", check_output=False)

            # Install package
            self.console.print(f"[cyan]Installing {tool_name}...[/cyan]")
            self._run_command(f"apt-get install -y {package}", check_output=False)

            # Verify installation
            if self.check_tool(tool_name):
                self.console.print(f"[green]{tool_name} installed successfully[/green]")
                return True
            else:
                self.console.print(f"[red]Failed to verify {tool_name} installation[/red]")
                return False

        except Exception as e:
            self.console.print(f"[red]Error installing {tool_name}: {str(e)}[/red]")
            return False

    def check_all_tools(self) -> Dict[str, bool]:
        """Check status of all required tools"""
        status = {}
        for tool in self.REQUIRED_TOOLS:
            status[tool] = self.check_tool(tool)
        return status

    def install_missing_tools(self) -> bool:
        """Install all missing tools"""
        if not self.is_kali:
            self.console.print("[red]Error: Tool installation is only supported on Kali Linux[/red]")
            return False

        success = True
        status = self.check_all_tools()
        
        for tool, installed in status.items():
            if not installed:
                if not self.install_tool(tool):
                    success = False
                    
        return success

    def get_tool_info(self, tool_name: str) -> Dict:
        """Get information about a tool"""
        if tool_name not in self.REQUIRED_TOOLS:
            raise ValueError(f"Unknown tool: {tool_name}")
            
        info = self.REQUIRED_TOOLS[tool_name].copy()
        info['installed'] = self.check_tool(tool_name)
        return info
