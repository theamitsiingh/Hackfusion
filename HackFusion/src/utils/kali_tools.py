"""
Kali Linux Tools Manager
"""

import os
import subprocess
from typing import List, Dict, Optional
import shutil

class KaliToolsManager:
    """Manager for Kali Linux tools"""
    
    REQUIRED_TOOLS = {
        'nmap': {
            'package': 'nmap',
            'description': 'Network mapper and port scanner',
            'check_command': 'nmap -V'
        },
        'metasploit': {
            'package': 'metasploit-framework',
            'description': 'Penetration testing framework',
            'check_command': 'msfconsole -v'
        },
        'sqlmap': {
            'package': 'sqlmap',
            'description': 'SQL injection tool',
            'check_command': 'sqlmap --version'
        },
        'hydra': {
            'package': 'hydra',
            'description': 'Password cracking tool',
            'check_command': 'hydra -h'
        },
        'aircrack-ng': {
            'package': 'aircrack-ng',
            'description': 'Wireless network security tool',
            'check_command': 'aircrack-ng --help'
        },
        'john': {
            'package': 'john',
            'description': 'Password cracker',
            'check_command': 'john --version'
        },
        'wireshark': {
            'package': 'wireshark',
            'description': 'Network protocol analyzer',
            'check_command': 'wireshark --version'
        },
        'nikto': {
            'package': 'nikto',
            'description': 'Web server scanner',
            'check_command': 'nikto -Version'
        },
        'dirb': {
            'package': 'dirb',
            'description': 'Web content scanner',
            'check_command': 'dirb'
        },
        'hashcat': {
            'package': 'hashcat',
            'description': 'Advanced password recovery',
            'check_command': 'hashcat --version'
        }
    }

    def __init__(self):
        """Initialize Kali Tools Manager"""
        self.is_kali = self._check_kali_linux()
        if not self.is_kali:
            print("[yellow]Warning: Not running on Kali Linux. Some features may be limited.[/yellow]")

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
        if tool_name not in self.REQUIRED_TOOLS:
            raise ValueError(f"Unknown tool: {tool_name}")

        # First check if command exists in PATH
        if shutil.which(tool_name):
            return True

        # Try running the check command
        check_command = self.REQUIRED_TOOLS[tool_name]['check_command']
        return self._run_command(check_command) is not None

    def install_tool(self, tool_name: str) -> bool:
        """Install a Kali Linux tool"""
        if not self.is_kali:
            print("[red]Error: Tool installation is only supported on Kali Linux[/red]")
            return False

        if tool_name not in self.REQUIRED_TOOLS:
            raise ValueError(f"Unknown tool: {tool_name}")

        package = self.REQUIRED_TOOLS[tool_name]['package']
        try:
            # Update package list
            print(f"[cyan]Updating package list...[/cyan]")
            self._run_command("apt-get update", check_output=False)

            # Install package
            print(f"[cyan]Installing {tool_name}...[/cyan]")
            self._run_command(f"apt-get install -y {package}", check_output=False)

            # Verify installation
            if self.check_tool(tool_name):
                print(f"[green]{tool_name} installed successfully[/green]")
                return True
            else:
                print(f"[red]Failed to verify {tool_name} installation[/red]")
                return False

        except Exception as e:
            print(f"[red]Error installing {tool_name}: {str(e)}[/red]")
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
            print("[red]Error: Tool installation is only supported on Kali Linux[/red]")
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
