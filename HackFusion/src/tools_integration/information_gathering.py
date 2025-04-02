"""Information gathering tools integration"""

import subprocess
import json
import os
from typing import Dict, Any, Optional
from src.utils.kali_tools import KaliToolsManager

class InformationGathering:
    """Information gathering tools"""
    
    def __init__(self):
        """Initialize information gathering tools"""
        self.kali_tools = KaliToolsManager()
        self._check_required_tools()
        
    def _check_required_tools(self):
        """Check required tools"""
        required_tools = ['nmap', 'nikto', 'dirb']
        missing_tools = []
        
        for tool in required_tools:
            if not self.kali_tools.check_tool(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"[yellow]Missing required tools for information gathering: {', '.join(missing_tools)}[/yellow]")
            print("[yellow]Some functionality may be limited.[/yellow]")
            print("[yellow]Run the tool installer from the main menu to install missing tools.[/yellow]")
        
    def run_nmap_scan(self, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Nmap scan using native Kali Linux nmap"""
        if not self.kali_tools.check_tool('nmap'):
            return {'error': 'Nmap is not installed. Please install it first.'}
            
        try:
            # Default scan parameters
            scan_params = {
                'aggressive': '-A',  # Aggressive scan
                'version': '-sV',    # Version detection
                'os': '-O',         # OS detection
                'timing': '-T4',     # Timing template (0-5)
                'ports': '-p-'      # All ports
            }
            
            # Update with custom parameters if provided
            if params:
                scan_params.update(params)
                
            # Build nmap command
            cmd = ['nmap']
            for param in scan_params.values():
                cmd.extend(param.split())
            cmd.append(target)
            
            # Run nmap scan
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'error': f'Nmap scan failed: {result.stderr}'}
                
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Error running Nmap scan: {str(e)}'}
            
    def run_whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Run WHOIS lookup using native Kali Linux whois"""
        if not self.kali_tools.check_tool('whois'):
            return {'error': 'Whois is not installed. Please install it first.'}
            
        try:
            # Run whois command
            result = subprocess.run(['whois', domain], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'error': f'WHOIS lookup failed: {result.stderr}'}
                
            return {
                'output': result.stdout,
                'command': f'whois {domain}'
            }
            
        except Exception as e:
            return {'error': f'Error running WHOIS lookup: {str(e)}'}
            
    def run_dns_enum(self, domain: str) -> Dict[str, Any]:
        """Run DNS enumeration using dnsenum"""
        if not self.kali_tools.check_tool('dnsenum'):
            return {'error': 'Dnsenum is not installed. Please install it first.'}
            
        try:
            # Run dnsenum command
            cmd = ['dnsenum', '--noreverse', '--nocolor', domain]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'error': f'DNS enumeration failed: {result.stderr}'}
                
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Error running DNS enumeration: {str(e)}'}
            
    def run_nikto_scan(self, target: str) -> Dict[str, Any]:
        """Run Nikto web server scanner"""
        if not self.kali_tools.check_tool('nikto'):
            return {'error': 'Nikto is not installed. Please install it first.'}
            
        try:
            # Run nikto command
            cmd = ['nikto', '-h', target, '-Format', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'error': f'Nikto scan failed: {result.stderr}'}
                
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                output = result.stdout
                
            return {
                'output': output,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Error running Nikto scan: {str(e)}'}
            
    def run_dirb_scan(self, target: str) -> Dict[str, Any]:
        """Run Dirb web content scanner"""
        if not self.kali_tools.check_tool('dirb'):
            return {'error': 'Dirb is not installed. Please install it first.'}
            
        try:
            # Run dirb command
            cmd = ['dirb', target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'error': f'Dirb scan failed: {result.stderr}'}
                
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Error running Dirb scan: {str(e)}'}
