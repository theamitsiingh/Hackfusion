"""Wireless attacks tools integration"""

import subprocess
import json
from typing import Dict, Any

class WirelessAttacks:
    """Wireless attacks tools"""
    
    def __init__(self):
        """Initialize wireless attack tools"""
        self.required_tools = [
            # WiFi Cracking
            'aircrack-ng', 'reaver', 'wifite', 'bully', 
            'fern-wifi-cracker', 'pixiewps', 'cowpatty', 
            'asleap', 'hashcat', 'john', 'wireshark',
            
            # Packet Injection
            'mdk3', 'kismet', 'aireplay-ng', 'airbase-ng', 
            'hostapd', 'wifi-pineapple', 'wifi-honey',
            
            # Wireless Network Detection
            'wireshark', 'tcpdump', 'netdiscover', 'wavemon', 
            'airmon-ng', 'airodump-ng', 'wash', 'horst',
            
            # Bluetooth Tools
            'bluez', 'bluemaho', 'btscanner', 'bluesnarfer', 
            'bluediving', 'hcitool', 'rfkill', 'blueborne',
            
            # GPS and Location Tools
            'gpsd', 'kismet-gps', 'gpx', 'gpsbabel', 
            
            # Advanced Wireless Tools
            'aircrack-ng', 'wifite', 'bully', 'reaver', 
            'pixiewps', 'wifi-pineapple', 'hostapd', 
            'dnsmasq', 'airbase-ng', 'airodump-ng', 
            'aireplay-ng', 'mdk3', 'wash', 'hcitool', 
            'rfkill', 'macchanger'
        ]
        self._check_required_tools()
        
    def _check_required_tools(self):
        """Check required wireless attack tools"""
        missing_tools = []
        
        for tool in self.required_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_tools.append(tool)
            except Exception:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"[yellow]Missing wireless attack tools: {', '.join(missing_tools)}[/yellow]")
            print("[yellow]Some wireless attack features may be limited.[/yellow]")
            print("[yellow]Run the tool installer from the main menu to install missing tools.[/yellow]")
            
    def run_wifi_scan(self, interface: str = 'wlan0') -> Dict[str, Any]:
        """Run wireless network scan"""
        results = {}
        
        # Put interface in monitor mode
        try:
            cmd = ['airmon-ng', 'start', interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            monitor_interface = interface + 'mon'
            results['monitor_mode'] = {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
        except Exception as e:
            return {'error': f'Failed to enable monitor mode: {str(e)}'}
            
        try:
            # Run airodump-ng scan
            cmd = ['airodump-ng', monitor_interface, '--output-format', 'csv', '--write', '/tmp/wifi_scan']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results['airodump'] = {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
            # Read scan results
            with open('/tmp/wifi_scan-01.csv', 'r') as f:
                results['networks'] = f.read()
                
        except subprocess.TimeoutExpired:
            # This is expected as airodump-ng runs continuously
            pass
        except Exception as e:
            results['scan_error'] = str(e)
            
        finally:
            # Disable monitor mode
            try:
                cmd = ['airmon-ng', 'stop', monitor_interface]
                subprocess.run(cmd, capture_output=True, text=True)
            except Exception as e:
                results['cleanup_error'] = str(e)
                
        return results
        
    def run_wps_scan(self, interface: str = 'wlan0', target_bssid: str = None) -> Dict[str, Any]:
        """Run WPS vulnerability scan"""
        try:
            cmd = ['wash', '-i', interface]
            if target_bssid:
                cmd.extend(['-b', target_bssid])
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'WPS scan failed: {str(e)}'}
            
    def run_bluetooth_scan(self) -> Dict[str, Any]:
        """Run Bluetooth device scan"""
        try:
            # Enable Bluetooth if needed
            subprocess.run(['rfkill', 'unblock', 'bluetooth'], capture_output=True)
            
            # Run hcitool scan
            cmd = ['hcitool', 'scan']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Bluetooth scan failed: {str(e)}'}
            
    def run_deauth_attack(self, interface: str, target_bssid: str, client_mac: str = None) -> Dict[str, Any]:
        """Run deauthentication attack"""
        try:
            cmd = ['aireplay-ng', '--deauth', '5', '-a', target_bssid]
            if client_mac:
                cmd.extend(['-c', client_mac])
            cmd.append(interface)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return {
                'output': result.stdout,
                'command': ' '.join(cmd)
            }
            
        except Exception as e:
            return {'error': f'Deauth attack failed: {str(e)}'}
