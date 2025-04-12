"""
Reverse Engineering module for HackFusion
Handles integration with reverse engineering tools
"""

import os
import subprocess
from typing import Dict, List, Optional, Any
import glob

class ReverseEngineering:
    """Class for handling reverse engineering tools"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize ReverseEngineering module

        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Verify Ghidra installation
        self.ghidra_path = self._find_ghidra_installation(config.get('ghidra_path', ''))
        
        self.radare2_path = config.get('radare2_path', 'r2')
        self.required_tools = [
            # Static Analysis
            'radare2', 'ghidra', 'ida', 'hopper', 'cutter', 
            'rizin', 'binary-ninja', 'retdec', 'snowman', 
            
            # Disassemblers
            'gdb', 'objdump', 'binwalk', 'readelf', 
            'ndisasm', 'capstone', 'distorm3', 'udis86',
            
            # Dynamic Analysis
            'strace', 'ltrace', 'valgrind', 'pin', 'frida', 
            'dynamorio', 'qemu', 'wine', 'windbg',
            
            # Decompilers
            'jad', 'jadx', 'dex2jar', 'procyon', 
            'fernflower', 'cfr', 'krakatau', 
            
            # Debugging
            'windbg', 'x64dbg', 'ollydbg', 'ida', 
            'gdb-multiarch', 'peda', 'gef', 'lldb',
            
            # Malware Analysis
            'dnspy', 'dotpeek', 'ilspy', 'reflector', 
            'ida', 'hopper', 'binary-ninja', 
            
            # Binary Analysis
            'angr', 'triton', 'manticore', 'symbolic-execution', 
            'z3', 'bap', 'qemu', 'pin', 'valgrind',
            
            # Emulators and Sandboxes
            'qemu', 'bochs', 'virtualbox', 'vmware', 
            'cuckoo', 'sandboxie', 'wine',
            
            # Additional Tools
            'keystone', 'unicorn', 'capstone', 'distorm3', 
            'binwalk', 'foremost', 'scalpel', 'autopsy', 
            'volatility', 'rekall', 'bulk_extractor'
        ]
        self._check_required_tools()

    def _find_ghidra_installation(self, config_path: str = '') -> str:
        """Find Ghidra installation path

        Args:
            config_path: Path provided in configuration

        Returns:
            str: Path to Ghidra launch script or empty string if not found
        """
        # Potential Ghidra installation paths
        potential_paths = [
            config_path,  # User-configured path
            '/opt/ghidra/ghidra_*',  # Common installation in /opt
            os.path.expanduser('~/ghidra_*'),  # User's home directory
            '/usr/local/ghidra_*',  # Local installation
            '/usr/share/ghidra_*'   # System-wide installation
        ]

        # Look for Ghidra launch script
        for path_pattern in potential_paths:
            try:
                # Use glob to find matching directories
                matching_paths = glob.glob(path_pattern)
                
                for path in matching_paths:
                    # Check for launch script
                    launch_script = os.path.join(path, 'ghidraRun')
                    if os.path.exists(launch_script) and os.access(launch_script, os.X_OK):
                        return launch_script
            except Exception:
                pass

        # Check system PATH
        try:
            result = subprocess.run(['which', 'ghidra'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        return ''

    def _verify_ghidra_installation(self) -> bool:
        """Verify Ghidra installation

        Returns:
            bool: True if Ghidra is installed and working, False otherwise
        """
        if not self.ghidra_path:
            print("[yellow]Ghidra installation not found.[/yellow]")
            return False

        try:
            # Run Ghidra with a simple version check
            version_cmd = [self.ghidra_path, '-version']
            result = subprocess.run(version_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[green]Ghidra found at: {self.ghidra_path}[/green]")
                return True
            else:
                print(f"[yellow]Ghidra version check failed: {result.stderr}[/yellow]")
                return False
        except subprocess.TimeoutExpired:
            print("[yellow]Ghidra version check timed out.[/yellow]")
            return False
        except Exception as e:
            print(f"[yellow]Error verifying Ghidra: {e}[/yellow]")
            return False

    def _check_required_tools(self):
        """Check required reverse engineering tools"""
        missing_tools = []
        
        for tool in self.required_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_tools.append(tool)
            except Exception:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"[yellow]Missing reverse engineering tools: {', '.join(missing_tools)}[/yellow]")
            print("[yellow]Some reverse engineering features may be limited.[/yellow]")
            print("[yellow]Run the tool installer from the main menu to install missing tools.[/yellow]")

    def analyze_with_ghidra(self, binary_path: str, project_name: str) -> Dict[str, Any]:
        """Analyze a binary using Ghidra

        Args:
            binary_path: Path to the binary file
            project_name: Name for the Ghidra project

        Returns:
            Dict containing analysis results or error
        """
        # First, verify Ghidra installation
        if not self._verify_ghidra_installation():
            return {
                'error': 'Ghidra is not properly installed. Please install Ghidra and configure its path.',
                'suggested_actions': [
                    'Install Ghidra from official website',
                    'Add Ghidra to system PATH',
                    'Configure Ghidra path in HackFusion settings'
                ]
            }

        try:
            if not os.path.exists(binary_path):
                return {'error': f'Binary file not found: {binary_path}'}

            cmd = [
                self.ghidra_path,
                project_name,
                '-import',
                binary_path,
                '-analyze'
            ]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return {
                    'error': f'Ghidra analysis failed: {stderr}',
                    'output': stdout
                }

            return {
                'success': True,
                'output': stdout,
                'project_name': project_name
            }

        except Exception as e:
            return {'error': str(e)}

    def analyze_with_radare2(self, binary_path: str, commands: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze a binary using Radare2

        Args:
            binary_path: Path to the binary file
            commands: Optional list of r2 commands to run

        Returns:
            Dict containing analysis results or error
        """
        try:
            if not os.path.exists(binary_path):
                return {'error': f'Binary file not found: {binary_path}'}

            if commands is None:
                commands = [
                    'aaa',  # Analyze all
                    'afl',  # List functions
                    'ii',   # List imports
                    'is',   # List symbols
                ]

            cmd = [self.radare2_path, '-q', '-c', ';'.join(commands), binary_path]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return {
                    'error': f'Radare2 analysis failed: {stderr}',
                    'output': stdout
                }

            return {
                'success': True,
                'output': stdout,
                'commands': commands
            }

        except Exception as e:
            return {'error': str(e)}

    def extract_strings(self, binary_path: str, min_length: int = 4) -> Dict[str, Any]:
        """Extract strings from a binary file

        Args:
            binary_path: Path to the binary file
            min_length: Minimum string length to extract

        Returns:
            Dict containing extracted strings or error
        """
        try:
            if not os.path.exists(binary_path):
                return {'error': f'Binary file not found: {binary_path}'}

            cmd = ['strings', f'-n {min_length}', binary_path]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return {
                    'error': f'String extraction failed: {stderr}',
                    'output': stdout
                }

            strings = stdout.splitlines()
            return {
                'success': True,
                'strings': strings,
                'count': len(strings)
            }

        except Exception as e:
            return {'error': str(e)}
