"""
Reverse Engineering module for HackFusion
Handles integration with reverse engineering tools
"""

import os
import subprocess
from typing import Dict, List, Optional, Any

class ReverseEngineering:
    """Class for handling reverse engineering tools"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize ReverseEngineering module

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.ghidra_path = config.get('ghidra_path', '')
        self.radare2_path = config.get('radare2_path', 'r2')

    def analyze_with_ghidra(self, binary_path: str, project_name: str) -> Dict[str, Any]:
        """Analyze a binary using Ghidra

        Args:
            binary_path: Path to the binary file
            project_name: Name for the Ghidra project

        Returns:
            Dict containing analysis results or error
        """
        try:
            if not os.path.exists(binary_path):
                return {'error': f'Binary file not found: {binary_path}'}

            if not self.ghidra_path:
                return {'error': 'Ghidra path not configured'}

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
