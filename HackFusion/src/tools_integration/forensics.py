"""
Digital Forensics module for HackFusion
Handles forensics analysis tools and utilities
"""

import subprocess
from typing import Dict, List, Optional
import logging
import os
import json

logger = logging.getLogger('HackFusion')

class Forensics:
    def __init__(self, config: Dict):
        self.config = config
        self.tools = config.get('forensics', {})

    def analyze_memory_dump(
        self,
        dump_file: str,
        profile: str,
        plugins: Optional[List[str]] = None
    ) -> Dict:
        """
        Analyze memory dump using Volatility
        
        Args:
            dump_file: Path to memory dump file
            profile: Volatility profile to use
            plugins: List of Volatility plugins to run
        
        Returns:
            Dict containing analysis results
        """
        if not self.tools.get('volatility', {}).get('enabled'):
            return {'error': 'Volatility is not enabled'}

        try:
            results = {}
            
            # Default plugins if none specified
            if not plugins:
                plugins = [
                    'pslist',      # Process listing
                    'netscan',     # Network connections
                    'filescan',    # File handles
                    'hivelist',    # Registry hives
                    'hashdump'     # Password hashes
                ]

            for plugin in plugins:
                cmd = [
                    'vol.py',
                    '-f', dump_file,
                    '--profile', profile,
                    plugin
                ]

                logger.info(f"Running Volatility plugin {plugin}: {' '.join(cmd)}")
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                results[plugin] = {
                    'success': process.returncode == 0,
                    'output': process.stdout,
                    'error': process.stderr if process.returncode != 0 else None
                }

            return {
                'success': all(r['success'] for r in results.values()),
                'results': results
            }
        except Exception as e:
            logger.error(f"Error analyzing memory dump: {str(e)}")
            return {'error': str(e)}

    def analyze_disk_image(
        self,
        image_path: str,
        output_dir: str,
        case_name: str
    ) -> Dict:
        """
        Analyze disk image using Autopsy
        
        Args:
            image_path: Path to disk image
            output_dir: Directory for analysis output
            case_name: Name of the case
        
        Returns:
            Dict containing analysis status
        """
        if not self.tools.get('autopsy', {}).get('enabled'):
            return {'error': 'Autopsy is not enabled'}

        try:
            # Create case directory
            case_dir = os.path.join(output_dir, case_name)
            os.makedirs(case_dir, exist_ok=True)

            # Create Autopsy case file
            case_file = os.path.join(case_dir, f"{case_name}.aut")
            with open(case_file, 'w') as f:
                f.write(f"case_name={case_name}\n")
                f.write(f"image_path={image_path}\n")

            cmd = [
                'autopsy',
                '-c', case_file,
                '-d', case_dir
            ]

            logger.info(f"Starting Autopsy analysis: {' '.join(cmd)}")
            process = subprocess.Popen(cmd)

            return {
                'success': True,
                'case_dir': case_dir,
                'case_file': case_file,
                'pid': process.pid
            }
        except Exception as e:
            logger.error(f"Error analyzing disk image: {str(e)}")
            return {'error': str(e)}

    def extract_artifacts(
        self,
        target_path: str,
        artifact_types: List[str],
        output_dir: str
    ) -> Dict:
        """
        Extract forensic artifacts from target
        
        Args:
            target_path: Path to target directory/file
            artifact_types: List of artifact types to extract
            output_dir: Output directory for artifacts
        
        Returns:
            Dict containing extraction results
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            results = {}

            for artifact_type in artifact_types:
                artifact_dir = os.path.join(output_dir, artifact_type)
                os.makedirs(artifact_dir, exist_ok=True)

                if artifact_type == 'browser_history':
                    results[artifact_type] = self._extract_browser_history(target_path, artifact_dir)
                elif artifact_type == 'system_logs':
                    results[artifact_type] = self._extract_system_logs(target_path, artifact_dir)
                elif artifact_type == 'registry':
                    results[artifact_type] = self._extract_registry(target_path, artifact_dir)
                else:
                    results[artifact_type] = {'error': f'Unsupported artifact type: {artifact_type}'}

            return {
                'success': all(r.get('success', False) for r in results.values()),
                'results': results,
                'output_dir': output_dir
            }
        except Exception as e:
            logger.error(f"Error extracting artifacts: {str(e)}")
            return {'error': str(e)}

    def _extract_browser_history(self, source: str, output_dir: str) -> Dict:
        """Extract browser history artifacts"""
        browser_paths = {
            'chrome': os.path.join(source, 'AppData/Local/Google/Chrome/User Data/Default/History'),
            'firefox': os.path.join(source, 'AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite'),
            'edge': os.path.join(source, 'AppData/Local/Microsoft/Edge/User Data/Default/History')
        }

        results = {}
        for browser, path in browser_paths.items():
            try:
                if os.path.exists(path):
                    output_file = os.path.join(output_dir, f"{browser}_history.sqlite")
                    cmd = ['cp', path, output_file]
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    results[browser] = {
                        'success': process.returncode == 0,
                        'path': output_file
                    }
            except Exception as e:
                results[browser] = {'error': str(e)}

        return results

    def _extract_system_logs(self, source: str, output_dir: str) -> Dict:
        """Extract system log artifacts"""
        log_paths = ['/var/log', 'C:/Windows/System32/winevt/Logs']
        results = {}

        for path in log_paths:
            if os.path.exists(path):
                try:
                    cmd = ['cp', '-r', path, output_dir]
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    results[path] = {
                        'success': process.returncode == 0,
                        'output_dir': output_dir
                    }
                except Exception as e:
                    results[path] = {'error': str(e)}

        return results

    def _extract_registry(self, source: str, output_dir: str) -> Dict:
        """Extract Windows registry hives"""
        registry_paths = {
            'sam': 'C:/Windows/System32/config/SAM',
            'system': 'C:/Windows/System32/config/SYSTEM',
            'software': 'C:/Windows/System32/config/SOFTWARE'
        }

        results = {}
        for hive, path in registry_paths.items():
            try:
                if os.path.exists(path):
                    output_file = os.path.join(output_dir, f"{hive}.hive")
                    cmd = ['cp', path, output_file]
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    results[hive] = {
                        'success': process.returncode == 0,
                        'path': output_file
                    }
            except Exception as e:
                results[hive] = {'error': str(e)}

        return results
