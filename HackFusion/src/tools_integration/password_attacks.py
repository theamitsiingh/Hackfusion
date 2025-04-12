"""
Password Attacks module for HackFusion
Handles password cracking and analysis tools
"""

import subprocess
from typing import Dict, List, Optional
import logging
import os

logger = logging.getLogger('HackFusion')

class PasswordAttacks:
    def __init__(self, config: Dict):
        self.config = config
        self.tools = config.get('password_attacks', {})
        self.required_tools = [
            # Brute Force & Dictionary Attacks
            'john', 'hydra', 'medusa', 'ncrack', 
            
            # Password Recovery
            'hashcat', 'rainbowcrack', 'ophcrack', 
            
            # Wordlist and Dictionary Tools
            'crunch', 'wordlists', 'cupp', 
            
            # Network Password Tools
            'crowbar', 'thc-hydra', 'patator', 
            
            # Web Password Tools
            'brutespray', 'webscarab', 
            
            # Additional Tools
            'fcrackzip', 'chntpw', 'samdump2'
        ]
        self._check_required_tools()

    def _check_required_tools(self):
        """Check required password attack tools"""
        missing_tools = []
        
        for tool in self.required_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_tools.append(tool)
            except Exception:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"[yellow]Missing password attack tools: {', '.join(missing_tools)}[/yellow]")
            print("[yellow]Some password cracking features may be limited.[/yellow]")
            print("[yellow]Run the tool installer from the main menu to install missing tools.[/yellow]")

    def run_hashcat(
        self,
        hash_file: str,
        hash_type: str,
        wordlist: str,
        rules: Optional[str] = None,
        workload: int = 2
    ) -> Dict:
        """
        Run Hashcat password cracker
        
        Args:
            hash_file: Path to file containing hashes
            hash_type: Hash type identifier
            wordlist: Path to wordlist file
            rules: Optional rules file
            workload: Performance workload profile (1-4)
        
        Returns:
            Dict containing cracking results
        """
        if not self.tools.get('hashcat', {}).get('enabled'):
            return {'error': 'Hashcat is not enabled'}

        try:
            cmd = [
                'hashcat',
                '-m', hash_type,
                '-w', str(workload),
                '-o', f'{hash_file}.cracked',
                hash_file,
                wordlist
            ]

            if rules:
                cmd.extend(['-r', rules])

            logger.info(f"Running Hashcat: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Read cracked passwords if successful
            cracked = []
            if process.returncode == 0 and os.path.exists(f'{hash_file}.cracked'):
                with open(f'{hash_file}.cracked', 'r') as f:
                    cracked = f.readlines()

            return {
                'success': process.returncode == 0,
                'output': process.stdout,
                'error': process.stderr if process.returncode != 0 else None,
                'cracked': cracked
            }
        except Exception as e:
            logger.error(f"Error running Hashcat: {str(e)}")
            return {'error': str(e)}

    def run_john(
        self,
        hash_file: str,
        format: Optional[str] = None,
        wordlist: Optional[str] = None
    ) -> Dict:
        """
        Run John the Ripper password cracker
        
        Args:
            hash_file: Path to file containing hashes
            format: Optional hash format
            wordlist: Optional path to wordlist file
        
        Returns:
            Dict containing cracking results
        """
        if not self.tools.get('john', {}).get('enabled'):
            return {'error': 'John the Ripper is not enabled'}

        try:
            cmd = ['john']
            if format:
                cmd.extend(['--format', format])
            if wordlist:
                cmd.extend(['--wordlist', wordlist])
            cmd.append(hash_file)

            logger.info(f"Running John the Ripper: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)

            # Show cracked passwords
            show_cmd = ['john', '--show', hash_file]
            if format:
                show_cmd.extend(['--format', format])
            
            show_process = subprocess.run(show_cmd, capture_output=True, text=True)

            return {
                'success': process.returncode == 0,
                'output': process.stdout,
                'cracked': show_process.stdout if show_process.returncode == 0 else '',
                'error': process.stderr if process.returncode != 0 else None
            }
        except Exception as e:
            logger.error(f"Error running John the Ripper: {str(e)}")
            return {'error': str(e)}

    def analyze_password_strength(self, password: str) -> Dict:
        """
        Analyze password strength using custom metrics
        
        Args:
            password: Password to analyze
        
        Returns:
            Dict containing strength analysis
        """
        score = 0
        feedback = []

        # Length check
        if len(password) >= 12:
            score += 2
            feedback.append("Good length")
        elif len(password) >= 8:
            score += 1
            feedback.append("Minimum length met")
        else:
            feedback.append("Password too short")

        # Character variety
        if any(c.isupper() for c in password):
            score += 1
            feedback.append("Contains uppercase")
        if any(c.islower() for c in password):
            score += 1
            feedback.append("Contains lowercase")
        if any(c.isdigit() for c in password):
            score += 1
            feedback.append("Contains numbers")
        if any(not c.isalnum() for c in password):
            score += 1
            feedback.append("Contains special characters")

        return {
            'strength': score,
            'max_strength': 6,
            'rating': ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'][min(score, 4)],
            'feedback': feedback
        }
