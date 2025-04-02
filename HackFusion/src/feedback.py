"""
Feedback manager for HackFusion
Handles user interaction and result display
"""

from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

class FeedbackManager:
    """Manages user feedback and display"""

    def __init__(self):
        """Initialize FeedbackManager"""
        self.console = Console()

    def print_banner(self):
        """Print welcome banner"""
        banner = """
 _    _            _    ______          _             
| |  | |          | |   |  ___|        (_)            
| |  | | __ _  ___| | __| |_ _   _ ___  _  ___  _ __  
| |  | |/ _` |/ __| |/ /|  _| | | / __|| |/ _ \| '_ \ 
| |__| | (_| | (__|   < | | | |_| \__ \| | (_) | | | |
 \____/ \__,_|\___|_|\_\\_|  \__,_|___/|_|\___/|_| |_|
                                                      
        Advanced Cybersecurity Toolkit
================================================
"""
        print(banner)

    def display_tool_results(self, results: Dict[str, Any]):
        """Display tool execution results
        
        Args:
            results: Dictionary containing tool results
        """
        for tool_name, result in results.items():
            if isinstance(result, dict):
                if 'error' in result:
                    self.console.print(f"\n[red]Error in {tool_name}:[/red]")
                    self.console.print(f"[red]{result['error']}[/red]")
                else:
                    self.console.print(f"\n[green]Results from {tool_name}:[/green]")
                    if 'output' in result:
                        self.console.print(result['output'])
                    else:
                        for key, value in result.items():
                            if key != 'success':
                                self.console.print(f"{key}: {value}")
            else:
                self.console.print(f"\n[green]Results from {tool_name}:[/green]")
                self.console.print(str(result))

    def display_progress(self, message: str):
        """Display progress message
        
        Args:
            message: Progress message to display
        """
        self.console.print(f"[blue]{message}...[/blue]")

    def display_error(self, message: str):
        """Display error message
        
        Args:
            message: Error message to display
        """
        self.console.print(f"[red]Error: {message}[/red]")

    def display_success(self, message: str):
        """Display success message
        
        Args:
            message: Success message to display
        """
        self.console.print(f"[green]{message}[/green]")

    def prompt_user(self, message: str) -> str:
        """Prompt user for input
        
        Args:
            message: Prompt message
            
        Returns:
            User input string
        """
        return self.console.input(f"{message}: ")
