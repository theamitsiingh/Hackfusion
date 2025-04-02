"""
Feedback manager for HackFusion
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

class FeedbackManager:
    """Class for managing user feedback and display"""

    def __init__(self):
        """Initialize FeedbackManager"""
        self.console = Console()

    def display_welcome(self):
        """Display welcome message and ASCII art"""
        welcome_text = """
    ╔╗ ╔═╗╔═╗╦╔═╔═╗╦ ╦╔═╗╦╔═╗╔╗╔
    ╠╩╗╠═╣║  ╠╩╗╠╣ ║ ║╚═╗║║ ║║║║
    ╚═╝╩ ╩╚═╝╩ ╩╚  ╚═╝╚═╝╩╚═╝╝╚╝
        [Security Through Innovation]
        """
        
        self.console.print(
            Panel(
                Text(welcome_text, justify="center"),
                title="Welcome to HackFusion",
                expand=True
            )
        )
        
        self.console.print("\nAdvanced Cybersecurity Toolkit")
        self.console.print("Version 1.0.0\n")

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

    def display_info(self, message: str):
        """Display info message
        
        Args:
            message: Info message to display
        """
        self.console.print(f"[blue]{message}[/blue]")
