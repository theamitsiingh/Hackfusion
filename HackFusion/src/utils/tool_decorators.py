import functools
import threading
import time
import sys
from typing import Callable, Any, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

def tool_loading_animation(func: Callable) -> Callable:
    """
    A decorator to add a loading animation to tool execution methods.
    
    :param func: The tool execution method to wrap
    :return: Wrapped method with loading animation
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        console = Console()
        
        # Determine tool name (use first argument or function name)
        tool_name = "Tool Execution"
        if len(args) > 1 and isinstance(args[1], str):
            tool_name = str(args[1])
        elif len(args) > 0 and hasattr(args[0], '__class__'):
            tool_name = f"{args[0].__class__.__name__}.{func.__name__}"
        else:
            tool_name = func.__name__
        
        # Create a threading event to control the animation
        stop_event = threading.Event()
        
        def loading_animation():
            """
            Create a dynamic loading animation for tool execution.
            """
            spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            try:
                with Live(Panel(Text(f"Initializing {tool_name}...", style="bold yellow"), 
                                border_style="cyan", title="Tool Execution")) as live:
                    frame_index = 0
                    while not stop_event.is_set():
                        live.update(Panel(
                            Text(f"{spinner_frames[frame_index]} Preparing {tool_name}", style="bold yellow"),
                            border_style="cyan", 
                            title="Tool Execution"
                        ))
                        frame_index = (frame_index + 1) % len(spinner_frames)
                        time.sleep(0.1)
            except Exception:
                pass
        
        # Create and start the loading animation in a separate thread
        loading_thread = threading.Thread(target=loading_animation)
        loading_thread.daemon = True  # Ensure thread exits when main thread exits
        loading_thread.start()
        
        try:
            # Execute the original function
            result = func(*args, **kwargs)
            
            # Stop the loading animation
            stop_event.set()
            loading_thread.join(timeout=1)
            
            # Add a success message
            console.print(Panel(
                Text(f"✅ {tool_name} Execution Completed", style="bold green"),
                border_style="green"
            ))
            
            return result
        
        except Exception as e:
            # Stop the loading animation
            stop_event.set()
            loading_thread.join(timeout=1)
            
            # Print error message
            console.print(Panel(
                Text(f"❌ {tool_name} Execution Failed: {str(e)}", style="bold red"),
                border_style="red"
            ))
            
            raise
    
    return wrapper
