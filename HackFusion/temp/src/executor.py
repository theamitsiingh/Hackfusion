"""
Tool execution and orchestration module
"""

import subprocess
import threading
import queue
import time
from typing import Dict, List, Optional, Callable
import logging
from tools_integration.information_gathering import InformationGathering

logger = logging.getLogger('HackFusion')

class ToolExecutor:
    def __init__(self):
        self.running_tasks: Dict[str, Dict] = {}
        self.results_queue = queue.Queue()
        self.config = {}
        self.modules = {}
        self._initialize_modules()

    def _initialize_modules(self):
        """Initialize tool integration modules"""
        try:
            self.modules['info_gathering'] = InformationGathering(self.config)
            # Initialize other modules as they are implemented
        except Exception as e:
            logger.error(f"Error initializing modules: {str(e)}")

    def execute_tool(
        self,
        tool_name: str,
        args: Dict,
        callback: Optional[Callable] = None
    ) -> str:
        """
        Execute a security tool with given arguments
        
        Args:
            tool_name: Name of the tool to execute
            args: Dictionary of tool arguments
            callback: Optional callback function for async execution
        
        Returns:
            task_id: Unique identifier for the task
        """
        task_id = f"{tool_name}_{int(time.time())}"
        
        try:
            # Create task entry
            self.running_tasks[task_id] = {
                'tool': tool_name,
                'status': 'running',
                'start_time': time.time(),
                'args': args,
                'callback': callback
            }

            # Start task in background thread
            thread = threading.Thread(
                target=self._run_tool,
                args=(task_id, tool_name, args)
            )
            thread.daemon = True
            thread.start()

            return task_id

        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            self.running_tasks[task_id] = {
                'tool': tool_name,
                'status': 'failed',
                'error': str(e)
            }
            return task_id

    def _run_tool(self, task_id: str, tool_name: str, args: Dict):
        """Internal method to run a tool and handle its execution"""
        try:
            result = None
            
            # Route to appropriate module based on tool name
            if tool_name == 'nmap':
                result = self.modules['info_gathering'].run_nmap_scan(
                    args.get('target', ''),
                    args.get('scan_args')
                )
            elif tool_name == 'whois':
                result = self.modules['info_gathering'].gather_whois_info(
                    args.get('domain', '')
                )
            # Add more tool handlers as they are implemented
            
            # Update task status
            self.running_tasks[task_id]['status'] = 'completed'
            self.running_tasks[task_id]['result'] = result
            self.running_tasks[task_id]['end_time'] = time.time()

            # Call callback if provided
            if self.running_tasks[task_id].get('callback'):
                self.running_tasks[task_id]['callback'](result)

            # Put result in queue
            self.results_queue.put((task_id, result))

        except Exception as e:
            logger.error(f"Error in task {task_id}: {str(e)}")
            self.running_tasks[task_id]['status'] = 'failed'
            self.running_tasks[task_id]['error'] = str(e)

    def get_task_status(self, task_id: str) -> Dict:
        """Get the status of a running or completed task"""
        return self.running_tasks.get(task_id, {
            'status': 'not_found',
            'error': 'Task ID not found'
        })

    def get_running_tasks(self) -> List[str]:
        """Get list of currently running tasks"""
        return [
            task_id for task_id, task in self.running_tasks.items()
            if task['status'] == 'running'
        ]

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task
        
        Args:
            task_id: ID of the task to cancel
        
        Returns:
            bool: True if task was cancelled, False otherwise
        """
        if task_id in self.running_tasks:
            if self.running_tasks[task_id]['status'] == 'running':
                self.running_tasks[task_id]['status'] = 'cancelled'
                return True
        return False
