"""
Configuration loader for HackFusion
"""

import os
import yaml
from typing import Dict, Any, Optional

class ConfigLoader:
    """Configuration loader class"""

    def __init__(self, config_dir: str = None):
        """Initialize ConfigLoader
        
        Args:
            config_dir: Directory containing configuration files
        """
        if config_dir is None:
            config_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'config'
            )
        self.config_dir = config_dir
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load all configuration files
        
        Returns:
            Dict containing merged configuration
        """
        config = {}
        
        # Load tools configuration
        tools_config = os.path.join(self.config_dir, 'tools.yaml')
        if os.path.exists(tools_config):
            with open(tools_config, 'r') as f:
                config.update(yaml.safe_load(f))
        
        return config

    def is_tool_enabled(self, category: str, tool: str) -> bool:
        """Check if a tool is enabled in configuration
        
        Args:
            category: Tool category (e.g., 'information_gathering')
            tool: Tool name (e.g., 'nmap')
            
        Returns:
            bool indicating if tool is enabled
        """
        try:
            return self.config.get(category, {}).get(tool, {}).get('enabled', False)
        except Exception as e:
            print(f"Error checking tool status: {str(e)}")
            return False

    def get_tool_config(self, category: str, tool: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration for a tool or category
        
        Args:
            category: Tool category
            tool: Optional tool name
            
        Returns:
            Dict containing tool/category configuration
        """
        if tool:
            return self.config.get(category, {}).get(tool, {})
        return self.config.get(category, {})
