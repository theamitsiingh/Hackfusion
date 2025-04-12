"""
AI-powered security tool recommendation system
"""

import numpy as np
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger('HackFusion')

class AIRecommender:
    def __init__(self):
        self.scaler = StandardScaler()
        self.tool_features = {}
        self.initialize_tool_features()

    def initialize_tool_features(self):
        """Initialize feature vectors for different security tools"""
        # Feature vector format: [effectiveness, speed, resource_usage, risk_level]
        self.tool_features = {
            'nmap': [0.8, 0.7, 0.3, 0.2],
            'nikto': [0.7, 0.5, 0.4, 0.3],
            'sqlmap': [0.9, 0.4, 0.6, 0.7],
            'metasploit': [0.9, 0.6, 0.7, 0.8],
            'wireshark': [0.8, 0.8, 0.4, 0.1],
            'burpsuite': [0.9, 0.7, 0.6, 0.5],
            'hashcat': [0.8, 0.9, 0.8, 0.3],
            'john': [0.7, 0.8, 0.5, 0.3]
        }

    def get_tool_recommendations(self, task_type: str, context: Dict) -> List[Tuple[str, float]]:
        """
        Get AI-powered tool recommendations based on task type and context
        
        Args:
            task_type: Type of security task (e.g., 'recon', 'exploit', 'post-exploit')
            context: Dictionary containing context information
        
        Returns:
            List of tuples containing (tool_name, confidence_score)
        """
        try:
            # Extract context features
            target_type = context.get('target_type', 'unknown')
            risk_tolerance = context.get('risk_tolerance', 0.5)
            time_constraint = context.get('time_constraint', 1.0)

            recommendations = []
            for tool, features in self.tool_features.items():
                score = self._calculate_tool_score(
                    tool, features, task_type, target_type, risk_tolerance, time_constraint
                )
                recommendations.append((tool, score))

            # Sort by score in descending order
            recommendations.sort(key=lambda x: x[1], reverse=True)
            return recommendations[:3]  # Return top 3 recommendations

        except Exception as e:
            logger.error(f"Error generating tool recommendations: {str(e)}")
            return []

    def _calculate_tool_score(
        self, 
        tool: str, 
        features: List[float], 
        task_type: str, 
        target_type: str, 
        risk_tolerance: float, 
        time_constraint: float
    ) -> float:
        """Calculate a score for a tool based on context and features"""
        effectiveness, speed, resource_usage, risk_level = features

        # Adjust weights based on context
        time_weight = 2.0 if time_constraint < 0.5 else 1.0
        risk_weight = 2.0 if risk_tolerance < 0.3 else 1.0

        # Calculate weighted score
        score = (
            effectiveness * 1.0 +
            speed * time_weight +
            (1 - resource_usage) * 0.5 +
            (1 - abs(risk_tolerance - risk_level)) * risk_weight
        ) / (2.5 + time_weight + risk_weight)

        # Apply task-specific adjustments
        if task_type == 'recon' and tool in ['nmap', 'nikto']:
            score *= 1.2
        elif task_type == 'exploit' and tool in ['metasploit', 'sqlmap']:
            score *= 1.2

        return round(score, 3)

    def update_tool_effectiveness(self, tool: str, success: bool, execution_time: float):
        """Update tool effectiveness based on usage results"""
        if tool in self.tool_features:
            current_effectiveness = self.tool_features[tool][0]
            # Apply simple moving average
            self.tool_features[tool][0] = (current_effectiveness * 0.8 + 
                                         (1.0 if success else 0.0) * 0.2)
