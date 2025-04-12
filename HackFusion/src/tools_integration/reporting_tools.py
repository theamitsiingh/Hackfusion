"""
Report Generation module for HackFusion
Handles security assessment report generation
"""

import os
from typing import Dict, List, Optional
import logging
import json
from datetime import datetime
import markdown
import jinja2
import pdfkit

logger = logging.getLogger('HackFusion')

class ReportGenerator:
    def __init__(self, config: Dict):
        self.config = config
        self.report_settings = config.get('reporting', {})
        self.template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'templates'
        )
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir)
        )

    def generate_report(
        self,
        findings: List[Dict],
        metadata: Dict,
        output_format: str = 'pdf',
        template: str = 'default_report.html'
    ) -> Dict:
        """
        Generate security assessment report
        
        Args:
            findings: List of security findings
            metadata: Report metadata
            output_format: Output format (pdf/html)
            template: Template name to use
        
        Returns:
            Dict containing report generation status
        """
        try:
            # Prepare report data
            report_data = {
                'title': metadata.get('title', 'Security Assessment Report'),
                'date': datetime.now().strftime('%Y-%m-%d'),
                'client': metadata.get('client', ''),
                'scope': metadata.get('scope', ''),
                'findings': self._process_findings(findings),
                'summary': self._generate_executive_summary(findings),
                'risk_matrix': self._generate_risk_matrix(findings)
            }

            # Load and render template
            template = self.jinja_env.get_template(template)
            html_content = template.render(**report_data)

            # Generate output file
            output_dir = os.path.join(os.getcwd(), 'reports')
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"security_report_{timestamp}"

            if output_format == 'pdf':
                output_file = os.path.join(output_dir, f"{base_filename}.pdf")
                self._generate_pdf(html_content, output_file)
            else:
                output_file = os.path.join(output_dir, f"{base_filename}.html")
                with open(output_file, 'w') as f:
                    f.write(html_content)

            return {
                'success': True,
                'output_file': output_file,
                'format': output_format
            }
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return {'error': str(e)}

    def _process_findings(self, findings: List[Dict]) -> List[Dict]:
        """Process and categorize findings"""
        processed = []
        for finding in findings:
            severity = self._calculate_severity(
                finding.get('impact', 0),
                finding.get('likelihood', 0)
            )
            processed.append({
                'title': finding.get('title', ''),
                'description': finding.get('description', ''),
                'severity': severity,
                'impact': finding.get('impact', 0),
                'likelihood': finding.get('likelihood', 0),
                'recommendation': finding.get('recommendation', ''),
                'evidence': finding.get('evidence', []),
                'references': finding.get('references', [])
            })
        return processed

    def _calculate_severity(self, impact: int, likelihood: int) -> str:
        """Calculate finding severity based on impact and likelihood"""
        score = impact * likelihood
        if score >= 16:
            return 'Critical'
        elif score >= 12:
            return 'High'
        elif score >= 8:
            return 'Medium'
        elif score >= 4:
            return 'Low'
        return 'Informational'

    def _generate_executive_summary(self, findings: List[Dict]) -> str:
        """Generate executive summary from findings"""
        summary = []
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }

        for finding in findings:
            severity = self._calculate_severity(
                finding.get('impact', 0),
                finding.get('likelihood', 0)
            )
            severity_counts[severity] += 1

        summary.append("## Executive Summary\n")
        summary.append("### Key Findings\n")
        for severity, count in severity_counts.items():
            if count > 0:
                summary.append(f"- {count} {severity} severity finding{'s' if count > 1 else ''}")

        return '\n'.join(summary)

    def _generate_risk_matrix(self, findings: List[Dict]) -> Dict:
        """Generate risk matrix visualization data"""
        matrix = [[0 for _ in range(5)] for _ in range(5)]
        
        for finding in findings:
            impact = min(finding.get('impact', 1), 5) - 1
            likelihood = min(finding.get('likelihood', 1), 5) - 1
            matrix[impact][likelihood] += 1

        return {
            'matrix': matrix,
            'impact_levels': ['Minimal', 'Low', 'Moderate', 'High', 'Critical'],
            'likelihood_levels': ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain']
        }

    def _generate_pdf(self, html_content: str, output_file: str):
        """Generate PDF from HTML content"""
        options = {
            'page-size': 'A4',
            'margin-top': '20mm',
            'margin-right': '20mm',
            'margin-bottom': '20mm',
            'margin-left': '20mm',
            'encoding': 'UTF-8',
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'no-outline': None
        }

        pdfkit.from_string(html_content, output_file, options=options)
