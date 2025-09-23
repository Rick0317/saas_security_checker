"""
Comprehensive Security Report Generator
Generates detailed security reports in multiple formats with severity analysis
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def generate_json_report(self, results: Dict, output_path: Path):
        """Generate JSON security report"""
        try:
            # Prepare comprehensive report data
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'target': self.config['target']['url'],
                    'tool_version': '1.0.0',
                    'config': self.config
                },
                'summary': self._generate_summary(results),
                'results': results,
                'vulnerabilities': self._extract_all_vulnerabilities(results),
                'recommendations': self._extract_all_recommendations(results),
                'risk_assessment': self._calculate_risk_assessment(results)
            }
            
            # Write JSON report
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            self.logger.info(f"JSON report generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
    
    def generate_html_report(self, results: Dict, output_path: Path):
        """Generate HTML security report"""
        try:
            html_content = self._generate_html_content(results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
    
    def generate_console_report(self, results: Dict):
        """Generate console security report"""
        try:
            # Display summary
            self._display_summary(results)
            
            # Display vulnerabilities by severity
            self._display_vulnerabilities_by_severity(results)
            
            # Display recommendations by priority
            self._display_recommendations_by_priority(results)
            
            # Display test results summary
            self._display_test_results_summary(results)
            
        except Exception as e:
            self.logger.error(f"Error generating console report: {str(e)}")
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate executive summary"""
        summary = {
            'total_tests': len(results),
            'completed_tests': 0,
            'failed_tests': 0,
            'skipped_tests': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'total_recommendations': 0,
            'high_priority_recommendations': 0,
            'medium_priority_recommendations': 0,
            'low_priority_recommendations': 0
        }
        
        for test_name, test_result in results.items():
            status = test_result.get('status', 'unknown')
            if status == 'completed':
                summary['completed_tests'] += 1
            elif status == 'error':
                summary['failed_tests'] += 1
            elif status == 'skipped':
                summary['skipped_tests'] += 1
            
            # Count vulnerabilities
            vulnerabilities = test_result.get('vulnerabilities', [])
            summary['total_vulnerabilities'] += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown').lower()
                if severity == 'critical':
                    summary['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    summary['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    summary['medium_vulnerabilities'] += 1
                elif severity == 'low':
                    summary['low_vulnerabilities'] += 1
            
            # Count recommendations
            recommendations = test_result.get('recommendations', [])
            summary['total_recommendations'] += len(recommendations)
            
            for rec in recommendations:
                priority = rec.get('priority', 'unknown').lower()
                if priority == 'high':
                    summary['high_priority_recommendations'] += 1
                elif priority == 'medium':
                    summary['medium_priority_recommendations'] += 1
                elif priority == 'low':
                    summary['low_priority_recommendations'] += 1
        
        return summary
    
    def _extract_all_vulnerabilities(self, results: Dict) -> List[Dict]:
        """Extract all vulnerabilities from all tests"""
        all_vulnerabilities = []
        
        for test_name, test_result in results.items():
            vulnerabilities = test_result.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                vuln['test_source'] = test_name
                all_vulnerabilities.append(vuln)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
        all_vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'unknown').lower(), 4))
        
        return all_vulnerabilities
    
    def _extract_all_recommendations(self, results: Dict) -> List[Dict]:
        """Extract all recommendations from all tests"""
        all_recommendations = []
        
        for test_name, test_result in results.items():
            recommendations = test_result.get('recommendations', [])
            for rec in recommendations:
                rec['test_source'] = test_name
                all_recommendations.append(rec)
        
        # Sort by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2, 'unknown': 3}
        all_recommendations.sort(key=lambda x: priority_order.get(x.get('priority', 'unknown').lower(), 3))
        
        return all_recommendations
    
    def _calculate_risk_assessment(self, results: Dict) -> Dict:
        """Calculate overall risk assessment"""
        vulnerabilities = self._extract_all_vulnerabilities(results)
        
        # Risk scoring
        risk_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            total_score += risk_scores.get(severity, 0)
        
        # Determine risk level
        if total_score >= 50:
            risk_level = 'Critical'
        elif total_score >= 30:
            risk_level = 'High'
        elif total_score >= 15:
            risk_level = 'Medium'
        elif total_score >= 5:
            risk_level = 'Low'
        else:
            risk_level = 'Very Low'
        
        return {
            'risk_level': risk_level,
            'risk_score': total_score,
            'max_possible_score': len(vulnerabilities) * 10,
            'risk_percentage': (total_score / (len(vulnerabilities) * 10)) * 100 if vulnerabilities else 0
        }
    
    def _display_summary(self, results: Dict):
        """Display executive summary in console"""
        summary = self._generate_summary(results)
        risk_assessment = self._calculate_risk_assessment(results)
        
        # Create summary table
        table = Table(title="Security Assessment Summary", show_header=True, header_style="bold blue")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="magenta")
        
        table.add_row("Total Tests", str(summary['total_tests']))
        table.add_row("Completed Tests", str(summary['completed_tests']))
        table.add_row("Failed Tests", str(summary['failed_tests']))
        table.add_row("Skipped Tests", str(summary['skipped_tests']))
        table.add_row("", "")
        table.add_row("Total Vulnerabilities", str(summary['total_vulnerabilities']))
        table.add_row("Critical Vulnerabilities", str(summary['critical_vulnerabilities']), style="red")
        table.add_row("High Vulnerabilities", str(summary['high_vulnerabilities']), style="yellow")
        table.add_row("Medium Vulnerabilities", str(summary['medium_vulnerabilities']), style="blue")
        table.add_row("Low Vulnerabilities", str(summary['low_vulnerabilities']), style="green")
        table.add_row("", "")
        table.add_row("Risk Level", risk_assessment['risk_level'], style="bold red" if risk_assessment['risk_level'] in ['Critical', 'High'] else "bold yellow")
        table.add_row("Risk Score", f"{risk_assessment['risk_score']}/{risk_assessment['max_possible_score']}")
        
        console.print(table)
        console.print()
    
    def _display_vulnerabilities_by_severity(self, results: Dict):
        """Display vulnerabilities grouped by severity"""
        vulnerabilities = self._extract_all_vulnerabilities(results)
        
        if not vulnerabilities:
            console.print(Panel("No vulnerabilities found", title="Vulnerabilities", style="green"))
            return
        
        # Group by severity
        severity_groups = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Display each severity group
        severity_colors = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'green'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_groups:
                vulns = severity_groups[severity]
                color = severity_colors.get(severity, 'white')
                
                table = Table(title=f"{severity.title()} Vulnerabilities ({len(vulns)})", 
                             show_header=True, header_style=f"bold {color}")
                table.add_column("Type", style="cyan", no_wrap=True)
                table.add_column("Description", style="white")
                table.add_column("Source", style="dim")
                
                for vuln in vulns:
                    table.add_row(
                        vuln.get('type', 'Unknown'),
                        vuln.get('description', 'No description'),
                        vuln.get('test_source', 'Unknown')
                    )
                
                console.print(table)
                console.print()
    
    def _display_recommendations_by_priority(self, results: Dict):
        """Display recommendations grouped by priority"""
        recommendations = self._extract_all_recommendations(results)
        
        if not recommendations:
            console.print(Panel("No recommendations available", title="Recommendations", style="green"))
            return
        
        # Group by priority
        priority_groups = {}
        for rec in recommendations:
            priority = rec.get('priority', 'unknown').lower()
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(rec)
        
        # Display each priority group
        priority_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'green'
        }
        
        for priority in ['high', 'medium', 'low']:
            if priority in priority_groups:
                recs = priority_groups[priority]
                color = priority_colors.get(priority, 'white')
                
                table = Table(title=f"{priority.title()} Priority Recommendations ({len(recs)})", 
                             show_header=True, header_style=f"bold {color}")
                table.add_column("Recommendation", style="cyan", no_wrap=True)
                table.add_column("Details", style="white")
                table.add_column("Source", style="dim")
                
                for rec in recs:
                    table.add_row(
                        rec.get('recommendation', 'Unknown'),
                        rec.get('details', 'No details'),
                        rec.get('test_source', 'Unknown')
                    )
                
                console.print(table)
                console.print()
    
    def _display_test_results_summary(self, results: Dict):
        """Display test results summary"""
        table = Table(title="Test Results Summary", show_header=True, header_style="bold blue")
        table.add_column("Test", style="cyan", no_wrap=True)
        table.add_column("Status", justify="center")
        table.add_column("Vulnerabilities", justify="right", style="magenta")
        table.add_column("Recommendations", justify="right", style="green")
        
        for test_name, test_result in results.items():
            status = test_result.get('status', 'unknown')
            vuln_count = len(test_result.get('vulnerabilities', []))
            rec_count = len(test_result.get('recommendations', []))
            
            # Color code status
            if status == 'completed':
                status_style = "green"
            elif status == 'error':
                status_style = "red"
            elif status == 'skipped':
                status_style = "yellow"
            else:
                status_style = "white"
            
            table.add_row(
                test_name.replace('_', ' ').title(),
                Text(status.title(), style=status_style),
                str(vuln_count),
                str(rec_count)
            )
        
        console.print(table)
    
    def _generate_html_content(self, results: Dict) -> str:
        """Generate HTML report content"""
        summary = self._generate_summary(results)
        vulnerabilities = self._extract_all_vulnerabilities(results)
        recommendations = self._extract_all_recommendations(results)
        risk_assessment = self._calculate_risk_assessment(results)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #333;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }}
        .summary-card.critical {{ border-left-color: #dc3545; }}
        .summary-card.high {{ border-left-color: #fd7e14; }}
        .summary-card.medium {{ border-left-color: #ffc107; }}
        .summary-card.low {{ border-left-color: #28a745; }}
        .vulnerability {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .vulnerability.critical {{ background-color: #f8d7da; border-left-color: #dc3545; }}
        .vulnerability.high {{ background-color: #fff3cd; border-left-color: #fd7e14; }}
        .vulnerability.medium {{ background-color: #d1ecf1; border-left-color: #ffc107; }}
        .vulnerability.low {{ background-color: #d4edda; border-left-color: #28a745; }}
        .recommendation {{
            margin-bottom: 15px;
            padding: 15px;
            background-color: #e9ecef;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }}
        .recommendation.high {{ border-left-color: #dc3545; }}
        .recommendation.medium {{ border-left-color: #fd7e14; }}
        .recommendation.low {{ border-left-color: #28a745; }}
        .test-result {{
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
        .status.completed {{ color: #28a745; font-weight: bold; }}
        .status.error {{ color: #dc3545; font-weight: bold; }}
        .status.skipped {{ color: #ffc107; font-weight: bold; }}
        .risk-level {{
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        .risk-level.critical {{ background-color: #dc3545; color: white; }}
        .risk-level.high {{ background-color: #fd7e14; color: white; }}
        .risk-level.medium {{ background-color: #ffc107; color: black; }}
        .risk-level.low {{ background-color: #28a745; color: white; }}
        .risk-level.very-low {{ background-color: #6c757d; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {self.config['target']['url']}</p>
        </div>
        
        <div class="risk-level {risk_assessment['risk_level'].lower().replace(' ', '-')}">
            Risk Level: {risk_assessment['risk_level']} (Score: {risk_assessment['risk_score']})
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>{summary['total_tests']}</h3>
                <p>Total Tests</p>
            </div>
            <div class="summary-card">
                <h3>{summary['completed_tests']}</h3>
                <p>Completed</p>
            </div>
            <div class="summary-card critical">
                <h3>{summary['critical_vulnerabilities']}</h3>
                <p>Critical Vulnerabilities</p>
            </div>
            <div class="summary-card high">
                <h3>{summary['high_vulnerabilities']}</h3>
                <p>High Vulnerabilities</p>
            </div>
            <div class="summary-card medium">
                <h3>{summary['medium_vulnerabilities']}</h3>
                <p>Medium Vulnerabilities</p>
            </div>
            <div class="summary-card low">
                <h3>{summary['low_vulnerabilities']}</h3>
                <p>Low Vulnerabilities</p>
            </div>
        </div>
        
        <h2>Vulnerabilities</h2>
        {self._generate_vulnerabilities_html(vulnerabilities)}
        
        <h2>Recommendations</h2>
        {self._generate_recommendations_html(recommendations)}
        
        <h2>Test Results</h2>
        {self._generate_test_results_html(results)}
        
        <div style="margin-top: 50px; text-align: center; color: #6c757d;">
            <p>Report generated by SaaS Security Checker v1.0.0</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_vulnerabilities_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for vulnerabilities section"""
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
        
        html = ""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            html += f"""
            <div class="vulnerability {severity}">
                <h4>{vuln.get('type', 'Unknown')}</h4>
                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No recommendation')}</p>
                <p><strong>Source:</strong> {vuln.get('test_source', 'Unknown')}</p>
            </div>
            """
        
        return html
    
    def _generate_recommendations_html(self, recommendations: List[Dict]) -> str:
        """Generate HTML for recommendations section"""
        if not recommendations:
            return "<p>No recommendations available.</p>"
        
        html = ""
        for rec in recommendations:
            priority = rec.get('priority', 'unknown').lower()
            html += f"""
            <div class="recommendation {priority}">
                <h4>{rec.get('recommendation', 'Unknown')}</h4>
                <p><strong>Priority:</strong> {rec.get('priority', 'Unknown')}</p>
                <p><strong>Details:</strong> {rec.get('details', 'No details')}</p>
                <p><strong>Source:</strong> {rec.get('test_source', 'Unknown')}</p>
            </div>
            """
        
        return html
    
    def _generate_test_results_html(self, results: Dict) -> str:
        """Generate HTML for test results section"""
        html = ""
        for test_name, test_result in results.items():
            status = test_result.get('status', 'unknown')
            vuln_count = len(test_result.get('vulnerabilities', []))
            rec_count = len(test_result.get('recommendations', []))
            
            html += f"""
            <div class="test-result">
                <h4>{test_name.replace('_', ' ').title()}</h4>
                <p><strong>Status:</strong> <span class="status {status}">{status.title()}</span></p>
                <p><strong>Vulnerabilities:</strong> {vuln_count}</p>
                <p><strong>Recommendations:</strong> {rec_count}</p>
            </div>
            """
        
        return html

