#!/usr/bin/env python3
"""
SaaS Security Checker - Comprehensive Security Testing Tool
Combines multiple security testing techniques into a single run
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler

from security_modules.sql_injection import SQLInjectionTester
from security_modules.port_discovery import PortDiscoveryTester
from security_modules.dns_checks import DNSChecker
from security_modules.http_headers import HTTPHeaderAnalyzer
from security_modules.tls_security import TLSSecurityChecker
from security_modules.web_scanner import WebScanner
from security_modules.dependency_checker import DependencyChecker
from security_modules.auth_security import AuthSecurityChecker
from security_modules.password_checker import PasswordStrengthChecker
from security_modules.rce_tester import RCETester
from security_modules.zap_integration import ZAPIntegration
from security_modules.zap_java_integration import ZAPJavaIntegration
from security_modules.packet_sniffing_prevention import PacketSniffingPrevention
from security_modules.dns_hijacking_prevention import DNSHijackingPrevention
from reporting.report_generator import ReportGenerator

console = Console()

class SecurityTestOrchestrator:
    """Main orchestrator for comprehensive security testing"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.results = {}
        self.start_time = None
        
        # Setup logging
        self._setup_logging()
        
        # Initialize test modules
        self._init_modules()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        default_config = {
            "target": {
                "url": "https://example.com",
                "timeout": 30,
                "user_agent": "SaaS-Security-Checker/1.0"
            },
            "tests": {
                "sql_injection": {"enabled": True, "risk_level": 3},
                "port_discovery": {"enabled": True, "ports": "1-1000"},
                "dns_checks": {"enabled": True},
                "http_headers": {"enabled": True},
                "tls_security": {"enabled": True},
                "web_scanner": {"enabled": True, "depth": 2},
                "dependency_check": {"enabled": True},
                "auth_security": {"enabled": True},
                "password_check": {"enabled": True},
                "rce_testing": {"enabled": True},
                "zap_integration": {"enabled": True},
                "zap_java_testing": {"enabled": True},
                "packet_sniffing_prevention": {"enabled": True},
                "dns_hijacking_prevention": {"enabled": True}
            },
            "output": {
                "format": ["json", "html", "console"],
                "directory": "./reports"
            }
        }
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Merge with defaults
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
        
        return default_config
    
    def _setup_logging(self):
        """Setup rich logging"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, rich_tracebacks=True)]
        )
        self.logger = logging.getLogger("SecurityChecker")
    
    def _init_modules(self):
        """Initialize all security testing modules"""
        self.modules = {
            'sql_injection': SQLInjectionTester(self.config),
            'port_discovery': PortDiscoveryTester(self.config),
            'dns_checks': DNSChecker(self.config),
            'http_headers': HTTPHeaderAnalyzer(self.config),
            'tls_security': TLSSecurityChecker(self.config),
            'web_scanner': WebScanner(self.config),
            'dependency_check': DependencyChecker(self.config),
            'auth_security': AuthSecurityChecker(self.config),
            'password_check': PasswordStrengthChecker(self.config),
            'rce_testing': RCETester(self.config),
            'zap_integration': ZAPIntegration(self.config),
            'zap_java_testing': ZAPJavaIntegration(self.config),
            'packet_sniffing_prevention': PacketSniffingPrevention(self.config),
            'dns_hijacking_prevention': DNSHijackingPrevention(self.config)
        }
    
    def run_all_tests(self) -> Dict:
        """Run all enabled security tests"""
        self.start_time = datetime.now()
        target_url = self.config['target']['url']
        
        console.print(Panel(f"[bold blue]Starting Security Assessment[/bold blue]\nTarget: {target_url}\nTime: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", title="SaaS Security Checker"))
        
        # Parse target URL
        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Run each enabled test
            for test_name, module in self.modules.items():
                if self.config['tests'][test_name]['enabled']:
                    task = progress.add_task(f"Running {test_name.replace('_', ' ').title()}...", total=None)
                    
                    try:
                        self.logger.info(f"Starting {test_name} test")
                        result = module.run_test(target_url, target_domain)
                        self.results[test_name] = result
                        progress.update(task, description=f"[green]✓ {test_name.replace('_', ' ').title()} completed")
                        
                    except Exception as e:
                        self.logger.error(f"Error in {test_name}: {str(e)}")
                        self.results[test_name] = {
                            'status': 'error',
                            'error': str(e),
                            'timestamp': datetime.now().isoformat()
                        }
                        progress.update(task, description=f"[red]✗ {test_name.replace('_', ' ').title()} failed")
        
        # Generate comprehensive report
        self._generate_report()
        
        return self.results
    
    def _generate_report(self):
        """Generate comprehensive security report"""
        report_generator = ReportGenerator(self.config)
        
        # Create output directory
        output_dir = Path(self.config['output']['directory'])
        output_dir.mkdir(exist_ok=True)
        
        timestamp = self.start_time.strftime('%Y%m%d_%H%M%S')
        
        # Generate reports in requested formats
        for format_type in self.config['output']['format']:
            if format_type == 'json':
                report_generator.generate_json_report(self.results, output_dir / f"security_report_{timestamp}.json")
            elif format_type == 'html':
                report_generator.generate_html_report(self.results, output_dir / f"security_report_{timestamp}.html")
            elif format_type == 'console':
                report_generator.generate_console_report(self.results)
    
    def run_single_test(self, test_name: str) -> Dict:
        """Run a single specific test"""
        if test_name not in self.modules:
            raise ValueError(f"Unknown test: {test_name}")
        
        target_url = self.config['target']['url']
        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc
        
        console.print(f"[bold blue]Running {test_name.replace('_', ' ').title()} test...[/bold blue]")
        
        try:
            result = self.modules[test_name].run_test(target_url, target_domain)
            return result
        except Exception as e:
            self.logger.error(f"Error in {test_name}: {str(e)}")
            return {'status': 'error', 'error': str(e)}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="SaaS Security Checker - Comprehensive Security Testing Tool")
    parser.add_argument("--target", "-t", help="Target URL to test")
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file path")
    parser.add_argument("--test", help="Run specific test only")
    parser.add_argument("--list-tests", action="store_true", help="List available tests")
    
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = SecurityTestOrchestrator(args.config)
    
    # Override target if provided
    if args.target:
        orchestrator.config['target']['url'] = args.target
    
    # List available tests
    if args.list_tests:
        console.print("\n[bold blue]Available Security Tests:[/bold blue]")
        for test_name in orchestrator.modules.keys():
            console.print(f"  • {test_name.replace('_', ' ').title()}")
        return
    
    # Run tests
    if args.test:
        result = orchestrator.run_single_test(args.test)
        console.print(f"\n[bold green]Test completed:[/bold green] {json.dumps(result, indent=2)}")
    else:
        orchestrator.run_all_tests()
        console.print("\n[bold green]Security assessment completed![/bold green]")
        console.print(f"Reports saved to: {orchestrator.config['output']['directory']}")

if __name__ == "__main__":
    main()
