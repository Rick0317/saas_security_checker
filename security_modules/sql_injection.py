"""
SQL Injection Testing Module
Integrates with SQLMap for comprehensive SQL injection testing
"""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

class SQLInjectionTester:
    """SQL Injection testing using SQLMap"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.sqlmap_path = self._find_sqlmap()
        
    def _find_sqlmap(self) -> Optional[str]:
        """Find SQLMap installation"""
        possible_paths = [
            '/usr/local/bin/sqlmap',
            '/usr/bin/sqlmap',
            '/opt/sqlmap/sqlmap.py',
            './sqlmap/sqlmap.py'
        ]
        
        # Check if sqlmap is in PATH
        try:
            result = subprocess.run(['which', 'sqlmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Check common installation paths
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Try to find sqlmap.py in current directory
        if os.path.exists('sqlmap.py'):
            return './sqlmap.py'
            
        return None
    
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run SQL injection tests"""
        if not self.sqlmap_path:
            return {
                'status': 'skipped',
                'reason': 'SQLMap not found. Please install SQLMap or provide path.',
                'timestamp': datetime.now().isoformat()
            }
        
        self.logger.info(f"Starting SQL injection test for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Create temporary directory for SQLMap output
            with tempfile.TemporaryDirectory() as temp_dir:
                output_file = os.path.join(temp_dir, 'sqlmap_results.json')
                
                # Build SQLMap command
                cmd = [
                    'python3', self.sqlmap_path,
                    '-u', target_url,
                    '--batch',  # Non-interactive mode
                    '--risk', str(self.config['tests']['sql_injection'].get('risk_level', 3)),
                    '--level', '3',  # Test level
                    '--output-dir', temp_dir,
                    '--dump-all',  # Dump all data if vulnerable
                    '--threads', '10',
                    '--timeout', '30',
                    '--retries', '3',
                    '--randomize', 'User-Agent',
                    '--tamper', 'space2comment,charencode,charunicodeencode',
                    '--technique', 'BEUSTQ',  # Boolean, Error, Union, Stacked, Time, Query
                    '--dbms', 'auto',  # Auto-detect database
                    '--os', 'auto',  # Auto-detect OS
                    '--batch',  # Non-interactive
                    '--no-logging'  # Reduce log output
                ]
                
                # Add additional parameters based on config
                if self.config['tests']['sql_injection'].get('crawl', False):
                    cmd.extend(['--crawl', '2'])  # Crawl depth
                
                if self.config['tests']['sql_injection'].get('forms', True):
                    cmd.extend(['--forms'])  # Test forms
                
                # Run SQLMap
                self.logger.info(f"Running SQLMap command: {' '.join(cmd)}")
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Parse results
                if process.returncode == 0:
                    results['sqlmap_output'] = process.stdout
                    results['sqlmap_errors'] = process.stderr
                    
                    # Check for vulnerabilities in output
                    if 'is vulnerable' in process.stdout.lower():
                        results['vulnerabilities'].append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': 'SQL injection vulnerability detected',
                            'details': self._parse_sqlmap_vulnerabilities(process.stdout)
                        })
                        
                        results['recommendations'].append({
                            'priority': 'High',
                            'recommendation': 'Implement parameterized queries and input validation',
                            'details': 'Use prepared statements and validate all user inputs'
                        })
                    else:
                        results['status'] = 'no_vulnerabilities'
                        results['message'] = 'No SQL injection vulnerabilities detected'
                
                else:
                    results['status'] = 'error'
                    results['error'] = f"SQLMap failed: {process.stderr}"
                    
        except subprocess.TimeoutExpired:
            results['status'] = 'timeout'
            results['error'] = 'SQLMap test timed out'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _parse_sqlmap_vulnerabilities(self, output: str) -> List[Dict]:
        """Parse SQLMap output for vulnerability details"""
        vulnerabilities = []
        
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'is vulnerable' in line.lower():
                # Extract vulnerability details
                vuln_info = {
                    'parameter': 'Unknown',
                    'payload': 'Unknown',
                    'technique': 'Unknown'
                }
                
                # Try to extract parameter name
                if 'Parameter:' in line:
                    vuln_info['parameter'] = line.split('Parameter:')[1].strip()
                
                # Look for payload in subsequent lines
                for j in range(i+1, min(i+5, len(lines))):
                    if 'Payload:' in lines[j]:
                        vuln_info['payload'] = lines[j].split('Payload:')[1].strip()
                    elif 'technique:' in lines[j].lower():
                        vuln_info['technique'] = lines[j].split('technique:')[1].strip()
                
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities
    
    def test_specific_endpoints(self, endpoints: List[str]) -> Dict:
        """Test specific endpoints for SQL injection"""
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'endpoints_tested': len(endpoints),
            'vulnerabilities': []
        }
        
        for endpoint in endpoints:
            try:
                endpoint_result = self.run_test(endpoint, urlparse(endpoint).netloc)
                if endpoint_result.get('vulnerabilities'):
                    results['vulnerabilities'].extend(endpoint_result['vulnerabilities'])
            except Exception as e:
                self.logger.error(f"Error testing endpoint {endpoint}: {str(e)}")
        
        return results

