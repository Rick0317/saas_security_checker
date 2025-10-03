"""
ZAP Java Testing Module
Integrates ZAP's comprehensive Java-based scanning capabilities into the SaaS Security Checker
"""

import os
import subprocess
import tempfile
import logging
import sys
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import json
import yaml

class ZAPJavaTester:
    """Main ZAP Java testing orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.zap_home = "/Users/rick/saas_security_checker/zaproxy-main"
        self.zap_root = f"{self.zap_home}/zap/src/main/java"
        self.scan_results = {}
        self.java_classpath = self._build_classpath()
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.ZAPJavaTester")
        
    def _build_classpath(self) -> str:
        """Build Java classpath for ZAP components"""
        classpath_dirs = [
            f"{self.zap_home}/zap/build/libs",
            f"{self.zap_root}",
            f"{self.zap_home}/lib",
            f"{self.zap_home}/zaproxy-main"
        ]
        
        # Look for jar files
        jar_files = []
        for dir_path in classpath_dirs:
            if os.path.exists(dir_path):
                jar_files.extend([f"{dir_path}/{f}" for f in os.listdir(dir_path) if f.endswith('.jar')])
        
        # Add to classpath
        classpath_parts = [
            f"{self.zap_root}",
            *jar_files,
            "/System/Library/Frameworks/JavaVM.framework/Classes/classes.jar",  # macOS Java
            "/usr/lib/jvm/java-*"  # Linux Java
        ]
        
        return ":".join([p for p in classpath_parts if os.path.exists(p)])
    
    def run_test(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run comprehensive ZAP Java-based security tests"""
        self.logger.info(f"Starting ZAP Java testing for {target_url}")
        
        start_time = datetime.now()
        
        try:
            # Initialize scanner
            scan_result = {}
            
            # Run different scan types
            scan_types = {
                'xss_scanner': self._run_xss_scanner,
                'sql_injection_scanner': self._run_sql_injection_scanner,
                'directory_traversal_scanner': self._run_directory_traversal_scanner,
                'command_injection_scanner': self._run_command_injection_scanner,
                'file_inclusion_scanner': self._run_file_inclusion_scanner,
                'csrf_scanner': self._run_csrf_scanner,
                'information_disclosure_scanner': self._run_info_disclosure_scanner,
                'authentication_scanner': self._run_authentication_scanner,
                'session_management_scanner': self._run_session_scanner,
                'path_traversal_scanner': self._run_path_traversal_scanner
            }
            
            # Execute enabled scans
            for scan_name, scan_function in scan_types.items():
                if self.config.get('tests', {}).get('zap_java_testing', {}).get(scan_name, True):
                    try:
                        result = scan_function(target_url, targetドメイン)
                        scan_result[scan_name] = result
                        self.logger.info(f"Completed {scan_name} scan")
                    except Exception as e:
                        self.logger.error(f"Error in {scan_name}: {str(e)}")
                        scan_result[scan_name] = {'status': 'error', 'error': str(e)}
            
            # Collect overall results
            self.scan_results = {
                'target_url': target_url,
                'target_domain': target_domain,
                'status': 'completed',
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'scan_results': scan_result,
                'summary': self._generate_summary(scan_result)
            }
            
            return self.scan_results
            
        except Exception as e:
            self.logger.error(f"ZAP Java testing failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'target_url': target_url,
                'target_domain': target_domain,
                'timestamp': datetime.now().isoformat()
            }
    
    def _run_xss_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Cross-Site Scripting vulnerability scanner"""
        return self._execute_java_scanner("XSSScanner", target_url, {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'tech_set': ['WEB', 'ALL']
        })
    
    def _run_sql_injection_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run SQL Injection vulnerability scanner"""
        return self._execute_java_scanner("SQLInjectionScanner", target_url, {
            'attack_strength': 'HIGH',
            'alert_threshold': 'HIGH',
            'tech_set': ['WEB', 'DATABASE', 'ALL'],
            'check_param_names': True,
            'check_header_names': True,
            'check_cookie_names': True
        })
    
    def _run_directory_traversal_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Directory traversal vulnerability scanner"""
        return self._execute_java_scanner("DirectoryTraversalScanner", target_url, {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'tech_set': ['WEB', 'FILE', 'ALL'],
            'path_traversal_patterns': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '....//....//....//etc/passwd'
            ]
        })
    
    def _run_command_injection_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Command Injection vulnerability scanner"""
        return self._execute_java_scanner("CommandInjection Scanner", target_url, {
            'attack_strength': 'HIGH',
            'alert_threshold': 'HIGH',
            'tech_set': ['WEB', 'OS', 'ALL'],
            'command_injection_patterns': [
                '; cat /etc/passwd',
                '| whoami',
                '&& id',
                '`pwd`',
                '$(whoami)'
            ]
        })
    
    def _run_file_inclusion_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run File Inclusion vulnerability scanner"""
        return self._execute_java_scanner("FileInclusionScanner", target_url, {
            'attack_strength': 'HIGH',
            'alert_threshold': 'HIGH',
            'tech_set': ['WEB', 'FILE', 'ALL'],
            'lfi_patterns': [
                'php://filter/convert.base64-encode/resource=',
                'file:///etc/passwd',
                '/etc/passwd',
                '../../../../etc/passwd'
            ]
        })
    
    def _run_csrf_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run CSRF vulnerability scanner"""
        return self._execute_java_scanner("CSRFScanner", target_url, {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'tech_set': ['WEB', 'ALL'],
            'check_state_changing_methods': True,
            'token_validation': True
        })
    
    def _run_info_disclosure_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Information Disclosure vulnerability scanner"""
        return self._execute_java_scanner("InfoDisclosureScanner", target_url, {
            'attack_strength': 'LOW',
            'alert_threshold': 'LOW',
            'tech_set': ['WEB', 'ALL'],
            'check_error_messages': True,
            'check_comment_disclosure': True,
            'check_metadata_disclosure': True
        })
    
    def _run_authentication_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Authentication vulnerability scanner"""
        return self._execute_java_scanner("AuthenticationScanner", target_url, {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'tech_set': ['WEB', 'AUTH', 'ALL'],
            'brute_force_testing': True,
            'session_fixation_testing': True,
            'weak_password_testing': True
        })
    
    def _run_session_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Session Management vulnerability scanner"""
        return self._execute_java_scanner("SessionScanner", target_url, {
            'attack_strength': 'MEDIUM',
            'alert_threshold': 'MEDIUM',
            'tech_set': ['WEB', 'SESSION', 'ALL'],
            'session_mgmt_testing': True,
            'cookie_security_testing': True,
            'session_id_strength_testing': True
        })
    
    def _run_path_traversal_scanner(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run Path Traversal vulnerability scanner"""
        return self._execute_java_scanner("PathTraversalScanner", target_url, {
            'attack_strength': 'HIGH',
            'alert_threshold': 'HIGH', 
            'tech_set': ['WEB', 'FILE', 'ALL'],
            'path_traversal_patterns': [
                '../',
                '..\\',
                '%2e%2e%2f',
                '%252e%252e%252f',
                '....//',
                '....\\'
            ]
        })
    
    def _execute_java_scanner(self, scanner_class: str, target_url: str, scan_params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a Java-based scanner"""
        try:
            # Create temporary config file
            config_data = {
                'scanner_class': scanner_class,
                'target_url': target_url,
                'scan_params': scan_params
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
                json.dump(config_data, config_file)
                config_path = config_file.name
            
            # Prepare Java command
            java_class = f"org.zaproxy.zap.{scanner_class.lower()}.CustomScannerWrapper"
            
            cmd = [
                'java',
                '-cp', self.java_classpath,
                '-Djava.awt.headless=true',
                java_class,
                target_url,
                config_path
            ]
            
            self.logger.info(f"Executing: {' '.join(cmd[:3])} [config]")
            
            # Execute Java scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.zap_home
            )
            
            # Clean up temporary config
            os.unlink(config_path)
            
            if result.returncode == 0:
                return {
                    'status': 'success',
                    'scanner': scanner_class,
                    'target': target_url,
                    'vulnerabilities_found': self._parse_vulnerabilities(result.stdout),
                    'execution_time': 'completed',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'status': 'error',
                    'scanner': scanner_class,
                    'target': target_url,
                    'error': result.stderr,
                    'timestamp': datetime.now().isoformat()
                }
                
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'scanner': scanner_class,
                'target': target_url,
                'error': 'Scanner execution timed out',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'status': 'error',
                'scanner': scanner_class,
                'target': target_url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_vulnerabilities(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from Java scanner output"""
        vulnerabilities = []
        
        try:
            lines = stdout.strip().split('\n')
            current_vuln = {}
            
            for line in lines:
                if line.startswith('VULNERABILITY:'):
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {'type': line.split(':', 1)[1].strip()}
                elif line.startswith('SEVERITY:'):
                    current_vuln['severity'] = line.split(':', 1)[1].strip().upper()
                elif line.startswith('URL:'):
                    current_vuln['url'] = line.split(':', 1)[1].strip()
                elif line.startswith('PARAMETER:'):
                    current_vuln['parameter'] = line.split(':', 1)[1].strip()
                elif line.startswith('ATTACK:'):
                    current_vuln['attack_payload'] = line.split(':', 1)[1].strip()
                elif line.startswith('EVIDENCE:'):
                    current_vuln['evidence'] = line.split(':', 1)[1].strip()
                elif line.startswith('CWE:'):
                    current_vuln['cwe'] = line.split(':', 1)[1].strip()
            
            if current_vuln:
                vulnerabilities.append(current_vuln)
                
        except Exception as e:
            self.logger.warning(f"Failed to parse vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of scan results"""
        total_scans = len(scan_results)
        successful_scans = sum(1 for result in scan_results.values() if result.get('status') == 'success')
        failed_scans = total_scans - successful_scans
        
        total_vulnerabilities = 0
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        for result in scan_results.values():
            if result.get('status') == 'success' and 'vulnerabilities_found' in result:
                vulns = result['vulnerabilities_found']
                total_vulnerabilities += len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
        
        return {
            'total_scans_run': total_scans,
            'successful_scans': successful_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities_found': total_vulnerabilities,
            'severity_breakdown': severity_counts,
            'scan_success_rate': f"{(successful_scans/total_scans*100):.1f}%" if total_scans > 0 else "0%"
        }
