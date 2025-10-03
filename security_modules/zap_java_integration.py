"""
ZAP Java Integration Module
Python wrapper for executing ZAP Java-based security tests
"""

import os
import subprocess
import tempfile
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

class ZAPJavaIntegration:
    """Python wrapper for ZAP Java security modules"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.zap_modules_path = Path(__file__).parent.parent / "java_security_modules"
        self.zaproxy_home = Path(__file__).parent.parent / "zaproxy-main"
        self.java_home = self._find_java_home()
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.ZAPJavaIntegration")
        
    def _find_java_home(self) -> Optional[str]:
        """Find Java installation"""
        try:
            result = subprocess.run(
                ["which", "java"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                java_path = result.stdout.strip()
                # Navigate to JAVA_HOME from java executable path
                if os.path.exists(java_path):
                    java_bin = os.path.dirname(java_path)
                    java_home = os.path.dirname(java_bin)
                    return java_home
        except Exception as e:
            self.logger.warning(f"Could not find Java: {e}")
        
        # Try common Java installation paths
        common_paths = [
            "/System/Library/Frameworks/JavaVM.framework/Home",  # macOS system
            "/usr/lib/jvm/java-11-openjdk",  # Ubuntu/Debian
            "/usr/lib/jvm/java-8-openjdk",
            "/Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home",  # macOS JDK
            "/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home",
            "/usr/java/jdk-11",  # CentOS/RHEL
            "/usr/java/jdk-17"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def run_test(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Run ZAP Java security tests"""
        self.logger.info(f"Starting ZAP Java security test for {target_url}")
        
        start_time = datetime.now()
        
        try:
            # Compile Java modules if needed
            if not self._compile_java_modules():
                return {
                    'status': 'error',
                    'error': 'Failed to compile Java modules',
                    'target_url': target_url,
                    'timestamp': start_time.isoformat()
                }
            
            # Execute security scans
            scan_results = self._execute_java_security_scans(target_url, target_domain)
            
            # Generate summary
            summary = self._generate_scan_summary(scan_results)
            
            return {
                'status': 'completed',
                'target_url': target_url,
                'target_domain': target_domain,
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'scan_results': scan_results,
                'summary': summary,
                'java_modules_used': self._get_enabled_modules()
            }
            
        except Exception as e:
            self.logger.error(f"ZAP Java testing failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'target_url': target_url,
                'target_domain': target_domain,
                'timestamp': start_time.isoformat()
            }
    
    def _compile_java_modules(self) -> bool:
        """Compile Java security modules using simplified approach"""
        try:
            # Check if the simple ZapRunner class already exists
            classes_dir = self.zap_modules_path / "classes"
            if classes_dir.exists() and (classes_dir / "ZapRunner.class").exists():
                self.logger.info("ZapRunner already compiled")
                return True
            
            # Create classes directory
            classes_dir.mkdir(exist_ok=True)
            
            # Only compile the simplified ZapRunner.java (no dependencies)
            zap_runner_file = self.zap_modules_path / "ZapRunner.java"
            if not zap_runner_file.exists():
                self.logger.error("ZapRunner.java not found")
                return False
            
            # Simple compilation without ZAP dependencies
            cmd = [
                "javac",
                "-d", str(classes_dir),
                str(zap_runner_file)
            ]
            
            self.logger.info(f"Compiling simplified Java module: javac ZapRunner.java")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.error(f"Compilation failed: {result.stderr}")
                return False
            
            self.logger.info("ZapRunner compiled successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to compile ZapRunner: {e}")
            return False
    
    def _execute_java_security_scans(self, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Execute Java-based security scans using simplified ZapRunner"""
        scan_results = {}
        
        # Run comprehensive security scan using ZapRunner
        try:
            self.logger.info("Running comprehensive Java security scan")
            result = self._execute_java_module("comprehensive_scan", target_url, target_domain)
            scan_results["comprehensive_java_security_scan"] = result
            self.logger.info("Completed comprehensive Java security scan")
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive scan: {str(e)}")
            scan_results["comprehensive_java_security_scan"] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
        
        return scan_results
    
    def _execute_java_module(self, module_name: str, target_url: str, target_domain: str) -> Dict[str, Any]:
        """Execute a specific Java security module"""
        
        # Use the simplified ZapRunner for all tests
        java_class = 'ZapRunner'
        
        # Create temporary config
        config_data = {
            'module_name': module_name,
            'java_class': java_class,
            'target_url': target_url,
            'target_domain': target_domain,
            'config': self.config.get('tests', {}).get('zap_java_testing', {})
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as config_file:
            json.dump(config_data, config_file)
            config_path = config_file.name
        
        try:
            # Build classpath for execution
            classes_dir = self.zap_modules_path / "classes"
            
            # Java execution command - use simple classpath
            cmd = [
                "java",
                "-cp", str(classes_dir),
                "-Djava.awt.headless=true",
                "ZapRunner",
                target_url,
                target_domain,
                config_path
            ]
            
            self.logger.info(f"Executing: {' '.join(cmd[:4])} ...")
            
            # Execute Java module
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=str(classes_dir)
            )
            
            # Clean up
            os.unlink(config_path)
            
            if result.returncode == 0:
                return self._parse_java_output(result.stdout, module_name)
            else:
                return {
                    'status': 'error',
                    'scanner_class': java_class,
                    'target': target_url,
                    'error': result.stderr,
                    'stdout': result.stdout,
                    'timestamp': datetime.now().isoformat()
                }
                
        except subprocess.TimeoutExpired:
            os.unlink(config_path)
            return {
                'status': 'timeout',
                'scanner_class': java_class,
                'target': target_url,
                'error': 'Java module execution timed out',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            if os.path.exists(config_path):
                os.unlink(config_path)
            return {
                'status': 'error',
                'scanner_class': java_class,
                'target': target_url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_java_output(self, stdout: str, module_name: str) -> Dict[str, Any]:
        """Parse output from Java modules"""
        try:
            # Try to parse JSON output first
            if stdout.strip().startswith('{'):
                return json.loads(stdout)
            
            # Parse text output format
            vulnerabilities = []
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
                elif line.startswith('PAYLOAD:'):
                    current_vuln['payload'] = line.split(':', 1)[1].strip()
                elif line.startswith('EVIDENCE:'):
                    current_vuln['evidence'] = line.split(':', 1)[1].strip()
                elif line.startswith('CWE:'):
                    current_vuln['cwe'] = line.split(':', 1)[1].strip()
                elif line.startswith('WASC:'):
                    current_vuln['wasc'] = line.split(':', 1)[1].strip()
            
            if current_vuln:
                vulnerabilities.append(current_vuln)
            
            return {
                'status': 'success',
                'module': module_name,
                'vulnerabilities_found': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'timestamp': datetime.now().isoformat(),
                'raw_output': stdout
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to parse Java output: {e}")
            return {
                'status': 'success',
                'module': module_name,
                'raw_output': stdout,
                'parsing_error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_enabled_modules(self) -> List[str]:
        """Get list of enabled Java security modules"""
        default_modules = [
            'xss_scanner',
            'sql_injection_scanner', 
            'directory_traversal_scanner',
            'command_injection_scanner',
            'file_inclusion_scanner',
            'csrf_scanner',
            'information_disclosure_scanner',
            'authentication_scanner',
            'session_management_scanner',
            'ssl_tls_scanner'
        ]
        
        zap_config = self.config.get('tests', {}).get('zap_java_testing', {})
        if zap_config.get('enabled', True):
            return default_modules
        
        return [module for module in default_modules if zap_config.get(module, True)]
    
    def _generate_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of scan results"""
        total_modules = len(scan_results)
        successful_scans = 0
        failed_scans = 0
        total_vulnerabilities = 0
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        module_details = {}
        
        for module_name, result in scan_results.items():
            module_details[module_name] = {
                'status': result.get('status', 'unknown'),
                'vulnerability_count': 0,
                'execution_time': result.get('execution_time', 'unknown')
            }
            
            if result.get('status') == 'success':
                successful_scans += 1
                vulnerabilities = result.get('vulnerabilities_found', [])
                module_details[module_name]['vulnerability_count'] = len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    total_vulnerabilities += 1
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
            else:
                failed_scans += 1
        
        return {
            'total_modules_run': total_modules,
            'successful_scans': successful_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities_found': total_vulnerabilities,
            'severity_breakdown': severity_counts,
            'scan_success_rate': f"{(successful_scans/total_modules*100):.1f}%" if total_modules > 0 else "0%",
            'module_summary': module_details
        }
