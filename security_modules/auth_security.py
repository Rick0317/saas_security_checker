"""
Authentication and Session Security Checker
Comprehensive authentication and session management security analysis
"""

import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

class AuthSecurityChecker:
    """Authentication and session security analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive authentication security analysis"""
        self.logger.info(f"Starting authentication security analysis for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'auth_endpoints': [],
            'session_analysis': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Discover authentication endpoints
            results['auth_endpoints'] = self._discover_auth_endpoints(target_url)
            
            # Analyze session security
            results['session_analysis'] = self._analyze_session_security(target_url)
            
            # Check for authentication vulnerabilities
            self._check_auth_vulnerabilities(target_url, results)
            
            # Test for common authentication bypasses
            self._test_auth_bypasses(target_url, results)
            
            # Generate recommendations
            self._generate_auth_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during authentication analysis: {str(e)}")
        
        return results
    
    def _discover_auth_endpoints(self, target_url: str) -> List[Dict]:
        """Discover authentication-related endpoints"""
        auth_endpoints = []
        
        # Common authentication endpoint patterns
        auth_patterns = [
            '/login', '/signin', '/auth', '/authenticate',
            '/logout', '/signout', '/auth/logout',
            '/register', '/signup', '/auth/register',
            '/password', '/reset', '/forgot',
            '/admin', '/administrator', '/dashboard',
            '/api/auth', '/api/login', '/api/register',
            '/oauth', '/oauth2', '/sso',
            '/2fa', '/mfa', '/totp',
            '/session', '/sessions'
        ]
        
        for pattern in auth_patterns:
            try:
                test_url = urljoin(target_url, pattern)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code in [200, 302, 401, 403]:
                    endpoint_info = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'type': self._classify_auth_endpoint(pattern),
                        'forms': [],
                        'vulnerabilities': []
                    }
                    
                    # Check for forms on the page
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        forms = soup.find_all('form')
                        
                        for form in forms:
                            form_info = self._analyze_auth_form(form, test_url)
                            endpoint_info['forms'].append(form_info)
                    
                    auth_endpoints.append(endpoint_info)
                    
            except Exception as e:
                self.logger.debug(f"Error checking auth endpoint {pattern}: {str(e)}")
        
        return auth_endpoints
    
    def _classify_auth_endpoint(self, pattern: str) -> str:
        """Classify authentication endpoint type"""
        if any(x in pattern.lower() for x in ['login', 'signin', 'auth']):
            return 'login'
        elif any(x in pattern.lower() for x in ['logout', 'signout']):
            return 'logout'
        elif any(x in pattern.lower() for x in ['register', 'signup']):
            return 'registration'
        elif any(x in pattern.lower() for x in ['password', 'reset', 'forgot']):
            return 'password_reset'
        elif any(x in pattern.lower() for x in ['admin', 'administrator']):
            return 'admin'
        elif any(x in pattern.lower() for x in ['api']):
            return 'api'
        elif any(x in pattern.lower() for x in ['oauth', 'sso']):
            return 'sso'
        elif any(x in pattern.lower() for x in ['2fa', 'mfa', 'totp']):
            return 'mfa'
        else:
            return 'unknown'
    
    def _analyze_auth_form(self, form, base_url: str) -> Dict:
        """Analyze authentication form for security issues"""
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'vulnerabilities': []
        }
        
        # Analyze form inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            input_info = {
                'name': input_elem.get('name', ''),
                'type': input_elem.get('type', 'text'),
                'required': input_elem.has_attr('required'),
                'placeholder': input_elem.get('placeholder', ''),
                'autocomplete': input_elem.get('autocomplete', '')
            }
            form_info['inputs'].append(input_info)
        
        # Check for security issues
        input_names = [inp['name'].lower() for inp in form_info['inputs']]
        
        # Check for password field
        has_password = any('password' in name for name in input_names)
        if has_password:
            password_inputs = [inp for inp in form_info['inputs'] if 'password' in inp['name'].lower()]
            for pwd_input in password_inputs:
                if pwd_input['type'] != 'password':
                    form_info['vulnerabilities'].append({
                        'type': 'Password Field Type',
                        'severity': 'High',
                        'description': f'Password field "{pwd_input["name"]}" is not type="password"',
                        'recommendation': 'Set password input type to "password"'
                    })
        
        # Check for CSRF protection
        has_csrf = any('csrf' in name or 'token' in name for name in input_names)
        if not has_csrf and form_info['method'] == 'POST':
            form_info['vulnerabilities'].append({
                'type': 'Missing CSRF Protection',
                'severity': 'High',
                'description': 'Form lacks CSRF protection',
                'recommendation': 'Implement CSRF tokens'
            })
        
        # Check for autocomplete
        sensitive_inputs = [inp for inp in form_info['inputs'] if 'password' in inp['name'].lower() or 'email' in inp['name'].lower()]
        for sensitive_input in sensitive_inputs:
            if sensitive_input['autocomplete'] not in ['off', 'false']:
                form_info['vulnerabilities'].append({
                    'type': 'Autocomplete Enabled',
                    'severity': 'Medium',
                    'description': f'Sensitive field "{sensitive_input["name"]}" has autocomplete enabled',
                    'recommendation': 'Disable autocomplete for sensitive fields'
                })
        
        return form_info
    
    def _analyze_session_security(self, target_url: str) -> Dict:
        """Analyze session security configuration"""
        session_analysis = {
            'cookies': [],
            'session_config': {},
            'vulnerabilities': []
        }
        
        try:
            # Make request to get cookies
            response = self.session.get(target_url, timeout=30)
            
            # Analyze cookies
            for cookie in self.session.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite'),
                    'expires': cookie.expires
                }
                session_analysis['cookies'].append(cookie_info)
                
                # Check cookie security
                if not cookie_info['secure']:
                    session_analysis['vulnerabilities'].append({
                        'type': 'Insecure Cookie',
                        'severity': 'High',
                        'description': f'Cookie "{cookie.name}" missing Secure flag',
                        'recommendation': 'Add Secure flag to cookies'
                    })
                
                if not cookie_info['httponly']:
                    session_analysis['vulnerabilities'].append({
                        'type': 'Cookie XSS Vulnerability',
                        'severity': 'High',
                        'description': f'Cookie "{cookie.name}" missing HttpOnly flag',
                        'recommendation': 'Add HttpOnly flag to prevent XSS access'
                    })
                
                if not cookie_info['samesite']:
                    session_analysis['vulnerabilities'].append({
                        'type': 'Cookie CSRF Vulnerability',
                        'severity': 'Medium',
                        'description': f'Cookie "{cookie.name}" missing SameSite attribute',
                        'recommendation': 'Add SameSite attribute to prevent CSRF attacks'
                    })
            
            # Check for session fixation
            session_analysis['session_config'] = self._check_session_configuration(response)
            
        except Exception as e:
            session_analysis['error'] = str(e)
            self.logger.error(f"Error analyzing session security: {str(e)}")
        
        return session_analysis
    
    def _check_session_configuration(self, response: requests.Response) -> Dict:
        """Check session configuration from response headers"""
        config = {}
        headers = response.headers
        
        # Check for session-related headers
        session_headers = [
            'set-cookie', 'x-session-id', 'x-csrf-token',
            'x-requested-with', 'x-frame-options'
        ]
        
        for header in session_headers:
            if header in headers:
                config[header] = headers[header]
        
        # Check for security headers
        security_headers = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'content-security-policy'
        ]
        
        config['security_headers'] = {}
        for header in security_headers:
            if header in headers:
                config['security_headers'][header] = headers[header]
        
        return config
    
    def _check_auth_vulnerabilities(self, target_url: str, results: Dict):
        """Check for common authentication vulnerabilities"""
        vulnerabilities = []
        
        # Check for default credentials
        default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('administrator', 'administrator'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('demo', 'demo')
        ]
        
        auth_endpoints = results.get('auth_endpoints', [])
        login_endpoints = [ep for ep in auth_endpoints if ep['type'] == 'login']
        
        for endpoint in login_endpoints:
            for form in endpoint['forms']:
                if form['method'] == 'POST':
                    for username, password in default_credentials:
                        try:
                            form_data = {}
                            for input_elem in form['inputs']:
                                if 'user' in input_elem['name'].lower() or 'email' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = username
                                elif 'pass' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = password
                            
                            action_url = urljoin(endpoint['url'], form['action'])
                            response = self.session.post(action_url, data=form_data, timeout=10)
                            
                            # Check for successful login indicators
                            if self._is_login_successful(response, endpoint['url']):
                                vulnerabilities.append({
                                    'type': 'Default Credentials',
                                    'severity': 'Critical',
                                    'description': f'Default credentials work: {username}:{password}',
                                    'recommendation': 'Change default credentials immediately'
                                })
                                break
                        except:
                            continue
        
        # Check for weak password policy
        weak_passwords = ['123456', 'password', '123456789', '12345678', '12345']
        for endpoint in login_endpoints:
            for form in endpoint['forms']:
                if form['method'] == 'POST':
                    for weak_password in weak_passwords:
                        try:
                            form_data = {}
                            for input_elem in form['inputs']:
                                if 'user' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = 'test'
                                elif 'pass' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = weak_password
                            
                            action_url = urljoin(endpoint['url'], form['action'])
                            response = self.session.post(action_url, data=form_data, timeout=10)
                            
                            if self._is_login_successful(response, endpoint['url']):
                                vulnerabilities.append({
                                    'type': 'Weak Password Policy',
                                    'severity': 'High',
                                    'description': f'Weak password accepted: {weak_password}',
                                    'recommendation': 'Implement strong password policy'
                                })
                                break
                        except:
                            continue
        
        # Check for account enumeration
        vulnerabilities.extend(self._check_account_enumeration(target_url))
        
        # Check for brute force protection
        vulnerabilities.extend(self._check_brute_force_protection(target_url))
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _is_login_successful(self, response: requests.Response, original_url: str) -> bool:
        """Determine if login was successful based on response"""
        # Check for redirect (common after successful login)
        if response.status_code in [301, 302]:
            return True
        
        # Check for success indicators in response
        success_indicators = [
            'welcome', 'dashboard', 'logout', 'profile',
            'success', 'logged in', 'authenticated'
        ]
        
        response_text = response.text.lower()
        if any(indicator in response_text for indicator in success_indicators):
            return True
        
        # Check for error indicators (if not present, might be success)
        error_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed',
            'error', 'denied', 'unauthorized'
        ]
        
        if not any(indicator in response_text for indicator in error_indicators):
            return True
        
        return False
    
    def _check_account_enumeration(self, target_url: str) -> List[Dict]:
        """Check for account enumeration vulnerabilities"""
        vulnerabilities = []
        
        # Test with non-existent user
        test_users = ['nonexistentuser12345', 'invaliduser99999']
        
        for test_user in test_users:
            try:
                # Try to find a password reset endpoint
                reset_urls = [
                    urljoin(target_url, '/password/reset'),
                    urljoin(target_url, '/forgot-password'),
                    urljoin(target_url, '/reset-password')
                ]
                
                for reset_url in reset_urls:
                    try:
                        response = self.session.get(reset_url, timeout=10)
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            forms = soup.find_all('form')
                            
                            for form in forms:
                                if form.get('method', 'GET').upper() == 'POST':
                                    form_data = {}
                                    inputs = form.find_all(['input', 'textarea'])
                                    
                                    for input_elem in inputs:
                                        if 'email' in input_elem.get('name', '').lower() or 'user' in input_elem.get('name', '').lower():
                                            form_data[input_elem['name']] = test_user
                                    
                                    if form_data:
                                        action_url = urljoin(reset_url, form.get('action', ''))
                                        response = self.session.post(action_url, data=form_data, timeout=10)
                                        
                                        # Check for different responses
                                        if 'user not found' in response.text.lower() or 'invalid user' in response.text.lower():
                                            vulnerabilities.append({
                                                'type': 'Account Enumeration',
                                                'severity': 'Medium',
                                                'description': f'Account enumeration possible via password reset at {reset_url}',
                                                'recommendation': 'Use generic error messages for password reset'
                                            })
                                            break
                    except:
                        continue
            except:
                continue
        
        return vulnerabilities
    
    def _check_brute_force_protection(self, target_url: str) -> List[Dict]:
        """Check for brute force protection"""
        vulnerabilities = []
        
        # Find login endpoint
        login_urls = [
            urljoin(target_url, '/login'),
            urljoin(target_url, '/signin'),
            urljoin(target_url, '/auth/login')
        ]
        
        for login_url in login_urls:
            try:
                response = self.session.get(login_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        if form.get('method', 'GET').upper() == 'POST':
                            # Test multiple failed login attempts
                            failed_attempts = 0
                            
                            for i in range(5):  # Test 5 failed attempts
                                try:
                                    form_data = {}
                                    inputs = form.find_all(['input', 'textarea'])
                                    
                                    for input_elem in inputs:
                                        if 'user' in input_elem.get('name', '').lower():
                                            form_data[input_elem['name']] = 'testuser'
                                        elif 'pass' in input_elem.get('name', '').lower():
                                            form_data[input_elem['name']] = 'wrongpassword'
                                    
                                    action_url = urljoin(login_url, form.get('action', ''))
                                    response = self.session.post(action_url, data=form_data, timeout=10)
                                    
                                    if not self._is_login_successful(response, login_url):
                                        failed_attempts += 1
                                    
                                    time.sleep(1)  # Small delay between attempts
                                
                                except:
                                    break
                            
                            # Check if account was locked or rate limited
                            if failed_attempts >= 5:
                                try:
                                    # Try one more time to see if account is locked
                                    form_data = {}
                                    inputs = form.find_all(['input', 'textarea'])
                                    
                                    for input_elem in inputs:
                                        if 'user' in input_elem.get('name', '').lower():
                                            form_data[input_elem['name']] = 'testuser'
                                        elif 'pass' in input_elem.get('name', '').lower():
                                            form_data[input_elem['name']] = 'wrongpassword'
                                    
                                    action_url = urljoin(login_url, form.get('action', ''))
                                    response = self.session.post(action_url, data=form_data, timeout=10)
                                    
                                    if 'locked' not in response.text.lower() and 'rate limit' not in response.text.lower():
                                        vulnerabilities.append({
                                            'type': 'No Brute Force Protection',
                                            'severity': 'High',
                                            'description': f'No brute force protection detected at {login_url}',
                                            'recommendation': 'Implement rate limiting and account lockout'
                                        })
                                except:
                                    pass
                            break
            except:
                continue
        
        return vulnerabilities
    
    def _test_auth_bypasses(self, target_url: str, results: Dict):
        """Test for common authentication bypasses"""
        bypass_vulnerabilities = []
        
        # Test for SQL injection in login
        sql_payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "admin'--",
            "admin'#"
        ]
        
        auth_endpoints = results.get('auth_endpoints', [])
        login_endpoints = [ep for ep in auth_endpoints if ep['type'] == 'login']
        
        for endpoint in login_endpoints:
            for form in endpoint['forms']:
                if form['method'] == 'POST':
                    for payload in sql_payloads:
                        try:
                            form_data = {}
                            for input_elem in form['inputs']:
                                if 'user' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = payload
                                elif 'pass' in input_elem['name'].lower():
                                    form_data[input_elem['name']] = 'anything'
                            
                            action_url = urljoin(endpoint['url'], form['action'])
                            response = self.session.post(action_url, data=form_data, timeout=10)
                            
                            if self._is_login_successful(response, endpoint['url']):
                                bypass_vulnerabilities.append({
                                    'type': 'Authentication Bypass',
                                    'severity': 'Critical',
                                    'description': f'SQL injection authentication bypass with payload: {payload}',
                                    'recommendation': 'Use parameterized queries and proper input validation'
                                })
                                break
                        except:
                            continue
        
        results['vulnerabilities'].extend(bypass_vulnerabilities)
    
    def _generate_auth_recommendations(self, results: Dict):
        """Generate authentication security recommendations"""
        recommendations = []
        
        # Count vulnerabilities by type
        vuln_types = {}
        for vuln in results.get('vulnerabilities', []):
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Generate specific recommendations
        if vuln_types.get('Default Credentials', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Change default credentials',
                'details': 'Default credentials are still active'
            })
        
        if vuln_types.get('Authentication Bypass', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Fix authentication bypass vulnerabilities',
                'details': 'SQL injection in authentication detected'
            })
        
        if vuln_types.get('No Brute Force Protection', 0) > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement brute force protection',
                'details': 'Add rate limiting and account lockout mechanisms'
            })
        
        if vuln_types.get('Missing CSRF Protection', 0) > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement CSRF protection',
                'details': 'Add CSRF tokens to all forms'
            })
        
        # Session security recommendations
        session_vulns = results.get('session_analysis', {}).get('vulnerabilities', [])
        if session_vulns:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Secure session cookies',
                'details': f'Found {len(session_vulns)} session security issues'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement multi-factor authentication',
                'details': 'Add MFA for enhanced security'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement password policy',
                'details': 'Enforce strong password requirements'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement account lockout',
                'details': 'Lock accounts after failed login attempts'
            },
            {
                'priority': 'Low',
                'recommendation': 'Implement session timeout',
                'details': 'Set appropriate session timeout values'
            }
        ])
        
        results['recommendations'].extend(recommendations)

