"""
HTTP Response Headers Security Analysis
Analyzes HTTP headers for security misconfigurations and missing security headers
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

class HTTPHeaderAnalyzer:
    """HTTP headers security analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run HTTP headers security analysis"""
        self.logger.info(f"Starting HTTP headers analysis for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'headers': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Make HTTP request and analyze headers
            response = self._make_request(target_url)
            if response:
                results['headers'] = dict(response.headers)
                results['status_code'] = response.status_code
                
                # Analyze security headers
                self._analyze_security_headers(results)
                
                # Check for information disclosure
                self._check_information_disclosure(results)
                
                # Generate recommendations
                self._generate_header_recommendations(results)
            else:
                results['status'] = 'error'
                results['error'] = 'Failed to retrieve HTTP response'
                
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during HTTP headers analysis: {str(e)}")
        
        return results
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request with proper headers"""
        headers = {
            'User-Agent': self.config['target'].get('user_agent', 'SaaS-Security-Checker/1.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.config['target'].get('timeout', 30),
                allow_redirects=True,
                verify=False  # For testing purposes
            )
            return response
        except Exception as e:
            self.logger.error(f"HTTP request failed: {str(e)}")
            return None
    
    def _analyze_security_headers(self, results: Dict):
        """Analyze security-related HTTP headers"""
        headers = results['headers']
        vulnerabilities = []
        
        # Check for missing HSTS header
        if 'strict-transport-security' not in headers:
            vulnerabilities.append({
                'type': 'Missing HSTS Header',
                'severity': 'High',
                'description': 'Strict-Transport-Security header not present',
                'recommendation': 'Add HSTS header to force HTTPS connections'
            })
        else:
            hsts_value = headers['strict-transport-security']
            if 'max-age=0' in hsts_value:
                vulnerabilities.append({
                    'type': 'HSTS Disabled',
                    'severity': 'High',
                    'description': 'HSTS is disabled (max-age=0)',
                    'recommendation': 'Enable HSTS with appropriate max-age value'
                })
        
        # Check for missing X-Content-Type-Options
        if 'x-content-type-options' not in headers:
            vulnerabilities.append({
                'type': 'Missing X-Content-Type-Options',
                'severity': 'Medium',
                'description': 'X-Content-Type-Options header not present',
                'recommendation': 'Add X-Content-Type-Options: nosniff header'
            })
        elif headers['x-content-type-options'].lower() != 'nosniff':
            vulnerabilities.append({
                'type': 'Incorrect X-Content-Type-Options',
                'severity': 'Medium',
                'description': f'X-Content-Type-Options value is incorrect: {headers["x-content-type-options"]}',
                'recommendation': 'Set X-Content-Type-Options to nosniff'
            })
        
        # Check for missing X-Frame-Options
        if 'x-frame-options' not in headers:
            vulnerabilities.append({
                'type': 'Missing X-Frame-Options',
                'severity': 'Medium',
                'description': 'X-Frame-Options header not present',
                'recommendation': 'Add X-Frame-Options header to prevent clickjacking'
            })
        else:
            xfo_value = headers['x-frame-options'].lower()
            if xfo_value not in ['deny', 'sameorigin']:
                vulnerabilities.append({
                    'type': 'Weak X-Frame-Options',
                    'severity': 'Low',
                    'description': f'X-Frame-Options value may be weak: {headers["x-frame-options"]}',
                    'recommendation': 'Use X-Frame-Options: DENY or SAMEORIGIN'
                })
        
        # Check for missing Content Security Policy
        if 'content-security-policy' not in headers:
            vulnerabilities.append({
                'type': 'Missing Content Security Policy',
                'severity': 'Medium',
                'description': 'Content-Security-Policy header not present',
                'recommendation': 'Implement Content Security Policy to prevent XSS attacks'
            })
        
        # Check for missing X-XSS-Protection
        if 'x-xss-protection' not in headers:
            vulnerabilities.append({
                'type': 'Missing X-XSS-Protection',
                'severity': 'Low',
                'description': 'X-XSS-Protection header not present',
                'recommendation': 'Add X-XSS-Protection header (though CSP is preferred)'
            })
        
        # Check for missing Referrer-Policy
        if 'referrer-policy' not in headers:
            vulnerabilities.append({
                'type': 'Missing Referrer-Policy',
                'severity': 'Low',
                'description': 'Referrer-Policy header not present',
                'recommendation': 'Add Referrer-Policy header to control referrer information'
            })
        
        # Check for missing Permissions-Policy
        if 'permissions-policy' not in headers:
            vulnerabilities.append({
                'type': 'Missing Permissions-Policy',
                'severity': 'Low',
                'description': 'Permissions-Policy header not present',
                'recommendation': 'Add Permissions-Policy header to control browser features'
            })
        
        # Check for missing Cross-Origin policies
        if 'cross-origin-embedder-policy' not in headers:
            vulnerabilities.append({
                'type': 'Missing COEP',
                'severity': 'Low',
                'description': 'Cross-Origin-Embedder-Policy header not present',
                'recommendation': 'Consider adding COEP header for enhanced security'
            })
        
        if 'cross-origin-opener-policy' not in headers:
            vulnerabilities.append({
                'type': 'Missing COOP',
                'severity': 'Low',
                'description': 'Cross-Origin-Opener-Policy header not present',
                'recommendation': 'Consider adding COOP header for enhanced security'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _check_information_disclosure(self, results: Dict):
        """Check for information disclosure in headers"""
        headers = results['headers']
        vulnerabilities = []
        
        # Check for server information disclosure
        if 'server' in headers:
            server_info = headers['server']
            vulnerabilities.append({
                'type': 'Server Information Disclosure',
                'severity': 'Low',
                'description': f'Server header reveals: {server_info}',
                'recommendation': 'Suppress or modify Server header to hide version information'
            })
        
        # Check for X-Powered-By disclosure
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            vulnerabilities.append({
                'type': 'Technology Information Disclosure',
                'severity': 'Low',
                'description': f'X-Powered-By header reveals: {powered_by}',
                'recommendation': 'Remove X-Powered-By header to hide technology stack'
            })
        
        # Check for X-AspNet-Version disclosure
        if 'x-aspnet-version' in headers:
            aspnet_version = headers['x-aspnet-version']
            vulnerabilities.append({
                'type': 'ASP.NET Version Disclosure',
                'severity': 'Medium',
                'description': f'X-AspNet-Version header reveals: {aspnet_version}',
                'recommendation': 'Remove X-AspNet-Version header'
            })
        
        # Check for X-AspNetMvc-Version disclosure
        if 'x-aspnetmvc-version' in headers:
            mvc_version = headers['x-aspnetmvc-version']
            vulnerabilities.append({
                'type': 'ASP.NET MVC Version Disclosure',
                'severity': 'Medium',
                'description': f'X-AspNetMvc-Version header reveals: {mvc_version}',
                'recommendation': 'Remove X-AspNetMvc-Version header'
            })
        
        # Check for PHP version disclosure
        if 'x-php-version' in headers:
            php_version = headers['x-php-version']
            vulnerabilities.append({
                'type': 'PHP Version Disclosure',
                'severity': 'Medium',
                'description': f'X-PHP-Version header reveals: {php_version}',
                'recommendation': 'Remove X-PHP-Version header'
            })
        
        # Check for debug information
        if 'x-debug' in headers:
            vulnerabilities.append({
                'type': 'Debug Information Disclosure',
                'severity': 'High',
                'description': 'X-Debug header present - debug mode may be enabled',
                'recommendation': 'Disable debug mode in production'
            })
        
        # Check for refresh header (potential redirect issue)
        if 'refresh' in headers:
            refresh_value = headers['refresh']
            vulnerabilities.append({
                'type': 'Refresh Header Present',
                'severity': 'Low',
                'description': f'Refresh header found: {refresh_value}',
                'recommendation': 'Review refresh header usage - may indicate redirect issues'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _generate_header_recommendations(self, results: Dict):
        """Generate security recommendations based on header analysis"""
        recommendations = []
        
        # Count missing security headers
        security_headers = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'content-security-policy',
            'referrer-policy',
            'permissions-policy'
        ]
        
        missing_headers = [h for h in security_headers if h not in results['headers']]
        
        if len(missing_headers) > 3:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement comprehensive security headers',
                'details': f'Missing {len(missing_headers)} critical security headers'
            })
        
        # Check for HTTPS enforcement
        if results.get('status_code') == 200 and not results['headers'].get('strict-transport-security'):
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Enforce HTTPS with HSTS',
                'details': 'Add Strict-Transport-Security header to force HTTPS connections'
            })
        
        # Check for information disclosure
        info_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-php-version']
        disclosed_info = [h for h in info_headers if h in results['headers']]
        
        if disclosed_info:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Suppress technology information',
                'details': f'Remove or modify headers: {", ".join(disclosed_info)}'
            })
        
        results['recommendations'].extend(recommendations)
    
    def check_cookie_security(self, target_url: str) -> Dict:
        """Check cookie security attributes"""
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'cookies': [],
            'vulnerabilities': []
        }
        
        try:
            response = self._make_request(target_url)
            if response and 'set-cookie' in response.headers:
                cookies = response.headers.get_list('set-cookie')
                
                for cookie in cookies:
                    cookie_info = self._parse_cookie(cookie)
                    results['cookies'].append(cookie_info)
                    
                    # Check cookie security
                    if not cookie_info.get('secure'):
                        results['vulnerabilities'].append({
                            'type': 'Insecure Cookie',
                            'severity': 'Medium',
                            'description': f'Cookie {cookie_info["name"]} missing Secure flag',
                            'recommendation': 'Add Secure flag to cookies'
                        })
                    
                    if not cookie_info.get('httponly'):
                        results['vulnerabilities'].append({
                            'type': 'Cookie XSS Vulnerability',
                            'severity': 'Medium',
                            'description': f'Cookie {cookie_info["name"]} missing HttpOnly flag',
                            'recommendation': 'Add HttpOnly flag to prevent XSS access'
                        })
                    
                    if not cookie_info.get('samesite'):
                        results['vulnerabilities'].append({
                            'type': 'Cookie CSRF Vulnerability',
                            'severity': 'Medium',
                            'description': f'Cookie {cookie_info["name"]} missing SameSite attribute',
                            'recommendation': 'Add SameSite attribute to prevent CSRF attacks'
                        })
        
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _parse_cookie(self, cookie_string: str) -> Dict:
        """Parse cookie string into components"""
        cookie_info = {'name': '', 'value': '', 'secure': False, 'httponly': False, 'samesite': None}
        
        parts = cookie_string.split(';')
        if parts:
            name_value = parts[0].split('=', 1)
            if len(name_value) == 2:
                cookie_info['name'] = name_value[0].strip()
                cookie_info['value'] = name_value[1].strip()
        
        for part in parts[1:]:
            part = part.strip().lower()
            if part == 'secure':
                cookie_info['secure'] = True
            elif part == 'httponly':
                cookie_info['httponly'] = True
            elif part.startswith('samesite='):
                cookie_info['samesite'] = part.split('=', 1)[1]
        
        return cookie_info

