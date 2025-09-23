"""
Web Server and Application Security Scanner
Comprehensive web application security scanning using multiple techniques
"""

import logging
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

class WebScanner:
    """Web application security scanner"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive web application security scan"""
        self.logger.info(f"Starting web application security scan for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'crawl_results': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Basic web application analysis
            results['crawl_results'] = self._crawl_application(target_url)
            
            # Check for common vulnerabilities
            self._check_common_vulnerabilities(target_url, results)
            
            # Directory and file discovery
            results['directory_discovery'] = self._directory_discovery(target_url)
            
            # Check for sensitive files
            results['sensitive_files'] = self._check_sensitive_files(target_url)
            
            # Generate recommendations
            self._generate_web_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during web scanning: {str(e)}")
        
        return results
    
    def _crawl_application(self, target_url: str) -> Dict:
        """Crawl web application to discover pages and functionality"""
        crawl_results = {
            'pages': [],
            'forms': [],
            'links': [],
            'technologies': []
        }
        
        try:
            response = self.session.get(target_url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract page information
                crawl_results['pages'].append({
                    'url': target_url,
                    'title': soup.title.string if soup.title else 'No title',
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                })
                
                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        form_info['inputs'].append({
                            'name': input_elem.get('name', ''),
                            'type': input_elem.get('type', 'text'),
                            'required': input_elem.has_attr('required')
                        })
                    
                    crawl_results['forms'].append(form_info)
                
                # Extract links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href.startswith('/') or href.startswith('http'):
                        full_url = urljoin(target_url, href)
                        crawl_results['links'].append({
                            'url': full_url,
                            'text': link.get_text().strip()
                        })
                
                # Detect technologies
                crawl_results['technologies'] = self._detect_technologies(response)
                
        except Exception as e:
            self.logger.error(f"Error crawling application: {str(e)}")
        
        return crawl_results
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect web technologies from response"""
        technologies = []
        
        # Check headers for technology indicators
        headers = response.headers
        if 'server' in headers:
            server = headers['server'].lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
        
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'express' in powered_by:
                technologies.append('Express.js')
        
        # Check content for technology indicators
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        elif 'joomla' in content:
            technologies.append('Joomla')
        
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        
        return technologies
    
    def _check_common_vulnerabilities(self, target_url: str, results: Dict):
        """Check for common web application vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for directory traversal
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd'
            ]
            
            for payload in traversal_payloads:
                test_url = f"{target_url.rstrip('/')}/{payload}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200 and ('root:' in response.text or 'localhost' in response.text):
                        vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'description': f'Directory traversal vulnerability detected with payload: {payload}',
                            'recommendation': 'Implement proper input validation and path sanitization'
                        })
                        break
                except:
                    continue
            
            # Check for SQL injection in forms
            crawl_results = results.get('crawl_results', {})
            forms = crawl_results.get('forms', [])
            
            for form in forms:
                if form['method'] == 'POST':
                    sql_payloads = ["' OR '1'='1", "' UNION SELECT 1--", "'; DROP TABLE users--"]
                    
                    for payload in sql_payloads:
                        try:
                            form_data = {}
                            for input_elem in form['inputs']:
                                if input_elem['type'] in ['text', 'email', 'password']:
                                    form_data[input_elem['name']] = payload
                            
                            action_url = urljoin(target_url, form['action'])
                            response = self.session.post(action_url, data=form_data, timeout=10)
                            
                            if any(error in response.text.lower() for error in ['mysql', 'sqlite', 'postgresql', 'oracle', 'microsoft']):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'description': f'Potential SQL injection in form at {action_url}',
                                    'recommendation': 'Use parameterized queries and input validation'
                                })
                                break
                        except:
                            continue
            
            # Check for XSS vulnerabilities
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")'
            ]
            
            for payload in xss_payloads:
                try:
                    test_url = f"{target_url}?test={payload}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'description': f'XSS vulnerability detected with payload: {payload}',
                            'recommendation': 'Implement proper output encoding and Content Security Policy'
                        })
                        break
                except:
                    continue
            
            # Check for information disclosure
            info_urls = [
                '/.git/',
                '/.svn/',
                '/.env',
                '/config.php',
                '/wp-config.php',
                '/phpinfo.php',
                '/test.php',
                '/info.php'
            ]
            
            for info_url in info_urls:
                try:
                    test_url = urljoin(target_url, info_url)
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'severity': 'Medium',
                            'description': f'Sensitive file accessible: {info_url}',
                            'recommendation': 'Remove or secure sensitive files'
                        })
                except:
                    continue
            
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {str(e)}")
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _directory_discovery(self, target_url: str) -> Dict:
        """Perform directory and file discovery"""
        discovery_results = {
            'directories': [],
            'files': [],
            'status_codes': {}
        }
        
        # Common directories and files to check
        common_paths = [
            '/admin/', '/administrator/', '/login/', '/wp-admin/', '/phpmyadmin/',
            '/backup/', '/backups/', '/old/', '/temp/', '/tmp/', '/test/',
            '/api/', '/v1/', '/v2/', '/docs/', '/documentation/',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/.htaccess', '/web.config', '/.env', '/config.php'
        ]
        
        for path in common_paths:
            try:
                test_url = urljoin(target_url, path)
                response = self.session.get(test_url, timeout=10)
                
                status_code = response.status_code
                if status_code not in discovery_results['status_codes']:
                    discovery_results['status_codes'][status_code] = 0
                discovery_results['status_codes'][status_code] += 1
                
                if status_code == 200:
                    if path.endswith('/'):
                        discovery_results['directories'].append({
                            'path': path,
                            'url': test_url,
                            'content_length': len(response.content)
                        })
                    else:
                        discovery_results['files'].append({
                            'path': path,
                            'url': test_url,
                            'content_length': len(response.content)
                        })
                
            except Exception as e:
                self.logger.debug(f"Error checking path {path}: {str(e)}")
        
        return discovery_results
    
    def _check_sensitive_files(self, target_url: str) -> List[Dict]:
        """Check for sensitive files and configurations"""
        sensitive_files = []
        
        sensitive_paths = [
            '/.git/config',
            '/.svn/entries',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/database.yml',
            '/.htpasswd',
            '/.htaccess',
            '/web.config',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/debug.php',
            '/error_log',
            '/access_log'
        ]
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(target_url, path)
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    sensitive_files.append({
                        'path': path,
                        'url': test_url,
                        'severity': 'High' if any(x in path for x in ['.git', '.env', 'config', 'htpasswd']) else 'Medium',
                        'description': f'Sensitive file accessible: {path}'
                    })
                
            except Exception as e:
                self.logger.debug(f"Error checking sensitive file {path}: {str(e)}")
        
        return sensitive_files
    
    def _generate_web_recommendations(self, results: Dict):
        """Generate web security recommendations"""
        recommendations = []
        
        # Check for forms without CSRF protection
        forms = results.get('crawl_results', {}).get('forms', [])
        forms_without_csrf = [f for f in forms if not any('csrf' in inp['name'].lower() for inp in f['inputs'])]
        
        if forms_without_csrf:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement CSRF protection',
                'details': f'{len(forms_without_csrf)} forms lack CSRF protection'
            })
        
        # Check for sensitive files
        sensitive_files = results.get('sensitive_files', [])
        if sensitive_files:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Secure sensitive files',
                'details': f'{len(sensitive_files)} sensitive files are accessible'
            })
        
        # Check for directory listing
        directories = results.get('directory_discovery', {}).get('directories', [])
        if len(directories) > 5:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Review directory exposure',
                'details': f'{len(directories)} directories are accessible'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement Web Application Firewall (WAF)',
                'details': 'Deploy WAF to protect against common attacks'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Regular security testing',
                'details': 'Perform regular penetration testing and vulnerability assessments'
            }
        ])
        
        results['recommendations'].extend(recommendations)
    
    def run_nikto_scan(self, target_url: str) -> Dict:
        """Run Nikto web vulnerability scanner"""
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'nikto_output': '',
            'vulnerabilities': []
        }
        
        try:
            # Check if Nikto is available
            nikto_path = self._find_nikto()
            if not nikto_path:
                results['status'] = 'skipped'
                results['reason'] = 'Nikto not found. Please install Nikto.'
                return results
            
            # Run Nikto scan
            cmd = [nikto_path, '-h', target_url, '-Format', 'txt']
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            results['nikto_output'] = process.stdout
            
            # Parse Nikto output for vulnerabilities
            if process.returncode == 0:
                vulnerabilities = self._parse_nikto_output(process.stdout)
                results['vulnerabilities'] = vulnerabilities
            
        except subprocess.TimeoutExpired:
            results['status'] = 'timeout'
            results['error'] = 'Nikto scan timed out'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _find_nikto(self) -> Optional[str]:
        """Find Nikto installation"""
        possible_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            './nikto/nikto.pl'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run(['which', 'nikto'], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip()
            except:
                pass
        
        for path in possible_paths:
            try:
                result = subprocess.run(['perl', path, '-Version'], capture_output=True, text=True)
                if result.returncode == 0:
                    return path
            except:
                pass
        
        return None
    
    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse Nikto output for vulnerabilities"""
        vulnerabilities = []
        
        lines = output.split('\n')
        for line in lines:
            if '+ OSVDB-' in line or '+ CVE-' in line:
                # Extract vulnerability information
                vuln_info = {
                    'type': 'Web Vulnerability',
                    'severity': 'Medium',
                    'description': line.strip(),
                    'source': 'Nikto'
                }
                
                # Determine severity based on keywords
                if any(keyword in line.lower() for keyword in ['critical', 'high', 'dangerous']):
                    vuln_info['severity'] = 'High'
                elif any(keyword in line.lower() for keyword in ['low', 'info', 'informational']):
                    vuln_info['severity'] = 'Low'
                
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities

