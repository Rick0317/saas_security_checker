"""
DNS and Host Resolution Security Checks
Comprehensive DNS analysis including subdomain enumeration and DNS security checks
"""

import logging
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import requests

class DNSChecker:
    """DNS security analysis and host resolution checks"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive DNS security checks"""
        self.logger.info(f"Starting DNS security checks for {target_domain}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_domain,
            'dns_records': {},
            'subdomains': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Basic DNS resolution
            results['dns_records'] = self._get_dns_records(target_domain)
            
            # Subdomain enumeration
            results['subdomains'] = self._enumerate_subdomains(target_domain)
            
            # DNS security checks
            self._check_dns_security(target_domain, results)
            
            # Reverse DNS lookup
            results['reverse_dns'] = self._reverse_dns_lookup(target_domain)
            
            # DNS over HTTPS (DoH) check
            results['doh_support'] = self._check_doh_support(target_domain)
            
            # Generate recommendations
            self._generate_dns_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during DNS checks: {str(e)}")
        
        return results
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Get various DNS records for the domain"""
        records = {}
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                records[record_type] = []
            except Exception as e:
                self.logger.warning(f"Error resolving {record_type} record for {domain}: {str(e)}")
                records[record_type] = []
        
        return records
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using various techniques"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'cdn', 'dev', 'test',
            'staging', 'stage', 'prod', 'production', 'secure', 'ssl', 'vpn', 'remote',
            'support', 'help', 'docs', 'documentation', 'status', 'monitor', 'stats',
            'analytics', 'metrics', 'logs', 'backup', 'backups', 'db', 'database',
            'mysql', 'postgres', 'redis', 'cache', 'memcache', 'elasticsearch',
            'kibana', 'grafana', 'jenkins', 'git', 'github', 'gitlab', 'jira',
            'confluence', 'wiki', 'forum', 'community', 'shop', 'store', 'ecommerce',
            'payment', 'payments', 'billing', 'invoice', 'accounting', 'hr', 'crm',
            'erp', 'sales', 'marketing', 'campaign', 'newsletter', 'email', 'imap',
            'pop', 'smtp', 'ldap', 'ad', 'active-directory', 'radius', 'auth',
            'authentication', 'login', 'signin', 'signup', 'register', 'profile',
            'user', 'users', 'account', 'accounts', 'dashboard', 'panel', 'control',
            'manage', 'management', 'admin', 'administrator', 'root', 'superuser'
        ]
        
        # Try common subdomains
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except socket.gaierror:
                pass
        
        # Try DNS resolution for additional subdomains
        additional_subdomains = [
            'm', 'mobile', 'wap', 'i', 'intranet', 'internal', 'private', 'local',
            'demo', 'sandbox', 'playground', 'lab', 'labs', 'research', 'rnd',
            'qa', 'quality', 'uat', 'preview', 'beta', 'alpha', 'gamma', 'delta',
            'release', 'releases', 'deploy', 'deployment', 'ci', 'cd', 'build',
            'builder', 'compile', 'compiler', 'pack', 'package', 'packages',
            'repo', 'repository', 'repositories', 'source', 'sources', 'src',
            'assets', 'static', 'media', 'images', 'img', 'pics', 'photos',
            'videos', 'files', 'download', 'downloads', 'upload', 'uploads'
        ]
        
        for subdomain in additional_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except socket.gaierror:
                pass
        
        return list(subdomains)
    
    def _check_dns_security(self, domain: str, results: Dict):
        """Check for DNS security issues"""
        vulnerabilities = []
        
        # Check for DNS zone transfer
        try:
            ns_records = results['dns_records'].get('NS', [])
            for ns in ns_records:
                try:
                    # Try zone transfer
                    answers = dns.resolver.resolve(domain, 'AXFR')
                    vulnerabilities.append({
                        'type': 'DNS Zone Transfer',
                        'severity': 'High',
                        'description': f'Zone transfer allowed from {ns}',
                        'recommendation': 'Disable zone transfers or restrict to authorized servers'
                    })
                except:
                    pass  # Zone transfer not allowed, which is good
        except Exception as e:
            self.logger.debug(f"Zone transfer check failed: {str(e)}")
        
        # Check for missing SPF record
        txt_records = results['dns_records'].get('TXT', [])
        has_spf = any('v=spf1' in record.lower() for record in txt_records)
        if not has_spf:
            vulnerabilities.append({
                'type': 'Missing SPF Record',
                'severity': 'Medium',
                'description': 'No SPF record found',
                'recommendation': 'Add SPF record to prevent email spoofing'
            })
        
        # Check for missing DMARC record
        has_dmarc = any('v=dmarc1' in record.lower() for record in txt_records)
        if not has_dmarc:
            vulnerabilities.append({
                'type': 'Missing DMARC Record',
                'severity': 'Medium',
                'description': 'No DMARC record found',
                'recommendation': 'Add DMARC record to prevent email spoofing'
            })
        
        # Check for missing DKIM record
        has_dkim = any('v=dkim1' in record.lower() for record in txt_records)
        if not has_dkim:
            vulnerabilities.append({
                'type': 'Missing DKIM Record',
                'severity': 'Low',
                'description': 'No DKIM record found',
                'recommendation': 'Consider adding DKIM record for email authentication'
            })
        
        # Check for DNS over HTTPS support
        if not results.get('doh_support', False):
            vulnerabilities.append({
                'type': 'No DNS over HTTPS',
                'severity': 'Low',
                'description': 'DNS over HTTPS not supported',
                'recommendation': 'Consider implementing DNS over HTTPS for privacy'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _reverse_dns_lookup(self, domain: str) -> Dict:
        """Perform reverse DNS lookup"""
        reverse_info = {}
        
        try:
            # Get A records
            a_records = self._get_dns_records(domain).get('A', [])
            for ip in a_records:
                try:
                    reverse_name = dns.reversename.from_address(ip)
                    reverse_answers = dns.resolver.resolve(reverse_name, 'PTR')
                    reverse_info[ip] = [str(answer) for answer in reverse_answers]
                except Exception as e:
                    reverse_info[ip] = []
                    self.logger.debug(f"Reverse DNS lookup failed for {ip}: {str(e)}")
        except Exception as e:
            self.logger.debug(f"Reverse DNS lookup failed: {str(e)}")
        
        return reverse_info
    
    def _check_doh_support(self, domain: str) -> bool:
        """Check if domain supports DNS over HTTPS"""
        doh_endpoints = [
            f"https://{domain}/dns-query",
            f"https://dns.{domain}/dns-query",
            f"https://{domain}/.well-known/dns-query"
        ]
        
        for endpoint in doh_endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
        
        return False
    
    def _generate_dns_recommendations(self, results: Dict):
        """Generate DNS security recommendations"""
        recommendations = []
        
        # Check for too many subdomains
        if len(results['subdomains']) > 50:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Review subdomain exposure',
                'details': f'Found {len(results["subdomains"])} subdomains. Consider if all are necessary.'
            })
        
        # Check for missing security records
        txt_records = results['dns_records'].get('TXT', [])
        has_spf = any('v=spf1' in record.lower() for record in txt_records)
        has_dmarc = any('v=dmarc1' in record.lower() for record in txt_records)
        
        if not has_spf:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement SPF record',
                'details': 'Add SPF record to prevent email spoofing attacks'
            })
        
        if not has_dmarc:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement DMARC record',
                'details': 'Add DMARC record to prevent email spoofing attacks'
            })
        
        # Check for DNS security extensions
        if not results.get('doh_support', False):
            recommendations.append({
                'priority': 'Low',
                'recommendation': 'Consider DNS over HTTPS',
                'details': 'Implement DNS over HTTPS for enhanced privacy'
            })
        
        results['recommendations'].extend(recommendations)
    
    def check_dns_amplification(self, domain: str) -> Dict:
        """Check for DNS amplification attack potential"""
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'amplification_factor': 0,
            'vulnerable_records': []
        }
        
        try:
            # Check for large TXT records
            txt_records = self._get_dns_records(domain).get('TXT', [])
            for record in txt_records:
                if len(record) > 100:  # Large TXT record
                    results['vulnerable_records'].append({
                        'type': 'TXT',
                        'size': len(record),
                        'content': record[:100] + '...' if len(record) > 100 else record
                    })
            
            # Calculate amplification factor
            if results['vulnerable_records']:
                total_size = sum(record['size'] for record in results['vulnerable_records'])
                results['amplification_factor'] = total_size / 64  # Assuming 64-byte query
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
