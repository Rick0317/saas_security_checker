"""
Packet Sniffing Prevention and Network Security Module
Detects and provides recommendations for preventing packet sniffing attacks
"""

import logging
import socket
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

class PacketSniffingPrevention:
    """Packet sniffing prevention and network security analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive packet sniffing prevention analysis"""
        self.logger.info(f"Starting packet sniffing prevention analysis for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'network_analysis': {},
            'encryption_analysis': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Analyze network security
            results['network_analysis'] = self._analyze_network_security(target_url, target_domain)
            
            # Check encryption implementation
            results['encryption_analysis'] = self._analyze_encryption_implementation(target_url)
            
            # Test for packet sniffing vulnerabilities
            self._check_packet_sniffing_vulnerabilities(target_url, results)
            
            # Analyze network protocols
            results['protocol_analysis'] = self._analyze_network_protocols(target_url, target_domain)
            
            # Check for network segmentation issues
            results['segmentation_analysis'] = self._analyze_network_segmentation(target_domain)
            
            # Generate prevention recommendations
            self._generate_prevention_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during packet sniffing prevention analysis: {str(e)}")
        
        return results
    
    def _analyze_network_security(self, target_url: str, target_domain: str) -> Dict:
        """Analyze network security configuration"""
        network_analysis = {
            'dns_over_https': False,
            'dns_over_tls': False,
            'ipv6_support': False,
            'cdn_usage': False,
            'network_path': [],
            'vulnerabilities': []
        }
        
        try:
            # Check DNS over HTTPS support
            network_analysis['dns_over_https'] = self._check_dns_over_https(target_domain)
            
            # Check DNS over TLS support
            network_analysis['dns_over_tls'] = self._check_dns_over_tls(target_domain)
            
            # Check IPv6 support
            network_analysis['ipv6_support'] = self._check_ipv6_support(target_domain)
            
            # Check CDN usage
            network_analysis['cdn_usage'] = self._check_cdn_usage(target_url)
            
            # Analyze network path
            network_analysis['network_path'] = self._analyze_network_path(target_domain)
            
        except Exception as e:
            network_analysis['error'] = str(e)
            self.logger.error(f"Error analyzing network security: {str(e)}")
        
        return network_analysis
    
    def _check_dns_over_https(self, domain: str) -> bool:
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
                continue
        
        return False
    
    def _check_dns_over_tls(self, domain: str) -> bool:
        """Check if domain supports DNS over TLS"""
        try:
            # Try to connect to DNS over TLS port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((domain, 853))  # DNS over TLS port
            sock.close()
            return result == 0
        except:
            return False
    
    def _check_ipv6_support(self, domain: str) -> bool:
        """Check if domain supports IPv6"""
        try:
            import socket
            # Try to resolve IPv6 address
            socket.getaddrinfo(domain, None, socket.AF_INET6)
            return True
        except:
            return False
    
    def _check_cdn_usage(self, target_url: str) -> bool:
        """Check if target uses CDN"""
        try:
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            # Check for CDN indicators
            cdn_indicators = [
                'cloudflare', 'cloudfront', 'fastly', 'maxcdn', 'keycdn',
                'cdn-cache', 'x-cache', 'x-served-by', 'x-cache-hits'
            ]
            
            for header_name, header_value in headers.items():
                for indicator in cdn_indicators:
                    if indicator in header_name.lower() or indicator in header_value.lower():
                        return True
            
            return False
        except:
            return False
    
    def _analyze_network_path(self, domain: str) -> List[Dict]:
        """Analyze network path using traceroute"""
        path_info = []
        
        try:
            # Use traceroute to analyze network path
            if self._is_command_available('traceroute'):
                result = subprocess.run(
                    ['traceroute', '-n', domain],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines[1:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                hop_info = {
                                    'hop': parts[0],
                                    'ip': parts[1],
                                    'latency': parts[2] if len(parts) > 2 else 'N/A'
                                }
                                path_info.append(hop_info)
            
            elif self._is_command_available('tracert'):
                # Windows tracert
                result = subprocess.run(
                    ['tracert', '-d', domain],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines[1:]:  # Skip header
                        if line.strip() and 'ms' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                hop_info = {
                                    'hop': parts[0],
                                    'ip': parts[1],
                                    'latency': 'N/A'
                                }
                                path_info.append(hop_info)
        
        except Exception as e:
            self.logger.debug(f"Error analyzing network path: {str(e)}")
        
        return path_info
    
    def _analyze_encryption_implementation(self, target_url: str) -> Dict:
        """Analyze encryption implementation"""
        encryption_analysis = {
            'https_enforcement': False,
            'hsts_enabled': False,
            'certificate_valid': False,
            'tls_version': None,
            'cipher_suite': None,
            'perfect_forward_secrecy': False,
            'vulnerabilities': []
        }
        
        try:
            parsed_url = urlparse(target_url)
            
            if parsed_url.scheme == 'https':
                encryption_analysis['https_enforcement'] = True
                
                # Make HTTPS request to analyze encryption
                response = requests.get(target_url, timeout=10, verify=True)
                
                # Check HSTS
                if 'strict-transport-security' in response.headers:
                    encryption_analysis['hsts_enabled'] = True
                
                # Check certificate validity
                try:
                    import ssl
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed_url.hostname, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                            encryption_analysis['certificate_valid'] = True
                            encryption_analysis['tls_version'] = ssock.version()
                            encryption_analysis['cipher_suite'] = ssock.cipher()
                            
                            # Check for Perfect Forward Secrecy
                            cipher_name = ssock.cipher()[0] if ssock.cipher() else ''
                            if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                                encryption_analysis['perfect_forward_secrecy'] = True
                except:
                    encryption_analysis['certificate_valid'] = False
            
        except Exception as e:
            encryption_analysis['error'] = str(e)
            self.logger.error(f"Error analyzing encryption: {str(e)}")
        
        return encryption_analysis
    
    def _check_packet_sniffing_vulnerabilities(self, target_url: str, results: Dict):
        """Check for packet sniffing vulnerabilities"""
        vulnerabilities = []
        
        # Check for HTTP traffic (unencrypted)
        if target_url.startswith('http://'):
            vulnerabilities.append({
                'type': 'Unencrypted HTTP Traffic',
                'severity': 'Critical',
                'description': 'HTTP traffic is unencrypted and vulnerable to packet sniffing',
                'recommendation': 'Force HTTPS and implement HSTS'
            })
        
        # Check for mixed content
        try:
            response = requests.get(target_url, timeout=10)
            content = response.text.lower()
            
            if 'http://' in content and target_url.startswith('https://'):
                vulnerabilities.append({
                    'type': 'Mixed Content',
                    'severity': 'High',
                    'description': 'HTTPS page loads HTTP resources, vulnerable to downgrade attacks',
                    'recommendation': 'Use HTTPS for all resources or implement Content Security Policy'
                })
        except:
            pass
        
        # Check for DNS over plain text
        network_analysis = results.get('network_analysis', {})
        if not network_analysis.get('dns_over_https', False) and not network_analysis.get('dns_over_tls', False):
            vulnerabilities.append({
                'type': 'Unencrypted DNS Queries',
                'severity': 'Medium',
                'description': 'DNS queries are sent in plain text, vulnerable to DNS hijacking',
                'recommendation': 'Implement DNS over HTTPS or DNS over TLS'
            })
        
        # Check for weak encryption
        encryption_analysis = results.get('encryption_analysis', {})
        if encryption_analysis.get('tls_version'):
            tls_version = encryption_analysis['tls_version']
            if tls_version in ['TLSv1', 'TLSv1.1']:
                vulnerabilities.append({
                    'type': 'Weak TLS Version',
                    'severity': 'High',
                    'description': f'Using deprecated TLS version: {tls_version}',
                    'recommendation': 'Upgrade to TLS 1.2 or higher'
                })
        
        if not encryption_analysis.get('perfect_forward_secrecy', False):
            vulnerabilities.append({
                'type': 'No Perfect Forward Secrecy',
                'severity': 'Medium',
                'description': 'TLS configuration does not support Perfect Forward Secrecy',
                'recommendation': 'Configure ECDHE or DHE cipher suites'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _analyze_network_protocols(self, target_url: str, target_domain: str) -> Dict:
        """Analyze network protocols for security"""
        protocol_analysis = {
            'supported_protocols': [],
            'insecure_protocols': [],
            'recommendations': []
        }
        
        try:
            # Test common ports and protocols
            common_ports = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3389: 'RDP'
            }
            
            for port, protocol in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target_domain, port))
                    sock.close()
                    
                    if result == 0:
                        protocol_analysis['supported_protocols'].append({
                            'port': port,
                            'protocol': protocol,
                            'secure': protocol.endswith('S') or protocol in ['SSH', 'HTTPS']
                        })
                        
                        # Check for insecure protocols
                        if protocol in ['FTP', 'Telnet', 'HTTP', 'SMTP', 'POP3', 'IMAP']:
                            protocol_analysis['insecure_protocols'].append({
                                'port': port,
                                'protocol': protocol,
                                'risk': 'High' if protocol in ['FTP', 'Telnet'] else 'Medium'
                            })
                
                except:
                    continue
        
        except Exception as e:
            protocol_analysis['error'] = str(e)
            self.logger.error(f"Error analyzing protocols: {str(e)}")
        
        return protocol_analysis
    
    def _analyze_network_segmentation(self, target_domain: str) -> Dict:
        """Analyze network segmentation and isolation"""
        segmentation_analysis = {
            'subnet_analysis': [],
            'routing_analysis': [],
            'isolation_issues': [],
            'recommendations': []
        }
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(target_domain)
            
            # Analyze subnet
            import ipaddress
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                segmentation_analysis['subnet_analysis'].append({
                    'ip': ip_address,
                    'version': 'IPv4' if ip_obj.version == 4 else 'IPv6',
                    'is_private': ip_obj.is_private,
                    'is_loopback': ip_obj.is_loopback,
                    'is_multicast': ip_obj.is_multicast
                })
                
                # Check for private IP exposure
                if ip_obj.is_private:
                    segmentation_analysis['isolation_issues'].append({
                        'type': 'Private IP Exposure',
                        'severity': 'High',
                        'description': f'Private IP address {ip_address} is publicly accessible',
                        'recommendation': 'Implement proper network segmentation and NAT'
                    })
                
            except:
                pass
            
            # Check for common network misconfigurations
            if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
                segmentation_analysis['isolation_issues'].append({
                    'type': 'Internal Network Exposure',
                    'severity': 'Critical',
                    'description': 'Internal network address is publicly accessible',
                    'recommendation': 'Implement proper firewall rules and network segmentation'
                })
        
        except Exception as e:
            segmentation_analysis['error'] = str(e)
            self.logger.error(f"Error analyzing network segmentation: {str(e)}")
        
        return segmentation_analysis
    
    def _generate_prevention_recommendations(self, results: Dict):
        """Generate packet sniffing prevention recommendations"""
        recommendations = []
        
        # Encryption recommendations
        encryption_analysis = results.get('encryption_analysis', {})
        if not encryption_analysis.get('https_enforcement', False):
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Implement HTTPS enforcement',
                'details': 'Force all traffic to use HTTPS to prevent packet sniffing'
            })
        
        if not encryption_analysis.get('hsts_enabled', False):
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement HSTS',
                'details': 'Add Strict-Transport-Security header to prevent downgrade attacks'
            })
        
        if not encryption_analysis.get('perfect_forward_secrecy', False):
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Enable Perfect Forward Secrecy',
                'details': 'Configure ECDHE or DHE cipher suites for forward secrecy'
            })
        
        # Network security recommendations
        network_analysis = results.get('network_analysis', {})
        if not network_analysis.get('dns_over_https', False) and not network_analysis.get('dns_over_tls', False):
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Implement encrypted DNS',
                'details': 'Use DNS over HTTPS or DNS over TLS to prevent DNS hijacking'
            })
        
        # Protocol security recommendations
        protocol_analysis = results.get('protocol_analysis', {})
        insecure_protocols = protocol_analysis.get('insecure_protocols', [])
        if insecure_protocols:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Disable insecure protocols',
                'details': f'Disable or secure {len(insecure_protocols)} insecure protocols'
            })
        
        # Network segmentation recommendations
        segmentation_analysis = results.get('segmentation_analysis', {})
        isolation_issues = segmentation_analysis.get('isolation_issues', [])
        if isolation_issues:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Implement network segmentation',
                'details': f'Address {len(isolation_issues)} network isolation issues'
            })
        
        # General prevention recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement network monitoring',
                'details': 'Deploy network monitoring tools to detect packet sniffing attempts'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Use VPN for sensitive communications',
                'details': 'Implement VPN for additional encryption layer'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement certificate pinning',
                'details': 'Pin SSL certificates to prevent man-in-the-middle attacks'
            },
            {
                'priority': 'Low',
                'recommendation': 'Regular security assessments',
                'details': 'Perform regular network security assessments'
            }
        ])
        
        results['recommendations'].extend(recommendations)
    
    def _is_command_available(self, command: str) -> bool:
        """Check if a command is available in the system"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except:
            return False
    
    def test_network_isolation(self, target_domain: str) -> Dict:
        """Test network isolation and segmentation"""
        isolation_test = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_domain,
            'isolation_issues': [],
            'recommendations': []
        }
        
        try:
            # Test for common network isolation issues
            ip_address = socket.gethostbyname(target_domain)
            
            # Check if it's a private IP
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ip_obj.is_private:
                isolation_test['isolation_issues'].append({
                    'type': 'Private IP Exposure',
                    'severity': 'Critical',
                    'description': f'Private IP {ip_address} is publicly accessible',
                    'recommendation': 'Implement proper network segmentation'
                })
            
            # Test for common vulnerable ports
            vulnerable_ports = [21, 23, 135, 139, 445, 3389]
            for port in vulnerable_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target_domain, port))
                    sock.close()
                    
                    if result == 0:
                        isolation_test['isolation_issues'].append({
                            'type': 'Vulnerable Port Open',
                            'severity': 'High',
                            'description': f'Port {port} is open and accessible',
                            'recommendation': f'Close or secure port {port}'
                        })
                except:
                    continue
        
        except Exception as e:
            isolation_test['status'] = 'error'
            isolation_test['error'] = str(e)
        
        return isolation_test
