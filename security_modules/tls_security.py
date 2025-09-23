"""
TLS/SSL Security Analysis Module
Comprehensive TLS certificate and configuration security checks
"""

import logging
import socket
import ssl
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class TLSSecurityChecker:
    """TLS/SSL security analysis and certificate validation"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive TLS security analysis"""
        self.logger.info(f"Starting TLS security analysis for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'certificate': {},
            'tls_config': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Parse URL to get hostname and port
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname or target_domain
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if port == 443 or parsed_url.scheme == 'https':
                # Get certificate information
                results['certificate'] = self._get_certificate_info(hostname, port)
                
                # Analyze TLS configuration
                results['tls_config'] = self._analyze_tls_config(hostname, port)
                
                # Check for TLS vulnerabilities
                self._check_tls_vulnerabilities(results)
                
                # Generate recommendations
                self._generate_tls_recommendations(results)
            else:
                results['status'] = 'skipped'
                results['reason'] = 'Target does not use HTTPS'
                
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during TLS analysis: {str(e)}")
        
        return results
    
    def _get_certificate_info(self, hostname: str, port: int) -> Dict:
        """Get SSL certificate information"""
        cert_info = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Extract certificate information
                    cert_info = {
                        'subject': self._get_cert_subject(cert),
                        'issuer': self._get_cert_issuer(cert),
                        'serial_number': str(cert.serial_number),
                        'version': cert.version.name,
                        'not_valid_before': cert.not_valid_before.isoformat(),
                        'not_valid_after': cert.not_valid_after.isoformat(),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key': self._get_public_key_info(cert),
                        'extensions': self._get_cert_extensions(cert),
                        'san_domains': self._get_san_domains(cert)
                    }
                    
                    # Check certificate validity
                    now = datetime.now()
                    if cert.not_valid_after < now:
                        cert_info['expired'] = True
                        cert_info['days_until_expiry'] = 0
                    else:
                        cert_info['expired'] = False
                        cert_info['days_until_expiry'] = (cert.not_valid_after - now).days
                    
                    if cert.not_valid_before > now:
                        cert_info['not_yet_valid'] = True
                    else:
                        cert_info['not_yet_valid'] = False
                    
        except Exception as e:
            cert_info['error'] = str(e)
            self.logger.error(f"Error getting certificate info: {str(e)}")
        
        return cert_info
    
    def _get_cert_subject(self, cert: x509.Certificate) -> Dict:
        """Extract subject information from certificate"""
        subject = {}
        for attribute in cert.subject:
            subject[attribute.oid._name] = attribute.value
        return subject
    
    def _get_cert_issuer(self, cert: x509.Certificate) -> Dict:
        """Extract issuer information from certificate"""
        issuer = {}
        for attribute in cert.issuer:
            issuer[attribute.oid._name] = attribute.value
        return issuer
    
    def _get_public_key_info(self, cert: x509.Certificate) -> Dict:
        """Extract public key information"""
        public_key = cert.public_key()
        key_info = {
            'type': type(public_key).__name__,
            'key_size': public_key.key_size if hasattr(public_key, 'key_size') else None
        }
        return key_info
    
    def _get_cert_extensions(self, cert: x509.Certificate) -> Dict:
        """Extract certificate extensions"""
        extensions = {}
        for ext in cert.extensions:
            extensions[ext.oid._name] = str(ext.value)
        return extensions
    
    def _get_san_domains(self, cert: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Name domains"""
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_domains.append(name.value)
        except x509.ExtensionNotFound:
            pass
        return san_domains
    
    def _analyze_tls_config(self, hostname: str, port: int) -> Dict:
        """Analyze TLS configuration and supported protocols/ciphers"""
        tls_config = {
            'supported_protocols': [],
            'supported_ciphers': [],
            'preferred_cipher': None,
            'tls_version': None
        }
        
        try:
            # Test different TLS versions
            tls_versions = [
                ('TLSv1.3', ssl.PROTOCOL_TLS),
                ('TLSv1.2', ssl.PROTOCOL_TLS),
                ('TLSv1.1', ssl.PROTOCOL_TLS),
                ('TLSv1.0', ssl.PROTOCOL_TLS),
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('SSLv2', ssl.PROTOCOL_SSLv23)
            ]
            
            for version_name, protocol in tls_versions:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            tls_config['supported_protocols'].append(version_name)
                            tls_config['tls_version'] = ssock.version()
                            tls_config['preferred_cipher'] = ssock.cipher()
                            break
                except:
                    continue
            
            # Get supported ciphers (simplified check)
            try:
                context = ssl.create_default_context()
                tls_config['supported_ciphers'] = context.get_ciphers()
            except:
                pass
                
        except Exception as e:
            tls_config['error'] = str(e)
            self.logger.error(f"Error analyzing TLS config: {str(e)}")
        
        return tls_config
    
    def _check_tls_vulnerabilities(self, results: Dict):
        """Check for TLS/SSL vulnerabilities"""
        vulnerabilities = []
        cert_info = results['certificate']
        tls_config = results['tls_config']
        
        # Check certificate expiration
        if cert_info.get('expired'):
            vulnerabilities.append({
                'type': 'Expired Certificate',
                'severity': 'High',
                'description': 'SSL certificate has expired',
                'recommendation': 'Renew SSL certificate immediately'
            })
        elif cert_info.get('days_until_expiry', 0) < 30:
            vulnerabilities.append({
                'type': 'Certificate Expiring Soon',
                'severity': 'Medium',
                'description': f'Certificate expires in {cert_info["days_until_expiry"]} days',
                'recommendation': 'Renew SSL certificate before expiration'
            })
        
        # Check certificate validity period
        if cert_info.get('not_yet_valid'):
            vulnerabilities.append({
                'type': 'Certificate Not Yet Valid',
                'severity': 'High',
                'description': 'SSL certificate is not yet valid',
                'recommendation': 'Check system time or certificate validity period'
            })
        
        # Check for weak key algorithms
        public_key = cert_info.get('public_key', {})
        if public_key.get('key_size') and public_key['key_size'] < 2048:
            vulnerabilities.append({
                'type': 'Weak Public Key',
                'severity': 'High',
                'description': f'Public key size is {public_key["key_size"]} bits (too small)',
                'recommendation': 'Use RSA keys with at least 2048 bits or ECDSA keys'
            })
        
        # Check signature algorithm
        sig_algorithm = cert_info.get('signature_algorithm', '')
        if 'sha1' in sig_algorithm.lower():
            vulnerabilities.append({
                'type': 'Weak Signature Algorithm',
                'severity': 'High',
                'description': 'Certificate uses SHA-1 signature algorithm',
                'recommendation': 'Use SHA-256 or stronger signature algorithm'
            })
        
        # Check supported TLS versions
        supported_protocols = tls_config.get('supported_protocols', [])
        if 'SSLv2' in supported_protocols or 'SSLv3' in supported_protocols:
            vulnerabilities.append({
                'type': 'Weak SSL Protocol',
                'severity': 'High',
                'description': 'Server supports weak SSL protocols (SSLv2/SSLv3)',
                'recommendation': 'Disable SSLv2 and SSLv3 support'
            })
        
        if 'TLSv1.0' in supported_protocols:
            vulnerabilities.append({
                'type': 'Deprecated TLS Protocol',
                'severity': 'Medium',
                'description': 'Server supports deprecated TLSv1.0',
                'recommendation': 'Disable TLSv1.0 support'
            })
        
        if 'TLSv1.1' in supported_protocols:
            vulnerabilities.append({
                'type': 'Deprecated TLS Protocol',
                'severity': 'Low',
                'description': 'Server supports deprecated TLSv1.1',
                'recommendation': 'Consider disabling TLSv1.1 support'
            })
        
        # Check for TLSv1.3 support
        if 'TLSv1.3' not in supported_protocols:
            vulnerabilities.append({
                'type': 'Missing TLSv1.3',
                'severity': 'Low',
                'description': 'Server does not support TLSv1.3',
                'recommendation': 'Enable TLSv1.3 support for better security'
            })
        
        # Check cipher strength
        preferred_cipher = tls_config.get('preferred_cipher')
        if preferred_cipher:
            cipher_name = preferred_cipher[0]
            if 'RC4' in cipher_name or 'DES' in cipher_name or 'MD5' in cipher_name:
                vulnerabilities.append({
                    'type': 'Weak Cipher Suite',
                    'severity': 'High',
                    'description': f'Server uses weak cipher: {cipher_name}',
                    'recommendation': 'Disable weak cipher suites'
                })
        
        # Check for certificate transparency
        extensions = cert_info.get('extensions', {})
        if 'signed_certificate_timestamp_list' not in extensions:
            vulnerabilities.append({
                'type': 'Missing Certificate Transparency',
                'severity': 'Low',
                'description': 'Certificate does not include SCT (Certificate Transparency)',
                'recommendation': 'Enable Certificate Transparency logging'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _generate_tls_recommendations(self, results: Dict):
        """Generate TLS security recommendations"""
        recommendations = []
        
        # Certificate recommendations
        cert_info = results['certificate']
        if cert_info.get('days_until_expiry', 0) < 90:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement certificate monitoring',
                'details': 'Set up automated monitoring for certificate expiration'
            })
        
        # Protocol recommendations
        tls_config = results['tls_config']
        supported_protocols = tls_config.get('supported_protocols', [])
        
        if 'TLSv1.3' not in supported_protocols:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Enable TLSv1.3',
                'details': 'TLSv1.3 provides better security and performance'
            })
        
        # Cipher recommendations
        if tls_config.get('preferred_cipher'):
            cipher_name = tls_config['preferred_cipher'][0]
            if 'AES' not in cipher_name and 'ChaCha20' not in cipher_name:
                recommendations.append({
                    'priority': 'High',
                    'recommendation': 'Use strong cipher suites',
                    'details': 'Configure server to use AES or ChaCha20 cipher suites'
                })
        
        # General recommendations
        recommendations.append({
            'priority': 'Medium',
            'recommendation': 'Regular security assessments',
            'details': 'Perform regular TLS configuration security assessments'
        })
        
        results['recommendations'].extend(recommendations)
    
    def check_ssl_labs_rating(self, hostname: str) -> Dict:
        """Check SSL Labs rating (requires external API)"""
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'ssl_labs_rating': None
        }
        
        try:
            # Note: This would require SSL Labs API integration
            # For now, we'll provide a placeholder
            results['ssl_labs_rating'] = 'Not implemented - requires SSL Labs API'
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results

