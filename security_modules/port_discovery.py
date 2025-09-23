"""
Port Discovery and Service Detection Module
Uses nmap for comprehensive port scanning and service detection
"""

import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

import nmap

class PortDiscoveryTester:
    """Port discovery and service detection using nmap"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run port discovery and service detection"""
        self.logger.info(f"Starting port discovery for {target_domain}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_domain,
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Get port range from config
            port_range = self.config['tests']['port_discovery'].get('ports', '1-1000')
            
            # Run nmap scan
            self.logger.info(f"Scanning ports {port_range} on {target_domain}")
            scan_result = self.nm.scan(
                target_domain,
                port_range,
                arguments='-sV -sC -O --script vuln'  # Service version, default scripts, OS detection, vulnerability scripts
            )
            
            if target_domain in self.nm.all_hosts():
                host_info = self.nm[target_domain]
                
                # Extract port information
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    for port in ports:
                        port_info = host_info[protocol][port]
                        
                        port_data = {
                            'port': port,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        results['ports'].append(port_data)
                        
                        # Check for common vulnerabilities
                        self._check_port_vulnerabilities(port_data, results)
                
                # Extract OS information
                if 'osmatch' in host_info:
                    results['os_info'] = []
                    for os_match in host_info['osmatch']:
                        results['os_info'].append({
                            'name': os_match['name'],
                            'accuracy': os_match['accuracy']
                        })
                
                # Extract service information
                results['services'] = self._extract_service_info(results['ports'])
                
                # Generate recommendations
                self._generate_port_recommendations(results)
                
            else:
                results['status'] = 'error'
                results['error'] = 'Host not found or unreachable'
                
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during port scan: {str(e)}")
        
        return results
    
    def _check_port_vulnerabilities(self, port_data: Dict, results: Dict):
        """Check for common port vulnerabilities"""
        port = port_data['port']
        service = port_data['service'].lower()
        
        # Check for dangerous open ports
        dangerous_ports = {
            21: 'FTP - Consider disabling or securing',
            23: 'Telnet - Insecure protocol, disable',
            135: 'RPC - Windows vulnerability',
            139: 'NetBIOS - Windows vulnerability',
            445: 'SMB - Windows vulnerability',
            1433: 'SQL Server - Secure configuration required',
            3389: 'RDP - Secure configuration required',
            5432: 'PostgreSQL - Secure configuration required',
            3306: 'MySQL - Secure configuration required',
            6379: 'Redis - Secure configuration required',
            11211: 'Memcached - Secure configuration required'
        }
        
        if port in dangerous_ports and port_data['state'] == 'open':
            results['vulnerabilities'].append({
                'type': 'Dangerous Port Open',
                'severity': 'Medium',
                'port': port,
                'service': service,
                'description': dangerous_ports[port],
                'recommendation': f'Secure or disable port {port}'
            })
        
        # Check for version disclosure
        if port_data['version'] and port_data['state'] == 'open':
            results['vulnerabilities'].append({
                'type': 'Version Disclosure',
                'severity': 'Low',
                'port': port,
                'service': service,
                'description': f'Version information disclosed: {port_data["version"]}',
                'recommendation': 'Disable version disclosure in service configuration'
            })
    
    def _extract_service_info(self, ports: List[Dict]) -> List[Dict]:
        """Extract and categorize service information"""
        services = {}
        
        for port_data in ports:
            if port_data['state'] == 'open':
                service_name = port_data['service']
                if service_name not in services:
                    services[service_name] = {
                        'name': service_name,
                        'ports': [],
                        'versions': set(),
                        'products': set()
                    }
                
                services[service_name]['ports'].append(port_data['port'])
                if port_data['version']:
                    services[service_name]['versions'].add(port_data['version'])
                if port_data['product']:
                    services[service_name]['products'].add(port_data['product'])
        
        # Convert to list format
        service_list = []
        for service_name, service_info in services.items():
            service_list.append({
                'name': service_name,
                'ports': service_info['ports'],
                'versions': list(service_info['versions']),
                'products': list(service_info['products'])
            })
        
        return service_list
    
    def _generate_port_recommendations(self, results: Dict):
        """Generate security recommendations based on port scan results"""
        recommendations = []
        
        # Check for unnecessary open ports
        open_ports = [p for p in results['ports'] if p['state'] == 'open']
        if len(open_ports) > 10:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Reduce number of open ports',
                'details': f'Currently {len(open_ports)} ports are open. Consider closing unnecessary services.'
            })
        
        # Check for insecure protocols
        insecure_services = ['telnet', 'ftp', 'rlogin', 'rsh']
        for port_data in open_ports:
            if port_data['service'] in insecure_services:
                recommendations.append({
                    'priority': 'High',
                    'recommendation': f'Replace insecure {port_data["service"]} service',
                    'details': f'Port {port_data["port"]} runs {port_data["service"]} which is insecure'
                })
        
        # Check for database services
        db_services = ['mysql', 'postgresql', 'mongodb', 'redis', 'memcached']
        for port_data in open_ports:
            if port_data['service'] in db_services:
                recommendations.append({
                    'priority': 'High',
                    'recommendation': f'Secure {port_data["service"]} configuration',
                    'details': f'Database service on port {port_data["port"]} should be properly secured'
                })
        
        results['recommendations'].extend(recommendations)
    
    def run_ssl_scan(self, target_domain: str, port: int = 443) -> Dict:
        """Run SSL/TLS specific scan on HTTPS port"""
        self.logger.info(f"Running SSL scan on {target_domain}:{port}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': f"{target_domain}:{port}",
            'ssl_info': {},
            'vulnerabilities': []
        }
        
        try:
            # Scan SSL port with SSL-specific scripts
            scan_result = self.nm.scan(
                target_domain,
                str(port),
                arguments='-sV --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed'
            )
            
            if target_domain in self.nm.all_hosts():
                host_info = self.nm[target_domain]
                if 'tcp' in host_info and port in host_info['tcp']:
                    port_info = host_info['tcp'][port]
                    
                    # Extract SSL certificate information
                    if 'script' in port_info:
                        results['ssl_info'] = port_info['script']
                        
                        # Check for SSL vulnerabilities
                        if 'ssl-heartbleed' in port_info['script']:
                            results['vulnerabilities'].append({
                                'type': 'SSL Heartbleed',
                                'severity': 'High',
                                'description': 'Heartbleed vulnerability detected',
                                'recommendation': 'Update OpenSSL to patched version'
                            })
        
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results

