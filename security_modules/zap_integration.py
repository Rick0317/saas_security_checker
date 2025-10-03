"""
ZAP (Zed Attack Proxy) Integration Module
Integrates OWASP ZAP for comprehensive web application security testing
"""

import json
import logging
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

class ZAPIntegration:
    """OWASP ZAP integration for comprehensive security testing"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.zap_host = config.get('zap', {}).get('host', 'localhost')
        self.zap_port = config.get('zap', {}).get('port', 8080)
        self.zap_api_key = config.get('zap', {}).get('api_key', '')
        self.base_url = f"http://{self.zap_host}:{self.zap_port}"
        self.session = requests.Session()
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run comprehensive ZAP security testing"""
        self.logger.info(f"Starting ZAP security testing for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'zap_version': '',
            'spider_results': {},
            'active_scan_results': {},
            'alerts': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Check if ZAP is running
            if not self._check_zap_status():
                results['status'] = 'error'
                results['error'] = 'ZAP is not running or not accessible'
                return results
            
            # Get ZAP version
            results['zap_version'] = self._get_zap_version()
            
            # Set target URL
            self._set_target_url(target_url)
            
            # Run spider to discover endpoints
            results['spider_results'] = self._run_spider(target_url)
            
            # Run active scan for vulnerabilities
            results['active_scan_results'] = self._run_active_scan(target_url)
            
            # Get alerts (vulnerabilities)
            results['alerts'] = self._get_alerts()
            
            # Convert alerts to vulnerabilities format
            results['vulnerabilities'] = self._convert_alerts_to_vulnerabilities(results['alerts'])
            
            # Generate recommendations
            self._generate_zap_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during ZAP testing: {str(e)}")
        
        return results
    
    def _check_zap_status(self) -> bool:
        """Check if ZAP is running and accessible"""
        try:
            response = self.session.get(f"{self.base_url}/JSON/core/view/version/", timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def _get_zap_version(self) -> str:
        """Get ZAP version"""
        try:
            response = self.session.get(f"{self.base_url}/JSON/core/view/version/", timeout=10)
            if response.status_code == 200:
                return response.json().get('version', 'Unknown')
        except:
            pass
        return 'Unknown'
    
    def _set_target_url(self, target_url: str):
        """Set target URL in ZAP"""
        try:
            params = {'url': target_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/core/action/accessUrl/", 
                                      params=params, timeout=30)
            self.logger.info(f"ZAP target URL set: {target_url}")
        except Exception as e:
            self.logger.error(f"Error setting ZAP target URL: {str(e)}")
    
    def _run_spider(self, target_url: str) -> Dict:
        """Run ZAP spider to discover endpoints"""
        spider_results = {
            'status': 'completed',
            'scan_id': '',
            'progress': 0,
            'urls_found': 0
        }
        
        try:
            # Start spider
            params = {'url': target_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/spider/action/scan/", 
                                      params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                spider_results['scan_id'] = result.get('scan', '')
                
                # Wait for spider to complete
                while True:
                    time.sleep(2)
                    progress_response = self.session.get(f"{self.base_url}/JSON/spider/view/status/", 
                                                       params={'apikey': self.zap_api_key} if self.zap_api_key else {})
                    
                    if progress_response.status_code == 200:
                        progress_data = progress_response.json()
                        spider_results['progress'] = int(progress_data.get('status', 0))
                        
                        if spider_results['progress'] >= 100:
                            break
                
                # Get results
                results_response = self.session.get(f"{self.base_url}/JSON/spider/view/results/", 
                                                  params={'apikey': self.zap_api_key} if self.zap_api_key else {})
                
                if results_response.status_code == 200:
                    results_data = results_response.json()
                    spider_results['urls_found'] = len(results_data.get('results', []))
            
        except Exception as e:
            spider_results['status'] = 'error'
            spider_results['error'] = str(e)
            self.logger.error(f"Error running ZAP spider: {str(e)}")
        
        return spider_results
    
    def _run_active_scan(self, target_url: str) -> Dict:
        """Run ZAP active scan for vulnerabilities"""
        scan_results = {
            'status': 'completed',
            'scan_id': '',
            'progress': 0,
            'alerts_found': 0
        }
        
        try:
            # Start active scan
            params = {'url': target_url}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/action/scan/", 
                                      params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                scan_results['scan_id'] = result.get('scan', '')
                
                # Wait for scan to complete
                while True:
                    time.sleep(5)
                    progress_response = self.session.get(f"{self.base_url}/JSON/ascan/view/status/", 
                                                       params={'apikey': self.zap_api_key} if self.zap_api_key else {})
                    
                    if progress_response.status_code == 200:
                        progress_data = progress_response.json()
                        scan_results['progress'] = int(progress_data.get('status', 0))
                        
                        if scan_results['progress'] >= 100:
                            break
                
                # Get alerts count
                alerts_response = self.session.get(f"{self.base_url}/JSON/alert/view/numberOfAlerts/", 
                                                 params={'apikey': self.zap_api_key} if self.zap_api_key else {})
                
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    scan_results['alerts_found'] = int(alerts_data.get('numberOfAlerts', 0))
            
        except Exception as e:
            scan_results['status'] = 'error'
            scan_results['error'] = str(e)
            self.logger.error(f"Error running ZAP active scan: {str(e)}")
        
        return scan_results
    
    def _get_alerts(self) -> List[Dict]:
        """Get all alerts from ZAP"""
        alerts = []
        
        try:
            params = {}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/alert/view/alerts/", 
                                      params=params, timeout=30)
            
            if response.status_code == 200:
                alerts_data = response.json()
                alerts = alerts_data.get('alerts', [])
            
        except Exception as e:
            self.logger.error(f"Error getting ZAP alerts: {str(e)}")
        
        return alerts
    
    def _convert_alerts_to_vulnerabilities(self, alerts: List[Dict]) -> List[Dict]:
        """Convert ZAP alerts to our vulnerability format"""
        vulnerabilities = []
        
        # Risk level mapping
        risk_mapping = {
            'High': 'Critical',
            'Medium': 'High', 
            'Low': 'Medium',
            'Informational': 'Low'
        }
        
        for alert in alerts:
            vulnerability = {
                'type': alert.get('name', 'Unknown'),
                'severity': risk_mapping.get(alert.get('risk', 'Low'), 'Medium'),
                'description': alert.get('description', 'No description'),
                'url': alert.get('url', ''),
                'parameter': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe_id': alert.get('cweid', ''),
                'wasc_id': alert.get('wascid', ''),
                'confidence': alert.get('confidence', ''),
                'recommendation': alert.get('solution', 'Review and fix the identified vulnerability')
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_zap_recommendations(self, results: Dict):
        """Generate recommendations based on ZAP results"""
        recommendations = []
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Generate specific recommendations
        if severity_counts.get('Critical', 0) > 0:
            recommendations.append({
                'priority': 'Critical',
                'recommendation': 'Fix critical vulnerabilities immediately',
                'details': f'Found {severity_counts["Critical"]} critical vulnerabilities that require immediate attention'
            })
        
        if severity_counts.get('High', 0) > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Address high-severity vulnerabilities',
                'details': f'Found {severity_counts["High"]} high-severity vulnerabilities'
            })
        
        if severity_counts.get('Medium', 0) > 0:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Review medium-severity vulnerabilities',
                'details': f'Found {severity_counts["Medium"]} medium-severity vulnerabilities'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement regular ZAP scanning',
                'details': 'Include ZAP scanning in your CI/CD pipeline'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Review ZAP scan results regularly',
                'details': 'Set up automated alerts for new vulnerabilities'
            },
            {
                'priority': 'Low',
                'recommendation': 'Consider ZAP baseline scanning',
                'details': 'Use ZAP baseline mode for continuous security monitoring'
            }
        ])
        
        results['recommendations'].extend(recommendations)
    
    def get_scan_policies(self) -> List[Dict]:
        """Get available scan policies"""
        policies = []
        
        try:
            params = {}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/view/policies/", 
                                      params=params, timeout=30)
            
            if response.status_code == 200:
                policies_data = response.json()
                policies = policies_data.get('policies', [])
            
        except Exception as e:
            self.logger.error(f"Error getting ZAP scan policies: {str(e)}")
        
        return policies
    
    def set_scan_policy(self, policy_name: str) -> bool:
        """Set scan policy"""
        try:
            params = {'policyName': policy_name}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/action/setEnabledPolicies/", 
                                      params=params, timeout=30)
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error setting ZAP scan policy: {str(e)}")
            return False
    
    def get_scanners(self) -> List[Dict]:
        """Get available scanners"""
        scanners = []
        
        try:
            params = {}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/view/scanners/", 
                                      params=params, timeout=30)
            
            if response.status_code == 200:
                scanners_data = response.json()
                scanners = scanners_data.get('scanners', [])
            
        except Exception as e:
            self.logger.error(f"Error getting ZAP scanners: {str(e)}")
        
        return scanners
    
    def enable_scanner(self, scanner_id: str) -> bool:
        """Enable specific scanner"""
        try:
            params = {'ids': scanner_id}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/action/enableScanners/", 
                                      params=params, timeout=30)
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error enabling ZAP scanner: {str(e)}")
            return False
    
    def disable_scanner(self, scanner_id: str) -> bool:
        """Disable specific scanner"""
        try:
            params = {'ids': scanner_id}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = self.session.get(f"{self.base_url}/JSON/ascan/action/disableScanners/", 
                                      params=params, timeout=30)
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error disabling ZAP scanner: {str(e)}")
            return False

