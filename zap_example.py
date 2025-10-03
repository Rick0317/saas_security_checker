#!/usr/bin/env python3
"""
ZAP Integration Example
Demonstrates how to use ZAP for comprehensive security testing
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import SecurityTestOrchestrator

def example_zap_testing():
    """Example of ZAP security testing"""
    print("🕷️ ZAP Security Testing Example")
    print("=" * 40)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Set target URL
    target_url = "https://stg.archaive.jp/"
    orchestrator.config['target']['url'] = target_url
    
    print(f"Testing target: {target_url}")
    print("Running ZAP security assessment...")
    print("Note: ZAP must be running on localhost:8080")
    
    # Run ZAP integration test
    result = orchestrator.run_single_test('zap_integration')
    
    print(f"\n📊 ZAP Test Results:")
    print("-" * 30)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"ZAP Version: {result.get('zap_version', 'Unknown')}")
    
    if result.get('spider_results'):
        spider = result['spider_results']
        print(f"Spider Status: {spider.get('status', 'unknown')}")
        print(f"URLs Found: {spider.get('urls_found', 0)}")
    
    if result.get('active_scan_results'):
        scan = result['active_scan_results']
        print(f"Active Scan Status: {scan.get('status', 'unknown')}")
        print(f"Alerts Found: {scan.get('alerts_found', 0)}")
    
    print(f"Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
    
    if result.get('vulnerabilities'):
        print("\n🚨 Vulnerabilities detected:")
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"{i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
            print(f"   Description: {vuln.get('description', 'No description')}")
            print(f"   URL: {vuln.get('url', 'N/A')}")
            print(f"   Parameter: {vuln.get('parameter', 'N/A')}")
            print(f"   Solution: {vuln.get('solution', 'N/A')}")
            print()
    else:
        print("✅ No vulnerabilities detected")
    
    if result.get('recommendations'):
        print("💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec.get('recommendation', 'Unknown')} ({rec.get('priority', 'Unknown')})")
    
    return result

def example_zap_configuration():
    """Example with custom ZAP configuration"""
    print("\n⚙️ Custom ZAP Configuration Example")
    print("=" * 40)
    
    # Create custom configuration for ZAP
    custom_config = {
        "target": {
            "url": "https://stg.archaive.jp/",
            "timeout": 30,
            "user_agent": "ZAP-Security-Tester/1.0"
        },
        "zap": {
            "host": "localhost",
            "port": 8080,
            "api_key": "",  # Add your API key here
            "run_spider": True,
            "run_active_scan": True,
            "scan_policy": "Default Policy",
            "max_scan_duration": 1800  # 30 minutes
        },
        "tests": {
            "zap_integration": {
                "enabled": True
            },
            # Disable other tests for focused ZAP testing
            "sql_injection": {"enabled": False},
            "port_discovery": {"enabled": False},
            "dns_checks": {"enabled": False},
            "http_headers": {"enabled": False},
            "tls_security": {"enabled": False},
            "web_scanner": {"enabled": False},
            "dependency_check": {"enabled": False},
            "auth_security": {"enabled": False},
            "password_check": {"enabled": False},
            "rce_testing": {"enabled": False},
            "packet_sniffing_prevention": {"enabled": False},
            "dns_hijacking_prevention": {"enabled": False}
        },
        "output": {
            "format": ["console"],
            "directory": "./reports"
        }
    }
    
    # Initialize with custom config
    orchestrator = SecurityTestOrchestrator()
    orchestrator.config = custom_config
    
    print("Running focused ZAP testing...")
    print("Configuration:")
    print(f"  Host: {custom_config['zap']['host']}")
    print(f"  Port: {custom_config['zap']['port']}")
    print(f"  Scan Policy: {custom_config['zap']['scan_policy']}")
    print(f"  Max Duration: {custom_config['zap']['max_scan_duration']} seconds")
    
    # Run ZAP test
    result = orchestrator.run_single_test('zap_integration')
    
    print(f"ZAP test completed with status: {result.get('status', 'unknown')}")
    
    return result

def check_zap_status():
    """Check if ZAP is running and accessible"""
    print("\n🔍 Checking ZAP Status")
    print("=" * 25)
    
    import requests
    
    try:
        # Check if ZAP is accessible
        response = requests.get("http://localhost:8080/JSON/core/view/version/", timeout=10)
        
        if response.status_code == 200:
            version_data = response.json()
            print(f"✅ ZAP is running")
            print(f"   Version: {version_data.get('version', 'Unknown')}")
            print(f"   URL: http://localhost:8080")
            return True
        else:
            print(f"❌ ZAP is not accessible (Status: {response.status_code})")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ ZAP is not running or not accessible")
        print("   Please start ZAP with: zap.sh -daemon -host 0.0.0.0 -port 8080")
        return False
    except Exception as e:
        print(f"❌ Error checking ZAP status: {str(e)}")
        return False

def main():
    """Main function"""
    print("🚀 ZAP Integration Examples")
    print("=" * 30)
    print()
    
    try:
        # Check ZAP status first
        if not check_zap_status():
            print("\n⚠️  ZAP is not running. Please start ZAP first:")
            print("   zap.sh -daemon -host 0.0.0.0 -port 8080")
            print("\n   Or install ZAP from: https://www.zaproxy.org/download/")
            return
        
        # Example 1: Basic ZAP testing
        example_zap_testing()
        
        # Example 2: Custom ZAP configuration
        example_zap_configuration()
        
        print("\n✅ ZAP testing examples completed!")
        print("\n📝 Next steps:")
        print("1. Review the ZAP_INTEGRATION_GUIDE.md for detailed information")
        print("2. Configure ZAP for your specific needs")
        print("3. Integrate ZAP testing into your CI/CD pipeline")
        print("4. Set up regular ZAP scanning schedule")
        
    except Exception as e:
        print(f"\n❌ Error running ZAP examples: {str(e)}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure ZAP is running on localhost:8080")
        print("2. Check ZAP API accessibility")
        print("3. Verify target URL is accessible")
        print("4. Review the logs for detailed error information")

if __name__ == "__main__":
    main()

