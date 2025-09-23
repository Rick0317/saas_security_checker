#!/usr/bin/env python3
"""
Example usage of SaaS Security Checker
Demonstrates how to use the security testing tool programmatically
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import SecurityTestOrchestrator

def example_basic_usage():
    """Example of basic usage"""
    print("🔒 SaaS Security Checker - Basic Usage Example")
    print("=" * 50)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Set target URL
    target_url = "https://httpbin.org"  # Safe test target
    orchestrator.config['target']['url'] = target_url
    
    print(f"Testing target: {target_url}")
    print("Running security assessment...")
    
    # Run all tests
    results = orchestrator.run_all_tests()
    
    # Display summary
    print("\n📊 Assessment Summary:")
    print("-" * 30)
    
    total_tests = len(results)
    completed_tests = sum(1 for r in results.values() if r.get('status') == 'completed')
    failed_tests = sum(1 for r in results.values() if r.get('status') == 'error')
    
    print(f"Total tests: {total_tests}")
    print(f"Completed: {completed_tests}")
    print(f"Failed: {failed_tests}")
    
    # Count vulnerabilities
    total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())
    critical_vulns = sum(
        len([v for v in r.get('vulnerabilities', []) if v.get('severity', '').lower() == 'critical'])
        for r in results.values()
    )
    
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"Critical vulnerabilities: {critical_vulns}")
    
    return results

def example_single_test():
    """Example of running a single test"""
    print("\n🔍 Single Test Example")
    print("=" * 30)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Set target URL
    target_url = "https://httpbin.org"
    orchestrator.config['target']['url'] = target_url
    
    # Run only packet sniffing prevention test
    print(f"Running packet sniffing prevention test on {target_url}...")
    result = orchestrator.run_single_test('packet_sniffing_prevention')
    
    print(f"Test status: {result.get('status', 'unknown')}")
    
    if result.get('vulnerabilities'):
        print(f"Found {len(result['vulnerabilities'])} vulnerabilities:")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
    else:
        print("No vulnerabilities found")
    
    return result

def example_custom_config():
    """Example with custom configuration"""
    print("\n⚙️ Custom Configuration Example")
    print("=" * 35)
    
    # Create custom configuration
    custom_config = {
        "target": {
            "url": "https://httpbin.org",
            "timeout": 15,
            "user_agent": "Custom-Security-Checker/1.0"
        },
        "tests": {
            "sql_injection": {"enabled": False},  # Disable SQL injection test
            "port_discovery": {"enabled": True, "ports": "80,443"},  # Only test common ports
            "dns_checks": {"enabled": True},
            "http_headers": {"enabled": True},
            "tls_security": {"enabled": True},
            "web_scanner": {"enabled": False},  # Disable web scanner
            "dependency_check": {"enabled": False},  # Disable dependency check
            "auth_security": {"enabled": False},  # Disable auth security
            "password_check": {"enabled": False},  # Disable password check
            "packet_sniffing_prevention": {"enabled": True}  # Enable packet sniffing prevention
        },
        "output": {
            "format": ["console"],  # Only console output
            "directory": "./reports"
        }
    }
    
    # Initialize with custom config
    orchestrator = SecurityTestOrchestrator()
    orchestrator.config = custom_config
    
    print("Running tests with custom configuration...")
    print("Enabled tests: Port Discovery, DNS Checks, HTTP Headers, TLS Security, Packet Sniffing Prevention")
    
    # Run tests
    results = orchestrator.run_all_tests()
    
    print(f"Completed {len(results)} tests")
    
    return results

def main():
    """Main example function"""
    print("🚀 SaaS Security Checker Examples")
    print("=" * 40)
    print()
    
    try:
        # Example 1: Basic usage
        example_basic_usage()
        
        # Example 2: Single test
        example_single_test()
        
        # Example 3: Custom configuration
        example_custom_config()
        
        print("\n✅ All examples completed successfully!")
        print("\n📝 Next steps:")
        print("1. Review the generated reports in ./reports/")
        print("2. Customize config.yaml for your specific needs")
        print("3. Test your own applications (with proper authorization)")
        print("4. Integrate into your CI/CD pipeline")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {str(e)}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check that nmap and other tools are available")
        print("3. Verify network connectivity to test targets")
        print("4. Review the logs directory for detailed error information")

if __name__ == "__main__":
    main()

