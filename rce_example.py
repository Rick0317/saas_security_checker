#!/usr/bin/env python3
"""
RCE Testing Example
Demonstrates how to test for Remote Code Execution vulnerabilities
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import SecurityTestOrchestrator

def example_rce_testing():
    """Example of RCE testing"""
    print("🚨 RCE Testing Example")
    print("=" * 40)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Set target URL (use a safe test target)
    target_url = "https://httpbin.org"  # Safe test target
    orchestrator.config['target']['url'] = target_url
    
    print(f"Testing target: {target_url}")
    print("Running RCE security assessment...")
    
    # Run only RCE testing
    result = orchestrator.run_single_test('rce_testing')
    
    print(f"\n📊 RCE Test Results:")
    print("-" * 30)
    print(f"Status: {result.get('status', 'unknown')}")
    
    if result.get('vulnerabilities'):
        print(f"Found {len(result['vulnerabilities'])} vulnerabilities:")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
            print(f"    Severity: {vuln.get('severity', 'Unknown')}")
            if 'payload' in vuln:
                print(f"    Payload: {vuln['payload'][:50]}...")
    else:
        print("No RCE vulnerabilities found")
    
    if result.get('recommendations'):
        print(f"\n💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec.get('recommendation', 'Unknown')}")
            print(f"    Priority: {rec.get('priority', 'Unknown')}")
    
    return result

def example_custom_rce_config():
    """Example with custom RCE configuration"""
    print("\n⚙️ Custom RCE Configuration Example")
    print("=" * 40)
    
    # Create custom configuration for RCE testing
    custom_config = {
        "target": {
            "url": "https://httpbin.org",
            "timeout": 15,
            "user_agent": "RCE-Tester/1.0"
        },
        "tests": {
            "rce_testing": {
                "enabled": True,
                "test_command_injection": True,
                "test_deserialization": True,
                "test_file_upload": True,
                "test_template_injection": True,
                "test_eval_injection": True
            },
            # Disable other tests for focused RCE testing
            "sql_injection": {"enabled": False},
            "port_discovery": {"enabled": False},
            "dns_checks": {"enabled": False},
            "http_headers": {"enabled": False},
            "tls_security": {"enabled": False},
            "web_scanner": {"enabled": False},
            "dependency_check": {"enabled": False},
            "auth_security": {"enabled": False},
            "password_check": {"enabled": False},
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
    
    print("Running focused RCE testing...")
    
    # Run RCE test
    result = orchestrator.run_single_test('rce_testing')
    
    print(f"RCE test completed with status: {result.get('status', 'unknown')}")
    
    return result

def main():
    """Main example function"""
    print("🚀 RCE Testing Examples")
    print("=" * 30)
    print()
    
    try:
        # Example 1: Basic RCE testing
        example_rce_testing()
        
        # Example 2: Custom RCE configuration
        example_custom_rce_config()
        
        print("\n✅ RCE testing examples completed!")
        print("\n📝 Next steps:")
        print("1. Review the RCE_TESTING_GUIDE.md for detailed information")
        print("2. Test your own applications (with proper authorization)")
        print("3. Implement the recommended security measures")
        print("4. Regular RCE testing in your security workflow")
        
    except Exception as e:
        print(f"\n❌ Error running RCE examples: {str(e)}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure all dependencies are installed")
        print("2. Check that the target URL is accessible")
        print("3. Review the logs for detailed error information")

if __name__ == "__main__":
    main()
