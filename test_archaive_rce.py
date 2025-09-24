#!/usr/bin/env python3
"""
Targeted RCE Testing for Archaive API
Tests specific endpoints for Remote Code Execution vulnerabilities
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import SecurityTestOrchestrator

def test_archaive_rce():
    """Test Archaive API for RCE vulnerabilities"""
    print("🔍 Archaive API RCE Testing")
    print("=" * 35)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Set target to Archaive staging
    target_url = "https://stg.archaive.jp/"
    orchestrator.config['target']['url'] = target_url
    
    print(f"Testing target: {target_url}")
    print("Testing specific API endpoints...")
    
    # Run RCE testing
    result = orchestrator.run_single_test('rce_testing')
    
    print(f"\n📊 RCE Test Results:")
    print("-" * 25)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
    
    if result.get('vulnerabilities'):
        print("\n🚨 Vulnerabilities detected:")
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"{i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
            print(f"   Description: {vuln.get('description', 'No description')}")
            print(f"   Payload: {vuln.get('payload', 'N/A')}")
            print(f"   Recommendation: {vuln.get('recommendation', 'N/A')}")
            print()
    else:
        print("✅ No RCE vulnerabilities detected")
    
    if result.get('recommendations'):
        print("💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec.get('recommendation', 'Unknown')} ({rec.get('priority', 'Unknown')})")
    
    return result

def test_specific_endpoints():
    """Test specific Archaive endpoints manually"""
    print("\n🎯 Testing Specific Archaive Endpoints")
    print("=" * 40)
    
    import requests
    
    target_url = "https://stg.archaive.jp"
    session = requests.Session()
    
    # Your actual endpoints
    endpoints = [
        '/v1/account/auth/logout',
        '/v1/account/auth/me'
    ]
    
    for endpoint in endpoints:
        try:
            url = target_url + endpoint
            print(f"\nTesting: {url}")
            
            # Test GET request
            response = session.get(url, timeout=10)
            print(f"  GET Status: {response.status_code}")
            
            # Test POST request
            response = session.post(url, timeout=10)
            print(f"  POST Status: {response.status_code}")
            
            # Test with common parameters
            test_params = {'q': 'test', 'data': 'test', 'input': 'test'}
            response = session.get(url, params=test_params, timeout=10)
            print(f"  GET with params Status: {response.status_code}")
            
        except Exception as e:
            print(f"  Error: {str(e)}")

def main():
    """Main function"""
    try:
        # Test with the RCE module
        test_archaive_rce()
        
        # Test specific endpoints
        test_specific_endpoints()
        
        print("\n📝 Summary:")
        print("The RCE tester now focuses on:")
        print("1. Your actual API endpoints (/v1/account/auth/*)")
        print("2. Only tests endpoints that actually exist")
        print("3. Uses stricter detection criteria")
        print("4. Avoids false positives from non-existent endpoints")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
