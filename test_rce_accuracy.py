#!/usr/bin/env python3
"""
RCE Testing Verification Script
Tests the improved RCE detection to avoid false positives
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import SecurityTestOrchestrator

def test_rce_accuracy():
    """Test RCE detection accuracy"""
    print("🔍 RCE Testing Accuracy Verification")
    print("=" * 45)
    
    # Initialize the orchestrator
    orchestrator = SecurityTestOrchestrator("config.yaml")
    
    # Test with a known safe target first
    print("Testing with safe target (httpbin.org)...")
    orchestrator.config['target']['url'] = "https://httpbin.org"
    
    result = orchestrator.run_single_test('rce_testing')
    
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
    
    if result.get('vulnerabilities'):
        print("⚠️  False positives detected:")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
    else:
        print("✅ No false positives detected")
    
    print("\n" + "="*45)
    
    # Test with the original target
    print("Testing with original target (stg.archaive.jp)...")
    orchestrator.config['target']['url'] = "https://stg.archaive.jp/"
    
    result = orchestrator.run_single_test('rce_testing')
    
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
    
    if result.get('vulnerabilities'):
        print("🔍 Actual vulnerabilities found:")
        for vuln in result['vulnerabilities']:
            print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
            print(f"    URL: {vuln.get('url', 'N/A')}")
            print(f"    Payload: {vuln.get('payload', 'N/A')}")
    else:
        print("✅ No vulnerabilities detected")
    
    return result

def main():
    """Main function"""
    try:
        test_rce_accuracy()
        
        print("\n📝 Summary:")
        print("The improved RCE tester now:")
        print("1. Only tests endpoints that actually exist (status 200)")
        print("2. Uses stricter detection criteria")
        print("3. Requires multiple indicators for command execution")
        print("4. Avoids false positives from 404 responses")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
