#!/usr/bin/env python3
"""
ZAP Java Integration Demo
Demonstrates the multi-language security testing capabilities
"""

import json
import tempfile
import subprocess
from pathlib import Path

def demo_java_security_testing():
    """Demo the Java security testing capabilities"""
    
    print("🚀 ZAP Java Integration Demo")
    print("=" * 50)
    
    # Create a temporary config file
    config = {
        'module_name': 'comprehensive_security_test',
        'test_types': ['xss', 'sql_injection', 'directory_traversal', 'command_injection']
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.properties', delete=False) as config_file:
        # Java properties format
        for key, value in config.items():
            config_file.write(f"{key}={value}\n")
        config_path = config_file.name
    
    # Test parameters
    target_url = "https://httpbin.org/get"
    target_domain = "httpbin.org"
    
    print(f"🎯 Testing target: {target_url}")
    print(f"📋 Configuration: {config}")
    print()
    
    try:
        # Run Java security tests
        classes_dir = Path("java_security_modules/classes")
        if not classes_dir.exists():
            print("❌ Java classes not compiled. Please run:")
            print("   javac -d java_security_modules/classes java_security_modules/ZapRunner.java")
            return False
        
        cmd = [
            "java",
            "-cp", str(classes_dir),
            "-Djava.awt.headless=true",
            "ZapRunner",
            target_url,
            target_domain,
            config_path
        ]
        
        print("🔨 Executing Java security tests...")
        print(f"Command: {' '.join(cmd[:4])} ...")
        print()
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Java security tests completed successfully!")
            print()
            print("📊 Test Results:")
            print("-" * 30)
            print(result.stdout)
            
            # Parse results (simple extraction)
            vulnerability_count = result.stdout.count("VULNERABILITY:")
            print(f"\n📈 Summary:")
            print(f"   Tests completed: ✅")
            print(f"   Vulnerabilities checked: {vulnerability_count}")
            print(f"   Target URL: {target_url}")
            
            return True
        else:
            print("❌ Java security tests failed:")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Java tests timed out")
        return False
    except Exception as e:
        print(f"❌ Error running Java tests: {e}")
        return False
    finally:
        # Clean up
        try:
            Path(config_path).unlink()
        except:
            pass

def demo_integration_features():
    """Show integration features"""
    print("\n🔧 Integration Features:")
    print("-" * 30)
    print("✅ Multi-language architecture (Python + Java)")
    print("✅ Simplified Java compilation (no ZAP dependencies)")
    print("✅ JSON configuration integration")
    print("✅ Unified error handling")
    print("✅ Cross-platform execution")
    print("✅ Headless operation (no GUI required)")
    print()
    print("🎯 Security Test Types:")
    print("-" * 30)
    print("• Cross-Site Scripting (XSS)")
    print("• SQL Injection")
    print("• Directory Traversal")
    print("• Command Injection")
    print("• Information Disclosure")
    print()
    print("📚 Next Steps:")
    print("-" * 30)
    print("1. Run: python3 main.py --target https://example.com")
    print("2. View output in ./reports/ directory")
    print("3. Customize tests in config.yaml")

if __name__ == "__main__":
    success = demo_java_security_testing()
    demo_integration_features()
    
    if success:
        print("\n🎉 Demo completed successfully!")
        print("   The ZAP Java integration is working.")
    else:
        print("\n⚠️  Demo encountered issues.")
        print("   Check Java installation and compilation.")
