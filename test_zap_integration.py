#!/usr/bin/env python3
"""
Test script for ZAP Java Integration
Demonstrates the new multi-language security testing capabilities
"""

import os
import sys
import subprocess
from pathlib import Path

def test_java_compilation():
    """Test if Java modules can be compiled successfully"""
    print("🔨 Testing Java compilation...")
    
    # Check if compile script exists and is executable
    compile_script = Path("compile_java_modules.sh")
    if not compile_script.exists():
        print("❌ compile_java_modules.sh not found")
        return False
    
    # Make executable if needed
    if not os.access(compile_script, os.X_OK):
        os.chmod(compile_script, 0o755)
    
    # Run compilation
    try:
        result = subprocess.run(
            [str(compile_script)],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print("✅ Java modules compiled successfully")
            return True
        else:
            print(f"❌ Compilation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Compilation timed out")
        return False
    except Exception as e:
        print(f"❌ Compilation error: {e}")
        return False

def test_zap_modules_structure():
    """Test if ZAP modules structure is correct"""
    print("📁 Testing ZAP modules structure...")
    
    expected_files = [
        "java_security_modules/ZapSecurityTester.java",
        "java_security_modules/XssScanner.java", 
        "java_security_modules/SqlInjectionScanner.java",
        "java_security_modules/DirectoryTraversalScanner.java",
        "java_security_modules/CommandInjectionScanner.java",
        "security_modules/zap_java_integration.py",
        "zaproxy-main/zap/src/main/java/org/parosproxy/paros/core/scanner/",
    ]
    
    missing_files = []
    for file_path in expected_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files present")
        return True

def test_python_integration():
    """Test if Python integration works"""
    print("🐍 Testing Python integration...")
    
    try:
        # Test imports
        sys.path.insert(0, str(Path.cwd()))
        
        from security_modules.zap_java_integration import ZAPJavaIntegration
        print("✅ ZAPJavaIntegration import successful")
        
        # Test initialization with minimal config
        config = {'tests': {'zap_java_testing': {'enabled': True}}}
        tester = ZAPJavaIntegration(config)
        print("✅ ZAPJavaIntegration initialization successful")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        return False

def test_config_integration():
    """Test if main.py correctly references the new module"""
    print("⚙️  Testing configuration integration...")
    
    main_py = Path("main.py")
    if not main_py.exists():
        print("❌ main.py not found")
        return False
    
    with open(main_py, 'r') as f:
        content = f.read()
    
    required_imports = [
        "from security_modules.zap_java_integration import ZAPJavaIntegration",
        "'zap_java_testing': ZAPJavaIntegration(self.config)"
    ]
    
    missing_imports = []
    for req in required_imports:
        if req not in content:
            missing_imports.append(req)
    
    if missing_imports:
        print(f"❌ Missing imports/references: {missing_imports}")
        return False
    else:
        print("✅ main.py integration complete")
        return True

def test_list_tests_command():
    """Test if list-tests command includes ZAP Java testing"""
    print("📋 Testing list-tests command...")
    
    try:
        result = subprocess.run(
            [sys.executable, "main.py", "--list-tests"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            if "zap_java_testing" in result.stdout.lower():
                print("✅ ZAP Java testing listed in available tests")
                return True
            else:
                print("⚠️  ZAP Java testing not found in test list")
                print("Available tests:")
                print(result.stdout)
                return False
        else:
            print(f"❌ Command failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Command error: {e}")
        return False

def main():
    """Run all integration tests"""
    print("🚀 ZAP Java Integration Test Suite")
    print("=" * 50)
    
    tests = [
        ("ZAP Modules Structure", test_zap_modules_structure),
        ("Python Integration", test_python_integration),
        ("Configuration Integration", test_config_integration),
        ("Java Compilation", test_java_compilation),
        ("List Tests Command", test_list_tests_command)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                passed += 1
                print(f"✅ PASS: {test_name}")
            else:
                print(f"❌ FAIL: {test_name}")
        except Exception as e:
            print(f"💥 ERROR: {test_name} - {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! ZAP Java integration is ready.")
        print("\nNext steps:")
        print("1. Run: python main.py --target https://example.com")
        print("2. Check reports in ./reports/")
        print("3. Review ZAP_JAVA_INTEGRATION_GUIDE.md for advanced usage")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        print("Refer to ZAP_JAVA_INTEGRATION_GUIDE.md for troubleshooting.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
