#!/usr/bin/env python3
"""
Different Methods for Python to Execute Java Code
Demonstrates various approaches for Python-Java integration
"""

import subprocess
import json
import os
from pathlib import Path

class JavaExecutionMethods:
    """Shows different ways Python can execute Java code"""
    
    def __init__(self):
        self.java_classes_dir = Path("java_security_modules/classes")
    
    def method_1_subprocess(self, target_url: str) -> dict:
        """
        Method 1: Subprocess Execution (Current Implementation)
        ✅ Pros: Simple, isolated, flexible
        ❌ Cons: Processes overhead, slower for frequent calls
        """
        print("🔄 Method 1: Subprocess Execution")
        
        cmd = [
            "java",
            "-cp", str(self.java_classes_dir),
            "-Djava.awt.headless=true",
            "ZapRunner",
            target_url,
            "example.com",
            "/dev/null"  # No config file for demo
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return self._parse_java_output(result.stdout)
            else:
                return {'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'error': 'Java execution timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def method_2_popen_with_streaming(self, target_url: str) -> dict:
        """
        Method 2: Popen with Streaming (Real-time output)
        ✅ Pros: Real-time feedback, no timeout issues
        ❌ Cons: More complex, harder to parse
        """
        print("🔄 Method 2: Streaming Execution with Popen")
        
        cmd = [
            "java", "-cp", str(self.java_classes_dir),
            "-Djava.awt.headless=true", "ZapRunner",
            target_url, "example.com", "/dev/null"
        ]
        
        vulnerabilities = []
        current_vuln = {}
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            # Read output line by line as it comes
            for line in iter(process.stdout.readline, ''):
                print(f"📨 Java: {line.strip()}")
                
                # Parse vulnerability data in real-time
                if line.startswith("VULNERABILITY:"):
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {'type': line.split(':', 1)[1].strip()}
                elif line.startswith('SEVERITY:'):
                    current_vuln['severity'] = line.split(':', 1)[1].strip()
            
            if current_vuln:
                vulnerabilities.append(current_vuln)
            
            process.wait()  # Wait for completion
            
            return {
                'status': 'success',
                'vulnerabilities': vulnerabilities,
                'total_vulns': len(vulnerabilities)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def method_3_threading(self, target_urls: list) -> dict:
        """
        Method 3: Threaded Execution (Parallel Processing)
        ✅ Pros: Can test multiple URLs simultaneously
        ❌ Cons: Resource intensive, complex coordination
        """
        print("🔄 Method 3: Threaded Execution (Multiple URLs)")
        
        import threading
        import time
        
        results = {}
        
        def test_url(url):
            """Thread function to test a single URL"""
            result = self.method_1_subprocess(url)
            results[url] = result
        
        threads = []
        for url in target_urls:
            thread = threading.Thread(target=test_url, args=(url,))
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return results
    
    def method_4_asyncio(self, target_url: str) -> dict:
        """
        Method 4: Asyncio Execution (Async/Await)
        ✅ Pros: Non-blocking, efficient for I/O operations
        ❌ Cons: Complexity, requires async/await pattern
        """
        print("🔄 Method 4: Asynchronous Execution")
        
        try:
            import asyncio
            
            async def run_java_async():
                """Run Java process asynchronously"""
                process = await asyncio.create_subprocess_exec(
                    "java", "-cp", str(self.java_classes_dir),
                    "-Djava.awt.headless=true", "ZapRunner",
                    target_url, "example.com", "/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return self._parse_java_output(stdout.decode())
                else:
                    return {'error': stderr.decode()}
            
            # Run the async function
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(run_java_async())
            
        except ImportError:
            return {'error': 'asyncio not available'}
    
    def method_5_jpype_integration(self, target_url: str) -> dict:
        """
        Method 5: JPype Integration (Lift Java into Python)
        ✅ Pros: Native integration, no subprocess overhead
        ❌ Cons: Complex setup, platform dependent
        """
        print("🔄 Method 5: JPype Direct Integration")
        
        try:
            import jpype
            import jpype.imports as jimports
            
            # Start JVM with classpath
            classpath = str(self.java_classes_dir.resolve())
            jpype.startJVM(classpath=classpath)
            
            # Import and run Java classes directly
            JString = jpype.JClass("java.lang.String")
            ArrayList = jpype.JClass("java.util.ArrayList")
            
            # Create Java objects
            results = ArrayList()
            
            # Call Java methods directly
            zap_runner = jpype.JClass("ZapRunner")
            
            # This would allow direct method calls
            # vulnerability_list = zap_runner.testXSS(JString(target_url))
            
            jpype.shutdownJVM()
            
            return {'status': 'jpype_demo', 'note': 'Direct method calls possible'}
            
        except ImportError:
            return {'error': 'JPype not installed'}
        except Exception as e:
            return {'error': str(e)}
    
    def method_6_jython_hybrid(self, target_url: str) -> dict:
        """
        Method 6: Jython Hybrid (Run Python on JVM)
        ✅ Pros: Python and Java in same runtime
        ❌ Cons: Jython limitations, version compatibility
        """
        print("🔄 Method 6: Jython Hybrid Execution")
        
        # This would require Jython (Python on JVM)
        # and is shown here for completeness
        
        return {
            'status': 'demo',
            'note': 'Jython allows Python-Java hybrid code',
            'example': '''
            from org.example import JavaClass
            java_obj = JavaClass()
            result = java_obj.testSecurity(target_url)
            '''
        }
    
    def _parse_java_output(self, output: str) -> dict:
        """Parse Java output into structured data"""
        vulnerabilities = []
        lines = output.strip().split('\n')
        
        current_vuln = {}
        for line in lines:
            if line.startswith('VULNERABILITY:'):
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {'type': line.split(':', 1)[1].strip()}
            elif line.startswith('SEVERITY:'):
                current_vuln['severity'] = line.split(':', 1)[1].strip()
            elif line.startswith('URL:'):
                current_vuln['url'] = line.split(':', 1)[1].strip()
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return {
            'status': 'success',
            'vulnerabilities_found': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'method': 'java_execution'
        }

def demo_all_methods():
    """Demonstrate all Java execution methods"""
    executor = JavaExecutionMethods()
    target_url = "https://httpbin.org/get"
    
    print("🚀 Java Execution Methods Demo")
    print("=" * 50)
    
    methods = [
        ("Subprocess (Current)", executor.method_1_subprocess),
        ("Streaming with Popen", executor.method_2_popen_with_streaming),
        ("Threading", lambda url: executor.method_3_threading([url])),
        ("Asyncio", executor.method_4_asyncio),
        ("JPype Integration", executor.method_5_jpype_integration),
        ("Jython Hybrid", executor.method_6_jython_hybrid)
    ]
    
    for method_name, method_func in methods:
        print(f"\n📋 {method_name}")
        print("-" * 30)
        
        try:
            result = method_func(target_url)
            
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
            else:
                print(f"✅ Success: {result.get('total_vulnerabilities', 0)} vulnerabilities found")
                if 'vulnerabilities_found' in result:
                    for vuln in result['vulnerabilities_found'][:2]:  # Show first 2
                        print(f"   • {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                        
        except Exception as e:
            print(f"💥 Exception: {e}")

if __name__ == "__main__":
    demo_all_methods()
