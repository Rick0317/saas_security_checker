# ZAP Java Integration Guide

## Overview

This guide explains how to integrate ZAP's comprehensive Java-based security testing capabilities into the SaaS Security Checker. The integration provides advanced vulnerability detection using ZAP's battle-tested scanning engine.

## Architecture

The integration consists of:

1. **Java Security Modules** (`java_security_modules/`)
   - Adapted ZAP scanner classes
   - Comprehensive vulnerability detection
   - Custom security tests

2. **Python Integration Wrapper** (`security_modules/zap_java_integration.py`)
   - Compiles and executes Java modules
   - Provides Python interface
   - Manages configuration and results

3. **Main Orchestrator Integration** (`main.py`)
   - Invokes Java tests alongside Python tests
   - Generates unified reports
   - Provides single-command execution

## Features

### Security Testing Modules

| Module | Description | Vulnerability Types |
|--------|-------------|-------------------|
| **XSS Scanner** | Cross-Site Scripting detection | Reflected XSS, Stored XSS, DOM XSS |
| **SQL Injection Scanner** | Database injection attacks | Boolean-based, Time-based, Union-based, Error-based |
| **Directory Traversal** | File system access attempts | Path traversal, File inclusion, Local file disclosure |
| **Command Injection** | OS command execution | System command injection, Code execution |
| **CSRF Scanner** | Cross-site request forgery | State-changing operations, Token bypass |
| **Information Disclosure** | Data leakage detection | Error messages, Comments, Metadata |
| **Authentication Security** | Auth mechanism testing | Brute force, Weak passwords, Session fixation |
| **Session Management** | Session handling flaws | Cookie security, Session ID strength |

## Prerequisites

### System Requirements

- **Java JDK 8+** (standard Java runtime)
- **Python 3.7+** (for main orchestrator)
- **Linux/macOS/Windows** (cross-platform support)

### Required Dependencies

```bash
# Python dependencies (already included)
pip install -r requirements.txt

# Java development tools
# Ubuntu/Debian:
sudo apt-get install openjdk-11-jdk

# macOS:
brew install openjdk@11

# Windows:
# Download and install Oracle JDK or OpenJDK
```

## Installation

### 1. Simplified Java Compilation

The integration uses a simplified approach that doesn't require ZAP's extensive dependencies:

```bash
# Compile the simplified Java security runner
javac -d java_security_modules/classes java_security_modules/ZapRunner.java
```

This creates a standalone Java security testing module without external dependencies.

### 2. Verify Installation

```bash
# Check compiled classes
ls -la java_security_modules/classes/

# Should show:
# ZapRunner.class

# Test the Java module
java -cp java_security_modules/classes ZapRunner
# Should display usage information
```

### 3. Test Integration

```bash
# Run the demo to verify everything works
python3 demo_zap_integration.py
```

## Configuration

### Basic Configuration

Add to your `config.yaml`:

```yaml
tests:
  zap_java_testing:
    enabled: true
    
    # Individual scanner configuration
    xss_scanner: true
    sql_injection_scanner: true
    directory_traversal_scanner: true
    command_injection_scanner: true
    file_inclusion_scanner: true
    csrf_scanner: true
    information_disclosure_scanner: true
    authentication_scanner: true
    session_management_scanner: true
    ssl_tls_scanner: true
    
    # Scanner-specific options
    attack_strength: "MEDIUM"  # LOW, MEDIUM, HIGH, INSANE
    alert_threshold: "MEDIUM"  # LOW, MEDIUM, HIGH
    timeout: 300  # seconds per scanner
    
    # Threading options
    parallel_scans: true
    max_concurrent_scans: 3
```

### Advanced Configuration

```yaml
tests:
  zap_java_testing:
    enabled: true
    
    # Scanner-specific configurations
    scanners:
      xss_scanner:
        enabled: true
        payloads:
          - basic: true
          - encoded: true
          - context_specific: true
          - waf_bypass: false
        
      sql_injection_scanner:
        enabled: true
        techniques:
          - boolean_based: true
          - time_based: true
          - union_based: true
          - error_based: true
        databases:
          - mysql: true
          - postgresql: true
          - mssql: true
          - oracle: true
        
      directory_traversal_scanner:
        enabled: true
        payloads:
          - basic: true
          - encoded: true
          - double_encoded: false
          - null_byte: true
        
      command_injection_scanner:
        enabled: true
        payloads:
          - basic: true
          - time_based: true
          - os_specific: true
```

## Usage

### Command Line Interface

```bash
# Run all tests including Java modules
python main.py --target https://example.com

# Run only Java-based tests
python main.py --target https://example.com --test zap_java_testing

# List available tests
python main.py --list-tests
```

### Programmatic Usage

```python
from security_modules.zap_java_integration import ZAPJavaIntegration

# Initialize
config = {'tests': {'zap_java_testing': {'enabled': True}}}
tester = ZAPJavaIntegration(config)

# Execute tests
results = tester.run_test("https://example.com", "example.com")
```

## Output Formats

### JSON Output

```json
{
  "status": "completed",
  "target_url": "https://example.com",
  "scan_results": {
    "xss_scanner": {
      "status": "success",
      "vulnerabilities_found": [
        {
          "type": "Reflected Cross-Site Scripting",
          "severity": "HIGH",
          "url": "https://example.com/search",
          "parameter": "q",
          "payload": "<script>alert('XSS')</script>",
          "evidence": "Response contains injected script",
          "cwe": "79",
          "wasc": "8"
        }
      ]
    }
  },
  "summary": {
    "total_modules_run": 10,
    "successful_scans": 8,
    "total_vulnerabilities_found": 3,
    "severity_breakdown": {
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 0,
      "CRITICAL": 0
    }
  }
}
```

### HTML Report

Generates comprehensive HTML reports with:
- Vulnerability details and evidence
- Payload information
- Remediation recommendations
- Statistics and metrics

### Console Output

```
🚀 Starting ZAP Java Security Tests
✅ Java modules compiled successfully
📊 Running 10 security scanners...

🔍 XSS Scanner...                  ✓ Completed (2 vulnerabilities found)
🔍 SQL Injection Scanner...        ✓ Completed (1 vulnerability found)  
🔍 Directory Traversal...          ✓ Completed (0 vulnerabilities found)
🔍 Command Injection...             ✓ Completed (0 vulnerabilities found)
🔍 CSRF Scanner...                 ✓ Completed (1 vulnerability found)
...

📋 Summary: 4 vulnerabilities found across 10 scanners
   🔴 HIGH: 2
   🟡 MEDIUM: 1  
   🟢 LOW: 1
```

## Troubleshooting

### Common Issues

#### Java Not Found
```bash
# Check Java installation
java -version
javac -version

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
```

#### Compilation Errors
```bash
# Clean and recompile
rm -rf java_security_modules/classes/
./compile_java_modules.sh

# Check classpath
echo $CLASSPATH
```

#### Module Not Found
```bash
# Verify compiled classes
ls -la java_security_modules/classes/

# Check Java module availability
python -c "from security_modules.zap_java_integration import ZAPJavaIntegration; print('Success')"
```

### Performance Optimization

#### Concurrent Scanning
```yaml
tests:
  zap_java_testing:
    parallel_scans: true
    max_concurrent_scans: 3
    scanner_timeout: 300
```

#### Resource Management
```yaml
tests:
  zap_java_testing:
    memory_limit: "512m"
    cpu_cores_limit: 2
    disk_cache: true
```

## Security Considerations

### Safe Testing Practices

1. **Authorized Testing Only**: Only test systems you own or have explicit permission
2. **Controlled Environment**: Use isolated test environments when possible
3. **Rate Limiting**: Respect target server limits and resources
4. **Data Privacy**: Ensure compliance with data protection regulations

### Configuration Security

- Store sensitive configuration in encrypted files
- Use environment variables for secrets
- Rotate API keys and tokens regularly
- Implement access controls for test environments

## Advanced Features

### Custom Scanner Development

Create custom Java scanners by extending `AbstractPlugin`:

```java
public class CustomScanner extends AbstractAppParamPlugin {
    @Override
    public int getId() { return 99999; }
    
    @Override
    public String getName() { return "Custom Vulnerability Scanner"; }
    
    @Override
    public void scan() {
        // Your custom scanning logic
    }
}
```

### Integration with CI/CD

```yaml
# .github/workflows/security-test.yml
name: Security Testing
on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Java
        uses: actions/setup-java@v2
        with:
          java-version: '11'
      - name: Compile Java modules
        run: ./compile_java_modules.sh
      - name: Run security tests
        run: python main.py --target ${{ secrets.TEST_TARGET }}
```

## Contributing

### Adding New Scanners

1. Create Java scanner class in `java_security_modules/`
2. Update module mapping in `zap_java_integration.py`
3. Add configuration options
4. Update documentation

### Reporting Issues

- Use GitHub issues for bug reports
- Include system information and error logs
- Provide minimal reproduction cases
- Test with latest Java and Python versions

## Support

### Documentation
- ZAP Documentation: https://www.zaproxy.org/docs/
- OWASP Guidelines: https://owasp.org/
- CWE Database: https://cwe.mitre.org/

### Community
- ZAP User Group: https://groups.google.com/group/zaproxy-users
- GitHub Issues: https://github.com/zaproxy/zaproxy/issues
- Stack Overflow: Tag `zaproxy`

## Changelog

### Version 1.0.0
- Initial integration of ZAP Java scanners
- Support for 10 core vulnerability types
- Python wrapper implementation
- Comprehensive documentation
- Cross-platform compilation support

---

**Note**: This integration leverages ZAP's robust scanning capabilities while providing a unified interface for comprehensive security testing. Always test responsibly and only on systems you own or have permission to test.
