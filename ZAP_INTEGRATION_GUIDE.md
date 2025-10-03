# 🕷️ ZAP (Zed Attack Proxy) Integration Guide

## Overview

This guide shows how to integrate OWASP ZAP (Zed Attack Proxy) with your SaaS Security Checker for comprehensive web application security testing. ZAP provides advanced vulnerability detection capabilities that complement our existing security tests.

## 🚀 **What ZAP Adds to Your Security Testing**

### **Advanced Vulnerability Detection:**
- **OWASP Top 10** vulnerabilities
- **SQL Injection** (advanced detection)
- **Cross-Site Scripting (XSS)**
- **Cross-Site Request Forgery (CSRF)**
- **Security Misconfigurations**
- **Sensitive Data Exposure**
- **Broken Authentication**
- **Insecure Direct Object References**
- **Security Headers** analysis
- **SSL/TLS** configuration issues

### **Comprehensive Scanning:**
- **Spider crawling** to discover all endpoints
- **Active scanning** with 100+ vulnerability checks
- **Passive scanning** for real-time analysis
- **AJAX Spider** for modern web applications
- **Authentication** support for protected areas

## 📋 **Prerequisites**

### **1. Install ZAP**
```bash
# Download ZAP from https://www.zaproxy.org/download/
# Or use package manager

# Ubuntu/Debian
sudo apt-get install zaproxy

# macOS
brew install zaproxy

# Windows
# Download from https://www.zaproxy.org/download/
```

### **2. Start ZAP**
```bash
# Start ZAP in daemon mode (headless)
zap.sh -daemon -host 0.0.0.0 -port 8080

# Or start with API key for security
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=your-api-key
```

### **3. Verify ZAP is Running**
```bash
# Check if ZAP is accessible
curl http://localhost:8080/JSON/core/view/version/

# Expected response:
{"version":"2.12.0"}
```

## ⚙️ **Configuration**

### **1. Update config.yaml**
```yaml
# ZAP Integration
zap_integration:
  enabled: true
  host: "localhost"
  port: 8080
  api_key: ""  # Optional, for security
  run_spider: true
  run_active_scan: true
  scan_policy: "Default Policy"
  max_scan_duration: 3600  # 1 hour
```

### **2. Environment Variables (Optional)**
```bash
export ZAP_HOST=localhost
export ZAP_PORT=8080
export ZAP_API_KEY=your-secure-api-key
```

## 🔧 **Usage**

### **1. Basic ZAP Testing**
```bash
# Run ZAP integration test
uv run python main.py --target https://stg.archaive.jp/ --test zap_integration
```

### **2. Full Security Suite with ZAP**
```bash
# Run all tests including ZAP
uv run python main.py --target https://stg.archaive.jp/
```

### **3. Programmatic Usage**
```python
from main import SecurityTestOrchestrator

# Initialize orchestrator
orchestrator = SecurityTestOrchestrator("config.yaml")
orchestrator.config['target']['url'] = "https://stg.archaive.jp/"

# Run ZAP test
zap_results = orchestrator.run_single_test('zap_integration')

# Check results
print(f"ZAP Version: {zap_results['zap_version']}")
print(f"Vulnerabilities found: {len(zap_results['vulnerabilities'])}")

for vuln in zap_results['vulnerabilities']:
    print(f"- {vuln['type']}: {vuln['description']}")
    print(f"  Severity: {vuln['severity']}")
    print(f"  URL: {vuln['url']}")
```

## 📊 **Understanding ZAP Results**

### **Vulnerability Types:**
- **High Risk**: Critical vulnerabilities requiring immediate attention
- **Medium Risk**: Important vulnerabilities that should be addressed
- **Low Risk**: Minor issues that can be fixed over time
- **Informational**: Best practices and recommendations

### **Common ZAP Findings:**

#### **1. SQL Injection**
```json
{
  "type": "SQL Injection",
  "severity": "Critical",
  "description": "SQL injection vulnerability detected",
  "url": "https://stg.archaive.jp/api/search",
  "parameter": "q",
  "solution": "Use parameterized queries"
}
```

#### **2. Cross-Site Scripting (XSS)**
```json
{
  "type": "Cross Site Scripting (Reflected)",
  "severity": "High",
  "description": "XSS vulnerability in search parameter",
  "url": "https://stg.archaive.jp/search",
  "parameter": "query",
  "solution": "Implement proper input validation and output encoding"
}
```

#### **3. Security Headers**
```json
{
  "type": "Missing Anti-clickjacking Header",
  "severity": "Medium",
  "description": "X-Frame-Options header is missing",
  "url": "https://stg.archaive.jp/",
  "solution": "Add X-Frame-Options header"
}
```

## 🛠️ **Advanced Configuration**

### **1. Custom Scan Policies**
```python
# Get available policies
zap = ZAPIntegration(config)
policies = zap.get_scan_policies()

# Set custom policy
zap.set_scan_policy("High Security Policy")
```

### **2. Enable/Disable Specific Scanners**
```python
# Get available scanners
scanners = zap.get_scanners()

# Enable specific scanner
zap.enable_scanner("10045")  # SQL Injection scanner

# Disable specific scanner
zap.disable_scanner("10021")  # XSS scanner
```

### **3. Authentication Support**
```yaml
# Add authentication to config.yaml
zap_integration:
  authentication:
    enabled: true
    method: "form"
    login_url: "https://stg.archaive.jp/login"
    username_field: "username"
    password_field: "password"
    username: "test@example.com"
    password: "testpassword"
```

## 🔍 **ZAP API Endpoints Used**

Based on the [ZAP API documentation](https://www.zaproxy.org/docs/api/?python#basics-on-the-api-request), our integration uses:

### **Core API:**
- `GET /JSON/core/view/version/` - Get ZAP version
- `GET /JSON/core/action/accessUrl/` - Set target URL

### **Spider API:**
- `GET /JSON/spider/action/scan/` - Start spider scan
- `GET /JSON/spider/view/status/` - Get spider progress
- `GET /JSON/spider/view/results/` - Get spider results

### **Active Scan API:**
- `GET /JSON/ascan/action/scan/` - Start active scan
- `GET /JSON/ascan/view/status/` - Get scan progress
- `GET /JSON/ascan/view/policies/` - Get scan policies
- `GET /JSON/ascan/view/scanners/` - Get available scanners

### **Alert API:**
- `GET /JSON/alert/view/alerts/` - Get all alerts
- `GET /JSON/alert/view/numberOfAlerts/` - Get alert count

## 📈 **Performance Considerations**

### **Scan Duration:**
- **Spider**: 5-15 minutes (depending on site size)
- **Active Scan**: 30-60 minutes (depending on complexity)
- **Total**: 1-2 hours for comprehensive scan

### **Resource Usage:**
- **Memory**: 2-4GB RAM recommended
- **CPU**: Moderate usage during scanning
- **Network**: High bandwidth during active scanning

### **Optimization Tips:**
```yaml
# Optimize for faster scanning
zap_integration:
  max_scan_duration: 1800  # 30 minutes
  scan_policy: "Lightweight Policy"
  exclude_patterns:
    - "*.css"
    - "*.js"
    - "*.png"
    - "*.jpg"
```

## 🚨 **Security Considerations**

### **1. API Key Security**
```bash
# Use API key for production
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=secure-random-key
```

### **2. Network Security**
```bash
# Bind to localhost only
zap.sh -daemon -host 127.0.0.1 -port 8080
```

### **3. Firewall Rules**
```bash
# Allow only local connections
iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

## 🔄 **CI/CD Integration**

### **1. GitHub Actions**
```yaml
name: Security Testing with ZAP
on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Start ZAP
        run: |
          docker run -d -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080
          sleep 30
      
      - name: Run Security Tests
        run: |
          uv run python main.py --target ${{ env.TARGET_URL }} --test zap_integration
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: ./reports/
```

### **2. Docker Integration**
```dockerfile
# Dockerfile for ZAP integration
FROM python:3.9-slim

# Install ZAP
RUN apt-get update && apt-get install -y zaproxy

# Copy application
COPY . /app
WORKDIR /app

# Install dependencies
RUN pip install -r requirements.txt

# Start ZAP and run tests
CMD zap.sh -daemon -host 0.0.0.0 -port 8080 && \
    python main.py --target $TARGET_URL --test zap_integration
```

## 📋 **Troubleshooting**

### **Common Issues:**

#### **1. ZAP Not Accessible**
```bash
# Check if ZAP is running
ps aux | grep zap

# Check port
netstat -tlnp | grep 8080

# Restart ZAP
zap.sh -daemon -host 0.0.0.0 -port 8080
```

#### **2. Scan Timeout**
```yaml
# Increase timeout in config.yaml
zap_integration:
  max_scan_duration: 7200  # 2 hours
```

#### **3. Memory Issues**
```bash
# Increase ZAP memory
export ZAP_JVM_OPTS="-Xmx4g"
zap.sh -daemon -host 0.0.0.0 -port 8080
```

## 🎯 **Best Practices**

### **1. Regular Scanning**
- Run ZAP scans weekly
- Include in CI/CD pipeline
- Monitor for new vulnerabilities

### **2. Scan Coverage**
- Test all environments (dev, staging, production)
- Include authentication flows
- Test API endpoints

### **3. Result Analysis**
- Prioritize critical vulnerabilities
- Track remediation progress
- Document security improvements

### **4. Integration with Other Tools**
- Combine with SAST tools
- Use with dependency scanners
- Integrate with monitoring systems

## 📚 **Additional Resources**

- [ZAP Official Documentation](https://www.zaproxy.org/docs/)
- [ZAP API Reference](https://www.zaproxy.org/docs/api/?python#basics-on-the-api-request)
- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/desktop/)
- [ZAP Docker Images](https://hub.docker.com/r/owasp/zap2docker-stable)

## 🎉 **Conclusion**

ZAP integration significantly enhances your security testing capabilities by providing:

- **Comprehensive vulnerability detection**
- **OWASP Top 10 coverage**
- **Advanced scanning techniques**
- **Professional-grade security testing**
- **Integration with existing tools**

The combination of your custom security tests and ZAP's advanced capabilities provides a complete security testing solution for your SaaS application.

