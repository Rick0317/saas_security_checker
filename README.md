# SaaS Security Checker

A comprehensive security testing tool that combines multiple security testing techniques into a single run for SaaS applications.

## Features

- **SQL Injection Testing** - Uses SQLMap for comprehensive SQL injection detection
- **Port Discovery** - nmap-based port scanning and service detection
- **DNS Security Analysis** - Comprehensive DNS checks including subdomain enumeration
- **HTTP Headers Analysis** - Security header validation and misconfiguration detection
- **TLS/SSL Security** - Certificate analysis and TLS configuration validation
- **Web Application Scanning** - Directory discovery and vulnerability scanning
- **Dependency Security** - Supply chain security and vulnerable dependency detection
- **Authentication Security** - Login security, session management, and auth bypass testing
- **Password Strength Analysis** - Password policy validation and strength testing
- **Packet Sniffing Prevention** - Network security analysis and packet sniffing prevention
- **DNS Hijacking Prevention** - Comprehensive DNS security analysis and hijacking prevention

## Installation

### Quick Install (Recommended with uv)

```bash
# Clone the repository
git clone <repository-url>
cd saas_security_checker

# Run the installation script (installs uv and dependencies)
chmod +x install.sh
./install.sh
```

### Manual Installation with uv

1. **Install uv (if not already installed):**
   ```bash
   # macOS/Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh
   
   # Or with pip
   pip install uv
   ```

2. **Install Dependencies:**
   ```bash
   # Install Python dependencies with uv
   uv sync
   
   # System tools (macOS with Homebrew)
   brew install nmap nikto
   
   # System tools (Ubuntu/Debian)
   sudo apt-get install nmap nikto
   ```

3. **Install SQLMap:**
   ```bash
   git clone https://github.com/sqlmapproject/sqlmap.git
   ```

4. **Create directories:**
   ```bash
   mkdir -p reports logs
   ```

### Traditional pip Installation

1. **Install Dependencies:**
   ```bash
   # Python dependencies
   pip install -r requirements.txt
   
   # System tools (macOS with Homebrew)
   brew install nmap nikto
   
   # System tools (Ubuntu/Debian)
   sudo apt-get install nmap nikto python3-pip
   ```

2. **Install SQLMap:**
   ```bash
   git clone https://github.com/sqlmapproject/sqlmap.git
   ```

3. **Create directories:**
   ```bash
   mkdir -p reports logs
   ```

## Usage

### Basic Usage

```bash
# Run all tests on a target (with uv)
uv run python main.py --target https://example.com

# Run specific test only
uv run python main.py --target https://example.com --test sql_injection

# List available tests
uv run python main.py --list-tests

# Use custom configuration
uv run python main.py --target https://example.com --config custom_config.yaml

# Run examples
uv run python example.py
```

### Traditional Python Usage

```bash
# Run all tests on a target
python3 main.py --target https://example.com

# Run specific test only
python3 main.py --target https://example.com --test sql_injection

# List available tests
python3 main.py --list-tests

# Use custom configuration
python3 main.py --target https://example.com --config custom_config.yaml
```

### Configuration

Edit `config.yaml` to customize test parameters:

```yaml
target:
  url: "https://example.com"
  timeout: 30

tests:
  sql_injection:
    enabled: true
    risk_level: 3
  port_discovery:
    enabled: true
    ports: "1-1000"
  # ... other tests

output:
  format: ["json", "html", "console"]
  directory: "./reports"
```

### Command Line Options

- `--target, -t`: Target URL to test
- `--config, -c`: Configuration file path (default: config.yaml)
- `--test`: Run specific test only
- `--list-tests`: List available tests
- `--help`: Show help message

## Test Modules

### 1. SQL Injection Testing
- Uses SQLMap for comprehensive SQL injection detection
- Tests various injection techniques (Boolean, Error, Union, etc.)
- Configurable risk levels and test parameters

### 2. Port Discovery
- nmap-based port scanning
- Service version detection
- SSL/TLS specific scanning
- Vulnerability script execution

### 3. DNS Security
- DNS record analysis
- Subdomain enumeration
- DNS security checks (SPF, DMARC, DKIM)
- Reverse DNS lookup

### 4. HTTP Headers Analysis
- Security header validation
- Information disclosure detection
- Cookie security analysis
- Missing security headers identification

### 5. TLS/SSL Security
- Certificate analysis
- TLS configuration validation
- Protocol and cipher strength testing
- Certificate transparency checks

### 6. Web Application Scanning
- Directory and file discovery
- Form analysis and testing
- Technology detection
- Common vulnerability checks

### 7. Dependency Security
- Package manager file analysis
- Vulnerable dependency detection
- Supply chain security assessment
- CDN and external resource analysis

### 8. Authentication Security
- Login form analysis
- Session security validation
- Authentication bypass testing
- Brute force protection testing

### 9. Password Strength Analysis
- Password policy validation
- Strength testing
- Common password detection
- Policy compliance checking

### 10. Packet Sniffing Prevention
- Network security analysis
- Encryption implementation validation
- DNS over HTTPS/TLS checking
- Network segmentation analysis
- Protocol security assessment
- Perfect Forward Secrecy validation

### 11. DNS Hijacking Prevention
- DNS configuration analysis
- Hijacking indicators detection
- Resolution consistency testing
- DNSSEC validation
- Cache poisoning detection
- Encrypted DNS testing

## Output Formats

### JSON Report
Detailed machine-readable report with all findings:
```bash
python3 main.py --target https://example.com
# Generates: reports/security_report_YYYYMMDD_HHMMSS.json
```

### HTML Report
Visual HTML report with charts and detailed analysis:
```bash
python3 main.py --target https://example.com
# Generates: reports/security_report_YYYYMMDD_HHMMSS.html
```

### Console Output
Real-time console output with progress indicators:
```bash
python3 main.py --target https://example.com
# Displays results in terminal with Rich formatting
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorization**: Only test systems you own or have explicit permission to test
2. **Intrusive Tests**: Some tests may be intrusive and could affect system performance
3. **Rate Limiting**: The tool includes rate limiting, but be respectful of target systems
4. **Legal Compliance**: Ensure compliance with local laws and regulations
5. **Staging Environment**: Test in staging environments before production

## Troubleshooting

### Common Issues

1. **SQLMap not found:**
   ```bash
   # Ensure SQLMap is installed and in PATH
   git clone https://github.com/sqlmapproject/sqlmap.git
   export PATH=$PATH:$(pwd)/sqlmap
   ```

2. **nmap permission issues:**
   ```bash
   # On Linux, nmap may require sudo for certain scans
   sudo nmap -sS target.com
   ```

3. **Python dependencies:**
   ```bash
   # Install missing dependencies
   pip install -r requirements.txt
   ```

4. **SSL certificate warnings:**
   ```bash
   # The tool disables SSL verification for testing
   # This is intentional for security testing purposes
   ```

### Log Files

Check the `logs/` directory for detailed error information and debugging output.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any system.

## Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the configuration options

---

**Happy Security Testing! 🔒**
