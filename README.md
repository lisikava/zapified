# 🔒 Zapified - Automated Web Application Security Scanner

Zapified is a comprehensive Python-based security scanning tool that integrates OWASP ZAP (Zed Attack Proxy) into your development workflow to identify potential vulnerabilities before deployment.

## ✨ Features

- **Automated Security Scanning**: Spider crawling + active vulnerability scanning
- **Multiple Report Formats**: JSON, HTML, and human-readable summary reports  
- **Enhanced Sample App**: Includes intentional vulnerabilities for testing
- **Configurable Scans**: Customizable spider depth, scan policies, and options
- **Progress Tracking**: Real-time progress monitoring with colored output
- **Comprehensive Logging**: Detailed logs for debugging and audit trails
- **CLI Interface**: Easy-to-use command-line interface with multiple operation modes

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Docker (for running ZAP)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/lisikava/zapified.git
   cd zapified
   ```

2. **Set up Python environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Set up the environment**
   ```bash
   python main.py --setup
   ```

### Running a Complete Scan

1. **Start ZAP Docker container**
   ```bash
   python main.py --start-zap
   ```

2. **In another terminal, start your target application**
   ```bash
   # For the included sample app:
   python main.py --start-app
   
   # Or start your own application on any port
   ```

3. **Run the security scan**
   ```bash
   python main.py --scan http://localhost:5000
   ```

### Quick Demo

For a quick demonstration with the sample vulnerable app:
```bash
# Start ZAP first
python main.py --start-zap

# In another terminal, run the demo
python main.py --quick-demo
```

## 🛠️ Advanced Usage

### Direct Scanner Usage

For more control, use the enhanced `zapify.py` script directly:

```bash
# Basic scan
python zapify.py http://localhost:5000

# Custom configuration
python zapify.py http://localhost:5000 \
  --spider-depth 10 \
  --output-dir custom_reports \
  --zap-url http://localhost:8090 \
  --api-key your-api-key

# Spider-only scan (skip active scanning)
python zapify.py http://localhost:5000 --skip-active-scan
```

### Configuration Options

- `--spider-depth`: Maximum crawling depth (default: 5)
- `--output-dir`: Report output directory (default: reports)
- `--zap-url`: ZAP proxy URL (default: http://localhost:8090)
- `--api-key`: ZAP API key (default: change-me-9203935709)
- `--skip-active-scan`: Perform only spider scanning

## 📊 Reports

Zapified generates multiple report formats:

1. **JSON Report** (`zap_report_TIMESTAMP.json`): Machine-readable detailed results
2. **HTML Report** (`zap_report_TIMESTAMP.html`): Visual report with charts and details
3. **Summary Report** (`security_summary_TIMESTAMP.txt`): Human-readable vulnerability summary

Reports are categorized by risk levels:
- 🔴 **High**: Critical vulnerabilities requiring immediate attention
- 🟡 **Medium**: Important security issues
- 🔵 **Low**: Minor security concerns
- 🟢 **Informational**: Security-related information

## 🧪 Sample Vulnerable Application

The included `sample_app.py` contains intentional vulnerabilities for testing:

- **SQL Injection**: `/search` endpoint with unsafe query construction
- **Cross-Site Scripting (XSS)**: `/reflect` endpoint with unfiltered input reflection
- **Path Traversal**: `/file` endpoint with unrestricted file access
- **Weak Authentication**: `/login` with basic session management
- **Information Disclosure**: `/headers` endpoint exposing request details

**⚠️ Warning**: Never deploy the sample app in production environments!

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Target App    │    │   ZAP Proxy     │    │   Zapified      │
│   (Port 5000)   │◄──►│   (Port 8090)   │◄──►│   Scanner       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Reports       │
                       │ (JSON/HTML/TXT) │
                       └─────────────────┘
```

## 🔧 Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          
      - name: Start ZAP
        run: |
          docker run -d -p 8090:8090 --name zap \
            zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8090 \
            -config api.key=ci-scan-key
          sleep 30
          
      - name: Start application
        run: |
          python your_app.py &
          sleep 10
          
      - name: Run security scan
        run: |
          python zapify.py http://localhost:5000 \
            --api-key ci-scan-key \
            --output-dir security-reports
            
      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: security-reports/
```

## 🐛 Troubleshooting

### Common Issues

**ZAP Connection Failed**
- Ensure Docker is running
- Check if port 8090 is available
- Verify ZAP container is running: `docker ps`

**Target Application Not Accessible**
- Confirm your app is running on the specified port
- Check firewall settings
- Ensure the app accepts connections from localhost

**Scan Takes Too Long**
- Reduce spider depth with `--spider-depth`
- Use `--skip-active-scan` for faster results
- Check ZAP logs for performance issues

**Permission Errors**
- Ensure write permissions for the output directory
- Run with appropriate user permissions
- Check Docker daemon permissions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Always ensure you have proper authorization before scanning any web application. The sample vulnerable application should never be deployed in production environments.

## 🔗 Resources

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Application Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)