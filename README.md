#  Zapified - Automated Web Application Security Scanner

Zapified is a comprehensive Python-based security scanning tool that integrates OWASP ZAP (Zed Attack Proxy) into your development workflow to identify potential vulnerabilities before deployment.

##  Features

- **Automated Security Scanning**: Spider crawling + active vulnerability scanning
- **Multiple Report Formats**: JSON, HTML, and human-readable summary reports  
- **Enhanced Sample App**: Includes intentional vulnerabilities for testing
- **Configurable Scans**: Customizable spider depth, scan policies, and options
- **Progress Tracking**: Real-time progress monitoring with colored output
- **Comprehensive Logging**: Detailed logs for debugging and audit trails
- **CLI Interface**: Easy-to-use command-line interface with multiple operation modes

##  Quick Start

### Prerequisites
- Python 3.11+
- Docker (for running ZAP)
- Git

### Installation

1. **Set up Python environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt or uv sync
   ```

3. **Start a Zap Docker Container**
   ```bash
   sudo docker run -u zap -p 8090:8090 --network="host" -i zaproxy/zap-stable  zap.sh -daemon -host 0.0.0.0 -port 8090   -config api.addrs.addr.name=.*   -config api.addrs.addr.regex=true -config api.key=change-me-9203935709
   ```

3. **Run the ui app**
   ```bash
   streamlit run streamlit_app.py 
   ```
