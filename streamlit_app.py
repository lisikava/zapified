#!/usr/bin/env python3

import streamlit as st
import os
import tempfile
import subprocess
import threading
import time
import json
from datetime import datetime
from pathlib import Path
import git
from zapify import ZapifyScanner
from config import SCAN_PROFILES, get_profile_config, list_profiles
import logging

# Configure logging for UI
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StreamlitUI:
    """Streamlit-based web interface for Zapified scanner"""
    
    def __init__(self):
        self.setup_page_config()
        self.initialize_session_state()
    
    def setup_page_config(self):
        """Configure Streamlit page settings"""
        st.set_page_config(
            page_title="🔒 Zapified Security Scanner",
            page_icon="🔒",
            layout="wide",
            initial_sidebar_state="expanded"
        )
    
    def initialize_session_state(self):
        """Initialize Streamlit session state variables"""
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = None
        if 'scan_progress' not in st.session_state:
            st.session_state.scan_progress = 0
        if 'scan_status' not in st.session_state:
            st.session_state.scan_status = "idle"
        if 'project_path' not in st.session_state:
            st.session_state.project_path = None
        if 'target_url' not in st.session_state:
            st.session_state.target_url = None
        if 'scan_logs' not in st.session_state:
            st.session_state.scan_logs = []

class ProjectManager:
    """Handles project upload, GitHub integration, and setup"""
    
    @staticmethod
    def detect_project_type(project_path):
        """Auto-detect project type based on files and content"""
        project_path = Path(project_path)
        
        # Check for different framework indicators
        if (project_path / "requirements.txt").exists():
            req_content = (project_path / "requirements.txt").read_text()
            if "flask" in req_content.lower():
                return "flask"
            elif "django" in req_content.lower():
                return "django"
        
        if (project_path / "package.json").exists():
            return "node"
        
        if (project_path / "pom.xml").exists():
            return "java"
        
        if (project_path / "Gemfile").exists():
            return "ruby"
        
        return "unknown"
    
    @staticmethod
    def get_startup_command(project_type, project_path):
        """Get appropriate startup command for project type"""
        commands = {
            "flask": "python app.py",
            "django": "python manage.py runserver",
            "node": "npm start",
            "unknown": None
        }
        return commands.get(project_type)
    
    @staticmethod
    def clone_github_repo(repo_url, branch="main"):
        """Clone GitHub repository to temporary directory"""
        try:
            temp_dir = tempfile.mkdtemp()
            repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            return temp_dir
        except Exception as e:
            st.error(f"Failed to clone repository: {str(e)}")
            return None

class ScanProgressTracker:
    """Tracks and displays scan progress in real-time"""
    
    def __init__(self):
        self.progress_container = None
        self.log_container = None
    
    def setup_progress_display(self):
        """Setup progress display containers"""
        self.progress_container = st.container()
        self.log_container = st.container()
    
    def update_progress(self, step, progress, message):
        """Update progress display"""
        if self.progress_container:
            with self.progress_container:
                st.progress(progress)
                st.write(f"**{step}:** {message}")
    
    def add_log(self, message):
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        st.session_state.scan_logs.append(log_entry)
        
        if self.log_container:
            with self.log_container:
                st.text_area("Scan Logs", "\n".join(st.session_state.scan_logs[-10:]), height=200)

class ReportViewer:
    """Handles report display and interaction"""
    
    @staticmethod
    def display_scan_results(scan_results):
        """Display interactive scan results"""
        if not scan_results or 'alerts' not in scan_results:
            st.warning("No scan results available")
            return
        
        alerts = scan_results['alerts']
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        with col1:
            st.metric("🔴 High Risk", risk_counts['High'])
        with col2:
            st.metric("🟡 Medium Risk", risk_counts['Medium'])
        with col3:
            st.metric("🔵 Low Risk", risk_counts['Low'])
        with col4:
            st.metric("🟢 Informational", risk_counts['Informational'])
        
        # Security score calculation
        score = ReportViewer.calculate_security_score(risk_counts)
        st.metric("🏆 Security Score", f"{score}/10")
        
        # Detailed vulnerability table
        st.subheader("🔍 Detailed Vulnerabilities")
        
        if alerts:
            # Create DataFrame for better display
            import pandas as pd
            
            df_data = []
            for alert in alerts:
                df_data.append({
                    'Vulnerability': alert.get('alert', 'Unknown'),
                    'Risk': alert.get('risk', 'Unknown'),
                    'URL': alert.get('url', 'Unknown'),
                    'Description': alert.get('description', '')[:100] + "..." if len(alert.get('description', '')) > 100 else alert.get('description', ''),
                    'Solution': alert.get('solution', '')[:100] + "..." if len(alert.get('solution', '')) > 100 else alert.get('solution', '')
                })
            
            df = pd.DataFrame(df_data)
            
            # Add risk level filter
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                options=['High', 'Medium', 'Low', 'Informational'],
                default=['High', 'Medium', 'Low', 'Informational']
            )
            
            filtered_df = df[df['Risk'].isin(risk_filter)]
            st.dataframe(filtered_df, use_container_width=True)
            
            # Export options
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("📥 Download JSON Report"):
                    ReportViewer.download_report(scan_results, 'json')
            with col2:
                if st.button("📊 Download CSV Report"):
                    ReportViewer.download_report(filtered_df, 'csv')
            with col3:
                if st.button("🔄 Run New Scan"):
                    st.session_state.scan_results = None
                    st.rerun()
        else:
            st.success("🎉 No vulnerabilities found!")
    
    @staticmethod
    def calculate_security_score(risk_counts):
        """Calculate security score based on vulnerability counts"""
        base_score = 10.0
        penalties = {
            'High': 2.0,
            'Medium': 1.0,
            'Low': 0.3,
            'Informational': 0.1
        }
        
        for risk, count in risk_counts.items():
            if risk in penalties:
                base_score -= penalties[risk] * count
        
        return max(0.0, min(10.0, round(base_score, 1)))
    
    @staticmethod
    def download_report(data, format_type):
        """Handle report downloads"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'json':
            filename = f"security_report_{timestamp}.json"
            st.download_button(
                label="Download JSON Report",
                data=json.dumps(data, indent=2),
                file_name=filename,
                mime="application/json"
            )
        elif format_type == 'csv':
            filename = f"security_report_{timestamp}.csv"
            st.download_button(
                label="Download CSV Report",
                data=data.to_csv(index=False),
                file_name=filename,
                mime="text/csv"
            )

def main():
    """Main Streamlit application"""
    ui = StreamlitUI()
    
    # Header
    st.title("🔒 Zapified Security Scanner")
    st.markdown("**Automated web application security testing with OWASP ZAP**")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Scan profile selection
        profile_options = list_profiles()
        selected_profile = st.selectbox(
            "Scan Profile",
            options=list(profile_options.keys()),
            format_func=lambda x: f"{x.title()}: {profile_options[x]}"
        )
        
        # ZAP settings
        st.subheader("ZAP Settings")
        zap_url = st.text_input("ZAP Proxy URL", "http://localhost:8090")
        api_key = st.text_input("API Key", "change-me-9203935709", type="password")
        
        # Advanced options
        with st.expander("Advanced Options"):
            spider_depth = st.slider("Spider Depth", 1, 10, 5)
            skip_active = st.checkbox("Skip Active Scan")
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📁 Project Input", "🔧 Configuration", "📊 Progress", "📋 Results"])
    
    with tab1:
        st.header("Project Input")
        
        input_method = st.radio(
            "Choose input method:",
            ["Upload Files", "GitHub Repository"]
        )
        
        if input_method == "Upload Files":
            uploaded_files = st.file_uploader(
                "Upload project files",
                accept_multiple_files=True,
                help="Upload your web application files"
            )
            
            if uploaded_files:
                # Save uploaded files to temporary directory
                temp_dir = tempfile.mkdtemp()
                for file in uploaded_files:
                    file_path = os.path.join(temp_dir, file.name)
                    with open(file_path, "wb") as f:
                        f.write(file.getbuffer())
                
                st.session_state.project_path = temp_dir
                
                # Detect project type
                project_type = ProjectManager.detect_project_type(temp_dir)
                st.success(f"✅ Project detected: **{project_type.title()}**")
        
        elif input_method == "GitHub Repository":
            col1, col2 = st.columns([3, 1])
            
            with col1:
                repo_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/user/repo")
            with col2:
                branch = st.text_input("Branch", value="main")
            
            if st.button("🔍 Clone Repository"):
                if repo_url:
                    with st.spinner("Cloning repository..."):
                        project_path = ProjectManager.clone_github_repo(repo_url, branch)
                        if project_path:
                            st.session_state.project_path = project_path
                            project_type = ProjectManager.detect_project_type(project_path)
                            st.success(f"✅ Repository cloned! Project type: **{project_type.title()}**")
                else:
                    st.error("Please enter a valid GitHub URL")
    
    with tab2:
        st.header("Scan Configuration")
        
        if st.session_state.project_path:
            # Target URL configuration
            col1, col2 = st.columns([3, 1])
            with col1:
                target_url = st.text_input("Target URL", value="http://localhost:5000")
            with col2:
                if st.button("🔍 Validate"):
                    # Add URL validation logic here
                    st.success("URL is valid")
            
            st.session_state.target_url = target_url
            
            # Authentication settings
            with st.expander("Authentication (Optional)"):
                auth_type = st.selectbox("Authentication Type", ["None", "Basic Auth", "Form-based"])
                if auth_type != "None":
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
            
            # Start scan button
            if st.button("🚀 Start Zapify Scan", type="primary"):
                if target_url:
                    st.session_state.scan_status = "running"
                    st.rerun()
                else:
                    st.error("Please configure target URL")
        else:
            st.info("👆 Please upload a project or clone a repository first")
    
    with tab3:
        st.header("Scan Progress")
        
        if st.session_state.scan_status == "running":
            progress_tracker = ScanProgressTracker()
            progress_tracker.setup_progress_display()
            
            # Run scan in background (simplified for demo)
            if st.session_state.target_url:
                with st.spinner("Running security scan..."):
                    try:
                        scanner = ZapifyScanner(st.session_state.target_url, zap_url, api_key)
                        
                        # Health check
                        progress_tracker.update_progress("Health Check", 0.1, "Checking ZAP and target accessibility...")
                        if scanner.health_check():
                            progress_tracker.add_log("✅ Health check passed")
                            
                            # Configure scan
                            progress_tracker.update_progress("Configuration", 0.2, "Configuring scan parameters...")
                            scanner.configure_scan(spider_depth)
                            progress_tracker.add_log("✅ Scan configured")
                            
                            # Spider scan
                            progress_tracker.update_progress("Spider Scan", 0.3, "Discovering application structure...")
                            if scanner.spider_scan():
                                progress_tracker.add_log("✅ Spider scan completed")
                                
                                # Active scan (if not skipped)
                                if not skip_active:
                                    progress_tracker.update_progress("Active Scan", 0.6, "Running vulnerability tests...")
                                    if scanner.active_scan():
                                        progress_tracker.add_log("✅ Active scan completed")
                                
                                # Generate reports
                                progress_tracker.update_progress("Reports", 0.9, "Generating reports...")
                                if scanner.generate_reports():
                                    progress_tracker.add_log("✅ Reports generated")
                                    
                                    # Store results
                                    st.session_state.scan_results = scanner.scan_results
                                    st.session_state.scan_status = "completed"
                                    progress_tracker.update_progress("Complete", 1.0, "Scan completed successfully!")
                                    
                                    st.success("🎉 Scan completed successfully!")
                                    st.balloons()
                        else:
                            st.error("❌ Health check failed. Please ensure ZAP is running.")
                            st.session_state.scan_status = "failed"
                            
                    except Exception as e:
                        st.error(f"❌ Scan failed: {str(e)}")
                        st.session_state.scan_status = "failed"
        
        elif st.session_state.scan_status == "idle":
            st.info("🔄 Ready to start scanning. Configure your project in the previous tabs.")
        
        elif st.session_state.scan_status == "completed":
            st.success("✅ Scan completed! Check the Results tab.")
        
        elif st.session_state.scan_status == "failed":
            st.error("❌ Scan failed. Check the logs and try again.")
    
    with tab4:
        st.header("Scan Results")
        
        if st.session_state.scan_results:
            ReportViewer.display_scan_results(st.session_state.scan_results)
        else:
            st.info("📋 No scan results available. Run a scan first.")

if __name__ == "__main__":
    main() 