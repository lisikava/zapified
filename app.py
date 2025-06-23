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
from ui_components import UIComponents, ProjectDetector, ScanManager, ReportExporter
import logging

# Configure logging for Streamlit
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Streamlit page configuration
st.set_page_config(
    page_title="🔒 Zapified Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    defaults = {
        'scan_results': None,
        'scan_progress': 0,
        'scan_status': "idle",  # idle, running, completed, failed
        'project_path': None,
        'target_url': None,
        'scan_logs': [],
        'project_info': None,
        'scan_manager': ScanManager()
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def handle_file_upload():
    """Handle file upload functionality"""
    st.header("📁 Project Upload")
    
    uploaded_files = st.file_uploader(
        "Upload your web application files",
        accept_multiple_files=True,
        help="Upload your project files to scan for security vulnerabilities"
    )
    
    if uploaded_files:
        # Save uploaded files to temporary directory
        temp_dir = tempfile.mkdtemp()
        
        for file in uploaded_files:
            file_path = os.path.join(temp_dir, file.name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(file.getbuffer())
        
        st.session_state.project_path = temp_dir
        
        # Detect project type
        project_info = ProjectDetector.detect_project_type(temp_dir)
        st.session_state.project_info = project_info
        
        st.success(f"✅ **{len(uploaded_files)} files uploaded!**")
        st.info(f"🔍 **Detected project type:** {project_info['type'].title()}")
        
        if project_info['confidence'] == 'high':
            st.success(f"🚀 **Suggested startup command:** `{project_info['startup_cmd']}`")
            st.session_state.target_url = f"http://localhost:{project_info['default_port']}"
        else:
            st.warning("⚠️ Project type detection has low confidence. Manual configuration may be needed.")

def handle_github_integration():
    """Handle GitHub repository integration"""
    st.header("🐙 GitHub Repository")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        repo_url = st.text_input(
            "Repository URL", 
            placeholder="https://github.com/username/repository",
            help="Enter the GitHub repository URL to clone and scan"
        )
    
    with col2:
        branch = st.text_input("Branch", value="main")
    
    if st.button("🔄 Clone Repository", type="primary"):
        if repo_url:
            with st.spinner("Cloning repository..."):
                try:
                    temp_dir = tempfile.mkdtemp()
                    repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch)
                    
                    st.session_state.project_path = temp_dir
                    
                    # Detect project type
                    project_info = ProjectDetector.detect_project_type(temp_dir)
                    st.session_state.project_info = project_info
                    
                    st.success(f"✅ **Repository cloned successfully!**")
                    st.info(f"🔍 **Detected project type:** {project_info['type'].title()}")
                    
                    if project_info['confidence'] == 'high':
                        st.success(f"🚀 **Suggested startup command:** `{project_info['startup_cmd']}`")
                        st.session_state.target_url = f"http://localhost:{project_info['default_port']}"
                    
                except Exception as e:
                    st.error(f"❌ Failed to clone repository: {str(e)}")
        else:
            st.error("Please enter a valid GitHub repository URL")

def handle_scan_configuration():
    """Handle scan configuration"""
    st.header("⚙️ Scan Configuration")
    
    if not st.session_state.project_path:
        st.info("👆 Please upload a project or clone a repository first")
        return False
    
    # Display project information
    if st.session_state.project_info:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Project Type", st.session_state.project_info['type'].title())
        with col2:
            st.metric("Detection Confidence", st.session_state.project_info['confidence'].title())
        with col3:
            st.metric("Default Port", st.session_state.project_info['default_port'])
    
    # Target URL configuration
    st.subheader("🎯 Target Configuration")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        target_url = st.text_input(
            "Target URL", 
            value=st.session_state.target_url or "http://localhost:5000",
            help="URL of the running application to scan"
        )
        st.session_state.target_url = target_url
    
    with col2:
        if st.button("🔍 Validate URL"):
            # Add URL validation logic here
            try:
                import requests
                response = requests.get(target_url, timeout=5)
                if response.status_code == 200:
                    st.success("✅ URL is accessible")
                else:
                    st.warning(f"⚠️ URL returned status code: {response.status_code}")
            except Exception as e:
                st.error(f"❌ URL validation failed: {str(e)}")
    
    # Authentication configuration
    with st.expander("🔐 Authentication (Optional)"):
        auth_type = st.selectbox("Authentication Type", ["None", "Basic Auth", "Form-based"])
        
        if auth_type == "Basic Auth":
            col1, col2 = st.columns(2)
            with col1:
                username = st.text_input("Username")
            with col2:
                password = st.text_input("Password", type="password")
        
        elif auth_type == "Form-based":
            login_url = st.text_input("Login URL")
            username_field = st.text_input("Username Field Name", value="username")
            password_field = st.text_input("Password Field Name", value="password")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
    
    return True

def handle_scan_execution():
    """Handle scan execution"""
    st.header("🚀 Scan Execution")
    
    if not st.session_state.target_url:
        st.error("Please configure the target URL first")
        return
    
    # Scan controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔥 Start Security Scan", type="primary", disabled=st.session_state.scan_status == "running"):
            st.session_state.scan_status = "running"
            st.session_state.scan_logs = []
            st.rerun()
    
    with col2:
        if st.button("⏹️ Stop Scan", disabled=st.session_state.scan_status != "running"):
            st.session_state.scan_status = "idle"
            st.rerun()
    
    with col3:
        if st.button("🔄 Reset", disabled=st.session_state.scan_status == "running"):
            st.session_state.scan_status = "idle"
            st.session_state.scan_results = None
            st.session_state.scan_logs = []
            st.rerun()
    
    # Progress display
    if st.session_state.scan_status == "running":
        run_security_scan()
    elif st.session_state.scan_status == "completed":
        st.success("✅ Scan completed successfully!")
        st.balloons()
    elif st.session_state.scan_status == "failed":
        st.error("❌ Scan failed. Check the logs for details.")

def run_security_scan():
    """Execute the security scan"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    log_container = st.container()
    
    try:
        # Get scan configuration from sidebar
        profile = st.session_state.get('selected_profile', 'standard')
        zap_url = st.session_state.get('zap_url', 'http://localhost:8090')
        api_key = st.session_state.get('api_key', 'change-me-9203935709')
        
        # Initialize scanner
        scanner = ZapifyScanner(st.session_state.target_url, zap_url, api_key)
        
        # Health check
        status_text.text("🔍 Performing health check...")
        progress_bar.progress(0.1)
        
        if not scanner.health_check():
            st.error("❌ Health check failed. Ensure ZAP is running and target is accessible.")
            st.session_state.scan_status = "failed"
            return
        
        st.session_state.scan_logs.append("✅ Health check passed")
        
        # Configure scan
        status_text.text("⚙️ Configuring scan parameters...")
        progress_bar.progress(0.2)
        
        config = get_profile_config(profile)
        scanner.configure_scan(spider_max_depth=config.spider_max_depth)
        st.session_state.scan_logs.append("✅ Scan configured")
        
        # Spider scan
        status_text.text("🕷️ Running spider scan...")
        progress_bar.progress(0.3)
        
        if scanner.spider_scan():
            st.session_state.scan_logs.append("✅ Spider scan completed")
            progress_bar.progress(0.6)
        else:
            st.error("❌ Spider scan failed")
            st.session_state.scan_status = "failed"
            return
        
        # Active scan
        status_text.text("🔥 Running active vulnerability scan...")
        progress_bar.progress(0.7)
        
        skip_active = st.session_state.get('skip_active_scan', False)
        if not skip_active:
            if scanner.active_scan():
                st.session_state.scan_logs.append("✅ Active scan completed")
                progress_bar.progress(0.9)
            else:
                st.error("❌ Active scan failed")
                st.session_state.scan_status = "failed"
                return
        
        # Generate reports
        status_text.text("📊 Generating reports...")
        progress_bar.progress(0.95)
        
        if scanner.generate_reports():
            st.session_state.scan_logs.append("✅ Reports generated")
            st.session_state.scan_results = scanner.scan_results
            st.session_state.scan_status = "completed"
            progress_bar.progress(1.0)
            status_text.text("🎉 Scan completed successfully!")
        else:
            st.error("❌ Report generation failed")
            st.session_state.scan_status = "failed"
    
    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")
        st.session_state.scan_logs.append(f"❌ Error: {str(e)}")
        st.session_state.scan_status = "failed"
    
    # Display logs
    with log_container:
        if st.session_state.scan_logs:
            st.text_area("📋 Scan Logs", "\n".join(st.session_state.scan_logs), height=200)

def handle_results_display():
    """Handle results display"""
    st.header("📊 Scan Results")
    
    if not st.session_state.scan_results:
        st.info("🔄 No scan results available. Run a scan first.")
        return
    
    alerts = st.session_state.scan_results.get('alerts', [])
    
    if not alerts:
        st.success("🎉 **No vulnerabilities found!** Your application appears to be secure.")
        st.balloons()
        return
    
    # Summary metrics
    summary = ZapifyScanner.calculate_security_score(alerts)
    UIComponents.create_metric_cards(summary['risk_counts'])
    
    # Security score
    col1, col2 = st.columns(2)
    with col1:
        UIComponents.create_security_score_gauge(summary['security_score'])
    with col2:
        UIComponents.create_vulnerability_chart(alerts)
    
    # Detailed vulnerability table
    st.subheader("🔍 Vulnerability Details")
    df = UIComponents.create_vulnerability_table(alerts)
    
    if not df.empty:
        st.dataframe(df, use_container_width=True)
        
        # Export options
        st.subheader("📥 Export Reports")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            json_data = ReportExporter.export_to_json(st.session_state.scan_results)
            st.download_button(
                "📄 Download JSON",
                json_data,
                f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json"
            )
        
        with col2:
            csv_data = ReportExporter.export_to_csv(alerts)
            st.download_button(
                "📊 Download CSV",
                csv_data,
                f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv"
            )
        
        with col3:
            html_data = ReportExporter.export_to_html(st.session_state.scan_results)
            st.download_button(
                "🌐 Download HTML",
                html_data,
                f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                "text/html"
            )

def main():
    """Main Streamlit application"""
    initialize_session_state()
    
    # Header
    st.title("🔒 Zapified Security Scanner")
    st.markdown("**Automated web application security testing with OWASP ZAP**")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Scan profile selection
        profiles = list_profiles()
        selected_profile = st.selectbox(
            "📋 Scan Profile",
            options=list(profiles.keys()),
            format_func=lambda x: f"{x.title()}: {profiles[x]}"
        )
        st.session_state.selected_profile = selected_profile
        
        # ZAP settings
        st.subheader("🔧 ZAP Settings")
        zap_url = st.text_input("ZAP Proxy URL", "http://localhost:8090")
        api_key = st.text_input("API Key", "change-me-9203935709", type="password")
        st.session_state.zap_url = zap_url
        st.session_state.api_key = api_key
        
        # Advanced options
        with st.expander("🔬 Advanced Options"):
            skip_active = st.checkbox("Skip Active Scan", help="Perform only spider scan for faster results")
            st.session_state.skip_active_scan = skip_active
        
        # ZAP status indicator
        st.subheader("📡 ZAP Status")
        try:
            scanner = ZapifyScanner("http://test.com", zap_url, api_key)
            if scanner.health_check():
                st.success("🟢 ZAP Connected")
            else:
                st.error("🔴 ZAP Disconnected")
        except:
            st.error("🔴 ZAP Disconnected")
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📁 Project Input", 
        "⚙️ Configuration", 
        "🚀 Scan & Progress", 
        "📊 Results"
    ])
    
    with tab1:
        input_method = st.radio(
            "📋 Choose input method:",
            ["📁 Upload Files", "🐙 GitHub Repository"],
            horizontal=True
        )
        
        if input_method == "📁 Upload Files":
            handle_file_upload()
        else:
            handle_github_integration()
    
    with tab2:
        handle_scan_configuration()
    
    with tab3:
        handle_scan_execution()
    
    with tab4:
        handle_results_display()

if __name__ == "__main__":
    main() 