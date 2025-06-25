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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StreamlitUI:
    def __init__(self):
        self.setup_page_config()
        self.initialize_session_state()

    def setup_page_config(self):
        st.set_page_config(
            page_title="Zapified Security Scanner",
            page_icon="⚡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )

    def initialize_session_state(self):
        st.session_state.setdefault('scan_results', None)
        st.session_state.setdefault('scan_progress', 0)
        st.session_state.setdefault('scan_status', "idle")
        st.session_state.setdefault('project_path', None)
        st.session_state.setdefault('target_url', None)
        st.session_state.setdefault('scan_logs', [])
        st.session_state.setdefault('app_process', None)

class ProjectManager:
    @staticmethod
    def detect_project_type(project_path):
        project_path = Path(project_path)
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
    def get_startup_command(project_type):
        commands = {
            "flask": "python app.py",
            "django": "python manage.py runserver",
            "node": "npm start",
            "java": "mvn spring-boot:run",
            "ruby": "rails server"
        }
        return commands.get(project_type)

    @staticmethod
    def clone_github_repo(repo_url, branch="main"):
        try:
            temp_dir = tempfile.mkdtemp()
            git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            return temp_dir
        except Exception as e:
            st.error(f"Failed to clone repository: {str(e)}")
            return None

def start_target_application(project_path, project_type):
    command = ProjectManager.get_startup_command(project_type)
    if not command:
        st.error("Could not determine how to start the application.")
        return None
    try:
        return subprocess.Popen(
            command.split(),
            cwd=project_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except Exception as e:
        st.error(f"Failed to start application: {e}")
        return None

def stop_target_application():
    app_process = st.session_state.get("app_process")
    if app_process:
        app_process.terminate()
        app_process.wait()
        st.session_state.app_process = None

class ScanProgressTracker:
    def __init__(self):
        self.progress_container = None
        self.log_container = None

    def setup_progress_display(self):
        self.progress_container = st.container()
        self.log_container = st.container()

    def update_progress(self, step, progress, message):
        if self.progress_container:
            with self.progress_container:
                st.progress(progress)
                st.write(f"{step}: {message}")

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        st.session_state.scan_logs.append(log_entry)
        if self.log_container:
            with self.log_container:
                st.text_area("Scan Logs", "\n".join(st.session_state.scan_logs[-10:]), height=200)

class ReportViewer:
    @staticmethod
    def display_scan_results(scan_results):
        if not scan_results or 'alerts' not in scan_results:
            st.warning("No scan results available")
            return
        alerts = scan_results['alerts']
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            if risk in risk_counts:
                risk_counts[risk] += 1
        st.metric("High Risk", risk_counts['High'])
        st.metric("Medium Risk", risk_counts['Medium'])
        st.metric("Low Risk", risk_counts['Low'])
        st.metric("Informational", risk_counts['Informational'])

        st.subheader("Detailed Vulnerabilities")
        import pandas as pd
        df = pd.DataFrame([{
            'Vulnerability': a.get('alert', ''),
            'Risk': a.get('risk', ''),
            'URL': a.get('url', ''),
            'Description': a.get('description', ''),
            'Solution': a.get('solution', '')
        } for a in alerts])
        st.dataframe(df, use_container_width=True)

def main():
    ui = StreamlitUI()
    st.title("Zapified Security Scanner")
    st.markdown("Automated web application security testing with OWASP ZAP")

    with st.sidebar:
        st.header("Configuration")
        profile_options = list_profiles()
        selected_profile = st.selectbox("Scan Profile", options=list(profile_options.keys()))
        zap_url = st.text_input("ZAP Proxy URL", "http://localhost:8090")
        api_key = st.text_input("API Key", "change-me-9203935709", type="password")
        spider_depth = st.slider("Spider Depth", 1, 10, 5)
        skip_active = st.checkbox("Skip Active Scan")

    st.header("Project Setup")
    input_method = st.radio("Input Method", ["Upload Files", "GitHub Repo"])

    if input_method == "Upload Files":
        uploaded_files = st.file_uploader("Upload your app files", accept_multiple_files=True)
        if uploaded_files:
            temp_dir = tempfile.mkdtemp()
            for file in uploaded_files:
                with open(os.path.join(temp_dir, file.name), "wb") as f:
                    f.write(file.getbuffer())
            st.session_state.project_path = temp_dir
            project_type = ProjectManager.detect_project_type(temp_dir)
            st.session_state.project_type = project_type
            st.success(f"Uploaded and detected project type: {project_type}")

    else:
        repo_url = st.text_input("GitHub Repo URL")
        if st.button("Clone") and repo_url:
            path = ProjectManager.clone_github_repo(repo_url)
            if path:
                st.session_state.project_path = path
                project_type = ProjectManager.detect_project_type(path)
                st.session_state.project_type = project_type
                st.success(f"Cloned and detected project type: {project_type}")

    if st.session_state.project_path:
        target_url = st.text_input("Target URL", value="http://localhost:5000")
        st.session_state.target_url = target_url
        if st.button("Start Scan"):
            app_process = start_target_application(st.session_state.project_path, st.session_state.project_type)
            st.session_state.app_process = app_process
            time.sleep(3)
            tracker = ScanProgressTracker()
            tracker.setup_progress_display()
            with st.spinner("Running scan..."):
                try:
                    scanner = ZapifyScanner(target_url, zap_url, api_key)
                    tracker.update_progress("Health Check", 0.1, "Checking ZAP and target...")
                    if scanner.health_check():
                        tracker.update_progress("Configure", 0.2, "Setting up scan...")
                        scanner.configure_scan(spider_depth)
                        tracker.update_progress("Spider", 0.3, "Spider scanning...")
                        if scanner.spider_scan():
                            if not skip_active:
                                tracker.update_progress("Active", 0.6, "Active scanning...")
                                scanner.active_scan()
                            tracker.update_progress("Reporting", 0.9, "Generating reports...")
                            if scanner.generate_reports():
                                st.session_state.scan_results = scanner.scan_results
                                st.session_state.scan_status = "completed"
                                tracker.update_progress("Done", 1.0, "Scan complete!")
                                st.success("Scan completed!")
                    else:
                        st.error("Health check failed.")
                finally:
                    stop_target_application()

    if st.session_state.scan_results:
        st.header("Scan Results")
        ReportViewer.display_scan_results(st.session_state.scan_results)

if __name__ == "__main__":
    main()
