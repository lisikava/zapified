#!/usr/bin/env python3

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import tempfile
import os
from pathlib import Path
import subprocess
import threading
from typing import Dict, List, Optional, Tuple

class UIComponents:
    """Reusable UI components for Streamlit interface"""
    
    @staticmethod
    def create_metric_cards(risk_counts: Dict[str, int]) -> None:
        """Create metric cards for vulnerability counts"""
        col1, col2, col3, col4 = st.columns(4)
        
        risk_colors = {
            'High': '🔴',
            'Medium': '🟡', 
            'Low': '🔵',
            'Informational': '🟢'
        }
        
        cols = [col1, col2, col3, col4]
        for i, (risk, count) in enumerate(risk_counts.items()):
            if i < len(cols):
                with cols[i]:
                    st.metric(
                        f"{risk_colors.get(risk, '⚪')} {risk} Risk", 
                        count,
                        delta=None
                    )
    
    @staticmethod
    def create_security_score_gauge(score: float) -> None:
        """Create a gauge chart for security score"""
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Score"},
            delta = {'reference': 8.0},
            gauge = {
                'axis': {'range': [None, 10]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 5], 'color': "lightgray"},
                    {'range': [5, 8], 'color': "yellow"},
                    {'range': [8, 10], 'color': "green"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': score
                }
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    @staticmethod
    def create_vulnerability_chart(alerts: List[Dict]) -> None:
        """Create vulnerability distribution chart"""
        if not alerts:
            return
        
        # Count vulnerabilities by risk level
        risk_counts = {}
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Create pie chart
        fig = px.pie(
            values=list(risk_counts.values()),
            names=list(risk_counts.keys()),
            title="Vulnerability Distribution by Risk Level",
            color_discrete_map={
                'High': '#ff4b4b',
                'Medium': '#ffa500', 
                'Low': '#4169e1',
                'Informational': '#32cd32'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    
    @staticmethod
    def create_progress_display() -> Tuple[st.container, st.container]:
        """Create progress display containers"""
        progress_container = st.container()
        log_container = st.container()
        return progress_container, log_container
    
    @staticmethod
    def display_scan_timeline(scan_steps: List[Dict]) -> None:
        """Display scan execution timeline"""
        if not scan_steps:
            return
            
        df = pd.DataFrame(scan_steps)
        if not df.empty:
            st.subheader("📈 Scan Timeline")
            st.line_chart(df.set_index('timestamp')['progress'])
    
    @staticmethod
    def create_vulnerability_table(alerts: List[Dict], filterable: bool = True) -> pd.DataFrame:
        """Create interactive vulnerability table"""
        if not alerts:
            return pd.DataFrame()
        
        # Prepare data for table
        table_data = []
        for alert in alerts:
            table_data.append({
                'Vulnerability': alert.get('alert', 'Unknown'),
                'Risk': alert.get('risk', 'Unknown'),
                'URL': alert.get('url', 'Unknown'),
                'Description': UIComponents._truncate_text(alert.get('description', ''), 100),
                'Solution': UIComponents._truncate_text(alert.get('solution', ''), 100),
                'CWE': alert.get('cweid', 'N/A'),
                'Confidence': alert.get('confidence', 'Unknown')
            })
        
        df = pd.DataFrame(table_data)
        
        if filterable and not df.empty:
            # Add filters
            col1, col2 = st.columns(2)
            with col1:
                risk_filter = st.multiselect(
                    "Filter by Risk Level",
                    options=df['Risk'].unique(),
                    default=df['Risk'].unique()
                )
            with col2:
                confidence_filter = st.multiselect(
                    "Filter by Confidence",
                    options=df['Confidence'].unique(),
                    default=df['Confidence'].unique()
                )
            
            # Apply filters
            df = df[
                (df['Risk'].isin(risk_filter)) & 
                (df['Confidence'].isin(confidence_filter))
            ]
        
        return df
    
    @staticmethod
    def _truncate_text(text: str, max_length: int) -> str:
        """Truncate text to specified length"""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."

class ProjectDetector:
    """Detects project types and configurations"""
    
    FRAMEWORK_PATTERNS = {
        'flask': {
            'files': ['app.py', 'wsgi.py', 'requirements.txt'],
            'patterns': ['from flask import', 'Flask(__name__)'],
            'startup_cmd': 'python app.py',
            'default_port': 5000
        },
        'django': {
            'files': ['manage.py', 'settings.py', 'requirements.txt'],
            'patterns': ['DJANGO_SETTINGS_MODULE', 'django'],
            'startup_cmd': 'python manage.py runserver',
            'default_port': 8000
        },
        'node_express': {
            'files': ['package.json', 'server.js', 'app.js'],
            'patterns': ['express', '"start":', 'node'],
            'startup_cmd': 'npm start',
            'default_port': 3000
        },
        'react': {
            'files': ['package.json', 'src/App.js', 'public/index.html'],
            'patterns': ['react', 'react-scripts'],
            'startup_cmd': 'npm start',
            'default_port': 3000
        },
        'spring_boot': {
            'files': ['pom.xml', 'application.properties'],
            'patterns': ['spring-boot', '@SpringBootApplication'],
            'startup_cmd': 'mvn spring-boot:run',
            'default_port': 8080
        }
    }
    
    @classmethod
    def detect_project_type(cls, project_path: str) -> Dict[str, any]:
        """Detect project type and return configuration"""
        project_path = Path(project_path)
        
        for framework, config in cls.FRAMEWORK_PATTERNS.items():
            if cls._matches_framework(project_path, config):
                return {
                    'type': framework,
                    'startup_cmd': config['startup_cmd'],
                    'default_port': config['default_port'],
                    'confidence': 'high'
                }
        
        return {
            'type': 'unknown',
            'startup_cmd': None,
            'default_port': 8000,
            'confidence': 'low'
        }
    
    @classmethod
    def _matches_framework(cls, project_path: Path, config: Dict) -> bool:
        """Check if project matches framework patterns"""
        # Check for required files
        required_files = config.get('files', [])
        files_found = 0
        
        for file_pattern in required_files:
            if list(project_path.glob(file_pattern)) or (project_path / file_pattern).exists():
                files_found += 1
        
        # If most required files are found, check content patterns
        if files_found >= len(required_files) * 0.5:  # At least 50% of files found
            return cls._check_content_patterns(project_path, config.get('patterns', []))
        
        return False
    
    @classmethod
    def _check_content_patterns(cls, project_path: Path, patterns: List[str]) -> bool:
        """Check if any file contains the specified patterns"""
        if not patterns:
            return True
        
        # Check common files for patterns
        common_files = ['*.py', '*.js', '*.json', '*.txt', '*.xml', '*.properties']
        
        for file_pattern in common_files:
            for file_path in project_path.glob(file_pattern):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore').lower()
                    if any(pattern.lower() in content for pattern in patterns):
                        return True
                except:
                    continue
        
        return False

class ScanManager:
    """Manages scan execution and progress tracking"""
    
    def __init__(self):
        self.current_scan = None
        self.scan_thread = None
        
    def start_scan_async(self, scanner, progress_callback=None, log_callback=None):
        """Start scan in background thread"""
        def run_scan():
            try:
                if progress_callback:
                    progress_callback("Starting", 0.1, "Initializing scan...")
                
                # Health check
                if scanner.health_check():
                    if log_callback:
                        log_callback("✅ Health check passed")
                    if progress_callback:
                        progress_callback("Health Check", 0.2, "ZAP and target are accessible")
                else:
                    raise Exception("Health check failed")
                
                # Configure scan
                scanner.configure_scan()
                if log_callback:
                    log_callback("✅ Scan configured")
                if progress_callback:
                    progress_callback("Configuration", 0.3, "Scan parameters set")
                
                # Spider scan
                if progress_callback:
                    progress_callback("Spider Scan", 0.4, "Discovering application structure...")
                
                if scanner.spider_scan():
                    if log_callback:
                        log_callback("✅ Spider scan completed")
                    if progress_callback:
                        progress_callback("Spider Complete", 0.6, "Application structure mapped")
                else:
                    raise Exception("Spider scan failed")
                
                # Active scan
                if progress_callback:
                    progress_callback("Active Scan", 0.7, "Running vulnerability tests...")
                
                if scanner.active_scan():
                    if log_callback:
                        log_callback("✅ Active scan completed")
                    if progress_callback:
                        progress_callback("Active Complete", 0.9, "Vulnerability testing finished")
                else:
                    raise Exception("Active scan failed")
                
                # Generate reports
                if scanner.generate_reports():
                    if log_callback:
                        log_callback("✅ Reports generated")
                    if progress_callback:
                        progress_callback("Complete", 1.0, "Scan completed successfully!")
                    
                    return scanner.scan_results
                else:
                    raise Exception("Report generation failed")
                    
            except Exception as e:
                if log_callback:
                    log_callback(f"❌ Scan failed: {str(e)}")
                raise e
        
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.start()
        return self.scan_thread
    
    def is_scan_running(self) -> bool:
        """Check if scan is currently running"""
        return self.scan_thread and self.scan_thread.is_alive()

class ReportExporter:
    """Handles different report export formats"""
    
    @staticmethod
    def export_to_json(scan_results: Dict, filename: str = None) -> str:
        """Export scan results to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
        
        return json.dumps(scan_results, indent=2, ensure_ascii=False)
    
    @staticmethod
    def export_to_csv(alerts: List[Dict], filename: str = None) -> str:
        """Export vulnerabilities to CSV"""
        df = UIComponents.create_vulnerability_table(alerts, filterable=False)
        return df.to_csv(index=False)
    
    @staticmethod
    def export_to_html(scan_results: Dict, template: str = None) -> str:
        """Export scan results to HTML report"""
        # Simple HTML template - can be enhanced
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 10px; }
                .vulnerability { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
                .high { border-left-color: #ff4444; }
                .medium { border-left-color: #ffaa00; }
                .low { border-left-color: #4444ff; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {date}</p>
                <p>Total Vulnerabilities: {total}</p>
            </div>
            <div class="content">
                {vulnerabilities}
            </div>
        </body>
        </html>
        """
        
        alerts = scan_results.get('alerts', [])
        vuln_html = ""
        
        for alert in alerts:
            risk_class = alert.get('risk', '').lower()
            vuln_html += f"""
            <div class="vulnerability {risk_class}">
                <h3>{alert.get('alert', 'Unknown')}</h3>
                <p><strong>Risk:</strong> {alert.get('risk', 'Unknown')}</p>
                <p><strong>URL:</strong> {alert.get('url', 'Unknown')}</p>
                <p><strong>Description:</strong> {alert.get('description', 'No description')}</p>
                <p><strong>Solution:</strong> {alert.get('solution', 'No solution provided')}</p>
            </div>
            """
        
        return html_template.format(
            target=scan_results.get('target_url', 'Unknown'),
            date=scan_results.get('scan_timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            total=len(alerts),
            vulnerabilities=vuln_html
        ) 