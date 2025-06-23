#!/usr/bin/env python3

import streamlit as st
import tempfile
import os
from pathlib import Path
import json
from datetime import datetime
from zapify import ZapifyScanner
from config import list_profiles, get_profile_config

def main():
    """Main Streamlit application"""
    
    # Page configuration
    st.set_page_config(
        page_title="🔒 Zapified Security Scanner",
        page_icon="🔒",
        layout="wide"
    )
    
    # Initialize session state
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    if 'scan_status' not in st.session_state:
        st.session_state.scan_status = "idle"
    
    # Header
    st.title("🔒 Zapified Security Scanner")
    st.markdown("**Automated web application security testing with OWASP ZAP**")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Scan profile
        profiles = list_profiles()
        selected_profile = st.selectbox(
            "Scan Profile",
            options=list(profiles.keys()),
            format_func=lambda x: f"{x.title()}: {profiles[x]}"
        )
        
        # ZAP settings
        st.subheader("ZAP Settings")
        zap_url = st.text_input("ZAP Proxy URL", "http://localhost:8090")
        api_key = st.text_input("API Key", "change-me-9203935709", type="password")
        
        # Advanced options
        with st.expander("Advanced Options"):
            skip_active = st.checkbox("Skip Active Scan")
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["🎯 Target", "🚀 Scan", "📊 Results"])
    
    with tab1:
        st.header("Target Configuration")
        
        # File upload
        uploaded_files = st.file_uploader(
            "Upload project files (optional)",
            accept_multiple_files=True
        )
        
        if uploaded_files:
            st.success(f"✅ {len(uploaded_files)} files uploaded")
        
        # Target URL
        target_url = st.text_input(
            "Target URL",
            value="http://localhost:5000",
            help="URL of the application to scan"
        )
        
        if st.button("🔍 Test Connection"):
            try:
                import requests
                response = requests.get(target_url, timeout=5)
                st.success(f"✅ Connection successful (Status: {response.status_code})")
            except Exception as e:
                st.error(f"❌ Connection failed: {str(e)}")
    
    with tab2:
        st.header("Security Scan")
        
        if not target_url:
            st.warning("Please configure a target URL first")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🚀 Start Scan", type="primary"):
                    st.session_state.scan_status = "running"
                    
            with col2:
                if st.button("🔄 Reset"):
                    st.session_state.scan_status = "idle"
                    st.session_state.scan_results = None
            
            # Run scan
            if st.session_state.scan_status == "running":
                run_scan(target_url, zap_url, api_key, selected_profile, skip_active)
    
    with tab3:
        st.header("Scan Results")
        
        if st.session_state.scan_results:
            display_results(st.session_state.scan_results)
        else:
            st.info("No scan results available. Run a scan first.")

def run_scan(target_url, zap_url, api_key, profile, skip_active):
    """Execute the security scan"""
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text("🔍 Initializing scanner...")
        scanner = ZapifyScanner(target_url, zap_url, api_key)
        progress_bar.progress(0.1)
        
        status_text.text("🏥 Health check...")
        if not scanner.health_check():
            st.error("❌ Health check failed. Ensure ZAP is running.")
            st.session_state.scan_status = "failed"
            return
        progress_bar.progress(0.2)
        
        status_text.text("⚙️ Configuring scan...")
        config = get_profile_config(profile)
        scanner.configure_scan(spider_max_depth=config.spider_max_depth)
        progress_bar.progress(0.3)
        
        status_text.text("🕷️ Spider scanning...")
        if not scanner.spider_scan():
            st.error("❌ Spider scan failed")
            st.session_state.scan_status = "failed"
            return
        progress_bar.progress(0.6)
        
        if not skip_active:
            status_text.text("🔥 Active scanning...")
            if not scanner.active_scan():
                st.error("❌ Active scan failed")
                st.session_state.scan_status = "failed"
                return
            progress_bar.progress(0.9)
        
        status_text.text("📊 Generating reports...")
        if scanner.generate_reports():
            st.session_state.scan_results = scanner.scan_results
            st.session_state.scan_status = "completed"
            progress_bar.progress(1.0)
            status_text.text("✅ Scan completed!")
            st.success("🎉 Scan completed successfully!")
            st.balloons()
        else:
            st.error("❌ Report generation failed")
            st.session_state.scan_status = "failed"
            
    except Exception as e:
        st.error(f"❌ Scan failed: {str(e)}")
        st.session_state.scan_status = "failed"

def display_results(scan_results):
    """Display scan results"""
    
    alerts = scan_results.get('alerts', [])
    
    if not alerts:
        st.success("🎉 No vulnerabilities found!")
        return
    
    # Summary metrics  
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for alert in alerts:
        risk = alert.get('risk', 'Unknown')
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 High Risk", risk_counts['High'])
    with col2:
        st.metric("🟡 Medium Risk", risk_counts['Medium'])
    with col3:
        st.metric("🔵 Low Risk", risk_counts['Low'])
    with col4:
        st.metric("🟢 Info", risk_counts['Informational'])
    
    # Security score
    total_score = 10 - (risk_counts['High'] * 2 + risk_counts['Medium'] * 1 + risk_counts['Low'] * 0.3)
    security_score = max(0, min(10, round(total_score, 1)))
    st.metric("🏆 Security Score", f"{security_score}/10")
    
    # Vulnerability table
    st.subheader("🔍 Vulnerabilities")
    
    # Create table data
    table_data = []
    for alert in alerts:
        table_data.append({
            'Vulnerability': alert.get('alert', 'Unknown'),
            'Risk': alert.get('risk', 'Unknown'),
            'URL': alert.get('url', 'Unknown')[:50] + "..." if len(alert.get('url', '')) > 50 else alert.get('url', 'Unknown'),
            'Description': alert.get('description', '')[:100] + "..." if len(alert.get('description', '')) > 100 else alert.get('description', '')
        })
    
    if table_data:
        import pandas as pd
        df = pd.DataFrame(table_data)
        
        # Risk level filter
        risk_filter = st.multiselect(
            "Filter by Risk Level",
            options=['High', 'Medium', 'Low', 'Informational'],
            default=['High', 'Medium', 'Low', 'Informational']
        )
        
        filtered_df = df[df['Risk'].isin(risk_filter)]
        st.dataframe(filtered_df, use_container_width=True)
        
        # Export options
        st.subheader("📥 Export")
        col1, col2 = st.columns(2)
        
        with col1:
            json_data = json.dumps(scan_results, indent=2)
            st.download_button(
                "📄 Download JSON Report",
                json_data,
                f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json"
            )
        
        with col2:
            csv_data = filtered_df.to_csv(index=False)
            st.download_button(
                "📊 Download CSV Report",
                csv_data,
                f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv"
            )

if __name__ == "__main__":
    main() 