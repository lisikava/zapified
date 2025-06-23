#!/usr/bin/env python3

import os
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class ZapConfig:
    """Configuration settings for ZAP scanner"""
    
    # ZAP Connection Settings
    proxy_url: str = "http://localhost:8090"
    api_key: str = "change-me-9203935709"
    timeout: int = 300  # seconds
    
    # Scan Configuration
    spider_max_depth: int = 5
    spider_max_children: int = 10
    spider_max_duration: int = 20  # minutes
    
    active_scan_policy: str = "Default Policy"
    active_scan_max_duration: int = 60  # minutes
    
    # Target Configuration
    default_target: str = "http://localhost:5000"
    excluded_urls: List[str] = None
    included_urls: List[str] = None
    
    # Authentication (if needed)
    auth_method: Optional[str] = None  # "form", "script", "http", etc.
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_url: Optional[str] = None
    
    # Reporting
    output_dir: str = "reports"
    report_formats: List[str] = None  # ["json", "html", "xml", "txt"]
    include_request_response: bool = True
    
    # Performance
    concurrent_scans: int = 1
    request_delay: int = 0  # milliseconds between requests
    
    def __post_init__(self):
        if self.excluded_urls is None:
            self.excluded_urls = [
                ".*logout.*",
                ".*signout.*", 
                ".*\\.pdf$",
                ".*\\.zip$",
                ".*\\.exe$"
            ]
            
        if self.included_urls is None:
            self.included_urls = [".*"]
            
        if self.report_formats is None:
            self.report_formats = ["json", "html", "txt"]

@dataclass 
class ScanProfile:
    """Predefined scan profiles for different use cases"""
    
    name: str
    description: str
    config: ZapConfig

# Predefined scan profiles
SCAN_PROFILES = {
    "quick": ScanProfile(
        name="Quick Scan",
        description="Fast scan with basic coverage",
        config=ZapConfig(
            spider_max_depth=3,
            spider_max_duration=5,
            active_scan_max_duration=15,
            report_formats=["txt", "json"]
        )
    ),
    
    "standard": ScanProfile(
        name="Standard Scan", 
        description="Balanced scan with good coverage",
        config=ZapConfig(
            spider_max_depth=5,
            spider_max_duration=15,
            active_scan_max_duration=45,
            report_formats=["json", "html", "txt"]
        )
    ),
    
    "comprehensive": ScanProfile(
        name="Comprehensive Scan",
        description="Thorough scan with maximum coverage",
        config=ZapConfig(
            spider_max_depth=10,
            spider_max_children=20,
            spider_max_duration=45,
            active_scan_max_duration=120,
            include_request_response=True,
            report_formats=["json", "html", "xml", "txt"]
        )
    ),
    
    "ci_cd": ScanProfile(
        name="CI/CD Scan",
        description="Optimized for continuous integration",
        config=ZapConfig(
            spider_max_depth=4,
            spider_max_duration=10,
            active_scan_max_duration=30,
            report_formats=["json", "txt"],
            include_request_response=False
        )
    )
}

def load_config_from_env() -> ZapConfig:
    """Load configuration from environment variables"""
    return ZapConfig(
        proxy_url=os.getenv("ZAP_PROXY_URL", "http://localhost:8090"),
        api_key=os.getenv("ZAP_API_KEY", "change-me-9203935709"),
        timeout=int(os.getenv("ZAP_TIMEOUT", "300")),
        spider_max_depth=int(os.getenv("ZAP_SPIDER_DEPTH", "5")),
        active_scan_max_duration=int(os.getenv("ZAP_SCAN_DURATION", "60")),
        default_target=os.getenv("ZAP_TARGET", "http://localhost:5000"),
        output_dir=os.getenv("ZAP_OUTPUT_DIR", "reports")
    )

def get_profile_config(profile_name: str) -> ZapConfig:
    """Get configuration for a specific scan profile"""
    if profile_name not in SCAN_PROFILES:
        raise ValueError(f"Unknown profile: {profile_name}. Available: {list(SCAN_PROFILES.keys())}")
    
    return SCAN_PROFILES[profile_name].config

def list_profiles() -> Dict[str, str]:
    """List available scan profiles"""
    return {name: profile.description for name, profile in SCAN_PROFILES.items()} 