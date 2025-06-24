#!/usr/bin/env python3

import time
import json
import sys
import argparse
import os
from datetime import datetime
from zapv2 import ZAPv2
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zapify.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ZapifyScanner:
    def __init__(self, target_url, zap_proxy_url='http://localhost:8090', api_key='change-me-9203935709'):
        self.target_url = target_url
        self.zap_proxy_url = zap_proxy_url
        self.api_key = api_key
        self.zap = ZAPv2(
            proxies={'http': zap_proxy_url, 'https': zap_proxy_url}, 
            apikey=api_key
        )
        self.scan_results = {}
        
    def health_check(self):
        """Check if ZAP is running and target is accessible"""
        try:
            # Check ZAP status
            zap_version = self.zap.core.version
            logger.info(f"Connected to ZAP version: {zap_version}")
            
            # Check target accessibility
            self.zap.urlopen(self.target_url)
            logger.info(f"Target {self.target_url} is accessible")
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    def configure_scan(self, spider_max_depth=5, active_scan_policy='Default Policy'):
        """Configure scan parameters"""
        try:
            # Configure spider
            self.zap.spider.set_option_max_depth(spider_max_depth)
            logger.info(f"Spider max depth set to: {spider_max_depth}")
            
            # Set active scan policy
            policies = self.zap.ascan.policies()
            if active_scan_policy in policies:
                self.zap.ascan.set_option_default_policy(active_scan_policy)
                logger.info(f"Active scan policy set to: {active_scan_policy}")
        except Exception as e:
            logger.error(f"Configuration failed: {e}")

    def spider_scan(self):
        """Perform spider scan to discover application structure"""
        logger.info("Starting spider scan...")
        try:
            scan_id = self.zap.spider.scan(self.target_url)
            
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                logger.info(f'Spider progress: {progress}%')
                time.sleep(2)
            
            # Get discovered URLs
            urls = self.zap.spider.results(scan_id)
            self.scan_results['discovered_urls'] = urls
            logger.info(f"Spider completed. Discovered {len(urls)} URLs")
            return True
            
        except Exception as e:
            logger.error(f'Spider scan failed: {e}')
            return False

    def active_scan(self):
        """Perform active vulnerability scan"""
        logger.info("Starting active scan...")
        try:
            ascan_id = self.zap.ascan.scan(self.target_url)
            
            while int(self.zap.ascan.status(ascan_id)) < 100:
                progress = self.zap.ascan.status(ascan_id)
                logger.info(f'Active scan progress: {progress}%')
                time.sleep(5)
            
            logger.info("Active scan completed")
            return True
            
        except Exception as e:
            logger.error(f'Active scan failed: {e}')
            return False

    def generate_reports(self, output_dir='reports'):
        """Generate various report formats"""
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Get alerts
            alerts = self.zap.core.alerts()
            self.scan_results['alerts'] = alerts
            self.scan_results['scan_timestamp'] = timestamp
            self.scan_results['target_url'] = self.target_url
            
            # Generate JSON report
            json_file = os.path.join(output_dir, f'zap_report_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            
            # Generate HTML report
            html_report = self.zap.core.htmlreport()
            html_file = os.path.join(output_dir, f'zap_report_{timestamp}.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            # Generate summary report
            self._generate_summary_report(output_dir, timestamp)
            
            logger.info(f"Reports generated in {output_dir}/")
            return True
            
        except Exception as e:
            logger.error(f'Report generation failed: {e}')
            return False

    def _generate_summary_report(self, output_dir, timestamp):
        """Generate a human-readable summary report"""
        alerts = self.scan_results.get('alerts', [])
        
        # Categorize alerts by risk level
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        vulnerabilities = {'High': [], 'Medium': [], 'Low': [], 'Informational': []}
        
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            if risk in risk_counts:
                risk_counts[risk] += 1
                vulnerabilities[risk].append({
                    'name': alert.get('alert', 'Unknown'),
                    'description': alert.get('description', ''),
                    'url': alert.get('url', ''),
                    'solution': alert.get('solution', '')
                })
        
        # Generate summary
        summary_file = os.path.join(output_dir, f'security_summary_{timestamp}.txt')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"Security Scan Summary - {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Total URLs discovered: {len(self.scan_results.get('discovered_urls', []))}\n")
            f.write(f"Total vulnerabilities found: {len(alerts)}\n\n")
            
            f.write("Risk Level Breakdown:\n")
            for risk, count in risk_counts.items():
                f.write(f"  {risk}: {count}\n")
            f.write("\n")
            
            # Detailed vulnerabilities
            for risk_level in ['High', 'Medium', 'Low', 'Informational']:
                if vulnerabilities[risk_level]:
                    f.write(f"{risk_level.upper()} RISK VULNERABILITIES:\n")
                    f.write("-" * 30 + "\n")
                    for vuln in vulnerabilities[risk_level]:
                        f.write(f"• {vuln['name']}\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        if vuln['solution']:
                            f.write(f"  Solution: {vuln['solution']}\n")
                        f.write("\n")

    def get_scan_summary(self):
        """Get scan results summary as dictionary"""
        alerts = self.scan_results.get('alerts', [])
        
        # Count vulnerabilities by risk level
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        return {
            'target_url': self.target_url,
            'urls_discovered': len(self.scan_results.get('discovered_urls', [])),
            'total_vulnerabilities': len(alerts),
            'risk_counts': risk_counts,
            'alerts': alerts,
            'has_vulnerabilities': len(alerts) > 0
        }

def main():
    parser = argparse.ArgumentParser(description='ZAP Security Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--zap-url', default='http://localhost:8090', 
                       help='ZAP proxy URL (default: http://localhost:8090)')
    parser.add_argument('--api-key', default='change-me-9203935709',
                       help='ZAP API key')
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports')
    parser.add_argument('--spider-depth', type=int, default=5,
                       help='Maximum spider depth')
    parser.add_argument('--skip-active-scan', action='store_true',
                       help='Skip active scan (spider only)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = ZapifyScanner(args.target, args.zap_url, args.api_key)
    
    # Health check
    if not scanner.health_check():
        logger.error("Health check failed. Ensure ZAP is running and target is accessible.")
        sys.exit(1)
    
    # Configure scan
    scanner.configure_scan(spider_max_depth=args.spider_depth)
    
    # Perform spider scan
    if not scanner.spider_scan():
        logger.error("Spider scan failed")
        sys.exit(1)
    
    # Perform active scan (unless skipped)
    if not args.skip_active_scan:
        if not scanner.active_scan():
            logger.error("Active scan failed")
            sys.exit(1)
    
    # Generate reports
    if not scanner.generate_reports(args.output_dir):
        logger.error("Report generation failed")
        sys.exit(1)
    
    # Print summary
    scanner.print_scan_summary()
    
    logger.info("Scan completed successfully!")

if __name__ == "__main__":
    main()