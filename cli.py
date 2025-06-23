#!/usr/bin/env python3

import argparse
import sys
import logging
from zapify import ZapifyScanner
from config import get_profile_config, list_profiles

# Configure logging for CLI
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zapify.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CLIInterface:
    """Command-line interface for Zapified scanner"""
    
    def __init__(self):
        self.parser = self.setup_argument_parser()
    
    def setup_argument_parser(self):
        """Setup command-line argument parser"""
        parser = argparse.ArgumentParser(
            description='Zapified - Web Application Security Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  python cli.py http://localhost:5000
  python cli.py http://localhost:5000 --profile quick
  python cli.py http://localhost:5000 --spider-depth 10 --skip-active-scan
  python cli.py http://localhost:5000 --output-dir custom_reports
            '''
        )
        
        # Required arguments
        parser.add_argument('target', help='Target URL to scan')
        
        # Optional arguments
        parser.add_argument('--profile', choices=list(list_profiles().keys()),
                           help='Scan profile to use')
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
        parser.add_argument('--quiet', action='store_true',
                           help='Suppress progress output')
        parser.add_argument('--list-profiles', action='store_true',
                           help='List available scan profiles')
        
        return parser
    
    def run(self):
        """Run the CLI interface"""
        args = self.parser.parse_args()
        
        # Handle list profiles
        if args.list_profiles:
            self.list_scan_profiles()
            return
        
        # Initialize scanner
        scanner = ZapifyScanner(args.target, args.zap_url, args.api_key)
        
        # Apply profile configuration if specified
        if args.profile:
            config = get_profile_config(args.profile)
            scanner.configure_scan(
                spider_max_depth=config.spider_max_depth,
                active_scan_policy=config.active_scan_policy
            )
            if not args.quiet:
                logger.info(f"Using scan profile: {args.profile}")
        else:
            scanner.configure_scan(spider_max_depth=args.spider_depth)
        
        # Health check
        if not args.quiet:
            print("Performing health check...")
        
        if not scanner.health_check():
            logger.error("Health check failed. Ensure ZAP is running and target is accessible.")
            sys.exit(1)
        
        # Perform scanning
        success = True
        
        try:
            # Spider scan
            if not args.quiet:
                print("Starting spider scan...")
            
            if not scanner.spider_scan():
                logger.error("Spider scan failed")
                success = False
            
            # Active scan (unless skipped)
            if success and not args.skip_active_scan:
                if not args.quiet:
                    print("Starting active scan...")
                
                if not scanner.active_scan():
                    logger.error("Active scan failed")
                    success = False
            
            # Generate reports
            if success:
                if not args.quiet:
                    print("Generating reports...")
                
                if not scanner.generate_reports(args.output_dir):
                    logger.error("Report generation failed")
                    success = False
            
            # Print summary
            if success:
                self.print_scan_summary(scanner.scan_results, args.quiet)
                if not args.quiet:
                    logger.info("Scan completed successfully!")
            
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            sys.exit(1)
        
        sys.exit(0 if success else 1)
    
    def list_scan_profiles(self):
        """List available scan profiles"""
        profiles = list_profiles()
        print("\nAvailable Scan Profiles:")
        print("-" * 40)
        for name, description in profiles.items():
            print(f"{name:15} - {description}")
        print()
    
    def print_scan_summary(self, scan_results, quiet=False):
        """Print scan results summary"""
        if not scan_results or 'alerts' not in scan_results:
            print("No scan results available")
            return
        
        alerts = scan_results['alerts']
        
        if not quiet:
            print("\n" + "="*60)
            print("SECURITY SCAN RESULTS")
            print("="*60)
            print(f"Target: {scan_results.get('target_url', 'Unknown')}")
            print(f"URLs discovered: {len(scan_results.get('discovered_urls', []))}")
            print(f"Total vulnerabilities: {len(alerts)}")
        
        if alerts:
            # Count vulnerabilities by risk level
            risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            for alert in alerts:
                risk = alert.get('risk', 'Unknown')
                if risk in risk_counts:
                    risk_counts[risk] += 1
            
            if not quiet:
                print(f"\nRisk Level Breakdown:")
                for risk, count in risk_counts.items():
                    if count > 0:
                        print(f"  {risk}: {count}")
                
                print("\nVulnerabilities found:")
                for alert in alerts:
                    risk_color = {
                        'High': '\033[91m',      # Red
                        'Medium': '\033[93m',    # Yellow  
                        'Low': '\033[94m',       # Blue
                        'Informational': '\033[92m'  # Green
                    }.get(alert.get('risk', ''), '')
                    
                    reset_color = '\033[0m'
                    print(f"{risk_color}[{alert['risk']}]{reset_color} {alert['alert']}")
            else:
                # Quiet mode - just print counts
                print(f"High: {risk_counts['High']}, Medium: {risk_counts['Medium']}, Low: {risk_counts['Low']}, Info: {risk_counts['Informational']}")
        else:
            if not quiet:
                print("\n✅ No vulnerabilities found!")
            else:
                print("No vulnerabilities found")

def main():
    """Main entry point for CLI"""
    cli = CLIInterface()
    cli.run()

if __name__ == "__main__":
    main() 