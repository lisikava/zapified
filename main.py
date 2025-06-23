#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import time
import signal
from zapify import ZapifyScanner

def run_sample_app():
    """Start the sample vulnerable application"""
    print("Starting sample vulnerable application on port 5000...")
    try:
        process = subprocess.Popen([sys.executable, 'sample_app.py'])
        print("Sample app started. Press Ctrl+C to stop.")
        print("Access it at: http://localhost:5000")
        
        # Wait for the process to complete or be interrupted
        try:
            process.wait()
        except KeyboardInterrupt:
            print("\nStopping sample app...")
            process.terminate()
            process.wait()
            
    except Exception as e:
        print(f"Failed to start sample app: {e}")
        return False
    
    return True

def run_zap_docker():
    """Start ZAP in Docker container"""
    print("Starting ZAP Docker container...")
    zap_cmd = [
        'docker', 'run', '-u', 'zap', '-p', '8090:8090', 
        '--network=host', '-i', 'zaproxy/zap-stable',
        'zap.sh', '-daemon', '-host', '0.0.0.0', '-port', '8090',
        '-config', 'api.addrs.addr.name=.*',
        '-config', 'api.addrs.addr.regex=true',
        '-config', 'api.key=change-me-9203935709'
    ]
    
    try:
        print("ZAP command:", ' '.join(zap_cmd))
        process = subprocess.Popen(zap_cmd)
        print("ZAP Docker container started on port 8090")
        print("Press Ctrl+C to stop.")
        
        try:
            process.wait()
        except KeyboardInterrupt:
            print("\nStopping ZAP container...")
            process.terminate()
            process.wait()
            
    except Exception as e:
        print(f"Failed to start ZAP container: {e}")
        print("Make sure Docker is installed and running.")
        return False
    
    return True

def run_full_scan(target_url, output_dir='reports'):
    """Run a complete security scan"""
    print(f"Running full security scan on {target_url}")
    
    # Check if ZAP is accessible
    scanner = ZapifyScanner(target_url)
    if not scanner.health_check():
        print("ZAP is not accessible. Please start ZAP first with: python main.py --start-zap")
        return False
    
    # Run the scan
    scanner.configure_scan()
    
    if not scanner.spider_scan():
        print("Spider scan failed")
        return False
    
    if not scanner.active_scan():
        print("Active scan failed")
        return False
    
    if not scanner.generate_reports(output_dir):
        print("Report generation failed")
        return False
    
    scanner.print_scan_summary()
    print(f"Scan completed! Reports saved to {output_dir}/")
    return True

def setup_environment():
    """Set up the project environment"""
    print("Setting up zapified environment...")
    
    # Create reports directory
    os.makedirs('reports', exist_ok=True)
    print("✓ Created reports directory")
    
    # Create test database file for sample app
    if not os.path.exists('test.db'):
        print("✓ Database will be created when sample app starts")
    
    print("Environment setup complete!")

def main():
    parser = argparse.ArgumentParser(
        description='Zapified - Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py --setup                    Set up the environment
  python main.py --start-app               Start the sample vulnerable app
  python main.py --start-zap               Start ZAP Docker container
  python main.py --scan http://localhost:5000  Run full security scan
  python main.py --quick-demo              Run a quick demo (app + scan)
        '''
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--setup', action='store_true', 
                      help='Set up the project environment')
    group.add_argument('--start-app', action='store_true',
                      help='Start the sample vulnerable application')
    group.add_argument('--start-zap', action='store_true',
                      help='Start ZAP Docker container')
    group.add_argument('--scan', metavar='URL',
                      help='Run security scan on specified URL')
    group.add_argument('--quick-demo', action='store_true',
                      help='Run a quick demo with sample app and scan')
    
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for scan reports')
    
    args = parser.parse_args()
    
    if args.setup:
        setup_environment()
        
    elif args.start_app:
        run_sample_app()
        
    elif args.start_zap:
        run_zap_docker()
        
    elif args.scan:
        success = run_full_scan(args.scan, args.output_dir)
        sys.exit(0 if success else 1)
        
    elif args.quick_demo:
        print("Running quick demo...")
        print("This will start the sample app and run a basic scan.")
        print("Make sure ZAP Docker container is running first!")
        
        # Check if ZAP is running
        scanner = ZapifyScanner('http://localhost:5000')
        if not scanner.health_check():
            print("ZAP is not running. Please start it first with:")
            print("python main.py --start-zap")
            sys.exit(1)
        
        # Start sample app in background
        print("Starting sample app...")
        app_process = subprocess.Popen([sys.executable, 'sample_app.py'])
        
        try:
            # Wait a moment for app to start
            time.sleep(3)
            
            # Run scan
            success = run_full_scan('http://localhost:5000', args.output_dir)
            
        finally:
            # Clean up
            print("Stopping sample app...")
            app_process.terminate()
            app_process.wait()
        
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
