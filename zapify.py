import time
from zapv2 import ZAPv2

target = 'http://localhost:5000'
zap = ZAPv2(proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'}, apikey='change-me-9203935709')

print("Accessing target")
try:
    zap.urlopen(target)
except:
    print(f'Failed to connect to target {target}')

print("Starting spider")
try:
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status()) < 100:
        print(f'Spider progress: {zap.spider.status(scan_id)}%')
        time.sleep(2)
except:
    print(f'Failed to spider scan')

print("Starting active scan")
try:
    ascan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(ascan_id)) < 100:
        print(f'Active scan progress: {zap.ascan.status(ascan_id)}%')
        time.sleep(5)
except:
    print(f'Failed to do active scan')

try:
    alerts = zap.core.alerts()
    for alert in alerts:
        print(f"[{alert['risk']}] {alert['alert']}")

    with open("zap_report.json", "w") as f:
        f.write(zap.core.jsonreport())
except:
    print(f'Failed to generate report')