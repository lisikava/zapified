import time
from zapv2 import ZAPv2

target = 'http://localhost:5000'
zap = ZAPv2(proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'}, apikey='change-me-9203935709')

print("Accessing target...")
zap.urlopen(target)

print("Starting spider...")
scan_id = zap.spider.scan(target)
while int(zap.spider.status()) < 100:
    print(f'Spider progress: {zap.spider.status(scan_id)}%')
    time.sleep(2)

print('Spider completed.')

print("Starting active scan...")
ascan_id = zap.ascan.scan(target)
while int(zap.ascan.status(ascan_id)) < 100:
    print(f'Active scan progress: {zap.ascan.status(ascan_id)}%')
    time.sleep(2)
print('Active scan completed.')

alerts = zap.core.alerts()
for alert in alerts:
    print(f"[{alert['risk']}] {alert['alert']}")

with open("zap_report.json", "w") as f:
    f.write(zap.core.jsonreport())

