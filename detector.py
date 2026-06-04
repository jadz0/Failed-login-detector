from collections import Counter
from pathlib import Path
import re
from datetime import datetime

THRESHOLD = 5
ALERT_ID = "SOC-FLD-001"

pattern = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
)

counts = Counter()
log_file = Path(__file__).parent / "auth.log"

with log_file.open("r", encoding="utf-8") as file:
    for line in file:
        match = pattern.search(line)
        if match:
            user, ip = match.groups()
            counts[(ip, user)] += 1


def get_severity(count):
    if count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    return "LOW"


alerts = []
for (ip, user), count in counts.items():
    if count >= THRESHOLD:
        alerts.append({
            "ip": ip,
            "user": user,
            "count": count,
            "severity": get_severity(count)
        })

print("=" * 78)
print("SECURITY OPERATIONS CENTER - FAILED LOGIN ALERT".center(78))
print("=" * 78)
print(f"Alert ID        : {ALERT_ID}")
print(f"Detection Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Rule Name       : Repeated Failed SSH Logins")
print(f"Threshold       : {THRESHOLD} failed attempts")
print("-" * 78)

if alerts:
    print(f"{'Source IP':<18} {'Target User':<18} {'Attempts':<10} {'Severity':<10}")
    print("-" * 78)

    for alert in alerts:
        print(f"{alert['ip']:<18} {alert['user']:<18} {alert['count']:<10} {alert['severity']:<10}")

    print("-" * 78)
    print(f"Total Alerts    : {len(alerts)}")
    print("Triage Note     : Investigate source IP, targeted account, and login pattern.")
    print("Recommended Act.: Check for brute-force activity, review SSH logs,")
    print("                  validate account legitimacy, and block the IP if malicious.")
else:
    print("No suspicious failed logins found.")

print("=" * 78)
