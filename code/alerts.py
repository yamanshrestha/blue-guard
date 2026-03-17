import json
from pathlib import Path


class AlertManager:
    def __init__(self):
        self.alerts = []

    def add_alert(self, alert):
        if alert:
            self.alerts.append(alert)

    def add_alerts(self, alerts):
        if not alerts:
            return
        for alert in alerts:
            self.add_alert(alert)

    def save_json(self, output_path):
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(self.alerts, f, indent=2)

    def print_summary(self):
        print("\n=== Detection Summary ===")
        print(f"Total alerts: {len(self.alerts)}")

        if not self.alerts:
            return

        counts_by_rule = {}
        for alert in self.alerts:
            rule = alert.get("rule", "unknown")
            counts_by_rule[rule] = counts_by_rule.get(rule, 0) + 1

        print("\nAlerts by rule:")
        for rule, count in sorted(counts_by_rule.items()):
            print(f"  - {rule}: {count}")

        print("\nSample alerts:")
        for alert in self.alerts[:5]:
            print(
                f"  [{alert.get('severity', 'N/A')}] "
                f"{alert.get('rule')} | "
                f"user={alert.get('username')} | "
                f"ip={alert.get('source_ip')} | "
                f"{alert.get('description')}"
            )