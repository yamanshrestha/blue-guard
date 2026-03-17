import argparse
from pathlib import Path

from patterns import parse_auth_line
from rules import DetectionEngine
from alerts import AlertManager


def process_log_file(log_path, output_path, year=None):
    log_file = Path(log_path)

    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    engine = DetectionEngine()
    alert_manager = AlertManager()

    total_lines = 0
    parsed_events = 0

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            event = parse_auth_line(line, year=year)

            if not event:
                continue

            parsed_events += 1
            alerts = engine.process_event(event)
            alert_manager.add_alerts(alerts)

    alert_manager.save_json(output_path)

    print("\n=== Run Complete ===")
    print(f"Input file: {log_file}")
    print(f"Total lines read: {total_lines}")
    print(f"Parsed security events: {parsed_events}")
    print(f"Output written to: {output_path}")

    alert_manager.print_summary()


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Log Anomaly Detector for Linux auth.log files"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input auth.log file"
    )
    parser.add_argument(
        "--output",
        default="output/alerts.json",
        help="Path to output JSON alerts file"
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to inject into auth.log timestamps (default: current year)"
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    process_log_file(
        log_path=args.input,
        output_path=args.output,
        year=args.year
    )


if __name__ == "__main__":
    main()